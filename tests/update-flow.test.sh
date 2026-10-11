#!/bin/bash
# Contract test for the self-update flow (`upgrade`/`update`). No Docker needed:
# a throwaway checkout of this repo is cloned from a local bare origin and the
# wrapper runs from that clone with `--check` / `--no-build`.
#
# Usage: bash tests/update-flow.test.sh

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export TMPDIR="${TMPDIR:-/tmp/opencode}"
mkdir -p "$TMPDIR" 2>/dev/null || export TMPDIR="/tmp"
TMP="$(mktemp -d -p "$TMPDIR")"
trap 'rm -r "$TMP" 2>/dev/null || true' EXIT

fail() {
    echo "FAIL: $1"
    [ -n "${OUT:-}" ] && printf '%s\n' "$OUT" | tail -15
    exit 1
}

export HOME="$TMP/home"
export CONFIG_DIR="$TMP/cfg"
export OCODE_HOME="$CONFIG_DIR/home"
export OPENCODE_DOCKERIZED_ALLOW_CONTAINER_SYNC=1
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid
export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
mkdir -p "$HOME"

# Seed repo = tracked files of this checkout (working-tree content, so the test
# exercises uncommitted wrapper changes too).
SEED="$TMP/seed"
mkdir -p "$SEED"
(cd "$REPO_DIR" && git ls-files -z | xargs -0 -I{} cp --parents {} "$SEED/") ||
    fail "could not stage the seed tree"
git -C "$SEED" init -q -b master
git -C "$SEED" add -A
git -C "$SEED" commit -q -m seed
git clone -q --bare "$SEED" "$TMP/origin.git"
git clone -q "$TMP/origin.git" "$TMP/install"
git clone -q "$TMP/origin.git" "$TMP/other"
# Simulate an installed user: the clone's bin/ is on PATH (check_global_install).
export PATH="$TMP/install/bin:$PATH"
WRAPPER="$TMP/install/bin/opencode-dockerized"

run() {
    OUT="$("$@" 2>&1)"
    RC=$?
}

push_upstream_commit() {
    (cd "$TMP/other" && git pull -q --ff-only && echo "$1" >>CHANGELOG.test && git add -A &&
        git commit -q -m "$1" && git push -q origin HEAD:master)
}

# 1. Up to date: --check must succeed (exit 0), not abort under `set -e`.
run "$WRAPPER" upgrade --check
[ "$RC" -eq 0 ] || fail "upgrade --check on an up-to-date checkout must exit 0 (got $RC)"
grep -q 'Already up to date' <<<"$OUT" || fail "up-to-date message missing"

# 2. Up to date: update --no-build must still sync the security layer and finish.
run "$WRAPPER" update --no-build
[ "$RC" -eq 0 ] || fail "update --no-build on an up-to-date checkout must exit 0 (got $RC)"
grep -q 'Upgrade complete' <<<"$OUT" || fail "update must report completion when already up to date"

# 3. Behind upstream: --check reports it with the documented exit code (10).
push_upstream_commit one
run "$WRAPPER" upgrade --check
[ "$RC" -eq 10 ] || fail "upgrade --check with an update available must exit 10 (got $RC)"
grep -q 'Update available' <<<"$OUT" || fail "update-available message missing"
[ "$(git -C "$TMP/install" rev-parse HEAD)" != "$(git -C "$TMP/origin.git" rev-parse master)" ] ||
    fail "--check must not modify the checkout"

# 4. Behind upstream: update --no-build pulls exactly the upstream head.
run "$WRAPPER" update --no-build
[ "$RC" -eq 0 ] || fail "update --no-build must succeed when behind (got $RC)"
[ "$(git -C "$TMP/install" rev-parse HEAD)" = "$(git -C "$TMP/origin.git" rev-parse master)" ] ||
    fail "update must fast-forward to the upstream head"

# 5. Diverged: refuse, leave the checkout untouched, exit 1.
push_upstream_commit two
(cd "$TMP/install" && echo local >LOCAL.test && git add -A && git commit -q -m local)
local_head="$(git -C "$TMP/install" rev-parse HEAD)"
run "$WRAPPER" upgrade --yes --no-build
[ "$RC" -eq 1 ] || fail "a diverged checkout must exit 1 (got $RC)"
[ "$(git -C "$TMP/install" rev-parse HEAD)" = "$local_head" ] ||
    fail "a diverged checkout must not be modified"

echo "update-flow test passed"
