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
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
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

# 4b. A pull shows what it brings (U6), warns when the security layer changes,
# records the previous revision for rollback (U5) and re-executes the freshly
# pulled script instead of continuing with the old one (U3).
prev_head="$(git -C "$TMP/install" rev-parse HEAD)"
(cd "$TMP/other" && git pull -q --ff-only && echo '// touched' >>plugins/security-guard.js &&
    git add -A && git commit -q -m "tweak guard three" && git push -q origin HEAD:master)
run "$WRAPPER" update --no-build
[ "$RC" -eq 0 ] || fail "update --no-build must succeed with a guard change (got $RC)"
grep -q 'tweak guard three' <<<"$OUT" || fail "the incoming commit subjects must be listed"
grep -q 'security layer' <<<"$OUT" || fail "a change under plugins/ must be flagged as touching the security layer"
grep -q 'Restarting with the updated code' <<<"$OUT" || fail "update must re-exec the pulled wrapper"
[ "$(cat "$CONFIG_DIR/.previous-rev" 2>/dev/null)" = "$prev_head" ] ||
    fail "the pre-pull revision must be saved for rollback"

# 4c. Signature verification is opt-in and fails closed (the seed commits are unsigned).
push_upstream_commit four
before="$(git -C "$TMP/install" rev-parse HEAD)"
OCD_VERIFY_SIGNATURES=true run "$WRAPPER" update --no-build
[ "$RC" -eq 1 ] || fail "unsigned upstream commit must be refused with OCD_VERIFY_SIGNATURES=true (got $RC)"
[ "$(git -C "$TMP/install" rev-parse HEAD)" = "$before" ] ||
    fail "a refused pull must not move HEAD"

# 4d. Machine-readable --check.
run "$WRAPPER" upgrade --check --json
[ "$RC" -eq 10 ] || fail "--check --json must keep exit code 10 (got $RC)"
grep -q '"status":"available"' <<<"$OUT" || fail "--json must report status available"

# 4e. Concurrent runs are refused while the lock is held.
if command -v flock >/dev/null 2>&1; then
    mkdir -p "$CONFIG_DIR"
    (
        exec 8>"$CONFIG_DIR/.lock"
        flock -n 8 && sleep 4
    ) &
    holder=$!
    sleep 1
    run "$WRAPPER" update --no-build
    [ "$RC" -eq 1 ] || fail "update must refuse to run while another instance holds the lock (got $RC)"
    grep -q 'already running' <<<"$OUT" || fail "lock refusal message missing"
    wait "$holder" 2>/dev/null
fi

# 4f. Without flock (macOS) an atomic mkdir lock is used and released on exit.
NOFLOCK="$TMP/noflock-bin"
mkdir -p "$NOFLOCK"
for f in /usr/bin/* /bin/*; do
    [ "${f##*/}" = flock ] || ln -sf "$f" "$NOFLOCK/${f##*/}" 2>/dev/null
done
PATH_BACKUP="$PATH"
export PATH="$TMP/install/bin:$NOFLOCK"
run "$WRAPPER" update --no-build
[ "$RC" -eq 0 ] || fail "update --no-build without flock must succeed (got $RC)"
[ ! -d "$CONFIG_DIR/.lock.d" ] || fail "the mkdir lock must be released on exit"
mkdir "$CONFIG_DIR/.lock.d"
run "$WRAPPER" update --no-build
[ "$RC" -eq 1 ] || fail "a held mkdir lock must refuse a second run (got $RC)"
grep -q 'already running' <<<"$OUT" || fail "mkdir-lock refusal message missing"
rmdir "$CONFIG_DIR/.lock.d"
export PATH="$PATH_BACKUP"

# 5. Diverged: refuse, leave the checkout untouched, exit 1.
push_upstream_commit two
(cd "$TMP/install" && echo local >LOCAL.test && git add -A && git commit -q -m local)
local_head="$(git -C "$TMP/install" rev-parse HEAD)"
run "$WRAPPER" upgrade --yes --no-build
[ "$RC" -eq 1 ] || fail "a diverged checkout must exit 1 (got $RC)"
[ "$(git -C "$TMP/install" rev-parse HEAD)" = "$local_head" ] ||
    fail "a diverged checkout must not be modified"

echo "update-flow test passed"
