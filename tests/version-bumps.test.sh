#!/bin/bash
# Test for scripts/check-version-bumps.sh: behavior-defining files must come with
# a bumped version marker (guard) or VERSION file (policy rule sets).
#
# Usage: bash tests/version-bumps.test.sh

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export TMPDIR="${TMPDIR:-/tmp/opencode}"
mkdir -p "$TMPDIR" 2>/dev/null || export TMPDIR="/tmp"
TMP="$(mktemp -d -p "$TMPDIR")"
trap 'rm -r "$TMP" 2>/dev/null || true' EXIT

fail() {
    echo "FAIL: $1"
    exit 1
}

export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid
export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid

R="$TMP/repo"
mkdir -p "$R/plugins" "$R/policies" "$R/scripts"
cp "$REPO_DIR/scripts/check-version-bumps.sh" "$R/scripts/"
cd "$R" || fail "cannot enter the temp repo"
git init -q -b master
printf 'const M = "OPENCODE_DOCKERIZED_GUARD_VERSION=1";\n' >plugins/security-guard.js
echo '[]' >policies/unsafe-tool-patterns.json
echo 1 >policies/VERSION
echo hello >README.md
git add -A && git commit -q -m base

check() { bash scripts/check-version-bumps.sh master >"$TMP/out" 2>&1; RC=$?; OUT="$(cat "$TMP/out")"; }
commit_all() { git add -A && git commit -q -m "$1"; }
reset_to_base() { git checkout -q -B work master; }

reset_to_base
echo more >>README.md; commit_all docs
check
[ "$RC" -eq 0 ] || fail "unrelated changes must pass ($OUT)"

reset_to_base
printf '// changed\n' >>plugins/security-guard.js; commit_all "guard change"
check
[ "$RC" -ne 0 ] || fail "a guard change without a version bump must fail"
grep -q 'security-guard.js' <<<"$OUT" || fail "the failure must name the guard"

reset_to_base
printf 'const M = "OPENCODE_DOCKERIZED_GUARD_VERSION=2";\n' >plugins/security-guard.js; commit_all "guard bump"
check
[ "$RC" -eq 0 ] || fail "a bumped guard must pass ($OUT)"

reset_to_base
echo '[{"id":"x","pattern":"y","reason":"z"}]' >policies/unsafe-tool-patterns.json; commit_all "policy change"
check
[ "$RC" -ne 0 ] || fail "a policy change without bumping policies/VERSION must fail"
grep -q 'policies/VERSION' <<<"$OUT" || fail "the failure must name policies/VERSION"

reset_to_base
echo '[{"id":"x","pattern":"y","reason":"z"}]' >policies/unsafe-tool-patterns.json
echo 2 >policies/VERSION; commit_all "policy bump"
check
[ "$RC" -eq 0 ] || fail "a bumped policy set must pass ($OUT)"

echo "version-bumps test passed"
