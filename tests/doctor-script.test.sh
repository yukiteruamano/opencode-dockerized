#!/bin/bash
# Test for the in-container doctor script: extracted from bin/opencode-dockerized
# and run against a fake root (OCD_DOCTOR_ROOT) that mimics the container layout.
#
# Usage: bash tests/doctor-script.test.sh

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export TMPDIR="${TMPDIR:-/tmp/opencode}"
mkdir -p "$TMPDIR" 2>/dev/null || export TMPDIR="/tmp"
TMP="$(mktemp -d -p "$TMPDIR")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -r "$TMP" 2>/dev/null || true' EXIT

fail() {
    echo "FAIL: $1"
    [ -n "${OUT:-}" ] && printf '%s\n' "$OUT" | tail -25
    exit 1
}

SNIPPET="$(sed -n "/^DOCTOR_SCRIPT='/,/^'\$/p" "$REPO_DIR/bin/opencode-dockerized")"
[ -n "$SNIPPET" ] || fail "could not extract DOCTOR_SCRIPT"
eval "$SNIPPET"

# Fake container root: guard present, config tree read-only, one skill, scratch
# dir and cgroup limits in place.
build_root() {
    R="$TMP/root-$1"
    rm -rf "$R" 2>/dev/null
    mkdir -p "$R/home/coder/.config/opencode/plugins" "$R/home/coder/.claude/skills/review" \
        "$R/home/coder/.agents/skills/lint" "$R/tmp/opencode" "$R/sys/fs/cgroup"
    echo '// OPENCODE_DOCKERIZED_GUARD_VERSION=20' >"$R/home/coder/.config/opencode/plugins/security-guard.js"
    : >"$R/home/coder/.claude/skills/review/SKILL.md"
    : >"$R/home/coder/.agents/skills/lint/SKILL.md"
    echo 4096 >"$R/sys/fs/cgroup/pids.max"
    echo 2147483648 >"$R/sys/fs/cgroup/memory.max"
    chmod a-w "$R/home/coder/.config/opencode" "$R/home/coder/.claude/skills" "$R/home/coder/.agents/skills"
}

run_doctor() {
    OUT="$(OCD_DOCTOR_ROOT="$R" bash -c "$DOCTOR_SCRIPT" 2>&1)"
    RC=$?
}

# 1. Healthy container.
build_root ok
run_doctor
[ "$RC" -eq 0 ] || fail "a healthy layout must pass (got $RC)"
grep -q 'config dir: read-only' <<<"$OUT" || fail "doctor must confirm the config dir is read-only"
grep -q 'skills (claude): 1' <<<"$OUT" || fail "doctor must count the claude skills"
grep -q 'skills (agents): 1' <<<"$OUT" || fail "doctor must count the agents skills"
grep -q 'scratch /tmp/opencode: writable' <<<"$OUT" || fail "doctor must confirm the scratch dir"
grep -q 'pids limit: 4096' <<<"$OUT" || fail "doctor must report the pids limit"

# 2. A writable config tree is a problem (the read-only mount is the guard's anchor).
build_root writable-config
chmod u+w "$R/home/coder/.config/opencode"
run_doctor
[ "$RC" -ne 0 ] || fail "a writable config dir must fail the check"
grep -q 'config dir: WRITABLE' <<<"$OUT" || fail "the writable config dir must be named"

# 3. Writable skills are a problem too.
build_root writable-skills
chmod u+w "$R/home/coder/.claude/skills"
run_doctor
[ "$RC" -ne 0 ] || fail "writable skills must fail the check"
grep -q 'skills (claude): WRITABLE' <<<"$OUT" || fail "writable skills must be named"

# 4. No process cap means the wrapper's --pids-limit did not apply.
build_root nolimit
echo max >"$R/sys/fs/cgroup/pids.max"
run_doctor
[ "$RC" -ne 0 ] || fail "a missing pids limit must fail the check"
grep -q 'pids limit: NONE' <<<"$OUT" || fail "the missing pids limit must be named"

# 5. A missing scratch dir is a problem.
build_root noscratch
rmdir "$R/tmp/opencode"
run_doctor
[ "$RC" -ne 0 ] || fail "a missing scratch dir must fail the check"
grep -q 'scratch /tmp/opencode: MISSING' <<<"$OUT" || fail "the missing scratch dir must be named"

echo "doctor-script test passed"
