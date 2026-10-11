#!/bin/bash
# Test for the in-container "private server" script the wrapper uses for
# models/stats/debug/exec: it is extracted from bin/opencode-dockerized and run
# here with fake `opencode` and `curl` binaries (no Docker, no network).
#
# Usage: bash tests/server-script.test.sh

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export TMPDIR="${TMPDIR:-/tmp/opencode}"
mkdir -p "$TMPDIR" 2>/dev/null || export TMPDIR="/tmp"
TMP="$(mktemp -d -p "$TMPDIR")"
trap 'rm -r "$TMP" 2>/dev/null || true' EXIT

fail() {
    echo "FAIL: $1"
    [ -n "${OUT:-}" ] && printf '%s\n' "$OUT" | tail -10
    exit 1
}

# PRIVATE_SERVER_SCRIPT is a single-quoted assignment at the top of the wrapper.
SNIPPET="$(sed -n "/^PRIVATE_SERVER_SCRIPT='/,/^'\$/p" "$REPO_DIR/bin/opencode-dockerized")"
[ -n "$SNIPPET" ] || fail "could not extract PRIVATE_SERVER_SCRIPT"
eval "$SNIPPET"
[ -n "$PRIVATE_SERVER_SCRIPT" ] || fail "PRIVATE_SERVER_SCRIPT is empty after eval"

mkdir -p "$TMP/bin"
export PATH="$TMP/bin:$PATH"
export OPENCODE_STUB_LOG="$TMP/opencode.log"

# curl stub: the server answers readiness probes with the expected pattern.
cat >"$TMP/bin/curl" <<'STUB'
#!/bin/bash
echo '{"id":"model"}'
STUB
chmod +x "$TMP/bin/curl"

run_script() {
    # args: <ready_path> <pattern> <timeout> <opencode args...>
    OUT="$(timeout 20 bash -c "$PRIVATE_SERVER_SCRIPT" _ "$@" 2>&1)"
    RC=$?
}

# 1. Healthy server: the command runs against it and its status is returned.
cat >"$TMP/bin/opencode" <<'STUB'
#!/bin/bash
if [ "$1" = serve ]; then
    echo "listening on http://127.0.0.1:41234"
    exec sleep 30
fi
echo "ran: $*" >>"$OPENCODE_STUB_LOG"
exit 5
STUB
chmod +x "$TMP/bin/opencode"
run_script /api/model '"id"' 10 models
[ "$RC" -eq 5 ] || fail "the command's exit status must be returned (want 5, got $RC)"
grep -q 'ran: models --server http://127.0.0.1:41234' "$OPENCODE_STUB_LOG" ||
    fail "the command must run against the server URL"

# 2. A server that dies at once must fail fast, not wait for the whole timeout.
cat >"$TMP/bin/opencode" <<'STUB'
#!/bin/bash
echo "boom: cannot bind" >&2
exit 1
STUB
start=$SECONDS
run_script /api/model '"id"' 15 models
elapsed=$((SECONDS - start))
[ "$RC" -eq 1 ] || fail "a dead server must make the script fail (got $RC)"
[ "$elapsed" -lt 8 ] || fail "a dead server must be detected quickly (took ${elapsed}s of a 15s timeout)"
grep -q 'exited before it was ready' <<<"$OUT" || fail "the failure must say the server exited"
grep -q 'boom: cannot bind' <<<"$OUT" || fail "the server log must be shown"

# 3. A server that never becomes ready times out with its log.
cat >"$TMP/bin/opencode" <<'STUB'
#!/bin/bash
if [ "$1" = serve ]; then
    echo "starting..."
    exec sleep 30
fi
STUB
cat >"$TMP/bin/curl" <<'STUB'
#!/bin/bash
exit 22
STUB
run_script /api/model '"id"' 3 models
[ "$RC" -eq 1 ] || fail "a server that never gets ready must fail (got $RC)"
grep -q 'not ready after 3s' <<<"$OUT" || fail "the timeout message must name the limit"

# 4. The probe is bounded: a hung endpoint cannot stall the loop.
grep -q 'curl -sf --max-time' "$REPO_DIR/bin/opencode-dockerized" ||
    fail "the readiness probe must use curl --max-time"

echo "server-script test passed"
