#!/bin/bash
# Contract test for `run` against a stub `docker`: the stub records its arguments
# and returns the exit code it is told to, so the wrapper's docker flags, exit
# code propagation and signal handling can be checked without a daemon.
#
# Usage: bash tests/run-flow.test.sh

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
mkdir -p "$HOME" "$TMP/proj" "$TMP/bin"
export PATH="$REPO_DIR/bin:$TMP/bin:$PATH"

# Stub docker: log every call; `run` returns $DOCKER_STUB_RC.
export DOCKER_STUB_LOG="$TMP/docker.log"
cat >"$TMP/bin/docker" <<'STUB'
#!/bin/bash
echo "$*" >>"$DOCKER_STUB_LOG"
case "$1" in
run) exit "${DOCKER_STUB_RC:-0}" ;;
*) exit 0 ;;
esac
STUB
chmod +x "$TMP/bin/docker"

WRAPPER="$REPO_DIR/bin/opencode-dockerized"
run_wrapper() {
    : >"$DOCKER_STUB_LOG"
    OUT="$("$WRAPPER" "$@" 2>&1 </dev/null)"
    RC=$?
    # Only a command the wrapper does not handle may be reported as unexpected.
    if [ "${EXPECT_UNEXPECTED:-false}" != true ] && grep -q 'unexpected failure' <<<"$OUT"; then
        fail "spurious 'unexpected failure' report for: $*"
    fi
}
docker_run_line() { grep -m1 '^run ' "$DOCKER_STUB_LOG"; }

# 1. A normal run: the container gets an init process (zombie reaping, signals).
run_wrapper run "$TMP/proj"
[ "$RC" -eq 0 ] || fail "run must succeed with a stub docker (got $RC)"
docker_run_line | grep -q -- ' --init ' || fail "docker run must use --init"

# 1b. Safe defaults every session gets: process cap, scratch tmpfs, locale, label.
line="$(docker_run_line)"
grep -q -- ' --pids-limit 4096 ' <<<"$line" || fail "docker run must cap processes (--pids-limit 4096)"
grep -q -- ' --tmpfs /tmp/opencode:rw,' <<<"$line" || fail "the advertised scratch dir needs a tmpfs"
grep -q -- ' -e LANG=C.UTF-8 ' <<<"$line" || fail "LANG must default to C.UTF-8"
grep -q -- ' --label opencode-dockerized=1 ' <<<"$line" || fail "containers must carry the opencode-dockerized label"
if grep -q -- 'host.docker.internal' <<<"$line"; then
    fail "host.docker.internal mapping is only for bridge networking"
fi
TZ=Europe/Madrid LC_ALL=es_ES.UTF-8 run_wrapper run "$TMP/proj"
line="$(docker_run_line)"
grep -q -- ' -e TZ=Europe/Madrid ' <<<"$line" || fail "TZ must be forwarded when set"
grep -q -- ' -e LC_ALL=es_ES.UTF-8 ' <<<"$line" || fail "LC_ALL must be forwarded when set"

# 1c. Resource limits: memory also pins swap; a zero limit is rejected.
mkdir -p "$CONFIG_DIR"
printf 'setting.memory=2g\nsetting.pids_limit=512\nsetting.network=bridge\n' >"$CONFIG_DIR/config"
run_wrapper run "$TMP/proj"
line="$(docker_run_line)"
grep -q -- ' --memory 2g ' <<<"$line" || fail "setting.memory must reach docker"
grep -q -- ' --memory-swap 2g ' <<<"$line" || fail "memory must pin swap to the same value"
grep -q -- ' --pids-limit 512 ' <<<"$line" || fail "setting.pids_limit must override the default"
grep -q -- ' --add-host host.docker.internal:host-gateway ' <<<"$line" ||
    fail "bridge networking must map host.docker.internal"
printf 'setting.memory=0g\nsetting.pids_limit=0\n' >"$CONFIG_DIR/config"
run_wrapper run "$TMP/proj"
line="$(docker_run_line)"
if grep -q -- ' --memory ' <<<"$line"; then fail "a zero memory limit must be ignored"; fi
grep -q -- ' --pids-limit 4096 ' <<<"$line" || fail "an invalid pids_limit must fall back to the default"
rm -f "$CONFIG_DIR/config"

# 2. The container's exit code is propagated; only real failures are reported.
DOCKER_STUB_RC=3 run_wrapper run "$TMP/proj"
[ "$RC" -eq 3 ] || fail "run must exit with the container's code (want 3, got $RC)"
grep -q 'exited with code 3' <<<"$OUT" || fail "a non-zero exit must name the code"

for code in 130 143; do
    DOCKER_STUB_RC=$code run_wrapper run "$TMP/proj"
    [ "$RC" -eq "$code" ] || fail "interrupt code $code must be propagated (got $RC)"
    if grep -q 'exited with' <<<"$OUT"; then
        fail "a user interrupt ($code) must not be reported as a failure"
    fi
done

# 3. One-off commands propagate the code too.
DOCKER_STUB_RC=7 run_wrapper exec "hello"
[ "$RC" -eq 7 ] || fail "exec must propagate the container's code (want 7, got $RC)"

# 3b. Temp files go to a private per-user dir (mode 700), not a shared /tmp name.
cat >"$TMP/bin/docker" <<'STUB'
#!/bin/bash
echo "$*" >>"$DOCKER_STUB_LOG"
[ "$1" = run ] && echo "TMPDIR=$TMPDIR" >>"$DOCKER_STUB_LOG"
exit 0
STUB
mkdir -p "$TMP/xdg"
chmod 755 "$TMP/xdg"
: >"$DOCKER_STUB_LOG"
OUT="$(env -u TMPDIR XDG_RUNTIME_DIR="$TMP/xdg" "$WRAPPER" run "$TMP/proj" 2>&1 </dev/null)"
want="$TMP/xdg/opencode-$(id -u)"
grep -qx "TMPDIR=$want" "$DOCKER_STUB_LOG" || fail "TMPDIR must default to \$XDG_RUNTIME_DIR/opencode-<uid> (log: $(grep TMPDIR "$DOCKER_STUB_LOG"))"
[ "$(stat -c %a "$want" 2>/dev/null || stat -f %Lp "$want")" = 700 ] || fail "the private temp dir must be mode 700"
# A pre-existing world-readable dir is tightened, not trusted as is.
chmod 755 "$want"
OUT="$(env -u TMPDIR XDG_RUNTIME_DIR="$TMP/xdg" "$WRAPPER" run "$TMP/proj" 2>&1 </dev/null)"
[ "$(stat -c %a "$want" 2>/dev/null || stat -f %Lp "$want")" = 700 ] || fail "an existing temp dir must be re-tightened to 700"

# 3c. `clean` removes dead relay dirs but never a live session's.
RELAYS="$CONFIG_DIR/gnupg-relay"
mkdir -p "$RELAYS/live" "$RELAYS/dead" "$RELAYS/fresh"
sleep 30 &
live_pid=$!
echo "$live_pid" >"$RELAYS/live/pid"
(exit 0) &
dead_pid=$!
wait "$dead_pid"
echo "$dead_pid" >"$RELAYS/dead/pid"
# `fresh` has no pid yet (a session is still starting): it must survive too.
cat >"$TMP/bin/docker" <<'STUB'
#!/bin/bash
echo "$*" >>"$DOCKER_STUB_LOG"
exit 0
STUB
run_wrapper clean
kill "$live_pid" 2>/dev/null
[ "$RC" -eq 0 ] || fail "clean must succeed (got $RC)"
[ -d "$RELAYS/live" ] || fail "clean must not remove the relay of a live session"
[ -d "$RELAYS/fresh" ] || fail "clean must not remove a relay dir that is still being created"
[ ! -d "$RELAYS/dead" ] || fail "clean must remove the relay dir of a dead session"

# 4. An unexpected failure under set -e names the command and line.
cat >"$TMP/bin/docker" <<'STUB'
#!/bin/bash
echo "$*" >>"$DOCKER_STUB_LOG"
case "$1" in
build) exit 1 ;;
*) exit 0 ;;
esac
STUB
EXPECT_UNEXPECTED=true run_wrapper build
[ "$RC" -ne 0 ] || fail "a failing docker build must fail the wrapper"
grep -q 'unexpected failure' <<<"$OUT" || fail "an unexpected failure must be explained, not silent"
grep -q 'docker build' <<<"$OUT" || fail "the failing command must be named"

echo "run-flow test passed"
