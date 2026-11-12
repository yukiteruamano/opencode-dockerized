#!/bin/bash
# Smoke test: every wrapper command runs its happy path (or its documented
# refusal) against a stub docker and a throw-away HOME. Deep behavior lives in
# the dedicated flow tests (run, update, install, profile, doctor); this test
# guards the command surface itself: a command that breaks at dispatch, help
# drift, or a refusal that stops refusing.
#
# Usage: bash tests/commands-smoke.test.sh

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export TMPDIR="${TMPDIR:-/tmp/opencode}"
mkdir -p "$TMPDIR" 2>/dev/null || export TMPDIR="/tmp"
TMP="$(mktemp -d -p "$TMPDIR")"
trap 'rm -r "$TMP" 2>/dev/null || true' EXIT

export HOME="$TMP/home"
export CONFIG_DIR="$TMP/cfg"
export OPENCODE_DOCKERIZED_ALLOW_CONTAINER_SYNC=1
export NO_COLOR=1
mkdir -p "$HOME" "$TMP/proj" "$TMP/bin"
export PATH="$REPO_DIR/bin:$TMP/bin:$PATH"

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

W="$REPO_DIR/bin/opencode-dockerized"
failures=0
check() {
    # check <desc> <want_rc> <must_match> [env=val ...] -- <args...>
    local desc="$1" want_rc="$2" must="$3"
    shift 3
    local -a envs=()
    while [ "$1" != "--" ]; do
        envs+=("$1")
        shift
    done
    shift
    local out rc
    out="$(env "${envs[@]}" "$W" "$@" </dev/null 2>&1)"
    rc=$?
    if [ "$rc" -ne "$want_rc" ]; then
        failures=$((failures + 1))
        echo "FAIL [$desc] rc=$rc (want $want_rc)"
        printf '%s\n' "$out" | tail -5
        return
    fi
    if [ -n "$must" ] && ! grep -q -- "$must" <<<"$out"; then
        failures=$((failures + 1))
        echo "FAIL [$desc] output lacks '$must'"
        printf '%s\n' "$out" | tail -5
    fi
}

# Informational and local-only commands.
check "help" 0 "Usage:" -- help
check "version" 0 "GUARD_VERSION" -- version
check "uninstall" 0 "PATH line" -- uninstall
check "unknown command" 1 "Unknown command" -- definitely-not-a-command
check "config path" 0 "$CONFIG_DIR/profiles/default/config" -- config path
check "config init (creates)" 0 "" -- config init
check "config init (idempotent)" 0 "already exists" -- config init
check "config show" 0 "Profile: default" -- config show
check "config edit" 0 "" EDITOR=true -- config edit
check "config sync" 0 "" -- config sync
check "config sync --check" 0 "in sync" -- config sync --check
check "config opencode path" 0 "/.config/opencode/opencode.json" -- config opencode path
check "config opencode edit" 0 "" EDITOR=true -- config opencode edit
check "config badsub" 1 "Unknown config subcommand" -- config frobnicate

# Container-backed commands against the stub.
check "run DIR" 0 "" -- run "$TMP/proj"
check "run extra args" 1 "Unexpected argument" -- run "$TMP/proj" extra args
check "auth" 0 "Authentication complete" -- auth
check "models" 0 "" -- models
check "exec MSG" 0 "" -- exec "hello"
check "stats" 0 "" -- stats
check "debug (paths)" 0 "" -- debug
check "doctor" 0 "== container ==" -- doctor
check "build" 0 "" -- build
check "clean" 0 "" -- clean
check "mcp (list)" 0 "" -- mcp
check "plugin (list)" 0 "" -- plugin

# Self-management (network-dependent update/upgrade live in update-flow.test.sh).
check "install --yes --only config" 0 "" -- install --yes --only config
check "rollback (stubbed previous)" 0 "restored" -- rollback

# Host-only refusals must keep refusing.
check "mcp add is host-only" 1 "read-only" -- mcp add some-server
check "plugin add is host-only" 1 "read-only" -- plugin add some-plugin
check "plugin remove is host-only" 1 "read-only" -- plugin remove some-plugin

# Profile surface (deep coverage in tests/profile-flow.test.sh).
check "profile list" 0 "default \*" -- profile list
check "profile current" 0 "default" -- profile current
check "profile path" 0 "$CONFIG_DIR" -- profile path
check "profile create" 0 "created" -- profile create smoke
# The config template must be seeded before the sync parses it: no warning.
OUT="$("$W" profile create smoke2 2>&1 </dev/null)" || { failures=$((failures + 1)); echo "FAIL [profile create smoke2]"; }
if grep -q "Config file not found" <<<"$OUT"; then
    failures=$((failures + 1))
    echo "FAIL [profile create] must seed the config before syncing (got a not-found warning)"
fi
check "profile badsub" 1 "Unknown profile subcommand" -- profile frobnicate
check "--profile run" 0 "" -- --profile smoke run "$TMP/proj"
check "--profile doctor" 0 "Profile: smoke" -- --profile smoke doctor
check "profile remove needs confirm" 1 "--yes" -- profile remove smoke2
check "profile remove --yes" 0 "removed" -- profile remove smoke2 --yes
check "profile remove --yes (smoke)" 0 "removed" -- profile remove smoke --yes
check "invalid profile name" 1 "Invalid profile name" -- --profile "bad/../name" config path

# Every command that starts OpenCode must bring its own server: --standalone or
# the private server (`opencode serve` + --server). The background service
# rewrites a legacy ~/.config/opencode/service.json, which is read-only in the
# container (EROFS), and listens on a fixed localhost port shared with the host
# under --network host.
server_mode_check() {
    local desc="$1"
    shift
    : >"$DOCKER_STUB_LOG"
    "$W" "$@" </dev/null >/dev/null 2>&1
    if grep -q -- ' private-server /api/' "$DOCKER_STUB_LOG"; then
        return
    fi
    if grep -q -- '--standalone' "$DOCKER_STUB_LOG"; then
        return
    fi
    failures=$((failures + 1))
    echo "FAIL [$desc] starts OpenCode without --standalone or the private server (background service)"
    grep '^run ' "$DOCKER_STUB_LOG" | tail -1 | cut -c1-200
}
server_mode_check "run" run "$TMP/proj"
server_mode_check "auth" auth
server_mode_check "models" models
server_mode_check "exec" exec "hello"
server_mode_check "stats" stats
server_mode_check "debug" debug
server_mode_check "mcp (list)" mcp
server_mode_check "mcp auth" mcp auth Composio
server_mode_check "mcp logout" mcp logout Composio
server_mode_check "plugin (list)" plugin
server_mode_check "plugin check" plugin check
# The subcommand and its arguments reach the CLI unchanged.
: >"$DOCKER_STUB_LOG"
"$W" mcp auth Composio </dev/null >/dev/null 2>&1
grep -q -- ' private-server /api/config \. [0-9]* mcp auth Composio$' "$DOCKER_STUB_LOG" || {
    failures=$((failures + 1))
    echo "FAIL [mcp auth] must pass 'mcp auth Composio' to the private server"
}

# Every dispatched command must be documented in help (catches drift the
# completions test, which reads help, would then propagate silently).
help_out="$("$W" help 2>&1)"
for cmd in run auth models exec mcp plugin stats debug doctor install upgrade \
    build update rollback uninstall version config profile clean help; do
    grep -qE "^    $cmd( |$)" <<<"$help_out" || {
        failures=$((failures + 1))
        echo "FAIL help does not document the '$cmd' command"
    }
done

if [ "$failures" -gt 0 ]; then
    echo "$failures failure(s)"
    exit 1
fi
echo "commands smoke test passed"
