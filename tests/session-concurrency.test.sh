#!/bin/bash
# Concurrency contract for SSH/GnuPG forwarding: two sessions of the same
# profile run side by side without touching each other's agent plumbing.
#   1. Two real `run` wrappers (stub docker keeps each "container" alive until
#      released) with SSH and GnuPG forwarding, a forced relay and fake agents:
#      separate relays, shared agents untouched, a read-only mirror, and one
#      session ending never breaks the other.
#   2. entrypoint.sh gives each container its own GNUPGHOME seeded from the
#      read-only mirror (stub gpgconf).
#   3. With a keyboxd-capable GnuPG on the host: the real failure this design
#      prevents (one container's exit killing the shared keyboxd) stays fixed.
#
# Usage: bash tests/session-concurrency.test.sh

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export TMPDIR="${TMPDIR:-/tmp/opencode}"
mkdir -p "$TMPDIR" 2>/dev/null || export TMPDIR="/tmp"
TMP="$(mktemp -d -p "$TMPDIR")"
BG_PIDS=()
cleanup() {
    local p
    : >"$TMP/stub/release-all" 2>/dev/null
    for p in "${BG_PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    [ -n "${GPG_REAL_HOME:-}" ] && gpgconf --homedir "$GPG_REAL_HOME" --kill all >/dev/null 2>&1
    [ -n "${GPG_REAL_B:-}" ] && gpgconf --homedir "$GPG_REAL_B" --kill all >/dev/null 2>&1
    chmod -R u+w "$TMP" 2>/dev/null
    rm -r "$TMP" 2>/dev/null || true
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1"
    exit 1
}

# Wait up to ~10s for a condition.
# Usage: wait_for CMD...
wait_for() {
    local _
    for _ in $(seq 100); do
        "$@" && return 0
        sleep 0.1
    done
    return 1
}

# ---------------------------------------------------------------------------
# 1. Two concurrent wrapper sessions
# ---------------------------------------------------------------------------
if command -v node >/dev/null 2>&1; then
    export HOME="$TMP/home"
    export CONFIG_DIR="$TMP/cfg"
    export NO_COLOR=1
    export OPENCODE_DOCKERIZED_ALLOW_CONTAINER_SYNC=1
    unset OCODE_HOME OPENCODE_DOCKERIZED_PROFILE SSH_AUTH_SOCK
    mkdir -p "$HOME" "$TMP/pa" "$TMP/pb" "$TMP/bin" "$TMP/stub"
    export PATH="$TMP/bin:$PATH"
    PROFILE_DIR="$CONFIG_DIR/profiles/default"
    RELAYS="$CONFIG_DIR/gnupg-relay"

    # Stub docker: `run` records its arguments and blocks, like a running
    # container, until the test releases it (release-<name> or release-all).
    export DOCKER_STUB_DIR="$TMP/stub"
    cat >"$TMP/bin/docker" <<'STUB'
#!/bin/bash
[ "$1" = run ] || exit 0
name="" prev=""
for a in "$@"; do
    [ "$prev" = --name ] && name="$a"
    prev="$a"
done
printf '%s\n' "$*" >"$DOCKER_STUB_DIR/run-$name"
: >"$DOCKER_STUB_DIR/started-$name"
until [ -e "$DOCKER_STUB_DIR/release-$name" ] || [ -e "$DOCKER_STUB_DIR/release-all" ]; do sleep 0.1; done
exit 0
STUB
    chmod +x "$TMP/bin/docker"

    # Fake host agents: listening unix sockets. The relay is a node listener
    # too (test hook), so no socat is needed.
    serve_socket() {
        node -e 'require("net").createServer((c) => c.end()).listen(process.argv[1])' "$1" >/dev/null 2>&1 &
        BG_PIDS+=("$!")
        wait_for test -S "$1" || fail "could not create the test socket $1"
    }
    export SSH_AUTH_SOCK="$TMP/ssh-agent.sock"
    serve_socket "$SSH_AUTH_SOCK"
    export GPG_AGENT_EXTRA_SOCKET="$TMP/gpg-extra.sock"
    serve_socket "$GPG_AGENT_EXTRA_SOCKET"
    export GPG_AGENT_SOCKET="$TMP/gpg-main.sock"
    printf 'require("net").createServer((c) => c.end()).listen(process.env.RELAY_SOCK)\n' >"$TMP/relay.js"
    export OPENCODE_DOCKERIZED_TEST_HOOKS=1 GPG_RELAY_FORCE=true GPG_RELAY_CMD="node $TMP/relay.js"

    # Host GnuPG home with public material (and a private key that must never
    # be mirrored).
    export GNUPGHOME="$TMP/hostgpg"
    mkdir -m 700 "$GNUPGHOME" "$GNUPGHOME/private-keys-v1.d"
    printf 'PUB\n' >"$GNUPGHOME/pubring.kbx"
    printf 'keyid-format long\n' >"$GNUPGHOME/gpg.conf"
    : >"$GNUPGHOME/private-keys-v1.d/secret.key"

    mkdir -p "$PROFILE_DIR"
    printf 'setting.ssh_agent_support=true\nsetting.gpg_agent_support=true\nsetting.gpg_autostart_agent=false\n' \
        >"$PROFILE_DIR/config"

    # Start session A and wait until its "container" runs.
    "$REPO_DIR/bin/opencode-dockerized" run "$TMP/pa" </dev/null >"$TMP/a.out" 2>&1 &
    pid_a=$!
    BG_PIDS+=("$pid_a")
    started() { compgen -G "$DOCKER_STUB_DIR/started-*$1*" >/dev/null; }
    wait_for started pa || {
        cat "$TMP/a.out"
        fail "session A did not start"
    }
    name_a="$(basename "$(compgen -G "$DOCKER_STUB_DIR/started-*pa*")")"
    name_a="${name_a#started-}"
    relay_a="$RELAYS/$pid_a/relay.sock"
    [ -S "$relay_a" ] || fail "session A must run its own GnuPG relay ($relay_a)"
    relay_a_pid="$(cat "$RELAYS/$pid_a/pid")"

    # Start session B while A is running.
    "$REPO_DIR/bin/opencode-dockerized" run "$TMP/pb" </dev/null >"$TMP/b.out" 2>&1 &
    pid_b=$!
    BG_PIDS+=("$pid_b")
    wait_for started pb || {
        cat "$TMP/b.out"
        fail "session B did not start while A was running"
    }
    name_b="$(basename "$(compgen -G "$DOCKER_STUB_DIR/started-*pb*")")"
    name_b="${name_b#started-}"
    relay_b="$RELAYS/$pid_b/relay.sock"

    [ "$name_a" != "$name_b" ] || fail "concurrent sessions must get distinct container names"
    [ -S "$relay_b" ] || fail "session B must run its own GnuPG relay"
    [ "$relay_a" != "$relay_b" ] || fail "sessions must not share a relay socket"
    [ -S "$relay_a" ] && kill -0 "$relay_a_pid" 2>/dev/null ||
        fail "starting session B must not stop or remove session A's relay"
    [ -S "$SSH_AUTH_SOCK" ] && [ -S "$GPG_AGENT_EXTRA_SOCKET" ] ||
        fail "starting a session must never touch the host agent sockets"
    [ "$(find "$PROFILE_DIR/sessions" -type f | wc -l)" -eq 2 ] ||
        fail "both live sessions must be registered"

    run_a="$(cat "$DOCKER_STUB_DIR/run-$name_a")"
    run_b="$(cat "$DOCKER_STUB_DIR/run-$name_b")"
    for line in "$run_a" "$run_b"; do
        grep -qF -- "type=bind,source=$SSH_AUTH_SOCK,target=$SSH_AUTH_SOCK" <<<"$line" ||
            fail "each session must mount the host SSH agent socket"
        grep -qF -- "type=bind,source=$PROFILE_DIR/home/.gnupg,target=/home/coder/.gnupg-mirror,readonly" <<<"$line" ||
            fail "each session must mount the shared GnuPG mirror read-only"
        grep -qF -- '-e GNUPGHOME=/home/coder/.gnupg ' <<<"$line" ||
            fail "each session must use its own GNUPGHOME"
        grep -qF -- '-e OPENCODE_DOCKERIZED_GPG_AGENT_SOCK=/home/coder/.gnupg-agent/S.gpg-agent ' <<<"$line" ||
            fail "each session must announce its agent socket to the entrypoint"
    done
    grep -qF -- "source=$relay_a,target=/home/coder/.gnupg-agent/S.gpg-agent" <<<"$run_a" ||
        fail "session A must mount its own relay as the agent socket"
    grep -qF -- "source=$relay_b,target=/home/coder/.gnupg-agent/S.gpg-agent" <<<"$run_b" ||
        fail "session B must mount its own relay as the agent socket"
    [ ! -e "$PROFILE_DIR/home/.gnupg/S.gpg-agent" ] && [ ! -L "$PROFILE_DIR/home/.gnupg/S.gpg-agent" ] ||
        fail "the shared mirror must not get runtime entries"
    [ ! -e "$PROFILE_DIR/home/.gnupg/private-keys-v1.d" ] || fail "private keys must never be mirrored"

    # B ends first: its relay goes, A's stays alive.
    : >"$DOCKER_STUB_DIR/release-$name_b"
    wait "$pid_b"
    rc_b=$?
    [ "$rc_b" -eq 0 ] || {
        cat "$TMP/b.out"
        fail "session B must exit cleanly (got $rc_b)"
    }
    [ ! -e "$RELAYS/$pid_b" ] || fail "session B's relay must be removed when it ends"
    [ -S "$relay_a" ] && kill -0 "$relay_a_pid" 2>/dev/null ||
        fail "session B ending must not touch session A's relay"
    [ "$(find "$PROFILE_DIR/sessions" -type f | wc -l)" -eq 1 ] ||
        fail "only session A must remain registered"
    [ -S "$SSH_AUTH_SOCK" ] && [ -S "$GPG_AGENT_EXTRA_SOCKET" ] ||
        fail "a session ending must never touch the host agent sockets"

    # A third session starting while A runs must not disturb A either.
    "$REPO_DIR/bin/opencode-dockerized" run "$TMP/pb" </dev/null >"$TMP/c.out" 2>&1 &
    pid_c=$!
    BG_PIDS+=("$pid_c")
    wait_for test -S "$RELAYS/$pid_c/relay.sock" || fail "session C did not start"
    [ -S "$relay_a" ] && kill -0 "$relay_a_pid" 2>/dev/null || fail "session C must not touch session A's relay"
    : >"$DOCKER_STUB_DIR/release-all"
    wait "$pid_a" || fail "session A must exit cleanly"
    wait "$pid_c" || fail "session C must exit cleanly"
    [ ! -e "$RELAYS/$pid_a" ] && [ ! -e "$RELAYS/$pid_c" ] || fail "every relay must be removed when its session ends"
    [ "$(find "$PROFILE_DIR/sessions" -type f | wc -l)" -eq 0 ] || fail "no session may remain registered"
    relay_gone() { ! kill -0 "$relay_a_pid" 2>/dev/null; }
    wait_for relay_gone || fail "session A's relay process must be stopped"
    unset OPENCODE_DOCKERIZED_TEST_HOOKS GPG_RELAY_FORCE GPG_RELAY_CMD GPG_AGENT_EXTRA_SOCKET GPG_AGENT_SOCKET
    rm -f "$DOCKER_STUB_DIR/release-all"
else
    echo "SKIP: concurrent wrapper sessions (node is required for the test sockets)"
fi

# ---------------------------------------------------------------------------
# 2. entrypoint.sh seeds a GNUPGHOME of the container's own
# ---------------------------------------------------------------------------
SEED="$TMP/seed"
mkdir -m 700 "$SEED" "$SEED/public-keys.d"
printf 'KBX\n' >"$SEED/pubring.kbx"
printf 'DB\n' >"$SEED/public-keys.d/pubring.db"
printf 'use-keyboxd\n' >"$SEED/common.conf"
printf 'no-autostart\n' >"$SEED/gpg.conf"
printf 'leftover\n' >"$SEED/S.keyboxd" # legacy runtime entry: never copied
chmod -R a-w "$SEED"

# Stub gpgconf: records which GNUPGHOME it was launched for.
mkdir -p "$TMP/ebin"
cat >"$TMP/ebin/gpgconf" <<'STUB'
#!/bin/bash
echo "$GNUPGHOME $*" >>"$GPGCONF_LOG"
STUB
chmod +x "$TMP/ebin/gpgconf"
export GPGCONF_LOG="$TMP/gpgconf.log"
: >"$GPGCONF_LOG"

agent="$TMP/agent.sock"
python3 -c 'import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$agent" 2>/dev/null ||
    node -e 'require("net").createServer().listen(process.argv[1], () => process.exit(0))' "$agent" 2>/dev/null
[ -S "$agent" ] || fail "could not create the fake agent socket"

# Usage: boot HOME [AGENT]
boot() {
    (cd "$TMP" && PATH="$TMP/ebin:$PATH" GNUPGHOME="$1" OPENCODE_DOCKERIZED_GNUPG_SEED="$SEED" \
        OPENCODE_DOCKERIZED_GPG_AGENT_SOCK="${2:-}" bash "$REPO_DIR/entrypoint.sh" true) >/dev/null 2>&1
}
boot "$TMP/home-a" "$agent"
boot "$TMP/home-b"
for h in "$TMP/home-a" "$TMP/home-b"; do
    [ "$(stat -c %a "$h" 2>/dev/null || stat -f %Lp "$h")" = 700 ] || fail "GNUPGHOME must be mode 700 ($h)"
    for f in pubring.kbx common.conf gpg.conf public-keys.d/pubring.db; do
        [ -f "$h/$f" ] || fail "the entrypoint must copy $f into GNUPGHOME"
        [ "$(stat -c %a "$h/$f" 2>/dev/null || stat -f %Lp "$h/$f")" = 600 ] || fail "$f must be mode 600"
    done
    [ ! -e "$h/S.keyboxd" ] || fail "runtime entries in the seed must never be copied"
    grep -qxF -- "$h --launch keyboxd" "$GPGCONF_LOG" || fail "keyboxd must be launched for the container's own home ($h)"
done
[ "$(readlink "$TMP/home-a/S.gpg-agent")" = "$agent" ] || fail "a mounted agent socket must be linked into GNUPGHOME"
[ ! -e "$TMP/home-b/S.gpg-agent" ] && [ ! -L "$TMP/home-b/S.gpg-agent" ] ||
    fail "without an announced agent socket no link may be created"
boot "$TMP/home-c" "$TMP/not-a-socket"
[ ! -L "$TMP/home-c/S.gpg-agent" ] || fail "a missing agent socket must not be linked"
[ "$(cat "$SEED/pubring.kbx")" = KBX ] && [ ! -e "$SEED/S.gpg-agent" ] || fail "the seed must stay untouched"

# Without GNUPGHOME (forwarding off) the entrypoint does nothing GnuPG-related.
: >"$GPGCONF_LOG"
(cd "$TMP" && PATH="$TMP/ebin:$PATH" OPENCODE_DOCKERIZED_GNUPG_SEED="$SEED" env -u GNUPGHOME \
    bash "$REPO_DIR/entrypoint.sh" true) >/dev/null 2>&1
[ ! -s "$GPGCONF_LOG" ] || fail "without GnuPG forwarding the entrypoint must not launch keyboxd"
# A missing seed (older wrapper) never blocks the container.
boot "$TMP/home-d" && true
grep -qxF -- "$TMP/home-d --launch keyboxd" "$GPGCONF_LOG" || fail "keyboxd must still be launched without a seed"

# ---------------------------------------------------------------------------
# 3. Real GnuPG: one container's exit must not break the other's keyboxd
# ---------------------------------------------------------------------------
if command -v gpg >/dev/null 2>&1 && gpgconf --list-components 2>/dev/null | grep -q '^keyboxd:'; then
    GPG_REAL_HOME="$TMP/realhost"
    mkdir -m 700 "$GPG_REAL_HOME"
    echo use-keyboxd >"$GPG_REAL_HOME/common.conf"
    GNUPGHOME="$GPG_REAL_HOME" gpg --batch --passphrase '' \
        --quick-gen-key 'Concurrency <c@example.invalid>' ed25519 sign never >/dev/null 2>&1 ||
        fail "could not create a test key"
    gpgconf --homedir "$GPG_REAL_HOME" --kill all >/dev/null 2>&1
    RSEED="$TMP/realseed"
    mkdir -m 700 "$RSEED" "$RSEED/public-keys.d"
    cp "$GPG_REAL_HOME/common.conf" "$RSEED/"
    cp "$GPG_REAL_HOME/public-keys.d/pubring.db" "$RSEED/public-keys.d/"
    printf 'no-autostart\n' >"$RSEED/gpg.conf"
    chmod -R a-w "$RSEED"
    real_boot() {
        (cd "$TMP" && GNUPGHOME="$1" OPENCODE_DOCKERIZED_GNUPG_SEED="$RSEED" bash "$REPO_DIR/entrypoint.sh" true) >/dev/null 2>&1
    }
    GPG_REAL_A="$TMP/real-a"
    GPG_REAL_B="$TMP/real-b"
    real_boot "$GPG_REAL_A"
    real_boot "$GPG_REAL_B"
    pid_kbx_a="$(pgrep -u "$(id -u)" -f "keyboxd.*$GPG_REAL_A" | head -1)"
    [ -n "$pid_kbx_a" ] && pgrep -u "$(id -u)" -f "keyboxd.*$GPG_REAL_B" >/dev/null ||
        fail "each container must run its own keyboxd"
    kill -KILL "$pid_kbx_a"
    sleep 0.3
    GNUPGHOME="$GPG_REAL_B" gpg --batch --list-keys 2>&1 | grep -q 'c@example.invalid' ||
        fail "a session must keep reading its keyring after another session's container exits"
    gpgconf --homedir "$GPG_REAL_A" --kill all >/dev/null 2>&1
else
    echo "SKIP: real keyboxd check (needs GnuPG >= 2.3 with keyboxd)"
fi

echo "session concurrency test passed"
