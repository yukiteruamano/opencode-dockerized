#!/bin/bash
# Contract test for the wrapper's docker argument building and security-layer
# mirroring. No Docker required: it sources config-lib.sh with an isolated
# HOME/CONFIG_DIR and asserts the resulting files and docker flags.
#
# Usage: bash tests/wrapper-args.test.sh
# shellcheck disable=SC2034  # globals below are consumed by sourced config-lib.sh functions

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export TMPDIR="${TMPDIR:-/tmp/opencode}"
mkdir -p "$TMPDIR" 2>/dev/null || export TMPDIR="/tmp"
TMP="$(mktemp -d -p "$TMPDIR")"
trap 'rm -r "$TMP" 2>/dev/null || true' EXIT

# Sync tests run through sync_security_layer, which refuses to run inside
# containers (host-only); allow it here. A dedicated assertion below verifies
# the refusal without this override.
export OPENCODE_DOCKERIZED_ALLOW_CONTAINER_SYNC=1

# Some assertions need a real AF_UNIX socket file; node is the most portable way
# to create one here (present in the image and on CI runners).
have_node=false
command -v node >/dev/null 2>&1 && have_node=true

fail() {
    echo "FAIL: $1"
    exit 1
}

export HOME="$TMP/home"
export CONFIG_DIR="$TMP/cfg"
export OCODE_HOME="$CONFIG_DIR/home"
# Simulate an installed user: this checkout's bin/ is on PATH (Doom-style,
# no symlink in ~/.local/bin). check_global_install requires PATH resolution.
export PATH="$REPO_DIR/bin:$PATH"
PROJECT="$TMP/proj"
OC_CONFIG_DIR="$OCODE_HOME/.config/opencode"

mkdir -p \
    "$HOME/.mcp-auth" \
    "$HOME/.npm" \
    "$OC_CONFIG_DIR/plugins" \
    "$OC_CONFIG_DIR/agents" \
    "$OCODE_HOME/.local/share/opencode" \
    "$OCODE_HOME/.local/state/opencode" \
    "$OCODE_HOME/.cache/opencode" \
    "$CONFIG_DIR/plugins/policies" \
    "$PROJECT"

: >"$HOME/.gitconfig"
printf '{\n  "permissions": [{"action": "shell", "resource": "*", "effect": "allow"}]\n}\n' >"$CONFIG_DIR/opencode.json"

# shellcheck source=/dev/null
source "$REPO_DIR/lib/config-lib.sh"

# Generate the security layer and mirror it into the OpenCode config tree.
ensure_opencode_dockerized_config

[ -f "$OC_CONFIG_DIR/plugins/security-guard.js" ] ||
    fail "security guard was not mirrored into the config tree"
grep -q 'OPENCODE_DOCKERIZED_GUARD_VERSION' "$OC_CONFIG_DIR/plugins/security-guard.js" ||
    fail "mirrored guard is missing its version marker"
grep -q 'Security Rules' "$OC_CONFIG_DIR/AGENTS.md" ||
    fail "security rules were not mirrored into the config tree"
[ -f "$OC_CONFIG_DIR/plugins/policies/allow-patterns.json" ] ||
    fail "policy patterns were not mirrored into the config tree"

# Versioned policy set: the VERSION marker is seeded and matches the repo copy.
[ -f "$CONFIG_DIR/plugins/policies/VERSION" ] ||
    fail "policy VERSION marker was not seeded"
[ "$(cat "$CONFIG_DIR/plugins/policies/VERSION")" = "$(cat "$REPO_DIR/policies/VERSION")" ] ||
    fail "policy VERSION marker does not match the repo"

# GnuPG private keys must be denied by the generated permissions and listed as
# secrets in the generated rules (defense in depth even though they are never mounted).
grep -q 'private-keys-v1.d' "$CONFIG_DIR/opencode.json" ||
    fail "GnuPG private keys must be denied in the generated permissions"
grep -q 'private-keys-v1.d' "$OC_CONFIG_DIR/AGENTS.md" ||
    fail "GnuPG private keys must be listed as secrets in the generated rules"

# Expanded quality bar: Core Workflow plus per-language clean/modular/secure rules.
grep -q '## Core Workflow' "$OC_CONFIG_DIR/AGENTS.md" ||
    fail "Core Workflow section must be present in the generated rules"
grep -q 'Verify by execution' "$OC_CONFIG_DIR/AGENTS.md" ||
    fail "Core Workflow must require verification by execution"
grep -q 'ruff check' "$OC_CONFIG_DIR/AGENTS.md" ||
    fail "Python rules must require ruff"
grep -q 'tsc --noEmit' "$OC_CONFIG_DIR/AGENTS.md" ||
    fail "JS/TS rules must require tsc --noEmit"
grep -q 'cargo clippy' "$OC_CONFIG_DIR/AGENTS.md" ||
    fail "Rust rules must require clippy"
grep -q 'staticcheck' "$OC_CONFIG_DIR/AGENTS.md" ||
    fail "Go rules must mention staticcheck"
grep -q 'shellcheck' "$OC_CONFIG_DIR/AGENTS.md" ||
    fail "Bash rules must require shellcheck"

build_standard_volume_args "$PROJECT" false
build_common_docker_args

volumes="$(printf '%s\n' "${VOLUME_ARGS[@]}")"
common="$(printf '%s\n' "${DOCKER_COMMON_ARGS[@]}")"

# OpenCode declarative config must be read-only, delivered as a single dir mount.
grep -qx -- "$OC_CONFIG_DIR:/home/coder/.config/opencode:ro" <<<"$volumes" ||
    fail "OpenCode config dir must be mounted read-only"

# No nested mounts under the read-only config dir (Docker cannot create them).
if grep -q ':/home/coder/.config/opencode/' <<<"$volumes"; then
    fail "no nested mounts are allowed under the read-only config dir"
fi

# MCP OAuth store must be read-write.
grep -qx -- "$HOME/.mcp-auth:/home/coder/.mcp-auth:rw" <<<"$volumes" ||
    fail ".mcp-auth must be mounted read-write"

# Caches and ~/.gitconfig are NOT mounted anymore (security).
for banned in "$HOME/.npm" "$HOME/.gitconfig"; do
    if grep -qF -- "$banned:" <<<"$volumes"; then
        fail "$banned must not be mounted"
    fi
done

# Nothing from the wrapper config or install dirs may be mounted.
if grep -q 'opencode-dockerized' <<<"$volumes"; then
    fail "wrapper CONFIG_DIR must not be mounted into the container"
fi

# Sandbox rules are passed inline (native V2 `permissions`), not as a path.
grep -q '^OPENCODE_CONFIG_CONTENT=' <<<"$common" ||
    fail "sandbox rules must be passed via OPENCODE_CONFIG_CONTENT"
if grep -q '^OPENCODE_CONFIG=' <<<"$common"; then
    fail "OPENCODE_CONFIG must not be set (use OPENCODE_CONFIG_CONTENT)"
fi
grep -q '^OPENCODE_CONFIG_CONTENT=.*"permissions"' <<<"$common" ||
    fail "OPENCODE_CONFIG_CONTENT does not contain the native V2 permissions array"

# Auto-update is always disabled.
grep -qx 'OPENCODE_DISABLE_AUTOUPDATE=true' <<<"$common" ||
    fail "OPENCODE_DISABLE_AUTOUPDATE must be set"

# Removed features must not come back.
if grep -qE 'OPENCODE_DISABLE_LSP_DOWNLOAD|OPENCODE_DOCKERIZED_EXTRA_PATH' <<<"$common"; then
    fail "LSP/toolchain env vars must not be set anymore"
fi
if grep -q '"lsp"\|"formatter"' <<<"$common"; then
    fail "lsp/formatter must not be injected into OPENCODE_CONFIG_CONTENT"
fi

# Rootless runtime: the container runs as the host user, never as root.
grep -qx -- '--user' <<<"$common" ||
    fail "--user must be set (rootless runtime)"
grep -qx -- "$(id -u):$(id -g)" <<<"$common" ||
    fail "--user must map the host UID/GID"
grep -qx -- '--group-add' <<<"$common" ||
    fail "--group-add must be set (arbitrary-UID home writes)"
grep -qx -- 'coder' <<<"$common" ||
    fail "--group-add coder value missing"
if grep -q '^HOST_UID=\|^HOST_GID=' <<<"$common"; then
    fail "HOST_UID/HOST_GID must not be passed anymore (no runtime remap)"
fi

# Image contract for the `--group-add coder` above: the image's last USER is
# non-root and the home is owned coder:coder + group-writable, so granting the
# container's `coder` group at runtime (resolved against the image's /etc/group)
# keeps the non-mounted home usable for any host UID.
dockerfile="$REPO_DIR/Dockerfile"
grep -Eq '^[[:space:]]*chown -R coder:coder /home/coder' "$dockerfile" ||
    fail "Dockerfile must chown the home to coder:coder"
grep -Eq '^[[:space:]]*chmod -R g\+rwX /home/coder' "$dockerfile" ||
    fail "Dockerfile must make the home group-writable (chmod -R g+rwX)"
last_user="$(grep -E '^USER ' "$dockerfile" | tail -n1)"
[ "$last_user" = "USER coder" ] ||
    fail "last USER must be 'coder' (non-root image), got: '$last_user'"

# Project confinement: "/", $HOME and any ancestor of $HOME must be refused.
validate_project_dir "$PROJECT" >/dev/null 2>&1 ||
    fail "a project subdirectory must be accepted"
if validate_project_dir "/" >/dev/null 2>&1; then
    fail "must refuse '/' as the project"
fi
if validate_project_dir "$HOME" >/dev/null 2>&1; then
    fail "must refuse \$HOME as the project"
fi
if validate_project_dir "$(dirname "$HOME")" >/dev/null 2>&1; then
    fail "must refuse an ancestor of \$HOME as the project"
fi

# Custom mounts of SSH/GnuPG private material must be refused.
mkdir -p "$HOME/.ssh" "$HOME/.gnupg"
for bad in "$HOME/.ssh" "$HOME/.gnupg"; do
    CUSTOM_MOUNTS=("$bad:/home/coder/leak")
    CUSTOM_MOUNT_KEYS=(bad)
    if (build_mount_args) >/dev/null 2>&1; then
        fail "mounting $bad must be refused"
    fi
done
CUSTOM_MOUNTS=()
CUSTOM_MOUNT_KEYS=()
if add_mount "$HOME/.gnupg" /home/coder/leak >/dev/null 2>&1; then
    fail "add_mount must refuse ~/.gnupg"
fi

# A mount without an absolute container path must be rejected, not passed to
# docker as a broken `-v host::mode`.
CUSTOM_MOUNTS=("/tmp/hostonly")
CUSTOM_MOUNT_KEYS=(bad)
if (build_mount_args) >/dev/null 2>&1; then
    fail "a mount without an absolute container path must be rejected"
fi
CUSTOM_MOUNTS=("/tmp/hostonly:relative")
CUSTOM_MOUNT_KEYS=(bad)
if (build_mount_args) >/dev/null 2>&1; then
    fail "a mount with a relative container path must be rejected"
fi
CUSTOM_MOUNTS=()
CUSTOM_MOUNT_KEYS=()

# Cheap hardening flags.
grep -qx -- '--security-opt' <<<"$common" ||
    fail "--security-opt must be set"
grep -qx -- 'no-new-privileges:true' <<<"$common" ||
    fail "no-new-privileges must be set"
grep -qx -- '--cap-drop=ALL' <<<"$common" ||
    fail "--cap-drop=ALL must be set"

# Docker socket access is a supplementary group, not a root runtime step.
if [ -S /var/run/docker.sock ]; then
    build_standard_volume_args "$PROJECT" true
    volumes_sock="$(printf '%s\n' "${VOLUME_ARGS[@]}")"
    grep -qx -- "$(stat -c '%g' /var/run/docker.sock)" <<<"$volumes_sock" ||
        fail "docker socket GID must be granted via --group-add"
    build_standard_volume_args "$PROJECT" false
fi

# SSH agent forwarding: mount only the agent socket plus the non-secret
# config/known_hosts files (read-only). Private keys must never be mounted.
mkdir -p "$HOME/.ssh"
: >"$HOME/.ssh/config"
: >"$HOME/.ssh/known_hosts"
SSH_AGENT_SUPPORT=true
if [ "$have_node" = true ]; then
    ssh_sock="$TMP/ssh-agent.sock"
    node -e 'require("net").createServer().listen(process.argv[1])' "$ssh_sock" >/dev/null 2>&1 &
    ssh_sock_pid=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$ssh_sock" ] && break; sleep 0.1; done
    SSH_AUTH_SOCK="$ssh_sock"
    build_mount_args
    build_env_args
    ssh_mounts="$(printf '%s\n' "${DOCKER_MOUNT_ARGS[@]}")"
    ssh_envs="$(printf '%s\n' "${DOCKER_ENV_ARGS[@]}")"
    grep -qxF -- "type=bind,source=$ssh_sock,target=$ssh_sock" <<<"$ssh_mounts" ||
        fail "SSH agent socket must be mounted (--mount, not -v)"
    grep -qx -- "$HOME/.ssh/config:/home/coder/.ssh/config:ro" <<<"$ssh_mounts" ||
        fail "~/.ssh/config must be mounted read-only" # shellcheck disable=SC2088
    grep -qx -- "$HOME/.ssh/known_hosts:/home/coder/.ssh/known_hosts:ro" <<<"$ssh_mounts" ||
        fail "~/.ssh/known_hosts must be mounted read-only" # shellcheck disable=SC2088
    if grep -qE '(^|/)id_|\.ssh:/home/coder/\.ssh(:|$)' <<<"$ssh_mounts"; then
        fail "SSH private material must never be mounted"
    fi
    grep -qx -- "SSH_AUTH_SOCK=$ssh_sock" <<<"$ssh_envs" ||
        fail "SSH_AUTH_SOCK must be passed"
    grep -qx -- 'OPENCODE_DOCKERIZED_SSH_AGENT=true' <<<"$ssh_envs" ||
        fail "doctor SSH flag must be true when forwarding is enabled"
    kill "$ssh_sock_pid" 2>/dev/null || true
    wait "$ssh_sock_pid" 2>/dev/null || true
fi
SSH_AGENT_SUPPORT=false
unset SSH_AUTH_SOCK

# GnuPG agent forwarding: only public material is mirrored and mounted.
mkdir -p "$HOME/.gnupg/private-keys-v1.d"
: >"$HOME/.gnupg/pubring.kbx"
: >"$HOME/.gnupg/gpg.conf"
: >"$HOME/.gnupg/private-keys-v1.d/secret.key"
export GNUPGHOME="$HOME/.gnupg"
GPG_AGENT_SOCKET=""
GPG_AGENT_EXTRA_SOCKET=""
GPG_AGENT_SUPPORT=true
# Keep the test hermetic: never launch a real gpg-agent here.
GPG_AUTOSTART_AGENT=false
build_mount_args
build_env_args
gpg_mounts="$(printf '%s\n' "${DOCKER_MOUNT_ARGS[@]}")"
gpg_envs="$(printf '%s\n' "${DOCKER_ENV_ARGS[@]}")"
grep -qxF -- "type=bind,source=$OCODE_HOME/.gnupg,target=/home/coder/.gnupg" <<<"$gpg_mounts" ||
    fail "GnuPG public keyring must be mounted read-write"
if grep -q 'private-keys-v1.d' <<<"$gpg_mounts"; then
    fail "private-keys-v1.d must never be mounted"
fi
if grep -qF -- "source=$HOME/.gnupg,target" <<<"$gpg_mounts"; then
    fail "host ~/.gnupg must not be mounted directly"
fi
[ -f "$OCODE_HOME/.gnupg/pubring.kbx" ] ||
    fail "public keyring was not mirrored"
if [ -e "$OCODE_HOME/.gnupg/private-keys-v1.d" ]; then
    fail "private keys must not be mirrored"
fi
grep -qx -- 'GNUPGHOME=/home/coder/.gnupg' <<<"$gpg_envs" ||
    fail "GNUPGHOME must point at the mirrored keyring"
grep -qx -- 'OPENCODE_DOCKERIZED_GPG_AGENT=true' <<<"$gpg_envs" ||
    fail "doctor GPG flag must be true when forwarding is enabled"

# The mirrored gpg.conf must disable auto-start (the real agent is on the host).
grep -qE '^[[:space:]]*no-autostart([[:space:]]|$)' "$OCODE_HOME/.gnupg/gpg.conf" ||
    fail "mirrored gpg.conf must contain no-autostart"

# `use-keyboxd` must be mirrored verbatim: hosts that use it keep the public
# keyring in the keyboxd database, and the container starts keyboxd explicitly
# (entrypoint) so gpg can read it despite no-autostart.
printf 'use-keyboxd\n' >"$HOME/.gnupg/common.conf"
mkdir -p "$HOME/.gnupg/public-keys.d"
: >"$HOME/.gnupg/public-keys.d/pubring.db"
ensure_gpg_mirror
grep -qiE '^[[:space:]]*use-keyboxd([[:space:]]|$)' "$OCODE_HOME/.gnupg/common.conf" ||
    fail "use-keyboxd must be mirrored into common.conf"
[ -f "$OCODE_HOME/.gnupg/public-keys.d/pubring.db" ] ||
    fail "keyboxd public DB must be mirrored"

# A stale keyboxd socket from a previous run must be cleared before mounting.
: >"$OCODE_HOME/.gnupg/S.keyboxd"
ensure_gpg_mirror
[ ! -e "$OCODE_HOME/.gnupg/S.keyboxd" ] ||
    fail "stale keyboxd socket must be cleared from the mirror"

# The image entrypoint must start keyboxd so gpg can read that DB.
grep -q 'gpgconf --launch keyboxd' "$REPO_DIR/entrypoint.sh" ||
    fail "entrypoint must launch keyboxd for GnuPG forwarding"

# Prefer the restricted "extra" socket; fall back to the main one when missing.
if [ "$have_node" = true ]; then
    gpg_main="$TMP/gpg-main.sock"
    gpg_extra="$TMP/gpg-extra.sock"
    node -e 'require("net").createServer().listen(process.argv[1])' "$gpg_main" >/dev/null 2>&1 &
    gpg_main_pid=$!
    node -e 'require("net").createServer().listen(process.argv[1])' "$gpg_extra" >/dev/null 2>&1 &
    gpg_extra_pid=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        [ -S "$gpg_main" ] && [ -S "$gpg_extra" ] && break
        sleep 0.1
    done

    GPG_AGENT_SOCKET="$gpg_main"
    GPG_AGENT_EXTRA_SOCKET="$gpg_extra"
    build_mount_args
    gpg_sel="$(printf '%s\n' "${DOCKER_MOUNT_ARGS[@]}")"
    grep -qxF -- "type=bind,source=$gpg_extra,target=/home/coder/.gnupg-agent/S.gpg-agent" <<<"$gpg_sel" ||
        fail "restricted extra socket must be preferred as the agent socket"

    # The agent socket must be exposed through a symlink in the mirror, never a
    # nested bind mount (Docker can shadow the latter).
    [ -L "$OCODE_HOME/.gnupg/S.gpg-agent" ] ||
        fail "the mirror must contain an S.gpg-agent symlink"
    [ "$(readlink "$OCODE_HOME/.gnupg/S.gpg-agent")" = "/home/coder/.gnupg-agent/S.gpg-agent" ] ||
        fail "S.gpg-agent symlink must point at the dedicated agent path"
    if grep -qF -- "target=/home/coder/.gnupg/S.gpg-agent" <<<"$gpg_sel"; then
        fail "the agent socket must not be mounted inside the mirror (nested bind)"
    fi

    # Without the restricted extra socket and without explicit opt-in, the main
    # (full-control) socket must NOT be used.
    GPG_ALLOW_MAIN_SOCKET=false
    GPG_AGENT_EXTRA_SOCKET="$TMP/does-not-exist.sock"
    build_mount_args
    gpg_sel="$(printf '%s\n' "${DOCKER_MOUNT_ARGS[@]}")"
    if grep -qF -- "type=bind,source=$gpg_main,target=/home/coder/.gnupg-agent/S.gpg-agent" <<<"$gpg_sel"; then
        fail "main agent socket must not be used without explicit opt-in"
    fi

    # Explicit opt-in allows the fallback.
    GPG_ALLOW_MAIN_SOCKET=true
    build_mount_args
    gpg_sel="$(printf '%s\n' "${DOCKER_MOUNT_ARGS[@]}")"
    grep -qxF -- "type=bind,source=$gpg_main,target=/home/coder/.gnupg-agent/S.gpg-agent" <<<"$gpg_sel" ||
        fail "must fall back to the main agent socket when explicitly allowed"
    GPG_ALLOW_MAIN_SOCKET=false

    kill "$gpg_main_pid" "$gpg_extra_pid" 2>/dev/null || true
    wait "$gpg_main_pid" 2>/dev/null || true
    wait "$gpg_extra_pid" 2>/dev/null || true
fi

# Preflight autostart: with the extra socket missing and autostart enabled, the
# launch command runs and the newly created socket is mounted.
if [ "$have_node" = true ]; then
    lazy_extra="$TMP/lazy-extra.sock"
    GPG_AGENT_SOCKET="$TMP/lazy-main.sock"
    GPG_AGENT_EXTRA_SOCKET="$lazy_extra"
    GPG_AGENT_LAUNCH_CMD="node -e 'require(\"net\").createServer().listen(process.argv[1])' \"$lazy_extra\" & echo \$! > \"$TMP/lazy.pid\""
    GPG_AUTOSTART_AGENT=true
    build_mount_args
    lazy_mounts="$(printf '%s\n' "${DOCKER_MOUNT_ARGS[@]}")"
    grep -qxF -- "type=bind,source=$lazy_extra,target=/home/coder/.gnupg-agent/S.gpg-agent" <<<"$lazy_mounts" ||
        fail "autostart must launch the agent and mount the newly created socket"
    kill "$(cat "$TMP/lazy.pid" 2>/dev/null)" 2>/dev/null || true

    # With autostart disabled the launch command must not run and nothing mounts.
    rm -f "$lazy_extra"
    GPG_AUTOSTART_AGENT=false
    build_mount_args
    if grep -qF -- "type=bind,source=$lazy_extra,target=/home/coder/.gnupg-agent/S.gpg-agent" <<<"$(printf '%s\n' "${DOCKER_MOUNT_ARGS[@]}")"; then
        fail "autostart disabled must not mount a missing socket"
    fi
    unset GPG_AGENT_LAUNCH_CMD
fi

# A stray empty directory at the agent socket path must be removed so the
# agent can create its socket (P0 cleanup).
if [ "$have_node" = true ]; then
    stray_dir="$TMP/stray-gpg.sock"
    mkdir -p "$stray_dir"
    GPG_AGENT_SUPPORT=true
    GPG_AGENT_SOCKET=""
    GPG_AGENT_EXTRA_SOCKET="$stray_dir"
    GPG_AUTOSTART_AGENT=true
    GPG_AGENT_LAUNCH_CMD="node -e 'require(\"net\").createServer().listen(process.argv[1])' \"$stray_dir\" & echo \$! > \"$TMP/stray.pid\""
    build_mount_args
    [ ! -d "$stray_dir" ] || fail "an empty stray directory must be removed before launch"
    [ -S "$stray_dir" ] || fail "the agent socket must exist after the cleanup and launch"
    kill "$(cat "$TMP/stray.pid" 2>/dev/null)" 2>/dev/null || true
    unset GPG_AGENT_LAUNCH_CMD
    GPG_AGENT_SUPPORT=false
fi

# Liveness probe: an existing but unresponsive socket must trigger a launch,
# while a responsive agent must not be relaunched.
if [ "$have_node" = true ]; then
    live_extra="$TMP/live-extra.sock"
    node -e 'require("net").createServer().listen(process.argv[1])' "$live_extra" >/dev/null 2>&1 &
    live_pid=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$live_extra" ] && break; sleep 0.1; done
    GPG_AGENT_SUPPORT=true
    GPG_AGENT_SOCKET=""
    GPG_AGENT_EXTRA_SOCKET="$live_extra"

    rm -f "$TMP/launched.marker"
    GPG_AGENT_PROBE_CMD="true"
    GPG_AUTOSTART_AGENT=true
    GPG_AGENT_LAUNCH_CMD="touch \"$TMP/launched.marker\""
    build_mount_args
    [ ! -e "$TMP/launched.marker" ] ||
        fail "a responsive gpg-agent must not be relaunched"

    GPG_AGENT_PROBE_CMD="false"
    build_mount_args
    [ -e "$TMP/launched.marker" ] ||
        fail "an unresponsive gpg-agent socket must trigger a relaunch"

    kill "$live_pid" 2>/dev/null || true
    wait "$live_pid" 2>/dev/null || true
    unset GPG_AGENT_PROBE_CMD GPG_AGENT_LAUNCH_CMD
fi

# GPG socket relay: a socket Docker cannot bind (e.g. on tmpfs) is relayed
# through a socket on a normal filesystem. The relay command is overridden with
# a node server so the test does not need socat.
if [ "$have_node" = true ]; then
    cat >"$TMP/relay.js" <<'EOF'
require("net").createServer().listen(process.env.RELAY_SOCK)
EOF
    real_sock="$TMP/real-agent.sock"
    node -e 'require("net").createServer().listen(process.argv[1])' "$real_sock" >/dev/null 2>&1 &
    real_pid=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$real_sock" ] && break; sleep 0.1; done

    GPG_RELAY_CMD="node $TMP/relay.js"
    relay=$(start_gpg_relay "$real_sock")
    [ -S "$relay" ] || fail "start_gpg_relay must create a listening socket"
    case "$relay" in "$GPG_RELAY_DIR"/*) ;; *) fail "relay socket must live under GPG_RELAY_DIR" ;; esac
    stop_gpg_relay "$relay"
    [ ! -e "$relay" ] || fail "stop_gpg_relay must remove the relay socket"

    # stop_gpg_relay must only touch paths under GPG_RELAY_DIR.
    victim="$TMP/victim-dir"
    mkdir -p "$victim"
    stop_gpg_relay "$victim/S.gpg-agent.extra"
    [ -d "$victim" ] || fail "stop_gpg_relay must not delete paths outside GPG_RELAY_DIR"
    rm -rf "$victim"

    # relay_dir_ok rejects unsafe roots.
    if GPG_RELAY_DIR=/ relay_dir_ok; then
        fail "relay_dir_ok must reject /"
    fi
    GPG_RELAY_DIR="$TMP/cfg/gnupg-relay"

    # Stale relay dirs (dead pid) are purged.
    stale_dir="$GPG_RELAY_DIR/stale-test"
    mkdir -p "$stale_dir"
    echo 999999 >"$stale_dir/pid"
    cleanup_stale_relays
    [ ! -d "$stale_dir" ] || fail "cleanup_stale_relays must remove dead relay dirs"

    # build_mount_args must use the relay when forced (tmpfs case).
    GPG_AGENT_SUPPORT=true
    GPG_AGENT_SOCKET=""
    GPG_AGENT_EXTRA_SOCKET="$real_sock"
    GPG_AUTOSTART_AGENT=false
    GPG_RELAY=true
    GPG_RELAY_FORCE=true
    build_mount_args
    relay_mounts="$(printf '%s\n' "${DOCKER_MOUNT_ARGS[@]}")"
    case "$GPG_RELAY_SOCKET" in "$GPG_RELAY_DIR"/*) ;; *) fail "build_mount_args must start a relay" ;; esac
    grep -qF -- "source=$GPG_RELAY_SOCKET,target=/home/coder/.gnupg-agent/S.gpg-agent" <<<"$relay_mounts" ||
        fail "the mount must use the relay socket"
    stop_gpg_relay "$GPG_RELAY_SOCKET"
    GPG_RELAY_SOCKET=""

    # With the relay disabled, the real socket is mounted directly.
    GPG_RELAY=false
    build_mount_args
    relay_mounts="$(printf '%s\n' "${DOCKER_MOUNT_ARGS[@]}")"
    grep -qF -- "source=$real_sock,target=/home/coder/.gnupg-agent/S.gpg-agent" <<<"$relay_mounts" ||
        fail "with the relay disabled the real socket must be mounted"
    GPG_RELAY=true
    GPG_RELAY_FORCE=false

    kill "$real_pid" 2>/dev/null || true
    wait "$real_pid" 2>/dev/null || true
    unset GPG_RELAY_CMD

    # Overlong relay paths must fail gracefully instead of starting a relay
    # Docker could never bind (Unix socket limit ~108 chars).
    long_base="$TMP/cfg/$(printf 'd%.0s' $(seq 1 120))"
    GPG_RELAY_DIR_SAVED="$GPG_RELAY_DIR"
    GPG_RELAY_DIR="$long_base"
    if start_gpg_relay "$real_sock" >/dev/null 2>&1; then
        GPG_RELAY_DIR="$GPG_RELAY_DIR_SAVED"
        fail "start_gpg_relay must refuse an overlong socket path"
    fi
    GPG_RELAY_DIR="$GPG_RELAY_DIR_SAVED"
fi
GPG_AGENT_SUPPORT=false
unset GNUPGHOME

# Doctor state flags follow the config (disabled means skipped, not failure).
SSH_AGENT_SUPPORT=false
GPG_AGENT_SUPPORT=false
build_env_args
state_envs="$(printf '%s\n' "${DOCKER_ENV_ARGS[@]}")"
grep -qx -- 'OPENCODE_DOCKERIZED_SSH_AGENT=false' <<<"$state_envs" ||
    fail "doctor SSH flag must reflect the config"
grep -qx -- 'OPENCODE_DOCKERIZED_GPG_AGENT=false' <<<"$state_envs" ||
    fail "doctor GPG flag must reflect the config"

# Secrets file (setting.env_file): consumed host-side, never mounted.
printf 'EXA_API_KEY=test-key\n# comment\n\nPLAIN_OK=1\n' >"$CONFIG_DIR/env"
chmod 600 "$CONFIG_DIR/env"
ENV_FILE="$CONFIG_DIR/env"
build_env_file_args
envfile_args="$(printf '%s\n' "${DOCKER_ENV_FILE_ARGS[@]}")"
grep -qxF -- "--env-file" <<<"$envfile_args" || fail "--env-file flag missing"
grep -qxF -- "$CONFIG_DIR/env" <<<"$envfile_args" || fail "env file path missing"
build_mount_args
if grep -qF -- "$CONFIG_DIR/env" <<<"$(printf '%s\n' "${DOCKER_MOUNT_ARGS[@]}")"; then
    fail "env file must never be mounted"
fi
# Outside CONFIG_DIR it must be refused (could be mounted).
ENV_FILE="$TMP/outside.env"
: >"$TMP/outside.env"
if (build_env_file_args) >/dev/null 2>&1; then
    fail "env file outside CONFIG_DIR must be refused"
fi
# Missing file must fail loudly.
ENV_FILE="$CONFIG_DIR/does-not-exist.env"
if (build_env_file_args) >/dev/null 2>&1; then
    fail "missing env file must fail"
fi
ENV_FILE=""

# env_file_upsert: create/replace/preserve/permissions; value never printed.
UPF="$TMP/envtest"
env_file_upsert "$UPF" FOO first >/dev/null || fail "upsert must create"
[ "$(stat -c '%a' "$UPF")" = 600 ] || fail "env file must be 600"
env_file_upsert "$UPF" BAR second >/dev/null || fail "upsert must append"
printf '# comment\n' >>"$UPF"
env_file_upsert "$UPF" FOO third >/dev/null || fail "upsert must replace"
[ "$(grep -c '^FOO=' "$UPF")" -eq 1 ] || fail "replaced key must not duplicate"
grep -qx 'BAR=second' "$UPF" || fail "other keys preserved"
grep -qx '# comment' "$UPF" || fail "comments preserved"
if env_file_upsert "$UPF" 'bad-name' x >/dev/null 2>&1; then
    fail "invalid names must be rejected"
fi
out=$(env_file_upsert "$UPF" FOO third 2>&1)
grep -q 'third' <<<"$out" && fail "value must never be printed"
[ "$(grep -c '^FOO=third$' "$UPF")" -eq 1 ] || fail "idempotent replace"

# migrate_legacy_env_vars: moves values from host env, reports names only.
printf 'env.mig1=MIG_TEST_VAR\nsetting.gpg_agent_support=false\n' >"$CONFIG_FILE"
export MIG_TEST_VAR="mig-test-value"
mig_out=$(printf 'Y\n' | migrate_legacy_env_vars 2>&1)
grep -q 'MIG_TEST_VAR' <<<"$mig_out" || fail "migration must report key names"
grep -qx 'MIG_TEST_VAR=mig-test-value' "$CONFIG_DIR/env" || fail "migration must write the value"
[ "$(stat -c '%a' "$CONFIG_DIR/env")" = 600 ] || fail "migrated env file must be 600"
if grep -q 'mig-test-value' <<<"$mig_out"; then
    fail "migration must never print values"
fi
unset MIG_TEST_VAR

# Optional websearch provider is merged into the inline config.
WEBSEARCH_PROVIDER="exa"
build_common_docker_args
websearch_common="$(printf '%s\n' "${DOCKER_COMMON_ARGS[@]}")"
grep -qF -- '"websearch":{"provider":"exa"}' <<<"$websearch_common" ||
    fail "websearch provider must be merged into OPENCODE_CONFIG_CONTENT"
WEBSEARCH_PROVIDER="bogus"
build_common_docker_args
websearch_common="$(printf '%s\n' "${DOCKER_COMMON_ARGS[@]}")"
if grep -qF -- '"websearch"' <<<"$websearch_common"; then
    fail "invalid websearch provider must be skipped"
fi
WEBSEARCH_PROVIDER=""

# Optional theme is passed as inline CLI config.
THEME="catppuccin"
build_common_docker_args
theme_common="$(printf '%s\n' "${DOCKER_COMMON_ARGS[@]}")"
grep -qxF -- 'OPENCODE_CLI_CONFIG_CONTENT={"theme":{"name":"catppuccin"}}' <<<"$theme_common" ||
    fail "theme must be passed via OPENCODE_CLI_CONFIG_CONTENT"
THEME='x";evil'
build_common_docker_args
theme_common="$(printf '%s\n' "${DOCKER_COMMON_ARGS[@]}")"
if grep -q '^OPENCODE_CLI_CONFIG_CONTENT=' <<<"$theme_common"; then
    fail "invalid theme must be skipped"
fi
THEME=""

# Inline secrets in the user OpenCode config must block the run.
oc_user_config="$OC_CONFIG_DIR/opencode.json"
printf '{"model":"x","provider":{"p":{"options":{"apiKey":"live-secret"}}}}' >"$oc_user_config"
if (validate_opencode_config) >/dev/null 2>&1; then
    fail "inline secrets must block the run"
fi
printf '{"model":"x","provider":{"p":{"options":{"apiKey":"{env:PROVIDER_KEY}"}}}}' >"$oc_user_config"
validate_opencode_config >/dev/null 2>&1 || fail "{env:} references must pass validation"
printf '{"$schema": "https://opencode.ai/config.json"}' >"$oc_user_config"

# Optional resource limits are honored.
MEMORY="4g"
CPUS="2"
build_common_docker_args
common_lim="$(printf '%s\n' "${DOCKER_COMMON_ARGS[@]}")"
grep -qx -- '--memory' <<<"$common_lim" || fail "--memory not added when setting.memory is set"
grep -qx -- '4g' <<<"$common_lim" || fail "memory value not passed"
grep -qx -- '--cpus' <<<"$common_lim" || fail "--cpus not added when setting.cpus is set"
grep -qx -- '2' <<<"$common_lim" || fail "cpus value not passed"

# Container network defaults to host, honors bridge, and rejects garbage.
NETWORK="host"
build_common_docker_args
common_net="$(printf '%s\n' "${DOCKER_COMMON_ARGS[@]}")"
grep -qx -- '--network' <<<"$common_net" || fail "--network flag missing"
grep -qx -- 'host' <<<"$common_net" || fail "default network must be host"
NETWORK="bridge"
build_common_docker_args
common_net="$(printf '%s\n' "${DOCKER_COMMON_ARGS[@]}")"
grep -qx -- 'bridge' <<<"$common_net" || fail "bridge network must be honored"
NETWORK="bogus"
build_common_docker_args
common_net="$(printf '%s\n' "${DOCKER_COMMON_ARGS[@]}")"
grep -qx -- 'host' <<<"$common_net" || fail "invalid network must fall back to host"
if grep -qx -- 'bogus' <<<"$common_net"; then
    fail "invalid network value must never reach docker"
fi
NETWORK="host"

# config sync refreshes a stale guard copy (and --check detects drift).
printf '// OPENCODE_DOCKERIZED_GUARD_VERSION=0\n' >"$CONFIG_DIR/plugins/security-guard.js"
if sync_security_layer --check >/dev/null 2>&1; then
    fail "--check must detect a stale guard copy"
fi
sync_security_layer >/dev/null 2>&1 || fail "sync must refresh a stale guard copy"
[ -f "$CONFIG_DIR/plugins/security-guard.js.bak" ] ||
    fail "sync must back up the stale guard copy"
sync_security_layer --check >/dev/null 2>&1 || fail "must be in sync after refresh"

# Merge: an outdated opencode.json with user rules keeps the user rules,
# refreshes the template (template wins conflicts) and stays valid JSON.
printf '{\n  "$schema": "https://opencode.ai/config.json",\n  "permissions": [\n    { "action": "shell", "resource": "mycmd*", "effect": "ask" },\n    { "action": "shell", "resource": "sudo", "effect": "allow" }\n  ]\n}\n' >"$CONFIG_DIR/opencode.json"
sync_out=$(sync_security_layer 2>&1) || fail "sync with user rules must succeed"
grep -qF -- '{ "action": "shell", "resource": "mycmd*", "effect": "ask" }' "$CONFIG_DIR/opencode.json" ||
    fail "merge must preserve custom rules"
grep -qF -- '{ "action": "shell", "resource": "sudo", "effect": "deny" }' "$CONFIG_DIR/opencode.json" ||
    fail "merge must restore the template rule on conflict"
grep -q 'private-keys-v1.d' "$CONFIG_DIR/opencode.json" ||
    fail "merge must restore current markers"
grep -q 'overrode' <<<"$sync_out" ||
    fail "merge must report overridden rules"
if command -v node >/dev/null 2>&1; then
    node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' "$CONFIG_DIR/opencode.json" ||
        fail "merged opencode.json must be valid JSON"
fi

# Merge preserves multi-line hand-written rules verbatim (interior commas kept).
printf '{\n  "permissions": [\n    {\n      "action": "shell",\n      "resource": "longcmd*",\n      "effect": "ask"\n    }\n  ]\n}\n' >"$CONFIG_DIR/opencode.json"
sync_security_layer >/dev/null 2>&1 || fail "sync with multi-line rules must succeed"
grep -qF -- '"resource": "longcmd*"' "$CONFIG_DIR/opencode.json" ||
    fail "merge must preserve multi-line custom rules"
if command -v node >/dev/null 2>&1; then
    node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' "$CONFIG_DIR/opencode.json" ||
        fail "merged multi-line opencode.json must be valid JSON"
fi

# Broken cli.json is backed up and reseeded, never silently dropped.
printf 'not json{{{' >"$OC_CONFIG_DIR/cli.json"
sync_security_layer >/dev/null 2>&1 || fail "sync must survive a broken cli.json"
[ -f "$OC_CONFIG_DIR/cli.json.bak" ] || fail "broken cli.json must be backed up"
grep -qx '{}' "$OC_CONFIG_DIR/cli.json" || fail "cli.json must be reseeded"

# --check must not write anything.
before_hashes=$(find "$CONFIG_DIR" "$OC_CONFIG_DIR" -type f -exec md5sum {} + 2>/dev/null | sort)
sync_security_layer --check >/dev/null 2>&1 || fail "must be in sync now"
after_hashes=$(find "$CONFIG_DIR" "$OC_CONFIG_DIR" -type f -exec md5sum {} + 2>/dev/null | sort)
[ "$before_hashes" = "$after_hashes" ] || fail "--check must not modify files"

# Empty/valid settings load silently; invalid memory/cpus are ignored.
printf 'setting.theme=\nsetting.memory=2g\nsetting.cpus=1.5\nsetting.websearch_provider=\n' >"$CONFIG_FILE"
load_config >"$TMP/load.out" 2>&1 || true
if [ -s "$TMP/load.out" ]; then
    cat "$TMP/load.out"
    fail "valid settings must load silently"
fi
[ "$MEMORY" = "2g" ] || fail "valid memory must load"
[ "$CPUS" = "1.5" ] || fail "valid cpus must load"
printf 'setting.memory=bogus\nsetting.cpus=9x\n' >"$CONFIG_FILE"
load_config >/dev/null 2>&1 || true
[ -z "$MEMORY" ] || fail "invalid memory must be ignored"
[ -z "$CPUS" ] || fail "invalid cpus must be ignored"

# The generated sandbox permissions are scanned too (they travel inline).
cp "$CONFIG_DIR/opencode.json" "$TMP/opencode.json.orig"
printf '\n{"provider":{"p":{"options":{"accessToken":"live-xyz"}}}}\n' >>"$CONFIG_DIR/opencode.json"
if (validate_opencode_config) >/dev/null 2>&1; then
    cp "$TMP/opencode.json.orig" "$CONFIG_DIR/opencode.json"
    fail "inline secrets in CONFIG_DIR/opencode.json must block"
fi
cp "$TMP/opencode.json.orig" "$CONFIG_DIR/opencode.json"

# sync rejects unknown arguments.
if sync_security_layer --bogus >/dev/null 2>&1; then
    fail "sync must reject unknown arguments"
fi

# PATH install watch: nothing may live in ~/.local/bin; a legacy symlink is
# stale and sync removes it, while a real file is never touched.
mkdir -p "$HOME/.local/bin" 2>/dev/null || true
ln -sf "$REPO_DIR/bin/opencode-dockerized" "$HOME/.local/bin/opencode-dockerized" 2>/dev/null || true
if check_global_install >/dev/null 2>&1; then
    # If PATH happens to resolve (CI images with bin/ on PATH), the legacy
    # symlink still counts as stale only via the dedicated assertion below.
    :
fi
sync_security_layer >/dev/null 2>&1 || fail "sync must succeed with a legacy symlink present"
[ ! -L "$HOME/.local/bin/opencode-dockerized" ] ||
    fail "sync must remove the legacy ~/.local/bin symlink (nothing lives there anymore)"
# A non-symlink file must survive sync untouched.
printf 'not-a-link' >"$HOME/.local/bin/opencode-dockerized"
sync_security_layer >/dev/null 2>&1 || fail "sync must succeed with a real file present"
[ -f "$HOME/.local/bin/opencode-dockerized" ] && [ ! -L "$HOME/.local/bin/opencode-dockerized" ] ||
    fail "sync must not replace a non-symlink file"
grep -qx 'not-a-link' "$HOME/.local/bin/opencode-dockerized" ||
    fail "sync must not modify a real file"
rm -f "$HOME/.local/bin/opencode-dockerized" 2>/dev/null
# repo_script_path must point at bin/opencode-dockerized (no .sh, no symlink).
[ "$(repo_script_path)" = "$(readlink -f "$REPO_DIR/bin/opencode-dockerized")" ] ||
    fail "repo_script_path must point at bin/opencode-dockerized"

# sync is host-only: inside a container it must refuse (unless overridden).
if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then
    if (unset OPENCODE_DOCKERIZED_ALLOW_CONTAINER_SYNC; sync_security_layer --check) >/dev/null 2>&1; then
        fail "sync must refuse inside containers"
    fi
fi

# NO_COLOR strips ANSI codes (TERM=dumb behaves the same).
if NO_COLOR=1 bash -c 'source "$0" >/dev/null 2>&1; config_info hi' "$REPO_DIR/lib/config-lib.sh" | grep -q $'\x1b'; then
    fail "NO_COLOR must strip ANSI codes"
fi
if TERM=dumb bash -c 'source "$0" >/dev/null 2>&1; config_info hi' "$REPO_DIR/lib/config-lib.sh" | grep -q $'\x1b'; then
    fail "dumb terminals must not get ANSI codes"
fi

# Websearch/theme prompts accept valid values and reject the rest.
prompt_websearch_provider >/dev/null <<EOF
bogus
EOF
[ -z "$WEBSEARCH_PROVIDER" ] || fail "invalid provider must be rejected"
prompt_websearch_provider >/dev/null <<EOF
exa
EOF
[ "$WEBSEARCH_PROVIDER" = "exa" ] || fail "valid provider must be accepted"
prompt_theme >/dev/null <<EOF
not a theme!!
EOF
[ -z "$THEME" ] || fail "invalid theme must be rejected"
prompt_theme >/dev/null <<EOF
catppuccin
EOF
[ "$THEME" = "catppuccin" ] || fail "valid theme must be accepted"
WEBSEARCH_PROVIDER=""
THEME=""

# Drift hint appears only when stale.
printf '// OPENCODE_DOCKERIZED_GUARD_VERSION=0\n' >"$CONFIG_DIR/plugins/security-guard.js"
hint=$(maybe_drift_hint 2>&1) || true
grep -q 'config sync' <<<"$hint" || fail "drift hint must mention config sync"
sync_security_layer >/dev/null 2>&1 || fail "sync must refresh"
hint=$(maybe_drift_hint 2>&1) || true
[ -z "$hint" ] || fail "no hint when in sync"

# dry_run_print: one flag per line, secrets redacted.
dry_out=$(dry_run_print docker run -it --name x -e TERM=t -e 'OPENCODE_CONFIG_CONTENT={"a":1}' --env-file /tmp/f image opencode)
grep -qx 'docker run' <<<"$dry_out" || fail "dry run must start with a header line"
[ "$(printf '%s' "$dry_out" | wc -l)" -gt 3 ] || fail "dry run must be multiline"
grep -qx '  <redacted>' <<<"$dry_out" || fail "dry run must redact inline config"
if grep -q '{"a":1}' <<<"$dry_out"; then
    fail "dry run must not leak inline config values"
fi

# Config mode select must not hang on EOF (existing config file present).
if command -v timeout >/dev/null 2>&1; then
    if ! printf '' | timeout 10 bash -c 'source "$0" >/dev/null 2>&1; prompt_config_mode' "$REPO_DIR/lib/config-lib.sh" >/dev/null 2>&1; then
        fail "prompt_config_mode must survive EOF"
    fi
fi

# Doctor inner script must stay syntactically valid.
sed -n "/^DOCTOR_SCRIPT='\$/,/^'\$/p" "$REPO_DIR/bin/opencode-dockerized" | sed '1d;$d' | bash -n ||
    fail "doctor inner script must pass bash -n"

# `opencode-dockerized install` flags: --help, unknown options, and fully non-interactive --yes.
"$REPO_DIR/bin/opencode-dockerized" install --help >/dev/null 2>&1 || fail "install --help must exit 0"
if "$REPO_DIR/bin/opencode-dockerized" install --bogus >/dev/null 2>&1; then
    fail "install must reject unknown options"
fi
if "$REPO_DIR/bin/opencode-dockerized" install --only bogus >/dev/null 2>&1; then
    fail "install must reject unknown --only sections"
fi
SETUP_HOME="$TMP/setuphome"
mkdir -p "$SETUP_HOME"
: >"$SETUP_HOME/.bashrc"
: >"$SETUP_HOME/.zshrc"
: >"$SETUP_HOME/.bashrc"
if ! env -u CONFIG_DIR -u OCODE_HOME HOME="$SETUP_HOME" "$REPO_DIR/bin/opencode-dockerized" install --yes --only global <&- >/dev/null 2>&1; then
    fail "install --yes --only global must succeed with closed stdin"
fi
[ ! -L "$SETUP_HOME/.local/bin/opencode-dockerized" ] ||
    fail "install must never create a symlink in ~/.local/bin"
grep -qF -- 'opencode-dockerized/bin' "$SETUP_HOME/.bashrc" ||
    fail "install --yes --only global must add bin/ to PATH"
if ! env -u CONFIG_DIR -u OCODE_HOME HOME="$SETUP_HOME" "$REPO_DIR/bin/opencode-dockerized" install --yes <&- >/dev/null 2>&1; then
    fail "install --yes must succeed with closed stdin"
fi
[ -f "$SETUP_HOME/.config/opencode-dockerized/config" ] ||
    fail "install --yes must create the default config"

# resolve_editor prefers $EDITOR, falls back, or fails cleanly.
[ "$(EDITOR=myeditor resolve_editor)" = myeditor ] || fail "resolve_editor must prefer EDITOR"
if PATH=/nonexistent-tmp-dir resolve_editor >/dev/null 2>&1; then
    fail "resolve_editor must fail with no editors on PATH"
fi

# Stale managed aliases migrate to the PATH-based form; foreign same-name
# lines survive.
ALIAS_HOME="$TMP/aliashome"
mkdir -p "$ALIAS_HOME"
printf '# OpenCode Dockerized aliases\nalias ocd='"'"'/OLD/path/opencode-dockerized.sh'"'"'\nalias myown='"'"'echo hi'"'"'\n' >"$ALIAS_HOME/.bashrc"
env -u CONFIG_DIR -u OCODE_HOME HOME="$ALIAS_HOME" "$REPO_DIR/bin/opencode-dockerized" install --yes --only aliases <&- >/dev/null 2>&1 ||
    fail "install --yes --only aliases must succeed"
grep -qxF -- "alias ocd='opencode-dockerized'" "$ALIAS_HOME/.bashrc" ||
    fail "stale alias must migrate to the PATH-based form"
grep -qxF -- "alias ocd-run='opencode-dockerized run'" "$ALIAS_HOME/.bashrc" ||
    fail "missing alias must be added in PATH form"
grep -qxF -- "alias myown='echo hi'" "$ALIAS_HOME/.bashrc" ||
    fail "custom lines must be preserved"
[ "$(grep -c '^alias ocd=' "$ALIAS_HOME/.bashrc")" -eq 1 ] ||
    fail "no duplicate alias lines"
env -u CONFIG_DIR -u OCODE_HOME HOME="$ALIAS_HOME" "$REPO_DIR/bin/opencode-dockerized" install --yes --only aliases <&- >/dev/null 2>&1 ||
    fail "re-run must succeed"
[ "$(grep -c '^alias ocd=' "$ALIAS_HOME/.bashrc")" -eq 1 ] ||
    fail "re-run must stay idempotent"
# Installing aliases must never create a symlink; the command comes from PATH.
[ ! -L "$ALIAS_HOME/.local/bin/opencode-dockerized" ] ||
    fail "alias install must not create a ~/.local/bin symlink"

# --only limits sections: global-only run touches no completions/aliases/config.
ONLY_HOME="$TMP/onlyhome"
mkdir -p "$ONLY_HOME"
: >"$ONLY_HOME/.bashrc"
env -u CONFIG_DIR -u OCODE_HOME HOME="$ONLY_HOME" "$REPO_DIR/bin/opencode-dockerized" install --yes --only global <&- >/dev/null 2>&1 ||
    fail "install --yes --only global must succeed"
[ ! -L "$ONLY_HOME/.local/bin/opencode-dockerized" ] ||
    fail "--only global must never create a symlink"
grep -qF -- 'opencode-dockerized/bin' "$ONLY_HOME/.bashrc" ||
    fail "--only global must add bin/ to PATH"
if grep -q "OpenCode Dockerized completion" "$ONLY_HOME/.bashrc"; then
    fail "--only global must not touch completions"
fi
if grep -q "OpenCode Dockerized aliases" "$ONLY_HOME/.bashrc"; then
    fail "--only global must not touch aliases"
fi
[ ! -e "$ONLY_HOME/.config/opencode-dockerized/config" ] ||
    fail "--only global must not create config"

# bin/ must hold only the opencode-dockerized binary (no second install binary).
[ -x "$REPO_DIR/bin/opencode-dockerized" ] ||
    fail "bin/opencode-dockerized must exist and be executable"
[ ! -e "$REPO_DIR/bin/install" ] ||
    fail "bin/install must not exist (bin/ holds only opencode-dockerized)"

# Piped/curl installs (closed stdin, no --yes) must still perform the full
# setup: config, PATH, completions and aliases — no second manual run needed.
PIPE_HOME="$TMP/pipehome"
mkdir -p "$PIPE_HOME"
: >"$PIPE_HOME/.bashrc"
: >"$PIPE_HOME/.zshrc"
if ! env -u CONFIG_DIR -u OCODE_HOME HOME="$PIPE_HOME" "$REPO_DIR/bin/opencode-dockerized" install <&- >/dev/null 2>&1; then
    fail "install with closed stdin and no --yes must succeed (auto --yes)"
fi
[ -f "$PIPE_HOME/.config/opencode-dockerized/config" ] ||
    fail "piped install must create the default config"
grep -qF -- 'opencode-dockerized/bin' "$PIPE_HOME/.bashrc" ||
    fail "piped install must add bin/ to PATH"
grep -qF -- "alias ocd='opencode-dockerized'" "$PIPE_HOME/.bashrc" ||
    fail "piped install must add aliases"
grep -q "OpenCode Dockerized completion" "$PIPE_HOME/.bashrc" ||
    fail "piped install must add completions"

# config sync must remove the obsolete second install binary when present.
: >"$CONFIG_DIR/plugins/policies/VERSION"
touch "$OCODE_BIN_DIR" 2>/dev/null || true
STALE_BIN="$TMP/stale-bin-install"
mkdir -p "$STALE_BIN"
: >"$STALE_BIN/install"
OCODE_BIN_DIR_SAVED="$OCODE_BIN_DIR"
OCODE_BIN_DIR="$STALE_BIN"
sync_security_layer >/dev/null 2>&1 || true
OCODE_BIN_DIR="$OCODE_BIN_DIR_SAVED"
[ ! -e "$STALE_BIN/install" ] ||
    fail "sync must remove the obsolete install binary"

echo "wrapper-args test passed"
