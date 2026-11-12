#!/bin/bash

# config-lib.sh - Shared configuration module for opencode-dockerized
# This file is sourced by other scripts (not executed directly)
# Provides: config parsing, docker arg building, shared volume logic, and interactive prompts

# NOTE: Do not use "set -e" here — this is a library file sourced by callers.
# Let calling scripts control their own error handling.

# ============================================
# CONSTANTS
# ============================================

CONFIG_DIR="${CONFIG_DIR:-$HOME/.config/opencode-dockerized}"
CONFIG_FILE="${CONFIG_FILE:-$CONFIG_DIR/config}"

# Active profile (multi-account). The wrapper resolves --profile /
# OPENCODE_DOCKERIZED_PROFILE ("default" when none) before sourcing this file,
# points CONFIG_DIR at <base>/profiles/<name> and sets OCD_PROFILES_BASE, so
# every per-profile path below derives from CONFIG_DIR. The base holds every
# OTHER profile's credentials and state, so it stays as protected from mounts
# and project dirs as the active tree. Sourced on its own (tests), the base is
# recovered from CONFIG_DIR, or is CONFIG_DIR itself.
OCD_PROFILE="${OCD_PROFILE:-${OPENCODE_DOCKERIZED_PROFILE:-}}"
if [ -z "${OCD_PROFILES_BASE:-}" ]; then
    OCD_PROFILES_BASE="$CONFIG_DIR"
    if [ -n "$OCD_PROFILE" ]; then
        # Strip exactly the active profile's suffix: a custom CONFIG_DIR that
        # happens to contain "/profiles/" elsewhere must not widen the base.
        case "$CONFIG_DIR" in
        */profiles/"$OCD_PROFILE") OCD_PROFILES_BASE="${CONFIG_DIR%/profiles/"$OCD_PROFILE"}" ;;
        esac
    fi
fi

# Self-contained OpenCode state tree. The wrapper owns all of OpenCode's runtime
# state (config, data, state, cache) under this single host directory instead of
# spreading it across the host XDG dirs, so the setup is portable and replaces
# native host usage. It mirrors the container home layout and is mounted 1:1.
OCODE_HOME="${OCODE_HOME:-$CONFIG_DIR/home}"

# Directory holding active GPG relay sockets (one subdir per session PID). The
# relay lives on a normal filesystem so Docker can bind it (it cannot bind
# sockets under the per-user /run/user tmpfs). Install-wide, not per profile:
# subdirs are per process anyway, `clean` purges them all, and a short path
# keeps the socket under the 108-byte unix socket limit.
GPG_RELAY_DIR="${GPG_RELAY_DIR:-$OCD_PROFILES_BASE/gnupg-relay}"

# Container-side GnuPG paths. The profile's public-key mirror is mounted
# read-only at the seed path; entrypoint.sh copies it into GNUPGHOME (on the
# container's own layer, so every session has its own keyboxd socket and lock
# files) and links the forwarded agent socket there.
GPG_CONTAINER_HOME="/home/coder/.gnupg"
GPG_CONTAINER_SEED="/home/coder/.gnupg-mirror"
GPG_CONTAINER_AGENT_SOCK="/home/coder/.gnupg-agent/S.gpg-agent"
SESSIONS_DIR="${SESSIONS_DIR:-$CONFIG_DIR/sessions}"

# Self-contained install location (Doom-style). The git checkout lives here;
# the binary is always <install>/bin/opencode-dockerized, reached via PATH.
# Nothing is ever installed into ~/.local/bin (no symlink, no stub, no copy).
OCODE_INSTALL_DIR="${OCODE_INSTALL_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/opencode-dockerized}"
OCODE_BIN_DIR="$OCODE_INSTALL_DIR/bin"
# Printed verbatim by `opencode-dockerized install` for shells without an rc
# file on disk; $HOME/$PATH must stay unexpanded here.
# shellcheck disable=SC2034,SC2016 # consumed by lib/install-lib.sh; single quotes are intentional
OCODE_BIN_PATH_LINE='export PATH="$HOME/.local/share/opencode-dockerized/bin:$PATH"'

# ============================================
# COLOR DEFINITIONS (with defaults if not set)
# ============================================

# Same form as the callers' definitions (a literal backslash escape that
# `echo -e` interprets); no quotes inside the default, or they would be stored.
: "${RED:=\033[0;31m}"
: "${GREEN:=\033[0;32m}"
: "${YELLOW:=\033[1;33m}"
: "${BLUE:=\033[0;34m}"
: "${NC:=\033[0m}"

# Honor NO_COLOR (https://no-color.org) and dumb terminals: strip ANSI codes.
# Applied here so every script sourcing this library (wrapper, setup,
# run-simple, tests) respects it without further changes.
if [ -n "${NO_COLOR:-}" ] || [ "${TERM:-}" = "dumb" ]; then
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# ============================================
# LOGGING FUNCTIONS (use caller's style if available)
# ============================================

config_info() {
    if type print_info >/dev/null 2>&1; then
        print_info "$1"
    else
        echo -e "${BLUE}ℹ${NC} $1"
    fi
}

config_success() {
    if type print_success >/dev/null 2>&1; then
        print_success "$1"
    else
        echo -e "${GREEN}✓${NC} $1"
    fi
}

config_warning() {
    if type print_warning >/dev/null 2>&1; then
        print_warning "$1"
    else
        echo -e "${YELLOW}⚠${NC} $1"
    fi
}

config_error() {
    if type print_error >/dev/null 2>&1; then
        print_error "$1"
    else
        echo -e "${RED}✗${NC} $1"
    fi
}

# Command-override test seams (GPG_AGENT_PROBE_CMD, GPG_AGENT_LAUNCH_CMD,
# GPG_RELAY_CMD) run arbitrary shell code, so a stray variable in the user's
# environment must never activate them: they are honoured only when the test
# suites opt in explicitly with OPENCODE_DOCKERIZED_TEST_HOOKS=1.
# Usage: test_hooks_enabled && ...
test_hooks_enabled() {
    [ "${OPENCODE_DOCKERIZED_TEST_HOOKS:-}" = 1 ]
}

# Resolve an editor: $EDITOR first, then common fallbacks.
# Prints the editor command name, or nothing when none is available.
# Usage: editor=$(resolve_editor)
resolve_editor() {
    if [ -n "${EDITOR:-}" ]; then
        echo "$EDITOR"
        return 0
    fi
    local candidate
    for candidate in sensible-editor vi nano; do
        if command -v "$candidate" >/dev/null 2>&1; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

# ============================================
# CONFIG STATE (global arrays, populated by parse_config)
# ============================================

declare -a CUSTOM_MOUNTS=()     # Array of "host_path:container_path[:rw]" values
declare -a CUSTOM_MOUNT_KEYS=() # Parallel array of config key suffixes (after "mount.")
declare -a DOCKER_MOUNT_ARGS=() # Array of docker -v arguments (populated by build_mount_args)
declare -a DOCKER_ENV_ARGS=()   # Array of docker -e arguments (populated by build_env_args)
# shellcheck disable=SC2034 # populated here, consumed by callers (bin/opencode-dockerized, tests)
declare -a DOCKER_ENV_FILE_ARGS=() # Array of docker --env-file arguments (populated by build_env_file_args)
declare -a VOLUME_ARGS=()       # Array of standard volume mount arguments (populated by build_standard_volume_args)
declare -a GIT_WORKTREE_ARGS=() # Array of docker args for git worktree support (populated by build_git_worktree_args)
SSH_AGENT_SUPPORT=false         # Boolean flag for SSH agent forwarding support
GPG_AGENT_SUPPORT=false         # Boolean flag for GnuPG agent forwarding (git signing)
GPG_ALLOW_MAIN_SOCKET=false     # Allow fallback to the full-control agent socket
GPG_AUTOSTART_AGENT=true        # Launch the host gpg-agent when its socket is missing
GPG_RELAY=true                  # Relay the agent socket through a normal-fs socket
GPG_RELAY_SOCKET=""             # Active relay socket for the current session
DOCKER_SOCKET=false             # Boolean flag: mount the host Docker socket (opt-in, root-equivalent)
MOUNT_NPMRC=false               # Boolean flag: mount ~/.npmrc read-only (opt-in: it may hold registry tokens)
NETWORK="host"                  # Container network: host (default, simple) | bridge (more isolated)
SECURITY_POLICY="balanced"      # Security policy mode: strict | balanced | off
MEMORY=""                       # Optional container memory limit (docker --memory), e.g. 4g
CPUS=""                         # Optional container CPU limit (docker --cpus), e.g. 2
PIDS_LIMIT=4096                 # Max processes in the container (docker --pids-limit); stops fork bombs
ENV_FILE=""                     # Optional dotenv file with secrets (docker --env-file), must live under CONFIG_DIR
WEBSEARCH_PROVIDER=""           # Optional built-in websearch provider: exa | firecrawl | parallel | tavily | random
THEME=""                        # Optional TUI theme name (built-in, e.g. catppuccin); empty = OpenCode default
GPG_SOCKET=""                   # Resolved host agent socket (set by build_mount_args)

# ============================================
# SHARED HELPERS
# ============================================

# Expand a leading "~" or "~/" to $HOME. Other forms (~user) are returned
# unchanged, so callers then reject them as relative paths.
# Usage: path=$(expand_tilde "~/x")
expand_tilde() {
    local p="$1"
    case "$p" in
    "~") p="$HOME" ;;
    "~/"*) p="$HOME/${p#"~/"}" ;;
    esac
    printf '%s\n' "$p"
}

# The env file path to open. ENV_FILE keeps the value as written in the config
# (a portable `~/` form is saved back unchanged), so every reader and writer
# goes through this instead of using ENV_FILE as a path.
# Usage: path=$(env_file_path)
env_file_path() {
    [ -n "${ENV_FILE:-}" ] || return 0
    expand_tilde "$ENV_FILE"
}

# Collapse "//", "/./" and ".." in an absolute path without touching the
# filesystem (container paths, or the missing tail of a host path).
# Usage: path=$(normalize_path_lexical "/a//b/../c")
normalize_path_lexical() {
    local p="$1" part out=""
    local -a parts=() stack=()
    IFS='/' read -r -a parts <<<"$p"
    for part in "${parts[@]}"; do
        case "$part" in
        "" | .) ;;
        ..) [ "${#stack[@]}" -gt 0 ] && stack=("${stack[@]:0:${#stack[@]}-1}") ;;
        *) stack+=("$part") ;;
        esac
    done
    for part in "${stack[@]}"; do
        out="$out/$part"
    done
    printf '%s\n' "${out:-/}"
}

# Canonical absolute form of a host path: symlinks resolved and "//", "/./",
# ".." collapsed. A missing tail is kept (lexically normalized) below the
# canonical form of its longest existing ancestor, so a path that does not
# exist yet still compares correctly. Fails (returns 1) for relative paths.
# Usage: canon=$(canonical_path "/some/path") || ...
canonical_path() {
    local p="$1" out
    [[ "$p" == /* ]] || return 1
    if out=$(readlink -m -- "$p" 2>/dev/null) && [ -n "$out" ]; then
        printf '%s\n' "$out"
        return 0
    fi
    # Portable fallback (no GNU readlink -m, e.g. macOS).
    local head="$p" tail=""
    while [ "$head" != "/" ] && [ ! -e "$head" ]; do
        tail="/$(basename -- "$head")$tail"
        head=$(dirname -- "$head")
    done
    if [ -d "$head" ]; then
        head=$(cd -P -- "$head" 2>/dev/null && pwd -P) || return 1
    else
        head=$(readlink -f -- "$head" 2>/dev/null) || return 1
    fi
    normalize_path_lexical "$head$tail"
}

# True when A and B are the same path or one contains the other (both
# absolute and normalized).
# Usage: paths_overlap A B && ...
paths_overlap() {
    local a="$1" b="$2"
    [ "$a" = "$b" ] && return 0
    { [ "$a" = "/" ] || [ "$b" = "/" ]; } && return 0
    [[ "$a" == "$b"/* ]] && return 0
    [[ "$b" == "$a"/* ]] && return 0
    return 1
}

# Unix socket path from DOCKER_HOST (unix://...), empty otherwise.
# Usage: sock=$(docker_host_socket_path)
docker_host_socket_path() {
    case "${DOCKER_HOST:-}" in
    unix://*) printf '%s\n' "${DOCKER_HOST#unix://}" ;;
    esac
}

# Decide whether a canonical host path touches a protected host location: it
# is "/", $HOME itself, or it equals, lies under or contains the SSH/GnuPG
# homes, the wrapper config (incl. OCODE_HOME), ~/.claude or a Docker socket.
# Both the literal and the symlink-resolved form of each location are checked.
# With "project" as second argument, ~/.config as a whole is protected too.
# Sets PROTECTED_REASON / PROTECTED_HINT and returns 0 when protected.
# Usage: if host_path_is_protected "$canon" [project]; then ...; fi
host_path_is_protected() {
    local canon="$1" scope="${2:-mount}" home_c entry loc reason hint form
    PROTECTED_REASON=""
    PROTECTED_HINT=""
    home_c=$(canonical_path "$HOME" 2>/dev/null) || home_c="$HOME"

    if [ "$canon" = "/" ]; then
        PROTECTED_REASON="it is the whole host filesystem"
        PROTECTED_HINT="Use a dedicated subdirectory instead."
        return 0
    fi
    for form in "$(normalize_path_lexical "$HOME")" "$home_c"; do
        if [ "$canon" = "$form" ]; then
            PROTECTED_REASON="it is your home directory"
            PROTECTED_HINT="Use a dedicated subdirectory instead (e.g. ~/projects/my-app)."
            return 0
        fi
    done

    local docker_hint="Use setting.docker_socket=true to share the Docker socket (root-equivalent on the host)."
    local -a protected=(
        "$HOME/.ssh|SSH private keys|Use setting.ssh_agent_support=true instead (config/known_hosts are mounted read-only automatically)."
        "$HOME/.gnupg|GnuPG private keys|Use setting.gpg_agent_support=true instead (only the public keyring and the agent socket are shared)."
        "$CONFIG_DIR|the wrapper configuration and its security layer|Keep the wrapper config ($CONFIG_DIR) out of the container."
        "$OCODE_HOME|the OpenCode state tree (config, guard, auth)|Keep the wrapper state ($OCODE_HOME) out of the container."
        "$OCD_PROFILES_BASE|the wrapper configuration (every profile's credentials and state)|Keep the wrapper config ($OCD_PROFILES_BASE) out of the container."
        "$HOME/.claude|Claude Code credentials and history|Only skills, agents, commands and CLAUDE.md are shared, automatically and read-only."
        "/var/run/docker.sock|the Docker socket|$docker_hint"
        "/run/docker.sock|the Docker socket|$docker_hint"
    )
    local dh_sock
    dh_sock=$(docker_host_socket_path)
    [ -n "$dh_sock" ] && protected+=("$dh_sock|the Docker socket|$docker_hint")
    [ "$scope" = project ] && protected+=("$HOME/.config|your host configuration (incl. the wrapper config)|Keep projects outside ~/.config.")

    for entry in "${protected[@]}"; do
        loc="${entry%%|*}"
        reason="${entry#*|}"
        hint="${reason#*|}"
        reason="${reason%%|*}"
        [[ "$loc" == /* ]] || continue
        for form in "$(normalize_path_lexical "$loc")" "$(canonical_path "$loc" 2>/dev/null)"; do
            [ -n "$form" ] || continue
            if paths_overlap "$canon" "$form"; then
                PROTECTED_REASON="it overlaps $form ($reason)"
                PROTECTED_HINT="$hint"
                return 0
            fi
        done
    done
    return 1
}

# Container-side locations a custom mount must never shadow: the read-only
# OpenCode config tree (guard, policies, rules) and the SSH/GnuPG paths the
# wrapper itself manages.
# Usage: container_path_is_protected "/normalized/path" && ...
container_path_is_protected() {
    local path="$1" p
    [ "$path" = "/" ] && return 0
    for p in /home/coder/.config/opencode /home/coder/.ssh /home/coder/.gnupg /home/coder/.gnupg-agent /home/coder/.gnupg-mirror; do
        if [ "$path" = "$p" ] || [[ "$path" == "$p"/* ]]; then
            return 0
        fi
    done
    return 1
}

# Validate one custom mount (host path, container path, mode) and print the
# docker -v value ("<canonical host>:<normalized container>:<mode>"). Errors
# go to stderr and 1 is returned. The host path must be absolute (a leading ~
# is expanded) and is canonicalized before the protected-path checks, so
# symlinks, "//", "/./" and ".." cannot slip past them.
# Usage: spec=$(validate_custom_mount HOST CONTAINER [MODE]) || ...
validate_custom_mount() {
    local host_path container_path="$2" mode="${3:-}" canon c_norm
    host_path=$(expand_tilde "$1")

    if [ -z "$host_path" ] || [[ "$host_path" != /* ]]; then
        config_error "Invalid mount host path '$1': it must be absolute (or start with ~/)" >&2
        return 1
    fi
    if ! canon=$(canonical_path "$host_path") || [ -z "$canon" ]; then
        config_error "Could not resolve mount host path '$1'" >&2
        return 1
    fi
    case "$canon" in
    *:*)
        config_error "Invalid mount host path '$canon': ':' is not supported" >&2
        return 1
        ;;
    esac
    if host_path_is_protected "$canon"; then
        config_error "Refusing to mount $host_path: $PROTECTED_REASON." >&2
        config_info "$PROTECTED_HINT" >&2
        return 1
    fi

    if [ -z "$container_path" ] || [[ "$container_path" != /* ]]; then
        config_error "Invalid mount '$1:$container_path': container path must be absolute" >&2
        return 1
    fi
    c_norm=$(normalize_path_lexical "$container_path")
    if container_path_is_protected "$c_norm"; then
        config_error "Refusing to mount over $c_norm: it would shadow the read-only OpenCode config or the wrapper-managed SSH/GnuPG paths." >&2
        return 1
    fi

    # No mode means read-only. Otherwise only ro/rw, optionally with an
    # SELinux label (z/Z), are accepted: a bare label or any other word would
    # silently make the mount writable.
    [ -n "$mode" ] || mode="ro"
    if [[ ! "$mode" =~ ^(ro|rw)(,[zZ])?$ ]]; then
        config_error "Invalid mount mode '$mode' (use ro, rw, optionally with ,z or ,Z)" >&2
        return 1
    fi
    printf '%s\n' "$canon:$c_norm:$mode"
}

# Top-level directories of the container image. A project whose $HOME-relative
# path starts with one of them (~/bin, ~/usr, ~/tmp, ...) would be mounted over
# that system directory, so it is placed under /home/coder instead.
CONTAINER_RESERVED_TOPDIRS=" bin boot dev etc home lib lib32 lib64 libx32 media mnt opt proc root run sbin srv sys tmp usr var "

# Compute the container mount path for a project directory.
# Strips $HOME (literal or symlink-resolved) so the path is portable across
# machines/users. When the stripped path would land on a system directory of
# the image it is placed under /home/coder instead (always traversable by the
# container user, independent of the host user name).
# Example: /home/user/projects/acme/frontend -> /projects/acme/frontend
#          /home/user/bin/tool               -> /home/coder/bin/tool
#          /opt/work/myproject                -> /opt/work/myproject (unchanged)
# Usage: container_path=$(compute_container_path "/home/user/projects/myapp")
compute_container_path() {
    local host_path="$1" home_c rel="" first
    home_c=$(cd "$HOME" 2>/dev/null && pwd -P) || home_c="$HOME"

    if [[ "$host_path" == "$HOME"/* ]]; then
        rel="${host_path#"$HOME"}"
    elif [[ "$host_path" == "$home_c"/* ]]; then
        rel="${host_path#"$home_c"}"
    else
        echo "$host_path"
        return 0
    fi

    first="${rel#/}"
    first="${first%%/*}"
    case "$CONTAINER_RESERVED_TOPDIRS" in
    *" $first "*) echo "/home/coder$rel" ;;
    *) echo "$rel" ;;
    esac
}

# Reject project directories that would expose sensitive host locations to
# the sandbox (mounted read-write): "/", $HOME, any ancestor of $HOME, and
# anything that equals, lies under or contains ~/.ssh, ~/.gnupg, ~/.config,
# the wrapper config/state, ~/.claude or a Docker socket. Paths are compared
# in canonical form (and against the symlink-resolved $HOME).
# Usage: validate_project_dir "/abs/path" || exit 1
validate_project_dir() {
    local project_dir="$1" canon home_c

    if [ -z "$project_dir" ]; then
        config_error "A project directory is required."
        return 1
    fi
    if ! canon=$(canonical_path "$project_dir"); then
        config_error "The project directory must be an absolute path: $project_dir"
        return 1
    fi
    home_c=$(cd "$HOME" 2>/dev/null && pwd -P) || home_c="$HOME"

    if [ "$canon" = "/" ]; then
        config_error "Refusing to run with '/' as the project."
        config_info "Pass a project subdirectory instead (e.g. ~/projects/my-app)."
        return 1
    fi

    if [ "$canon" = "$HOME" ] || [ "$canon" = "$home_c" ]; then
        config_error "Refusing to run with the home directory ($HOME) as the project."
        config_info "Pass a project subdirectory instead."
        return 1
    fi

    # Any ancestor of $HOME (e.g. /home) would expose the home through the mount.
    if [[ "$HOME" == "$canon"/* ]] || [[ "$home_c" == "$canon"/* ]]; then
        config_error "Refusing to run with '$project_dir' as the project: it contains your home directory."
        config_info "Pass a project subdirectory instead (e.g. ~/projects/my-app)."
        return 1
    fi

    if host_path_is_protected "$canon" project; then
        config_error "Refusing to run with '$project_dir' as the project: $PROTECTED_REASON."
        config_info "Pass a regular project directory instead (e.g. ~/projects/my-app)."
        return 1
    fi

    return 0
}

# SHA-256 of a file (sha256sum on Linux, shasum on macOS, openssl as a last
# resort). Prints nothing and returns 1 when no tool is available.
# Usage: file_sha256 FILE
file_sha256() {
    local out=""
    if command -v sha256sum >/dev/null 2>&1; then
        out=$(sha256sum "$1" 2>/dev/null)
    elif command -v shasum >/dev/null 2>&1; then
        out=$(shasum -a 256 "$1" 2>/dev/null)
    elif command -v openssl >/dev/null 2>&1; then
        out=$(openssl dgst -sha256 -r "$1" 2>/dev/null)
    fi
    [ -n "$out" ] || return 1
    echo "${out%% *}"
}

# Keep only the newest N timestamped backups (FILE.bak.<stamp>[.<n>]) of a file.
# Usage: prune_backups FILE [N=3]
prune_backups() {
    local file="$1" keep="${2:-3}" old
    # shellcheck disable=SC2012  # names are ours (FILE.bak.<digits>), ordering by mtime is the point
    while IFS= read -r old; do
        [ -n "$old" ] && rm -f "$old" 2>/dev/null
    done < <(ls -1t "$file".bak.* 2>/dev/null | tail -n "+$((keep + 1))")
    return 0
}

# Install SRC at DEST only when the content differs. Writes go through a temp
# file in the same directory plus an atomic rename (a session starting at the
# same moment never reads a truncated file), the previous file is kept as
# DEST.bak.<timestamp> (rotated, see prune_backups) and the result is verified
# with cmp. A no-op when the content already matches, so live sessions are not
# disturbed. Returns 1 when the file could not be installed.
# Usage: install_managed_file SRC DEST LABEL [keep_backup=true|false]
install_managed_file() {
    local src="$1" dest="$2" label="$3" keep_backup="${4:-true}" tmp
    if [ ! -f "$src" ]; then
        config_warning "$label: source not found at $src"
        return 1
    fi
    if cmp -s "$src" "$dest" 2>/dev/null; then
        return 0
    fi
    if [ -f "$dest" ] && [ "$keep_backup" = true ]; then
        # Two refreshes within the same second must not overwrite each other's
        # backup: add a counter suffix when the stamp is taken (cp -n never
        # clobbers an existing backup).
        local stamp backup n=0
        stamp=$(date +%Y%m%d%H%M%S)
        backup="$dest.bak.$stamp"
        while [ -e "$backup" ] || [ -L "$backup" ]; do
            n=$((n + 1))
            backup="$dest.bak.$stamp.$n"
        done
        if cp -n "$dest" "$backup" 2>/dev/null && [ -f "$backup" ]; then
            prune_backups "$dest" 3
            config_warning "Backed up previous $label"
        fi
    fi
    tmp=$(mktemp "$dest.XXXXXX" 2>/dev/null) || {
        config_error "Could not install $label: $(dirname "$dest") is not writable"
        return 1
    }
    if cp "$src" "$tmp" 2>/dev/null && chmod 0644 "$tmp" 2>/dev/null && mv -f "$tmp" "$dest" 2>/dev/null && cmp -s "$src" "$dest"; then
        config_success "Installed $label at $dest"
        return 0
    fi
    rm -f "$tmp" 2>/dev/null
    config_error "Could not install $label at $dest"
    return 1
}

# Ensure all required OpenCode directories exist on host, inside the
# self-contained OCODE_HOME tree (see CONSTANTS). Fresh start only: existing
# files are never overwritten, and the host XDG dirs are left untouched.
ensure_opencode_dirs() {
    mkdir -p "$OCODE_HOME/.config/opencode" 2>/dev/null || true
    mkdir -p "$OCODE_HOME/.config/opencode/agents" 2>/dev/null || true
    mkdir -p "$OCODE_HOME/.config/opencode/plugins" 2>/dev/null || true
    mkdir -p "$OCODE_HOME/.config/opencode/commands" 2>/dev/null || true
    mkdir -p "$OCODE_HOME/.config/opencode/skills" 2>/dev/null || true
    mkdir -p "$OCODE_HOME/.local/share/opencode" 2>/dev/null || true
    mkdir -p "$OCODE_HOME/.local/state/opencode" 2>/dev/null || true
    mkdir -p "$OCODE_HOME/.cache/opencode" 2>/dev/null || true
    # Minimal functional seeds (V2 only) — created once, never overwritten.
    # Single quotes are intentional: the JSON $schema key must stay literal.
    # shellcheck disable=SC2016
    [ -f "$OCODE_HOME/.config/opencode/opencode.json" ] || echo '{"$schema": "https://opencode.ai/config.json"}' >"$OCODE_HOME/.config/opencode/opencode.json" 2>/dev/null || true
    # V2 terminal client settings, seeded empty up front (mounted read-only with
    # the rest of the config dir; inject inline via OPENCODE_CLI_CONFIG_CONTENT
    # if a writable variant is ever needed)
    [ -f "$OCODE_HOME/.config/opencode/cli.json" ] || echo '{}' >"$OCODE_HOME/.config/opencode/cli.json" 2>/dev/null || true
    # MCP OAuth store (`mcp-remote` servers) — mounted read-write so tokens persist
    mkdir -p "$HOME/.mcp-auth" 2>/dev/null || true
    # opencode-dockerized directory + generated security layer
    ensure_opencode_dockerized_config
}

# Ensure the opencode-dockerized directory and its generated security layer exist.
# This directory is the host-side source of truth for the sandbox: its
# opencode.json (permission rules) is read by the wrapper and passed inline via
# OPENCODE_CONFIG_CONTENT, and its AGENTS.md / plugin hooks / policies are mounted
# read-only into the container (no host symlinks). The directory itself is never
# mounted, so a session cannot reach or edit these sources.
# Files are only created when missing — user edits are never overwritten.
# Check whether a file parses as JSON. Tries node, then python3; without either
# the check is skipped (return 2 = unknown, never a false failure).
# Usage: json_valid <file> (0 valid, 1 invalid, 2 unknown)
json_valid() {
    if command -v node >/dev/null 2>&1; then
        node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' "$1" >/dev/null 2>&1
        return $?
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$1" >/dev/null 2>&1
        return $?
    fi
    return 2
}

# Merge program shared by the node and python3 implementations below (same
# semantics). Arguments: <installed> <template> <output>. Prints tab-separated
# report lines (ADDED n / OVERRIDDEN action:resource / SKIPPED n / LEGACY 1),
# or "ERROR<TAB>message" and exits 1. Messages never echo file content.
# shellcheck disable=SC2016 # JavaScript source, expanded by node, not bash
OPENCODE_MERGE_JS='
const fs = require("fs");
const [inst, tpl, out] = process.argv.slice(1);
const fail = (m) => { process.stdout.write("ERROR\t" + m + "\n"); process.exit(1); };
let u, t;
try { u = JSON.parse(fs.readFileSync(inst, "utf8")); } catch (e) { fail("your opencode.json is not valid JSON"); }
try { t = JSON.parse(fs.readFileSync(tpl, "utf8")); } catch (e) { fail("the permission template is not valid JSON"); }
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
if (!isObj(u)) fail("your opencode.json is not a JSON object");
if (!isObj(t) || !Array.isArray(t.permissions)) fail("the permission template has no permissions array");
const ur = u.permissions === undefined ? [] : u.permissions;
if (!Array.isArray(ur)) fail("\"permissions\" in your opencode.json is not an array");
const isRule = (r) => isObj(r) && typeof r.action === "string" && typeof r.resource === "string";
const key = (r) => r.action + "\u0000" + r.resource;
const canon = (r) => JSON.stringify(Object.keys(r).sort().map((k) => [k, r[k]]));
const tkeys = new Set(t.permissions.map(key));
const seen = new Set(t.permissions.map(canon));
const added = [];
const report = [];
let skipped = 0;
for (const r of ur) {
  if (!isRule(r)) { skipped++; continue; }
  const c = canon(r);
  if (seen.has(c)) continue;
  if (tkeys.has(key(r))) { report.push("OVERRIDDEN\t" + r.action + ":" + r.resource); continue; }
  seen.add(c);
  added.push(r);
}
const o = { "$schema": t["$schema"] };
for (const k of Object.keys(u)) if (k !== "permission" && k !== "permissions") o[k] = u[k];
for (const k of Object.keys(t)) if (k !== "permissions" && !(k in o)) o[k] = t[k];
o.permissions = t.permissions.concat(added);
const one = (r) => "{ " + Object.keys(r).map((k) => JSON.stringify(k) + ": " + JSON.stringify(r[k])).join(", ") + " }";
const keys = Object.keys(o);
const lines = ["{"];
keys.forEach((k, i) => {
  const comma = i < keys.length - 1 ? "," : "";
  if (k === "permissions") {
    lines.push("  \"permissions\": [");
    o.permissions.forEach((r, j) => lines.push("    " + one(r) + (j < o.permissions.length - 1 ? "," : "")));
    lines.push("  ]" + comma);
  } else {
    lines.push("  " + JSON.stringify(k) + ": " + JSON.stringify(o[k], null, 2).replace(/\n/g, "\n  ") + comma);
  }
});
lines.push("}");
fs.writeFileSync(out, lines.join("\n") + "\n");
report.push("ADDED\t" + added.length);
if (skipped) report.push("SKIPPED\t" + skipped);
if (u.permission !== undefined) report.push("LEGACY\t1");
process.stdout.write(report.join("\n") + "\n");
'

OPENCODE_MERGE_PY='
import json, sys
inst, tpl, out = sys.argv[1:4]
def fail(m):
    sys.stdout.write("ERROR\t" + m + "\n")
    sys.exit(1)
try:
    with open(inst, encoding="utf-8") as fh:
        u = json.load(fh)
except Exception:
    fail("your opencode.json is not valid JSON")
try:
    with open(tpl, encoding="utf-8") as fh:
        t = json.load(fh)
except Exception:
    fail("the permission template is not valid JSON")
if not isinstance(u, dict):
    fail("your opencode.json is not a JSON object")
if not isinstance(t, dict) or not isinstance(t.get("permissions"), list):
    fail("the permission template has no permissions array")
ur = u.get("permissions", [])
if not isinstance(ur, list):
    fail("\"permissions\" in your opencode.json is not an array")
def is_rule(r):
    return isinstance(r, dict) and isinstance(r.get("action"), str) and isinstance(r.get("resource"), str)
def key(r):
    return (r["action"], r["resource"])
def canon(r):
    return json.dumps(sorted(r.items(), key=lambda kv: kv[0]), sort_keys=True)
tkeys = set(key(r) for r in t["permissions"])
seen = set(canon(r) for r in t["permissions"])
added, report, skipped = [], [], 0
for r in ur:
    if not is_rule(r):
        skipped += 1
        continue
    c = canon(r)
    if c in seen:
        continue
    if key(r) in tkeys:
        report.append("OVERRIDDEN\t" + r["action"] + ":" + r["resource"])
        continue
    seen.add(c)
    added.append(r)
o = {"$schema": t.get("$schema")}
for k, v in u.items():
    if k not in ("permission", "permissions"):
        o[k] = v
for k, v in t.items():
    if k != "permissions" and k not in o:
        o[k] = v
o["permissions"] = t["permissions"] + added
def dump(v, **kw):
    return json.dumps(v, ensure_ascii=False, **kw)
def one(r):
    return "{ " + ", ".join(dump(k) + ": " + dump(v, separators=(",", ":")) for k, v in r.items()) + " }"
keys = list(o.keys())
lines = ["{"]
for i, k in enumerate(keys):
    comma = "," if i < len(keys) - 1 else ""
    if k == "permissions":
        lines.append("  \"permissions\": [")
        n = len(o["permissions"])
        for j, r in enumerate(o["permissions"]):
            lines.append("    " + one(r) + ("," if j < n - 1 else ""))
        lines.append("  ]" + comma)
    else:
        lines.append("  " + dump(k) + ": " + dump(o[k], indent=2).replace("\n", "\n  ") + comma)
lines.append("}")
with open(out, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
report.append("ADDED\t" + str(len(added)))
if skipped:
    report.append("SKIPPED\t" + str(skipped))
if "permission" in u:
    report.append("LEGACY\t1")
sys.stdout.write("\n".join(report) + "\n")
'

# Merge user-added permission rules into a fresh opencode.json template with a
# real JSON parser (node, else python3): rules are matched by
# (action,resource), template rules win conflicts (reported via
# MERGED_OVERRIDDEN), other user rules are kept verbatim (MERGED_ADDED), and
# so are the user's top-level keys other than permission/permissions.
# Fails closed: without a parser, or when the user file is not valid JSON,
# nothing usable is written, MERGE_ERROR explains why and 1 is returned.
# Usage: merge_opencode_permissions <installed> <template> <output>
# Sets: MERGED_ADDED, MERGED_OVERRIDDEN ("action:resource ..."), MERGED_SKIPPED,
#       MERGED_LEGACY (true when a V1 "permission" block was dropped), MERGE_ERROR
merge_opencode_permissions() {
    local installed="$1" template="$2" output="$3" report rc=0 kind val
    MERGED_ADDED=0
    MERGED_OVERRIDDEN=""
    MERGED_SKIPPED=0
    MERGED_LEGACY=false
    MERGE_ERROR=""

    if command -v node >/dev/null 2>&1; then
        report=$(node -e "$OPENCODE_MERGE_JS" "$installed" "$template" "$output" 2>/dev/null) || rc=$?
    elif command -v python3 >/dev/null 2>&1; then
        report=$(python3 -I -c "$OPENCODE_MERGE_PY" "$installed" "$template" "$output" 2>/dev/null) || rc=$?
    else
        MERGE_ERROR="neither node nor python3 is available on the host to merge JSON safely"
        return 1
    fi

    if [ "$rc" -ne 0 ]; then
        while IFS=$'\t' read -r kind val; do
            [ "$kind" = ERROR ] && MERGE_ERROR="$val" && break
        done <<<"$report"
        [ -n "$MERGE_ERROR" ] || MERGE_ERROR="the JSON merge failed"
        return 1
    fi
    while IFS=$'\t' read -r kind val; do
        case "$kind" in
        ADDED) MERGED_ADDED="$val" ;;
        OVERRIDDEN) MERGED_OVERRIDDEN="$MERGED_OVERRIDDEN $val" ;;
        SKIPPED) MERGED_SKIPPED="$val" ;;
        LEGACY) MERGED_LEGACY=true ;;
        esac
    done <<<"$report"

    # Validate before the caller moves anything into place.
    local v=0
    json_valid "$output" || v=$?
    if [ "$v" -eq 1 ]; then
        MERGE_ERROR="the merged result is not valid JSON"
        return 1
    fi
    return 0
}

ensure_opencode_dockerized_config() {
    # Failures installing the security layer are reported and returned: a
    # session must never start silently without the guard or its rules.
    local layer_rc=0
    if ! mkdir -p "$CONFIG_DIR/plugins" 2>/dev/null; then
        config_error "Could not create $CONFIG_DIR/plugins"
        return 1
    fi

    # Directory holding this library's checkout root (lib/ -> repo root),
    # used to locate the versioned security sources.
    local repo_dir
    repo_dir="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"

    # Install the sandbox permission rules (native OpenCode V2 `permissions`
    # ordered array). Existing V1-style files are treated as outdated and
    # migrated (with a backup) so every install uses the native V2 shape.
    # The `private-keys-v1.d` / `id_ed25519` markers refresh installs created
    # before those deny rules were added.
    if [ ! -f "$CONFIG_DIR/opencode.json" ] || ! grep -q '"permissions"' "$CONFIG_DIR/opencode.json" 2>/dev/null || ! grep -q 'private-keys-v1.d' "$CONFIG_DIR/opencode.json" 2>/dev/null || ! grep -q 'id_ed25519' "$CONFIG_DIR/opencode.json" 2>/dev/null; then
        local had_file=false template_tmp merged_tmp
        if [ -f "$CONFIG_DIR/opencode.json" ]; then
            had_file=true
            cp "$CONFIG_DIR/opencode.json" "$CONFIG_DIR/opencode.json.bak" 2>/dev/null || true
            config_warning "Backed up pre-V2 opencode.json to opencode.json.bak"
        fi
        # Temp files live next to the target so the final rename is atomic.
        template_tmp=$(mktemp "$CONFIG_DIR/.opencode.json.tpl.XXXXXX" 2>/dev/null) || {
            config_error "Could not write the sandbox permissions in $CONFIG_DIR"
            return 1
        }
        merged_tmp=$(mktemp "$CONFIG_DIR/.opencode.json.new.XXXXXX" 2>/dev/null) || {
            rm -f "$template_tmp"
            config_error "Could not write the sandbox permissions in $CONFIG_DIR"
            return 1
        }
        cat >"$template_tmp" <<'EOF'
{
  "$schema": "https://opencode.ai/config.json",
  "permissions": [
    { "action": "shell", "resource": "*", "effect": "allow" },
    { "action": "shell", "resource": "sudo", "effect": "deny" },
    { "action": "shell", "resource": "sudo *", "effect": "deny" },
    { "action": "shell", "resource": "rm -rf *", "effect": "deny" },
    { "action": "shell", "resource": "rm -fr *", "effect": "deny" },
    { "action": "shell", "resource": "mkfs*", "effect": "deny" },
    { "action": "shell", "resource": "dd *", "effect": "deny" },
    { "action": "shell", "resource": "shutdown*", "effect": "deny" },
    { "action": "shell", "resource": "reboot*", "effect": "deny" },
    { "action": "shell", "resource": "halt*", "effect": "deny" },
    { "action": "shell", "resource": "poweroff*", "effect": "deny" },
    { "action": "shell", "resource": "git push*", "effect": "ask" },
    { "action": "shell", "resource": "git reset --hard*", "effect": "ask" },
    { "action": "shell", "resource": "docker system prune*", "effect": "ask" },
    { "action": "read", "resource": "*", "effect": "allow" },
    { "action": "read", "resource": "*.env", "effect": "deny" },
    { "action": "read", "resource": "*.env.*", "effect": "deny" },
    { "action": "read", "resource": "*.env.example", "effect": "allow" },
    { "action": "read", "resource": "*.pem", "effect": "deny" },
    { "action": "read", "resource": "*.key", "effect": "deny" },
    { "action": "read", "resource": "auth.json", "effect": "deny" },
    { "action": "read", "resource": "credentials*", "effect": "deny" },
    { "action": "read", "resource": "*.credentials.json", "effect": "deny" },
    { "action": "read", "resource": "*/.claude/projects/*", "effect": "deny" },
    { "action": "read", "resource": "*/.claude/history.jsonl", "effect": "deny" },
    { "action": "read", "resource": "*.npmrc", "effect": "deny" },
    { "action": "read", "resource": ".mcp-auth/*", "effect": "deny" },
    { "action": "read", "resource": ".ssh/*", "effect": "deny" },
    { "action": "read", "resource": "private-keys-v1.d/*", "effect": "deny" },
    { "action": "read", "resource": ".gnupg/private-keys-v1.d/*", "effect": "deny" },
    { "action": "read", "resource": "id_rsa", "effect": "deny" },
    { "action": "read", "resource": "id_dsa", "effect": "deny" },
    { "action": "read", "resource": "id_ecdsa", "effect": "deny" },
    { "action": "read", "resource": "id_ed25519", "effect": "deny" },
    { "action": "read", "resource": "id_ecdsa_sk", "effect": "deny" },
    { "action": "read", "resource": "id_ed25519_sk", "effect": "deny" },
    { "action": "read", "resource": "id_eddsa", "effect": "deny" },
    { "action": "external_directory", "resource": "*", "effect": "ask" },
    { "action": "external_directory", "resource": "/tmp/opencode", "effect": "allow" },
    { "action": "external_directory", "resource": "/tmp/opencode/*", "effect": "allow" }
  ]
}
EOF
        # Fail closed: when the user's rules cannot be merged safely, the old
        # file is left untouched and the layer reports failure, so no session
        # starts with outdated permissions (fix or delete the file to proceed).
        local refreshed=false
        if [ "$had_file" = true ]; then
            if merge_opencode_permissions "$CONFIG_DIR/opencode.json" "$template_tmp" "$merged_tmp" &&
                mv -f "$merged_tmp" "$CONFIG_DIR/opencode.json" 2>/dev/null; then
                refreshed=true
                [ "$MERGED_ADDED" -gt 0 ] && config_success "Preserved $MERGED_ADDED custom rule(s) in $CONFIG_DIR/opencode.json"
                [ -n "$MERGED_OVERRIDDEN" ] && config_warning "Template overrode custom rule(s):$MERGED_OVERRIDDEN"
                [ "$MERGED_SKIPPED" -gt 0 ] && config_warning "Dropped $MERGED_SKIPPED permission entr(ies) without string action/resource (kept in opencode.json.bak)"
                [ "$MERGED_LEGACY" = true ] && config_warning "Dropped the legacy V1 \"permission\" block (kept in opencode.json.bak)"
            else
                config_error "Could not refresh the sandbox permissions: ${MERGE_ERROR:-could not replace $CONFIG_DIR/opencode.json}."
                config_info "Fix or delete $CONFIG_DIR/opencode.json (a copy is in opencode.json.bak), then run 'opencode-dockerized config sync'."
                layer_rc=1
            fi
        elif mv -f "$template_tmp" "$CONFIG_DIR/opencode.json" 2>/dev/null; then
            refreshed=true
        else
            config_error "Could not write $CONFIG_DIR/opencode.json"
            layer_rc=1
        fi
        rm -f "$template_tmp" "$merged_tmp"
        if [ "$refreshed" = true ]; then
            chmod 0644 "$CONFIG_DIR/opencode.json" 2>/dev/null || true
            config_success "Refreshed security permissions at $CONFIG_DIR/opencode.json"
        fi
    fi

    # (Re)generate the rules when missing, or when predating the Tool Usage,
    # Core Workflow or expanded Language Tooling sections (markers below).
    # A pre-existing file is backed up first — never silently overwritten.
    if [ ! -f "$CONFIG_DIR/AGENTS.md" ] || ! grep -q "Language Tooling" "$CONFIG_DIR/AGENTS.md" 2>/dev/null || ! grep -q "## Tool Usage" "$CONFIG_DIR/AGENTS.md" 2>/dev/null || ! grep -q "## Core Workflow" "$CONFIG_DIR/AGENTS.md" 2>/dev/null || ! grep -q "private-keys-v1.d" "$CONFIG_DIR/AGENTS.md" 2>/dev/null || ! grep -q "id_ed25519" "$CONFIG_DIR/AGENTS.md" 2>/dev/null || ! grep -q "setting.env_file" "$CONFIG_DIR/AGENTS.md" 2>/dev/null || grep -q "Prefer LSP servers and formatters" "$CONFIG_DIR/AGENTS.md" 2>/dev/null; then
        if [ -f "$CONFIG_DIR/AGENTS.md" ]; then
            cp "$CONFIG_DIR/AGENTS.md" "$CONFIG_DIR/AGENTS.md.bak" 2>/dev/null || true
            config_warning "Backed up pre-tooling AGENTS.md to AGENTS.md.bak"
        fi
        cat >"$CONFIG_DIR/AGENTS.md" <<'EOF'
# Security Rules — opencode-dockerized

Global rules for every session running inside the opencode-dockerized container.
They are enforced alongside the `permissions` rules in `opencode.json` and the
hooks in `plugins/security-guard.js`. Do not attempt to weaken or bypass them.

## Commands

- Never run `sudo` or anything as root.
- Never run destructive commands: `rm -rf /...`, `mkfs`, `dd`, `shutdown`, `reboot`.
- Treat `git push` (especially `--force`) as approval-required: explain first.
- Do not control the host Docker daemon (no `docker system prune`, no privileged containers).
- Do not install packages system-wide or change system configuration.

## Files and secrets

- Never read or print secret files: `.env*` (except `.env.example`), `*.pem`,
  `*.key`, `auth.json`, SSH keys (`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`,
  `id_*_sk`, `~/.ssh/`), `~/.npmrc`, `~/.mcp-auth/`, `~/.gnupg/private-keys-v1.d/`,
  tokens or credentials of any kind.
- Only modify files inside the mounted project directory; touching anything
  outside it requires explicit user approval (`external_directory` asks by default).

## Process

- Review diffs before applying risky changes; prefer small, verifiable edits.
- Ask the user when a command's impact is unclear.
- If a security rule seems wrong for a legitimate task, tell the user instead of
  working around it.

## Tool Usage

The security guard evaluates the whole command string — including prose inside
commit messages, heredocs and `grep` patterns. Keep that in mind:

- Never write the word `sudo` in any command, commit message or `grep` pattern;
  the built-in backstop matches it anywhere. Say "privilege escalation" instead.
- Writable locations are the project directory and `/tmp/opencode`. Any other
  path (`~/.config`, `/etc`, `/tmp` outside that folder, …) is denied. Change
  the wrapper config from the host (e.g. `opencode-dockerized config edit`).
- Never read or print secret files (`.env`, `*.pem`, `*.key`, `auth.json`,
  `.npmrc`, `.mcp-auth`, SSH keys). Avoid dumping the environment: it carries
  provider credentials from the secrets file (printing it is not blocked).
- Provider credentials arrive via environment variables from the host secrets
  file (`setting.env_file`); never write them into files or print them.
  Reference them in configs as `{env:VARNAME}`.
- `apt-get`/`apt` are blocked: install dependencies with `uv add` (Python) or
  `pnpm add` (Node).
- Do not reference `/var/run/docker.sock` directly; Docker access is opt-in.
- Prefer small, single-purpose commands; the full string is inspected.
- If a legitimate command is wrongly blocked, tell the user instead of finding
  a workaround.

## Core Workflow — quality bar for every task

Applies to all languages. Security sections above always win on conflict.

- Evidence before synthesis: inspect files with `read`/`grep` before claiming anything; reproduce a bug before fixing it.
- Verify by execution: after implementing or fixing, run the project's build + tests + lint/typecheck and report the output. Never mark work done without running it.
- Prefer project tooling: use `package.json` / `pyproject.toml` / `Makefile` / `CMakePresets.json` / `go.mod` / `Cargo.toml` scripts before generic commands.
- Small, verifiable diffs: prefer `edit` over creating files; never create files unless needed. Review the diff before risky changes.
- Clean code: small single-responsibility functions, intentional names, early returns, no dead code, no `TODO` without a ticket, keep complexity low.
- Maintainability: one module = one responsibility; split files past ~300-500 LOC; keep dependencies one-directional; inject dependencies instead of globals; document only non-obvious `why`, not `what`.
- Modularity: separate I/O / domain / infrastructure; public APIs small and explicit; accept small interfaces, return concrete types; no circular imports.
- Secure by default: validate inputs at the boundary, fail closed, least privilege, never log or return secrets/internals, handle every error path.

## Language Tooling & Practices

The container provides Node.js (NVM), pnpm, uv and Git. Other toolchains
are available only when the project brings them — the practices below still
apply wherever you work. Run lint/typecheck/format through the project's own
tooling when it exists.

### Python — uv only

- Never use `pip`, `python -m pip` or `ensurepip`, not even inside a venv.
- Always create a venv first: `uv venv`, then `uv sync`, run with `uv run`.
- Add dependencies with `uv add`, never by hand-editing `uv.lock`.
- One-off tools via `uvx` (e.g. `uvx httpie`).
- Respect `requires-python` in `pyproject.toml`.
- Clean/verify: `uv run ruff check`, `uv run ruff format --check`, `uv run mypy` or `pyright`, `uv run pytest -q` must pass before handing in work.
- Style: full type hints on public functions, pure functions where possible, `src/` layout, thin `__init__.py`, no circular imports.
- Security: no `eval`/`exec`/`pickle` on external input; use `secrets` for tokens; parameterize SQL; run `pip-audit`/`bandit` when available.

### JavaScript/TypeScript — pnpm only

- Never use `npm install`; use `pnpm add|install|run` and `pnpm dlx`.
- `npx` is acceptable only to serve local MCP servers.
- Respect the `packageManager` field and commit `pnpm-lock.yaml`.
- Clean/verify: `pnpm exec tsc --noEmit`, `pnpm lint`, `pnpm exec prettier --check .`, `pnpm test` must pass before handing in work.
- Style: `strict:true`, no untyped `any` at boundaries (validate with `zod`), small modules, no `eval` / `innerHTML` with untrusted data.
- Security: sanitize HTML, set CSRF/XSS headers server-side, run `pnpm audit` and fix high/critical.

### C/C++

- Set the standard explicitly (`-std=c17`, `-std=c++20`) with `-Wall -Wextra -Werror` in dev/CI.
- Keep builds out of the source tree; prefer CMake (see below).
- Format with the project's configured formatter (`clang-format --dry-run --Werror`); lint with `clang-tidy` when configured.
- Style: headers expose a minimal API (`#pragma once`), `.cpp` holds details; no `using namespace std` in headers; RAII in C++; no mutable globals.
- Security: no `strcpy`/`sprintf`/`gets`; check bounds and return codes; test with `-fsanitize=address,undefined`; pair every allocation with ownership.

### Rust

- `cargo fmt --check`, `cargo clippy -- -D warnings` and `cargo test` must pass before handing in work.
- Use edition 2021 or newer; commit `Cargo.lock` for binaries, not for libraries.
- Style: no `unwrap`/`expect` outside tests; propagate with `?`; `thiserror` for library errors; small modules, small traits.
- Security: no new `unsafe` without a `// SAFETY:` comment plus a test; run `cargo audit`/`cargo deny` when available; never `panic!` on network input.

### Go

- `gofmt -l` must be clean; run `go vet ./...` and `go test ./...` (plus `-race` for concurrent code) before handing in work.
- Always work inside a module (`go.mod`); use `staticcheck` and `govulncheck ./...` when available.
- Style: wrap errors with `%w`, never ignore `err`; `context.Context` as first arg on I/O; accept small interfaces, return structs; keep packages small (`internal/` for non-public).
- Security: validate inputs, set HTTP timeouts, parameterize SQL, no `unsafe`.

### Make

- Mark non-file targets `.PHONY`; keep recipes parallel-safe (`make -j`).
- Provide a `help` target documenting the available targets.
- Style: one target = one responsibility; delegate lint/test to `make lint` / `make test`; shellcheck recipe lines containing shell.

### CMake

- Always configure out-of-source (`cmake -S . -B build`); prefer presets (`CMakePresets.json`); build with `cmake --build --preset <p>` and test with `ctest --preset <p>`.
- Modern target-based style (`target_link_libraries`, no global `include_directories`); set `-Wall -Wextra -Werror` per target.
- Style: one directory = one target with a clear name; keep toolchain details in presets, not in logic.

### Meson + Ninja

- `meson setup builddir`, then build and test with `ninja -C builddir` / `meson test -C builddir --print-errorlogs`.
- Style: keep `meson_options.txt` typed with sane defaults; one test entry per suite.

### HTML/CSS

- Semantic HTML5 (`header`/`main`/`nav`/`section`, real `button`/`a` elements).
- Format with `prettier --check`; use design tokens and mobile-first responsive CSS; avoid large inline-style blocks.
- Accessibility bar (WCAG 2.2 AA): labels on inputs, alt text, visible focus, contrast >= 4.5:1; escape dynamic data; add `rel="noopener"` to `target="_blank"`.

### Bash — for repo and project scripts

- Start scripts with `#!/bin/bash` and `set -euo pipefail`; quote `"$vars"`; use `$()` and arrays for command args.
- `bash -n` and `shellcheck -S warning` must pass; format with `shfmt` when the project uses it.
- Style: `snake_case` functions with a usage comment; fail with a message on stderr and non-zero exit.

### Dockerfile — when touching images

- Pin the base (`debian:trixie-slim`, never `latest`); set `SHELL ["/bin/bash", "-o", "pipefail", "-c"]`; parameterize versions via `ARG`.
- Never add privilege escalation, the daemon, or `--privileged`; run as non-root; clean apt caches in the same `RUN` layer.
- Style: one concern per layer; verify with `hadolint` when available.

### Git workflow

- Small focused commits with conventional subjects (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`); explain `git push --force` and destructive history rewrites before running them.
- Never commit secrets, lockfile hand-edits outside the package manager, or generated build output.
EOF
        config_success "Created security rules at $CONFIG_DIR/AGENTS.md"
    fi

    # Install the security hooks from the versioned repo copy
    # (plugins/security-guard.js) so the guard can be linted and reviewed like
    # the rest of the code. Content, not the version marker, decides: a changed
    # file is backed up (timestamped) and replaced atomically.
    local guard_src="$repo_dir/plugins/security-guard.js"
    mkdir -p "$CONFIG_DIR/plugins" 2>/dev/null || true
    install_managed_file "$guard_src" "$CONFIG_DIR/plugins/security-guard.js" "security hooks" || layer_rc=1

    # Seed/refresh the ported opencode-policy pattern data (policies/ in the
    # repo; the copies are mirrored read-only into the container, see
    # build_standard_volume_args). VERSION is kept as the human-readable marker.
    local policy_src policy_dest pf
    policy_src="$repo_dir/policies"
    policy_dest="$CONFIG_DIR/plugins/policies"
    mkdir -p "$policy_dest" 2>/dev/null || true

    local -a policy_files=(unsafe-tool-patterns.json prompt-injection-patterns.json allow-patterns.json)
    for pf in "${policy_files[@]}"; do
        install_managed_file "$policy_src/$pf" "$policy_dest/$pf" "policy patterns $pf" || layer_rc=1
    done
    install_managed_file "$policy_src/VERSION" "$policy_dest/VERSION" "policy VERSION marker" false || layer_rc=1

    # Mirror the security layer into the OpenCode config tree, which is bind
    # mounted read-only into the container. A single read-only directory mount is
    # used because Docker cannot create nested mountpoints under a read-only
    # parent. These copies are wrapper-managed: they follow the repo (guard) and
    # the installed policy copies, so edit those sources, never the mirror.
    local oc_dir="$OCODE_HOME/.config/opencode"
    if [ -d "$oc_dir" ]; then
        mkdir -p "$oc_dir/plugins/policies" 2>/dev/null || layer_rc=1
        install_managed_file "$guard_src" "$oc_dir/plugins/security-guard.js" "config-tree guard" false || layer_rc=1
        for pf in "${policy_files[@]}"; do
            install_managed_file "$policy_dest/$pf" "$oc_dir/plugins/policies/$pf" "config-tree policy $pf" false || layer_rc=1
        done
        install_managed_file "$policy_dest/VERSION" "$oc_dir/plugins/policies/VERSION" "config-tree policy VERSION marker" false || layer_rc=1
        # Global rules: back up a user-authored AGENTS.md (not one of ours) once,
        # then keep the managed rules in place.
        if [ -f "$CONFIG_DIR/AGENTS.md" ]; then
            if [ -f "$oc_dir/AGENTS.md" ] && ! grep -q "Security Rules — opencode-dockerized" "$oc_dir/AGENTS.md" 2>/dev/null; then
                cp "$oc_dir/AGENTS.md" "$oc_dir/AGENTS.md.user.bak" 2>/dev/null || true
                config_warning "Backed up your AGENTS.md to AGENTS.md.user.bak (replaced by the read-only security rules)"
            fi
            install_managed_file "$CONFIG_DIR/AGENTS.md" "$oc_dir/AGENTS.md" "config-tree AGENTS.md" false || layer_rc=1
        fi
    fi

    # Clean up the legacy symlink from earlier versions if it still points at our
    # target (the security files now live directly in the config tree).
    local shared_link="$HOME/.config/opencode/plugins/security-guard.js"
    if [ -L "$shared_link" ]; then
        local link_target
        link_target=$(readlink "$shared_link" 2>/dev/null || true)
        if [ "$link_target" = "../../opencode-dockerized/plugins/security-guard.js" ]; then
            rm -f "$shared_link" 2>/dev/null || true
            config_info "Removed legacy security-guard symlink from host config"
        fi
    fi
    return "$layer_rc"
}

# Print the canonical install binary path (Doom-style: <install>/bin/opencode-dockerized).
# Usage: repo_script_path
repo_script_path() {
    local repo_dir
    repo_dir="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
    readlink -f "$repo_dir/bin/opencode-dockerized" 2>/dev/null || true
}

# Canonical install root for this checkout (lib/ -> repo root).
# Usage: install_root
install_root() {
    cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd
}

# Remove a legacy ~/.local/bin/opencode-dockerized symlink left by older
# versions. A real (non-symlink) file is never touched. Returns 0 when
# nothing remains to clean.
# Usage: cleanup_legacy_symlink
cleanup_legacy_symlink() {
    local link="$HOME/.local/bin/opencode-dockerized"
    if [ -L "$link" ]; then
        rm -f "$link" 2>/dev/null || true
        config_success "Removed legacy symlink $link (now reached via PATH)"
    fi
    return 0
}

# Verify the global host integration: <install>/bin on PATH plus the managed
# rc lines (aliases, completions, PATH). Report-only; sync never edits rc
# files (re-run `opencode-dockerized install` to repair them).
# Usage: check_global_install
check_global_install() {
    local stale=false
    local expected bin_file
    expected=$(repo_script_path)
    bin_file="$OCODE_BIN_DIR/opencode-dockerized"
    # The running checkout counts too: dev checkouts outside the canonical
    # path are fine as long as their bin/ is on PATH.
    local this_bin=""
    this_bin="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../bin" && pwd)/opencode-dockerized"
    if command -v opencode-dockerized >/dev/null 2>&1; then
        config_success "opencode-dockerized on PATH ($(command -v opencode-dockerized))"
    elif [ -n "$expected" ] && [ -x "$expected" ] && [[ ":$PATH:" == *":$(dirname "$expected"):"* ]]; then
        config_success "install bin/ on PATH ($(dirname "$expected"))"
    else
        config_warning "opencode-dockerized not on PATH; run 'opencode-dockerized install' to add $OCODE_BIN_DIR (or this checkout's bin/) to PATH"
        stale=true
    fi
    if [ -e "$HOME/.local/bin/opencode-dockerized" ] && [ -L "$HOME/.local/bin/opencode-dockerized" ]; then
        config_warning "legacy symlink present at $HOME/.local/bin/opencode-dockerized; sync removes it"
        stale=true
    fi
    # Obsolete second binary: bin/ must hold only opencode-dockerized.
    local stale_bin
    for stale_bin in "$OCODE_BIN_DIR/install" "$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../bin" 2>/dev/null && pwd)/install"; do
        if [ -n "$stale_bin" ] && [ -e "$stale_bin" ]; then
            config_warning "obsolete install binary present at $stale_bin; sync removes it (use 'opencode-dockerized install')"
            stale=true
        fi
    done
    for cand in "$expected" "$this_bin" "$bin_file"; do
        if [ -n "$cand" ] && [ -e "$cand" ] && [ ! -x "$cand" ]; then
            config_warning "binary is not executable ($cand); sync restores +x"
            stale=true
        fi
    done

    local rc kind missing
    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
        [ -f "$rc" ] || continue
        case "$rc" in
        *.bashrc) kind=bash ;;
        *) kind=zsh ;;
        esac
        missing=""
        if ! grep -qxF -- "alias ocd='opencode-dockerized'" "$rc" 2>/dev/null ||
            ! grep -qxF -- "alias ocd-run='opencode-dockerized run'" "$rc" 2>/dev/null ||
            ! grep -qxF -- "alias ocd-auth='opencode-dockerized auth'" "$rc" 2>/dev/null; then
            missing="$missing aliases"
        fi
        grep -qF -- "completions/$kind.sh" "$rc" 2>/dev/null || missing="$missing completion"
        if ! grep -qF -- 'opencode-dockerized/bin' "$rc" 2>/dev/null; then
            missing="$missing PATH"
        fi
        if [ -n "$missing" ]; then
            config_warning "$(basename "$rc"): stale host integration ($missing ); re-run 'opencode-dockerized install' to repair"
            stale=true
        else
            config_success "$(basename "$rc") host integration (in sync)"
        fi
    done

    if [ "$stale" = true ]; then
        return 1
    fi
    return 0
}

# Compare the versioned security layer (repo sources vs installed copies).
# Prints one status line per component and returns 1 when anything is stale.
# Pure reads only; never writes. Backs `config sync --check`.
# Usage: check_security_layer
check_security_layer() {
    local stale=false
    local repo_dir
    repo_dir="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"

    # Content decides, not the version marker: an edited or truncated copy with
    # the right marker is just as stale as an old one.
    local repo_guard inst_guard
    repo_guard=$(grep -oE 'OPENCODE_DOCKERIZED_GUARD_VERSION=[0-9]+' "$repo_dir/plugins/security-guard.js" 2>/dev/null | head -1)
    inst_guard=$(grep -oE 'OPENCODE_DOCKERIZED_GUARD_VERSION=[0-9]+' "$CONFIG_DIR/plugins/security-guard.js" 2>/dev/null | head -1)
    if [ -n "$repo_guard" ] && cmp -s "$repo_dir/plugins/security-guard.js" "$CONFIG_DIR/plugins/security-guard.js"; then
        config_success "security-guard.js $repo_guard (in sync)"
    else
        config_warning "security-guard.js stale (repo ${repo_guard:-missing} vs installed ${inst_guard:-missing}, or content differs)"
        stale=true
    fi

    local src_ver inst_ver pf policy_stale=false
    src_ver=$(cat "$repo_dir/policies/VERSION" 2>/dev/null || true)
    inst_ver=$(cat "$CONFIG_DIR/plugins/policies/VERSION" 2>/dev/null || true)
    for pf in unsafe-tool-patterns.json prompt-injection-patterns.json allow-patterns.json VERSION; do
        cmp -s "$repo_dir/policies/$pf" "$CONFIG_DIR/plugins/policies/$pf" || policy_stale=true
    done
    if [ -n "$src_ver" ] && [ "$policy_stale" = false ]; then
        config_success "policy patterns v$src_ver (in sync)"
    else
        config_warning "policy patterns stale (repo ${src_ver:-missing} vs installed ${inst_ver:-missing}, or content differs)"
        stale=true
    fi

    if [ -f "$CONFIG_DIR/opencode.json" ] && grep -q '"permissions"' "$CONFIG_DIR/opencode.json" 2>/dev/null && grep -q 'private-keys-v1.d' "$CONFIG_DIR/opencode.json" 2>/dev/null && grep -q 'id_ed25519' "$CONFIG_DIR/opencode.json" 2>/dev/null; then
        config_success "opencode.json permissions (in sync)"
    else
        config_warning "opencode.json permissions stale or missing"
        stale=true
    fi

    # Managed session rules must carry the current markers (sync regenerates
    # them with a backup when they predate the template).
    if [ -f "$CONFIG_DIR/AGENTS.md" ] && grep -q "Language Tooling" "$CONFIG_DIR/AGENTS.md" 2>/dev/null && grep -q "## Tool Usage" "$CONFIG_DIR/AGENTS.md" 2>/dev/null && grep -q "## Core Workflow" "$CONFIG_DIR/AGENTS.md" 2>/dev/null && grep -q 'private-keys-v1.d' "$CONFIG_DIR/AGENTS.md" 2>/dev/null && grep -q 'id_ed25519' "$CONFIG_DIR/AGENTS.md" 2>/dev/null && grep -q 'setting.env_file' "$CONFIG_DIR/AGENTS.md" 2>/dev/null && ! grep -q "Prefer LSP servers and formatters" "$CONFIG_DIR/AGENTS.md" 2>/dev/null; then
        config_success "AGENTS.md rules (in sync)"
    else
        config_warning "AGENTS.md rules stale or missing"
        stale=true
    fi

    # The read-only config tree must carry the installed layer (single mount).
    local oc_dir="$OCODE_HOME/.config/opencode"
    local mirror_guard mirror_stale=false
    mirror_guard=$(grep -oE 'OPENCODE_DOCKERIZED_GUARD_VERSION=[0-9]+' "$oc_dir/plugins/security-guard.js" 2>/dev/null | head -1)
    cmp -s "$repo_dir/plugins/security-guard.js" "$oc_dir/plugins/security-guard.js" || mirror_stale=true
    for pf in unsafe-tool-patterns.json prompt-injection-patterns.json allow-patterns.json VERSION; do
        cmp -s "$CONFIG_DIR/plugins/policies/$pf" "$oc_dir/plugins/policies/$pf" || mirror_stale=true
    done
    if [ -f "$CONFIG_DIR/AGENTS.md" ]; then
        cmp -s "$CONFIG_DIR/AGENTS.md" "$oc_dir/AGENTS.md" || mirror_stale=true
    fi
    if [ -n "$inst_guard" ] && [ "$mirror_stale" = false ]; then
        config_success "config-tree mirror $mirror_guard (in sync)"
    else
        config_warning "config-tree mirror stale (installed ${inst_guard:-missing} vs mirror ${mirror_guard:-missing}, or content differs)"
        stale=true
    fi

    # cli.json must exist and parse (user TUI settings live here; never
    # overwritten when valid).
    local cli="$oc_dir/cli.json" v
    if [ ! -f "$cli" ]; then
        config_warning "cli.json missing (reseeded on sync)"
        stale=true
    else
        v=0; json_valid "$cli" || v=$?
        if [ "$v" -eq 0 ]; then
            config_success "cli.json valid (in sync)"
        elif [ "$v" -eq 1 ]; then
            config_warning "cli.json is not valid JSON (backed up and reseeded on sync)"
            stale=true
        else
            config_info "cli.json present (no JSON parser available to validate)"
        fi
    fi

    # The user-managed OpenCode config (MCP/servers) is never touched by sync,
    # but an unparsable file breaks every session: fail the check early.
    local uoc
    for uoc in "$oc_dir/opencode.json" "$oc_dir/opencode.jsonc"; do
        [ -f "$uoc" ] || continue
        v=0; json_valid "$uoc" || v=$?
        if [ "$v" -eq 1 ]; then
            config_warning "$uoc is not valid JSON (fix it; sync never edits this file)"
            stale=true
        fi
    done

    # The secrets file is never read for values here; only its permissions.
    if [ -n "${ENV_FILE:-}" ]; then
        local env_path
        env_path=$(env_file_path)
        if [ ! -f "$env_path" ]; then
            config_warning "env file not found: $env_path"
            stale=true
        else
            local mode=""
            mode=$(stat -c '%a' "$env_path" 2>/dev/null || stat -f '%Lp' "$env_path" 2>/dev/null || true)
            if [ -n "$mode" ] && [ $((8#$mode & 8#044)) -ne 0 ]; then
                config_warning "env file is readable by group/others ($env_path); run: chmod 600"
            else
                config_success "env file permissions ok"
            fi
        fi
    fi

    # Global host integration (bin/ on PATH + rc lines); report-only here.
    # Sync never edits rc files; `opencode-dockerized install` repairs them.
    if ! check_global_install; then
        stale=true
    fi

    if [ "$stale" = true ]; then
        return 1
    fi
    return 0
}

# Print a one-line hint when the installed security layer drifts from the repo.
# Pure reads only (see check_security_layer).
# Usage: maybe_drift_hint
maybe_drift_hint() {
    check_security_layer >/dev/null 2>&1 || echo "Security layer drift detected: run 'opencode-dockerized config sync' to refresh."
}

# Refresh the versioned security layer from the repo and report the result.
# With --check it only reports drift (exit 1 when stale) and writes nothing.
# Local-only: no Docker required.
# Usage: sync_security_layer [--check]
sync_security_layer() {
    case "${1:-}" in
    "" | --check) ;;
    *)
        config_error "Usage: $0 config sync [--check]"
        return 1
        ;;
    esac
    # Host-only: inside a container CONFIG_DIR is ephemeral, so syncing there
    # creates a junk layer instead of updating the host. Tests override with
    # OPENCODE_DOCKERIZED_ALLOW_CONTAINER_SYNC=1.
    if [ -z "${OPENCODE_DOCKERIZED_ALLOW_CONTAINER_SYNC:-}" ] && { [ -f /.dockerenv ] || [ -f /run/.containerenv ]; }; then
        config_error "config sync is host-only; run it on the host, not inside a container."
        return 1
    fi
    if [ "${1:-}" = "--check" ]; then
        if check_security_layer; then
            config_success "Security layer is in sync with the repo."
            return 0
        fi
        config_error "Security layer is stale; run 'config sync' without --check to refresh."
        return 1
    fi

    config_info "Refreshing security layer from the repo..."
    ensure_opencode_dirs
    ensure_opencode_dockerized_config
    # Repair an unparsable cli.json (user TUI settings are only lost when the
    # file is already broken; the broken copy is kept as .bak).
    local cli="$OCODE_HOME/.config/opencode/cli.json" v
    if [ -f "$cli" ]; then
        v=0; json_valid "$cli" || v=$?
        if [ "$v" -eq 1 ]; then
            cp "$cli" "$cli.bak" 2>/dev/null || true
            echo '{}' >"$cli" 2>/dev/null || true
            config_warning "Backed up broken cli.json to cli.json.bak and reseeded it"
        fi
    fi
    # Drop the legacy ~/.local/bin symlink (nothing is ever installed there
    # anymore; the binary is reached via <install>/bin on PATH). A real file
    # is never touched. Binaries must stay executable for PATH resolution.
    # Also drop the obsolete second `install` binary: bin/ holds only
    # `opencode-dockerized` now (kept in sync as the config sync always does).
    cleanup_legacy_symlink || true
    local stale_install=""
    stale_install="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../bin" 2>/dev/null && pwd)/install"
    if [ -n "$stale_install" ] && [ -e "$stale_install" ]; then
        rm -f "$stale_install" 2>/dev/null || true
        config_info "Removed obsolete install binary ($stale_install; use 'opencode-dockerized install')"
    fi
    if [ -e "$OCODE_BIN_DIR/install" ]; then
        rm -f "$OCODE_BIN_DIR/install" 2>/dev/null || true
        config_info "Removed obsolete $OCODE_BIN_DIR/install (use 'opencode-dockerized install')"
    fi
    local want_bin
    want_bin=$(repo_script_path)
    if [ -n "$want_bin" ] && [ -e "$want_bin" ] && [ ! -x "$want_bin" ]; then
        if chmod +x "$want_bin" 2>/dev/null; then
            config_success "Made the opencode-dockerized binary executable"
        else
            config_warning "Binary is not executable ($want_bin)"
        fi
    fi
    echo ""
    if check_security_layer; then
        config_success "Security layer synced with the repo."
        return 0
    fi
    config_warning "Security layer still reports stale items after refresh (see above)."
    return 1
}

# Check if Docker image exists locally
# Usage: check_image "$IMAGE_NAME"
check_image() {
    local image_name="$1"
    if ! docker image inspect "$image_name" >/dev/null 2>&1; then
        config_error "Docker image '$image_name' not found. Run '$0 build' first."
        return 1
    fi
}

# Sanitize a string for use as part of a Docker container name
# Docker container names must match [a-zA-Z0-9][a-zA-Z0-9_.-]
# Usage: sanitize_container_name "my project dir"
sanitize_container_name() {
    local name="$1"
    name=$(echo "$name" | tr -cd '[:alnum:]._-')
    # Ensure it starts with alphanumeric
    while [[ "$name" =~ ^[^[:alnum:]] ]]; do name="${name#?}"; done
    [ -z "$name" ] && name="project"
    echo "$name"
}

# Generate a random hex suffix for container names
generate_random_suffix() {
    # 8 hex chars of OS entropy (avoids the collision-prone $RANDOM)
    head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

# Resolve the host's gpg-agent socket path.
# Prefers an explicit override (GPG_AGENT_SOCKET, used by tests), then gpgconf.
# Prints an empty string when neither is available.
resolve_gpg_agent_socket() {
    if [ -n "${GPG_AGENT_SOCKET:-}" ]; then
        echo "$GPG_AGENT_SOCKET"
        return 0
    fi
    if command -v gpgconf >/dev/null 2>&1; then
        gpgconf --list-dirs agent-socket 2>/dev/null || true
    fi
}

# Resolve the host's restricted gpg-agent "extra" socket path. This socket only
# allows signing/decryption, so a forwarded container cannot reconfigure the
# host agent. Prefers an explicit override (GPG_AGENT_EXTRA_SOCKET, used by
# tests), then gpgconf. Prints an empty string when neither is available.
resolve_gpg_agent_extra_socket() {
    if [ -n "${GPG_AGENT_EXTRA_SOCKET:-}" ]; then
        echo "$GPG_AGENT_EXTRA_SOCKET"
        return 0
    fi
    if command -v gpgconf >/dev/null 2>&1; then
        gpgconf --list-dirs agent-extra-socket 2>/dev/null || true
    fi
}

# Return 0 when the host gpg-agent looks reachable, 1 otherwise. Socket
# presence alone is not enough: a stale socket file would pass for "running",
# so on a real host the agent is probed with gpg-connect-agent (2s timeout).
# Test seams:
#   - GPG_AGENT_PROBE_CMD replaces the probe with an arbitrary command (only
#     with OPENCODE_DOCKERIZED_TEST_HOOKS=1, see test_hooks_enabled).
#   - GPG_AGENT_SOCKET / GPG_AGENT_EXTRA_SOCKET (plain test sockets, not real
#     agents) skip the probe and trust the socket.
# Usage: gpg_agent_is_running
gpg_agent_is_running() {
    local extra main
    extra=$(resolve_gpg_agent_extra_socket)
    main=$(resolve_gpg_agent_socket)

    if { [ -z "$extra" ] || [ ! -S "$extra" ]; } && { [ -z "$main" ] || [ ! -S "$main" ]; }; then
        return 1
    fi

    if [ -n "${GPG_AGENT_PROBE_CMD:-}" ] && test_hooks_enabled; then
        bash -c "$GPG_AGENT_PROBE_CMD" >/dev/null 2>&1 && return 0
        return 1
    fi

    # Test sockets are not real agents: trust the socket.
    if [ -n "${GPG_AGENT_SOCKET:-}" ] || [ -n "${GPG_AGENT_EXTRA_SOCKET:-}" ]; then
        return 0
    fi

    # Without the probe tooling, fall back to trusting the socket.
    if ! command -v gpg-connect-agent >/dev/null 2>&1 || ! command -v timeout >/dev/null 2>&1; then
        return 0
    fi
    if timeout 2 gpg-connect-agent --no-autostart 'getinfo version' /bye >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Prepare the host GnuPG agent before its socket is mounted. When the restricted
# extra socket is missing, launch the host agent (unless autostart is disabled)
# and wait briefly for it to appear. Never fails the run: it reports actionable
# warnings and lets build_mount_args skip the socket.
# Usage: ensure_gpg_agent_ready
ensure_gpg_agent_ready() {
    [ "$GPG_AGENT_SUPPORT" = true ] || return 0

    if ! command -v gpgconf >/dev/null 2>&1; then
        config_warning "gpgconf not found on the host; cannot prepare the GnuPG agent"
        return 0
    fi

    local extra main
    extra=$(resolve_gpg_agent_extra_socket)
    main=$(resolve_gpg_agent_socket)

    # Ready only when the socket we will actually mount is usable: the restricted
    # extra socket, or the main one when explicitly allowed. A live main socket
    # alone must not short-circuit, or a missing extra socket is never repaired.
    if [ -n "$extra" ] && [ -S "$extra" ]; then
        if gpg_agent_is_running; then
            return 0
        fi
    elif [ "$GPG_ALLOW_MAIN_SOCKET" = true ] && [ -n "$main" ] && [ -S "$main" ]; then
        if gpg_agent_is_running; then
            return 0
        fi
    fi

    if [ "$GPG_AUTOSTART_AGENT" != true ]; then
        config_warning "GnuPG agent socket not available and autostart is disabled (setting.gpg_autostart_agent=false)"
        return 0
    fi

    # A previous `-v` mount can leave an empty directory where the agent socket
    # belongs, which blocks gpg-agent from creating it. Remove empty ones (rmdir
    # refuses non-empty directories) before launching.
    local dir
    for dir in "$extra" "$main"; do
        if [ -n "$dir" ] && [ -d "$dir" ] && [ ! -S "$dir" ]; then
            if rmdir "$dir" 2>/dev/null; then
                config_warning "Removed an empty directory blocking the GnuPG agent socket: $dir"
            fi
        fi
    done

    config_info "Starting host gpg-agent for GnuPG forwarding..."
    if [ -n "${GPG_AGENT_LAUNCH_CMD:-}" ] && test_hooks_enabled; then
        bash -c "$GPG_AGENT_LAUNCH_CMD" >/dev/null 2>&1 || true
    else
        gpgconf --launch gpg-agent >/dev/null 2>&1 || config_warning "gpgconf --launch gpg-agent failed"
    fi

    # The socket appears asynchronously; give it up to ~2s.
    local i
    for ((i = 0; i < 20; i++)); do
        extra=$(resolve_gpg_agent_extra_socket)
        if [ -n "$extra" ] && [ -S "$extra" ]; then
            return 0
        fi
        main=$(resolve_gpg_agent_socket)
        if [ -n "$main" ] && [ -S "$main" ]; then
            return 0
        fi
        sleep 0.1
    done

    # Still missing: report the most likely cause (a non-empty directory
    # squatting on the socket path, e.g. created by an earlier Docker -v mount).
    if { [ -n "$extra" ] && [ -d "$extra" ]; } || { [ -n "$main" ] && [ -d "$main" ]; }; then
        config_warning "The GnuPG agent socket path is a non-empty directory, not a socket."
        config_info "Remove it on the host (usually under \$XDG_RUNTIME_DIR/gnupg) and re-run."
    else
        config_warning "Could not start the host gpg-agent; run 'gpgconf --launch gpg-agent' manually"
    fi
    return 0
}

# Validate the forwarded SSH agent before its socket is mounted. Deliberately
# never starts ssh-agent: a fresh agent would carry no host keys.
# Usage: ensure_ssh_agent_ready
ensure_ssh_agent_ready() {
    [ "$SSH_AGENT_SUPPORT" = true ] || return 0

    if [ -z "${SSH_AUTH_SOCK:-}" ]; then
        config_warning "SSH agent support enabled but SSH_AUTH_SOCK is not set in this environment"
        return 0
    fi

    if [ ! -S "$SSH_AUTH_SOCK" ]; then
        config_warning "SSH agent support enabled but $SSH_AUTH_SOCK is not a socket"
        if [ -d "$SSH_AUTH_SOCK" ]; then
            config_info "That path is a directory; remove it or point SSH_AUTH_SOCK at the real agent socket"
        fi
        return 0
    fi

    # The socket exists. Do not query it here (ssh-add against a non-agent
    # socket can block); the forwarded agent is used by git/ssh directly.
    return 0
}

# Rename SRC onto DST without ever moving *into* a directory (or a symlink to
# one) that appeared at DST: GNU mv -T; plain mv where -T is unavailable.
# Usage: gpg_mirror_rename SRC DST
gpg_mirror_rename() {
    if mv --version >/dev/null 2>&1; then
        mv -fT -- "$1" "$2" 2>/dev/null
    else
        mv -f -- "$1" "$2" 2>/dev/null
    fi
}

# Remove one top-level entry NAME of the GnuPG mirror. Strictly confined to
# $OCODE_HOME/.gnupg/<name>; rm never follows a symlink given as operand, so
# a planted link is dropped without touching its target.
# Usage: gpg_mirror_remove NAME
gpg_mirror_remove() {
    local name="$1"
    case "$name" in
    "" | */* | . | ..) return 1 ;;
    esac
    [ -n "$OCODE_HOME" ] || return 1
    rm -rf -- "${OCODE_HOME:?}/.gnupg/$name" 2>/dev/null
}

# Move the staged entry STAGE/NAME into the mirror. The mirror is mounted
# read-write into the container, so anything already at the target may be a
# planted symlink: nothing there is ever written through. Files replace the
# target with an atomic rename (a symlink or directory in the way is removed
# first); directories are swapped whole (the old entry is renamed aside into
# the stage dir), so no path component the container controls is traversed.
# Unchanged regular files are left alone (no churn under live sessions).
# Usage: gpg_mirror_place STAGE NAME
gpg_mirror_place() {
    local stage="$1" name="$2" target
    case "$name" in
    "" | */* | . | ..) return 1 ;;
    esac
    target="$OCODE_HOME/.gnupg/$name"

    if [ -d "$stage/$name" ] && [ ! -L "$stage/$name" ]; then
        if [ -d "$target" ] && [ ! -L "$target" ] && [ -f "$target/pubring.db" ] && [ ! -L "$target/pubring.db" ] &&
            cmp -s "$stage/$name/pubring.db" "$target/pubring.db"; then
            return 0
        fi
        if [ -e "$target" ] || [ -L "$target" ]; then
            gpg_mirror_rename "$target" "$stage/.old.$name" || return 1
        fi
        gpg_mirror_rename "$stage/$name" "$target"
        return
    fi

    if [ -f "$target" ] && [ ! -L "$target" ] && cmp -s "$stage/$name" "$target"; then
        return 0
    fi
    if [ -L "$target" ] || { [ -e "$target" ] && [ ! -f "$target" ]; }; then
        gpg_mirror_remove "$name" || return 1
    fi
    gpg_mirror_rename "$stage/$name" "$target"
}

# Mirror the host's *public* GnuPG material into $OCODE_HOME/.gnupg so the
# container can use the host gpg-agent (forwarded via its socket) without ever
# receiving the private keys. Only public files are copied; private-keys-v1.d,
# the agent sockets and random_seed are deliberately excluded.
# Every entry is built in a private stage dir next to the mirror and renamed
# into place (see gpg_mirror_place), because the container can plant symlinks
# in the mirror between runs.
# Usage: ensure_gpg_mirror
ensure_gpg_mirror() {
    local host_gpg_home="${GNUPGHOME:-$HOME/.gnupg}"
    local dest="$OCODE_HOME/.gnupg"

    if [ ! -d "$host_gpg_home" ]; then
        config_warning "GnuPG agent support enabled but no GnuPG home found at $host_gpg_home"
        return 0
    fi

    # The mirror root itself is never a link (only the wrapper creates it).
    [ -L "$dest" ] && rm -f -- "$dest" 2>/dev/null
    mkdir -p "$dest" 2>/dev/null || return 0
    chmod 700 "$dest" 2>/dev/null || true

    local stage
    if ! stage=$(mktemp -d "$OCODE_HOME/.gnupg-stage.XXXXXX" 2>/dev/null); then
        config_warning "Could not prepare the GnuPG mirror in $OCODE_HOME"
        return 0
    fi

    # Public keyring (GnuPG 2.x keybox) plus its lock/trust files. With keyboxd
    # the database can also live under public-keys.d/, so mirror that too.
    # Private keys (private-keys-v1.d) are never copied.
    local f
    for f in pubring.kbx trustdb.gpg sshcontrol; do
        if [ -f "$host_gpg_home/$f" ]; then
            if cp -- "$host_gpg_home/$f" "$stage/$f" 2>/dev/null && chmod 600 "$stage/$f" 2>/dev/null; then
                gpg_mirror_place "$stage" "$f" || config_warning "Could not mirror $f into $dest"
            fi
        fi
    done
    if [ -f "$host_gpg_home/public-keys.d/pubring.db" ]; then
        if mkdir -m 700 "$stage/public-keys.d" 2>/dev/null &&
            cp -- "$host_gpg_home/public-keys.d/pubring.db" "$stage/public-keys.d/pubring.db" 2>/dev/null &&
            chmod 600 "$stage/public-keys.d/pubring.db" 2>/dev/null; then
            gpg_mirror_place "$stage" public-keys.d || config_warning "Could not mirror public-keys.d into $dest"
        fi
    fi

    # Mirror the config verbatim, including `use-keyboxd`: on such hosts GnuPG
    # keeps the public keyring in the keyboxd database (public-keys.d/), so the
    # container must run keyboxd to read it. entrypoint.sh launches it at boot;
    # `no-autostart` (below) still prevents a keyless local gpg-agent. Stale
    # mirrored config is removed when the host has none.
    if [ -f "$host_gpg_home/common.conf" ]; then
        if cp -- "$host_gpg_home/common.conf" "$stage/common.conf" 2>/dev/null && chmod 600 "$stage/common.conf" 2>/dev/null; then
            gpg_mirror_place "$stage" common.conf || config_warning "Could not mirror common.conf into $dest"
        fi
    else
        gpg_mirror_remove common.conf || true
    fi

    # gpg.conf is rebuilt from the host copy on every run, so `no-autostart`
    # (never let the container's gpg auto-start a keyless local agent: the real
    # agent is the host's, reached through the forwarded socket) is added at
    # most once, and the result is renamed into place atomically.
    if [ -f "$host_gpg_home/gpg.conf" ]; then
        cp -- "$host_gpg_home/gpg.conf" "$stage/gpg.conf" 2>/dev/null || : >"$stage/gpg.conf"
    else
        : >"$stage/gpg.conf"
    fi
    if ! grep -qE '^[[:space:]]*no-autostart([[:space:]]|$)' "$stage/gpg.conf" 2>/dev/null; then
        # Keep the appended option on its own line.
        if [ -s "$stage/gpg.conf" ] && [ -n "$(tail -c 1 "$stage/gpg.conf" 2>/dev/null)" ]; then
            echo >>"$stage/gpg.conf"
        fi
        echo "no-autostart" >>"$stage/gpg.conf"
    fi
    chmod 600 "$stage/gpg.conf" 2>/dev/null || true
    gpg_mirror_place "$stage" gpg.conf || config_warning "Could not write $dest/gpg.conf"

    rm -rf -- "$stage" 2>/dev/null || true

    # Without a public keyring gpg cannot build a signature even when the agent
    # socket is forwarded: warn instead of failing silently later.
    if [ ! -f "$dest/pubring.kbx" ] && [ ! -f "$dest/public-keys.d/pubring.db" ]; then
        config_warning "No public GnuPG keyring found in $host_gpg_home (commit signing will not work)"
    fi

    # Clear runtime entries earlier versions left in the mirror, when it was
    # mounted read-write as GNUPGHOME: an S.gpg-agent link (or a directory a
    # `-v` mount with a missing source created), keyboxd's socket and lock.
    # The mirror is now a read-only seed; those live in each container's own
    # GNUPGHOME. A session still running an older image may use them, so they
    # are only removed when no other session of this profile is alive.
    if [ -d "$dest/S.gpg-agent" ] && [ ! -S "$dest/S.gpg-agent" ] && [ ! -L "$dest/S.gpg-agent" ]; then
        rmdir "$dest/S.gpg-agent" 2>/dev/null ||
            config_warning "Stray directory at $dest/S.gpg-agent; remove it on the host"
    fi
    if [ "$(live_sessions)" -eq 0 ]; then
        rm -f "$dest/S.gpg-agent" "$dest/S.keyboxd" "$dest/S.keyboxd.lock" 2>/dev/null || true
    fi
}

# Session bookkeeping: each wrapper that runs a container drops a marker named
# after its PID, so shared state (the GnuPG mirror) is only reset when nobody
# else is using it.
# Usage: register_session | unregister_session | live_sessions
register_session() {
    mkdir -p "$SESSIONS_DIR" 2>/dev/null || return 0
    echo "$$" >"$SESSIONS_DIR/$$" 2>/dev/null || true
}

unregister_session() {
    rm -f "$SESSIONS_DIR/$$" 2>/dev/null || true
}

# Print the number of OTHER live sessions (dead markers are dropped on the way).
live_sessions() {
    local marker pid count=0
    [ -d "$SESSIONS_DIR" ] || {
        echo 0
        return 0
    }
    for marker in "$SESSIONS_DIR"/*; do
        [ -f "$marker" ] || continue
        pid=$(cat "$marker" 2>/dev/null || true)
        if [ -n "$pid" ] && [ "$pid" != "$$" ] && kill -0 "$pid" 2>/dev/null; then
            count=$((count + 1))
        elif [ "$pid" != "$$" ]; then
            rm -f "$marker" 2>/dev/null || true
        fi
    done
    echo "$count"
}

# True when GPG_RELAY_DIR is a safe, non-root location to manage relays in.
# Usage: relay_dir_ok && ...
relay_dir_ok() {
    [ -n "$GPG_RELAY_DIR" ] || return 1
    case "$GPG_RELAY_DIR" in
        / | "") return 1 ;;
    esac
    case "$GPG_RELAY_DIR" in
        "$CONFIG_DIR"/* | "$OCD_PROFILES_BASE"/* | "$HOME"/*) return 0 ;;
    esac
    return 1
}

# Remove relay directories whose socat process is gone (crash, kill -9, stale
# session). Runs before starting a new relay.
# Usage: cleanup_stale_relays
cleanup_stale_relays() {
    relay_dir_ok || return 0
    [ -d "$GPG_RELAY_DIR" ] || return 0
    local d pid
    for d in "$GPG_RELAY_DIR"/*; do
        [ -d "$d" ] || continue
        pid=$(cat "$d/pid" 2>/dev/null || true)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            continue
        fi
        # A dir without a pid file may belong to a session that is starting right
        # now (mkdir happens before the pid is written): give it a minute.
        if [ -z "$pid" ] && [ -n "$(find "$d" -maxdepth 0 -mmin -1 2>/dev/null)" ]; then
            continue
        fi
        rm -rf "$d" 2>/dev/null || true
    done
}

# Relay a GnuPG agent socket through a socket on a normal filesystem so Docker
# can bind it. One process per session; the wrapper stops it when the container
# exits. Uses `socat` by default; GPG_RELAY_CMD overrides the command for tests
# (only with OPENCODE_DOCKERIZED_TEST_HOOKS=1, see test_hooks_enabled)
# (it receives RELAY_SOCK and RELAY_REAL in its environment).
# Usage: relay_socket=$(start_gpg_relay <real_socket>)
start_gpg_relay() {
    local real="$1"
    [ -n "$real" ] && [ -S "$real" ] || return 1
    relay_dir_ok || return 1

    local template=""
    test_hooks_enabled && template="${GPG_RELAY_CMD:-}"
    if [ -z "$template" ]; then
        command -v socat >/dev/null 2>&1 || return 1
        # Single quotes are intentional: expanded later via RELAY_SOCK/RELAY_REAL env.
        # shellcheck disable=SC2016
        template='socat "UNIX-LISTEN:$RELAY_SOCK,fork,max-children=8,mode=600" "UNIX-CONNECT:$RELAY_REAL"'
    fi

    mkdir -p "$GPG_RELAY_DIR" 2>/dev/null || return 1
    chmod 700 "$GPG_RELAY_DIR" 2>/dev/null || true
    # Keep the path short: Unix socket paths are limited to ~108 chars, and the
    # relay dir already nests under the wrapper config dir. The PID alone is
    # unique per live process (stale dirs are purged before each start).
    local dir sock pid i
    dir="$GPG_RELAY_DIR/$$"
    sock="$dir/relay.sock"
    if [ "${#sock}" -ge 108 ]; then
        config_warning "GPG relay path too long for a Unix socket (${#sock} chars); skipping relay"
        return 1
    fi
    mkdir -p "$dir" 2>/dev/null || return 1
    chmod 700 "$dir" 2>/dev/null || true

    # `exec` makes $! the relay process itself (not a wrapping bash), so
    # stop_gpg_relay reliably kills it.
    RELAY_SOCK="$sock" RELAY_REAL="$real" bash -c "exec $template" >/dev/null 2>&1 &
    pid=$!
    echo "$pid" >"$dir/pid" 2>/dev/null || true

    for ((i = 0; i < 20; i++)); do
        if [ -S "$sock" ]; then
            echo "$sock"
            return 0
        fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done

    kill "$pid" 2>/dev/null || true
    rm -rf "$dir" 2>/dev/null || true
    return 1
}

# Stop a relay started by start_gpg_relay and remove its directory.
# Usage: stop_gpg_relay <relay_socket>
stop_gpg_relay() {
    local sock="$1"
    [ -n "$sock" ] || return 0
    local dir
    dir=$(dirname "$sock")
    # Only ever touch directories we own under GPG_RELAY_DIR.
    case "$dir" in
        "$GPG_RELAY_DIR"/*) ;;
        *) return 0 ;;
    esac
    local pid
    pid=$(cat "$dir/pid" 2>/dev/null || true)
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    rm -rf "$dir" 2>/dev/null || true
}

# Detect if a directory is a git worktree and return the main repo's .git directory path
# A worktree has a .git FILE (not directory) containing "gitdir: <path>".
# That file lives in the project, so the container can rewrite it: it is only
# trusted when the round trip checks out on the host side, i.e. it points at
# <common>/worktrees/<name> and that directory's own `gitdir` file (outside the
# project, written by `git worktree add`) points back at this project's .git
# (canonical paths). Anything else is reported and mounts nothing.
# Returns (via stdout): "<git_common_dir>" if worktree, empty string otherwise
# Warnings go to stderr so callers can capture stdout.
# Usage: main_git_dir=$(detect_git_worktree "/path/to/worktree")
detect_git_worktree() {
    local project_dir="$1"

    # Quick check: if .git is a directory (normal repo) or doesn't exist, not a worktree
    if [ ! -f "$project_dir/.git" ] || [ -L "$project_dir/.git" ]; then
        return 0
    fi

    local line="" gitdir project_c gitdir_c common back="" back_c
    IFS= read -r line <"$project_dir/.git" 2>/dev/null || [ -n "$line" ] || return 0
    line="${line%$'\r'}"
    case "$line" in
    "gitdir: "*) gitdir="${line#gitdir: }" ;;
    *) return 0 ;;
    esac
    [ -n "$gitdir" ] || return 0
    [[ "$gitdir" == /* ]] || gitdir="$project_dir/$gitdir"

    project_c=$(canonical_path "$project_dir") || return 0
    gitdir_c=$(canonical_path "$gitdir") || gitdir_c=""

    if [ -z "$gitdir_c" ] || [ ! -d "$gitdir_c" ] || [ "$(basename -- "$(dirname -- "$gitdir_c")")" != worktrees ]; then
        config_warning "Ignoring untrusted git worktree pointer in $project_dir/.git (not <repo>/.git/worktrees/<name>); no main .git directory mounted" >&2
        return 0
    fi
    common=$(dirname -- "$(dirname -- "$gitdir_c")")

    if [ -f "$gitdir_c/gitdir" ]; then
        IFS= read -r back <"$gitdir_c/gitdir" 2>/dev/null || true
        back="${back%$'\r'}"
    fi
    [ -z "$back" ] || [[ "$back" == /* ]] || back="$gitdir_c/$back"
    back_c=""
    [ -n "$back" ] && back_c=$(canonical_path "$back" 2>/dev/null)
    if [ -z "$back_c" ] || [ "$back_c" != "$project_c/.git" ]; then
        config_warning "Ignoring untrusted git worktree pointer in $project_dir/.git (the worktree entry does not point back at this project); no main .git directory mounted" >&2
        return 0
    fi

    # Sanity check: the common dir should be a real .git directory
    if [ ! -d "$common/objects" ] || [ ! -d "$common/refs" ]; then
        return 0
    fi

    # Defense in depth: never mount a protected host location this way.
    if host_path_is_protected "$common"; then
        config_warning "Ignoring git worktree common dir $common: $PROTECTED_REASON" >&2
        return 0
    fi

    echo "$common"
}

# Build Docker volume/bind args needed for git worktree support
# When the project is a git worktree, the .git file points to the main repo's
# .git directory which lives outside the project dir. We mount the main .git
# directory (read-only) at its real host path so the gitdir pointer resolves
# correctly inside the container.
#
# Read-only is intentional: it preserves the sandbox boundary (container only
# has write access to the mounted project directory). Read operations like
# git log, status, diff, and branch work. Write operations (commit, stash,
# fetch) will fail — run those on the host.
#
# Populates GIT_WORKTREE_ARGS array
# Usage: build_git_worktree_args "/path/to/project"
build_git_worktree_args() {
    local project_dir="$1"

    GIT_WORKTREE_ARGS=()

    local git_common_dir
    git_common_dir=$(detect_git_worktree "$project_dir")

    if [ -z "$git_common_dir" ]; then
        return 0
    fi

    config_info "Git worktree detected — mounting main .git directory (read-only) for git support"
    config_info "Main git directory: $git_common_dir"

    # Mount the main repo's .git directory at its real host path (read-only)
    GIT_WORKTREE_ARGS+=(-v "$git_common_dir:$git_common_dir:ro")
}

# Reject inline secrets in OpenCode configs: every credential must use {env:VAR}
# or {file:path} substitution so secrets never rest in a file the agent can
# read (the config dir is mounted read-only, not secret) or in the inline
# OPENCODE_CONFIG_CONTENT passed to the container. Heuristic on key names; only
# offending key names are reported, never values.
# Called on every run; exits non-zero with remediation.
# Usage: validate_opencode_config || exit 1
validate_opencode_config() {
    local oc
    for oc in "$CONFIG_DIR/opencode.json" "$OCODE_HOME/.config/opencode/opencode.json" "$OCODE_HOME/.config/opencode/opencode.jsonc"; do
        [ -f "$oc" ] || continue
        local hits m keys=""
        hits=$(grep -oE '"(apiKey|api_key|api-key|accessToken|access_token|clientSecret|token|secret|password|passwd|authorization|bearer)"[[:space:]]*:[[:space:]]*"[^"]*"' "$oc" 2>/dev/null || true)
        [ -n "$hits" ] || continue
        while IFS= read -r m; do
            case "$m" in
            *'{env:'* | *'{file:'*) continue ;;
            esac
            keys="$keys $(printf '%s' "$m" | grep -oE '^"[A-Za-z_.-]+\"' || true)"
        done <<<"$hits"
        case "$keys" in
        "" | " ") ;;
        *)
            config_error "Inline secrets in $oc ($keys ): move credentials to {env:VAR} references."
            config_info "Put the values in setting.env_file instead of opencode.json (see README)."
            return 1
            ;;
        esac
    done
    return 0
}

# Print the inline sandbox config JSON with "websearch": {"provider": ID} set.
# With node or python3 the document is parsed and the key replaced (the
# setting wins over a hand-written one). Without a parser it falls back to a
# shape-checked text merge that handles "{}" and refuses (returns 1) when a
# "websearch" key already exists, so it never yields `{,` or a duplicate key.
# ID must already be allowlisted by the caller.
# Usage: merged=$(merge_websearch_provider "$json" exa) || ...
merge_websearch_provider() {
    local json="$1" provider="$2" out
    if command -v node >/dev/null 2>&1; then
        out=$(printf '%s' "$json" | node -e '
let o;
try { o = JSON.parse(require("fs").readFileSync(0, "utf8")); } catch (e) { process.exit(1); }
if (o === null || typeof o !== "object" || Array.isArray(o)) process.exit(1);
o.websearch = { provider: process.argv[1] };
process.stdout.write(JSON.stringify(o));
' "$provider" 2>/dev/null) && [ -n "$out" ] && {
            printf '%s\n' "$out"
            return 0
        }
        return 1
    fi
    if command -v python3 >/dev/null 2>&1; then
        out=$(printf '%s' "$json" | python3 -I -c '
import json, sys
try:
    o = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(o, dict):
    sys.exit(1)
o["websearch"] = {"provider": sys.argv[1]}
sys.stdout.write(json.dumps(o, separators=(",", ":"), ensure_ascii=False))
' "$provider" 2>/dev/null) && [ -n "$out" ] && {
            printf '%s\n' "$out"
            return 0
        }
        return 1
    fi

    # Text fallback on the known shape: a single object, first char "{" and
    # last char "}" (surrounding whitespace already trimmed by the caller).
    [[ "$json" == "{"*"}" ]] || return 1
    if [[ "$json" =~ \"websearch\"[[:space:]]*: ]]; then
        return 1
    fi
    local body="${json#\{}"
    body="${body%\}}"
    if [[ "$body" =~ ^[[:space:]]*$ ]]; then
        printf '%s\n' "{\"websearch\":{\"provider\":\"$provider\"}}"
    else
        printf '%s\n' "{${body},\"websearch\":{\"provider\":\"$provider\"}}"
    fi
}

# Build common Docker run arguments shared by run_opencode and run_auth
# Populates DOCKER_COMMON_ARGS array
# The container runs as the host user directly (no root): --user starts the
# process with the host UID/GID, so entrypoint.sh needs no privilege dropping or
# UID/GID remapping. --group-add coder keeps the group-writable (g+rwX) home
# tree accessible to any host UID; the name resolves against the container's
# /etc/group (gid 1000 here), so the host does not need a "coder" group.
# no-new-privileges neutralizes setuid binaries and cap-drop removes Linux
# capabilities the non-root process never needs.
# Usage: build_common_docker_args
build_common_docker_args() {
    # shellcheck disable=SC2034  # DOCKER_COMMON_ARGS is used by callers that source this file
    # Block runs whose user config carries inline secrets (must use {env:}).
    validate_opencode_config || exit 1
    # Allowlist the network mode (config values are user-edited).
    case "${NETWORK:-host}" in
    host | bridge) ;;
    *)
        config_warning "Invalid network '$NETWORK' (use host|bridge); falling back to host"
        NETWORK="host"
        ;;
    esac
    DOCKER_COMMON_ARGS=(
        --rm
        # PID 1 that reaps zombies and forwards signals (opencode is not an init).
        --init
        --label opencode-dockerized=1
        --network "$NETWORK"
        --user "$(id -u):$(id -g)"
        --group-add coder
        --security-opt no-new-privileges:true
        --cap-drop=ALL
        -e "TERM=${TERM:-xterm-256color}"
        # The advertised scratch dir (the only writable path outside the project)
        # does not exist in the image: give it a size-capped tmpfs.
        --tmpfs "/tmp/opencode:rw,mode=1777,size=512m"
        --pids-limit "$PIDS_LIMIT"
        -e "LANG=${LANG:-C.UTF-8}"
    )
    # Forward locale/timezone choices so commits and logs match the host.
    local locale_var
    for locale_var in LC_ALL TZ; do
        [ -n "${!locale_var:-}" ] && DOCKER_COMMON_ARGS+=(-e "$locale_var=${!locale_var}")
    done
    # On a bridge network the host is reachable as host.docker.internal only
    # when it is mapped explicitly (Linux does not provide it).
    [ "$NETWORK" = "bridge" ] && DOCKER_COMMON_ARGS+=(--add-host host.docker.internal:host-gateway)

    # Optional resource limits (setting.memory / setting.cpus). Pinning swap to
    # the memory value keeps the limit real (no silent swap doubling).
    [ -n "$MEMORY" ] && DOCKER_COMMON_ARGS+=(--memory "$MEMORY" --memory-swap "$MEMORY")
    [ -n "$CPUS" ] && DOCKER_COMMON_ARGS+=(--cpus "$CPUS")

    # Pass terminal identification variables so applications inside the container
    # can detect the host terminal and use its capabilities correctly.
    # Required for kitty OSC 99 terminal-mediated desktop notifications, true-color
    # rendering, and other terminal-specific features. All are conditional so they
    # have no effect on non-kitty terminals.
    local term_var
    for term_var in TERM_PROGRAM TERM_PROGRAM_VERSION KITTY_WINDOW_ID COLORTERM; do
        if [ -n "${!term_var}" ]; then
            DOCKER_COMMON_ARGS+=(-e "$term_var=${!term_var}")
        fi
    done

    # Activate the opencode-dockerized security layer by passing the generated
    # permission rules inline (OPENCODE_CONFIG_CONTENT). The file stays on the
    # host as the editable source of truth and is never mounted: this avoids
    # exposing the wrapper's INI/security sources inside the container and lets
    # the OpenCode config directory stay read-only.
    # OPENCODE_CONFIG_DIR must stay unset: it replaces the global config directory
    # (breaking MCP persistence and the seeded config) — the plugin hooks are
    # mirrored into the config tree on the host and delivered by its single
    # read-only directory mount instead (see ensure_opencode_dockerized_config
    # and build_standard_volume_args).
    if [ -f "$CONFIG_DIR/opencode.json" ]; then
        local sandbox_rule_json
        if sandbox_rule_json=$(tr -d '\r\n' <"$CONFIG_DIR/opencode.json" 2>/dev/null) && [ -n "$sandbox_rule_json" ]; then
            # Drop trailing whitespace so the closing brace is really last.
            sandbox_rule_json="${sandbox_rule_json%"${sandbox_rule_json##*[![:space:]]}"}"
            # Optional built-in websearch provider (setting.websearch_provider),
            # merged into the inline config alongside the permissions. The
            # provider id is allowlisted, so no JSON injection is possible.
            if [ -n "$WEBSEARCH_PROVIDER" ]; then
                case "$WEBSEARCH_PROVIDER" in
                exa | firecrawl | parallel | tavily | random)
                    local merged_cfg
                    if merged_cfg=$(merge_websearch_provider "$sandbox_rule_json" "$WEBSEARCH_PROVIDER"); then
                        sandbox_rule_json="$merged_cfg"
                    else
                        config_warning "Cannot merge websearch provider into sandbox rules (unexpected shape or existing \"websearch\" key); skipping"
                    fi
                    ;;
                *)
                    config_warning "Invalid websearch_provider '$WEBSEARCH_PROVIDER' (use exa|firecrawl|parallel|tavily|random); skipping"
                    ;;
                esac
            fi

            DOCKER_COMMON_ARGS+=(-e "OPENCODE_CONFIG_CONTENT=$sandbox_rule_json")
        else
            config_warning "Could not read $CONFIG_DIR/opencode.json — sandbox permission rules not applied"
        fi
    else
        config_warning "Sandbox permission rules not found at $CONFIG_DIR/opencode.json (run 'opencode-dockerized install')"
    fi

    # Security policy mode consumed by the mounted security-guard.js hook
    # (strict | balanced | off). Defaults to balanced when unset.
    DOCKER_COMMON_ARGS+=(-e "OPENCODE_DOCKERIZED_POLICY=$SECURITY_POLICY")

    # Keep OpenCode from trying to self-update inside the container.
    DOCKER_COMMON_ARGS+=(-e "OPENCODE_DISABLE_AUTOUPDATE=true")

    # Optional TUI theme (setting.theme). cli.json stays a minimal seed on the
    # host; this inline CLI config merges over it (supported by the V2 binary).
    # The name is restricted to a safe token so no JSON injection is possible.
    if [ -n "$THEME" ]; then
        if [[ "$THEME" =~ ^[A-Za-z0-9_-]+$ ]]; then
            DOCKER_COMMON_ARGS+=(-e "OPENCODE_CLI_CONFIG_CONTENT={\"theme\":{\"name\":\"$THEME\"}}")
        else
            config_warning "Invalid theme '$THEME' (use letters, numbers, - or _); skipping"
        fi
    fi
}

# Append a read-only bind mount to VOLUME_ARGS when the host path exists.
# Usage: add_ro_mount HOST_PATH CONTAINER_PATH
add_ro_mount() {
    local host_path="$1" container_path="$2"
    if [ -e "$host_path" ]; then
        VOLUME_ARGS+=(-v "$host_path:$container_path:ro")
    fi
}

# Build standard volume mount arguments for OpenCode directories
# Populates VOLUME_ARGS and CONTAINER_WORKDIR
# The project is mounted at a path derived from the host path (with $HOME stripped)
# so that OpenCode stores a unique, meaningful directory per project in its session DB.
build_standard_volume_args() {
    local project_dir="$1"
    local include_docker_socket="${2:-false}"

    VOLUME_ARGS=()

    # Compute container-side mount path: strip $HOME prefix for portability
    # e.g. /home/user/projects/acme/frontend -> /projects/acme/frontend
    CONTAINER_WORKDIR=$(compute_container_path "$project_dir")

    # Project directory (read-write) — mounted at the computed path
    # Skipped when no project is given (e.g. auth) or when it resolves to $HOME itself
    if [ -n "$project_dir" ] && [ -n "$CONTAINER_WORKDIR" ]; then
        VOLUME_ARGS+=(-v "$project_dir:$CONTAINER_WORKDIR")
        build_git_worktree_args "$project_dir"
    fi

    # OpenCode configuration directory (read-only, self-contained).
    # The host tree is the single source of truth: edit it on the host and
    # restart the container. OpenCode's own runtime state (auth, sessions,
    # caches, model selection) lives in the data/state/cache dirs below, so
    # nothing needs to write here — and a session cannot rewrite its own config,
    # plugins or MCP definitions. The security-layer files (AGENTS.md, guard,
    # policies) are mirrored into this tree by ensure_opencode_dockerized_config,
    # so the single read-only mount delivers them all.
    if [ -d "$OCODE_HOME/.config/opencode" ]; then
        VOLUME_ARGS+=(-v "$OCODE_HOME/.config/opencode:/home/coder/.config/opencode:ro")
    else
        config_warning "OpenCode config directory not found at $OCODE_HOME/.config/opencode"
    fi

    # OpenCode data directory (read-write for auth, logs, sessions, storage)
    if [ -d "$OCODE_HOME/.local/share/opencode" ]; then
        VOLUME_ARGS+=(-v "$OCODE_HOME/.local/share/opencode:/home/coder/.local/share/opencode")
    else
        config_warning "OpenCode data directory not found at $OCODE_HOME/.local/share/opencode"
        config_info "You'll need to run 'opencode auth login' inside the container"
    fi

    # OpenCode state directory (read-write for selected model, prompt history, locks)
    if [ -d "$OCODE_HOME/.local/state/opencode" ]; then
        VOLUME_ARGS+=(-v "$OCODE_HOME/.local/state/opencode:/home/coder/.local/state/opencode")
    fi

    # OpenCode provider package cache (improves startup time and prevents API errors)
    # See: https://opencode.ai/docs/troubleshooting/#ai_apicallerror-and-provider-package-issues
    if [ -d "$OCODE_HOME/.cache/opencode" ]; then
        VOLUME_ARGS+=(-v "$OCODE_HOME/.cache/opencode:/home/coder/.cache/opencode")
    fi

    # MCP authentication directory (optional) — read-write so OAuth for
    # `mcp-remote`-based MCP servers persists across sessions.
    if [ -d "$HOME/.mcp-auth" ]; then
        VOLUME_ARGS+=(-v "$HOME/.mcp-auth:/home/coder/.mcp-auth:rw")
    fi

    # NPM configuration: opt-in, since it can carry registry auth tokens
    # (setting.mount_npmrc=true).
    if [ "$MOUNT_NPMRC" = true ] && [ -f "$HOME/.npmrc" ]; then
        VOLUME_ARGS+=(-v "$HOME/.npmrc:/home/coder/.npmrc:ro")
    fi

    # Claude Code compatibility (optional): only skills, agents, commands and the
    # CLAUDE.md fallback rules, always read-only. The rest of ~/.claude
    # (.credentials.json, history, projects/) is never shared with the container.
    local compat_path
    for compat_path in skills agents commands CLAUDE.md; do
        add_ro_mount "$HOME/.claude/$compat_path" "/home/coder/.claude/$compat_path"
    done

    # Agent-compatible skills (optional)
    # OpenCode reads skills from ~/.agents/skills/<name>/SKILL.md
    add_ro_mount "$HOME/.agents/skills" "/home/coder/.agents/skills"

    # Docker socket (optional, for Docker-in-Docker operations). The container
    # runs as a non-root numeric UID, so access is granted with a supplementary
    # --group-add (the socket's GID) instead of a runtime `usermod` that required
    # root. It is appended to VOLUME_ARGS because it is part of what this
    # function contributes to the `docker run` command.
    # WARNING: root-equivalent on the host — enable only for Docker-in-Docker /
    # Testcontainers (setting.docker_socket=true).
    if [ "$include_docker_socket" = true ] && [ -S /var/run/docker.sock ]; then
        config_warning "Docker socket mounted: root-equivalent on the host (disable with setting.docker_socket=false when not needed)"
        VOLUME_ARGS+=(-v /var/run/docker.sock:/var/run/docker.sock)
        VOLUME_ARGS+=(--group-add "$(stat -c '%g' /var/run/docker.sock)")
    fi
}

# ============================================
# CONFIG FILE OPERATIONS
# ============================================

# Check if config file exists
config_exists() {
    [ -f "$CONFIG_FILE" ]
}

# Initialize config file with header
init_config_file() {
    mkdir -p "$CONFIG_DIR"
    cat >"$CONFIG_FILE" <<'EOF'
# OpenCode Dockerized User Configuration
# Generated by 'opencode-dockerized install' - edit manually or re-run 'opencode-dockerized install' to modify

# Settings
# SSH Agent Forwarding (enables git over SSH in container)
# Automatically mounts SSH_AUTH_SOCK socket and passes the environment variable
# setting.ssh_agent_support=false

# GnuPG Agent Forwarding (enables git commit signing with your host keys)
# Shares only the public keyring and the gpg-agent socket; private keys never
# enter the container. Requires a running gpg-agent on the host.
# setting.gpg_agent_support=false

# Allow falling back to the full-control gpg-agent socket when the restricted
# S.gpg-agent.extra socket is unavailable. NOT recommended: the main socket can
# reconfigure the host agent. Default: false (warn and skip instead).
# setting.gpg_allow_main_socket=false

# Launch the host gpg-agent automatically at run time when its socket is
# missing. Default: true. Set to false to only warn and never start it.
# setting.gpg_autostart_agent=true

# Relay the agent socket through a socket on a normal filesystem. Needed when
# socketdir is on tmpfs (/run/user/<uid>/gnupg), which Docker cannot bind.
# Requires `socat` on the host. Default: true.
# setting.gpg_relay=true

# Docker socket (opt-in). Mounting it grants the container full control of the
# host Docker daemon, which is effectively root on the host. Enable only when
# you need Docker-in-Docker / Testcontainers.
# setting.docker_socket=false

# Container network: host (default, simple; shares the host network namespace)
# or bridge (more isolated; host services are reached via host.docker.internal).
# setting.network=host

# Security policy mode enforced by the mounted security-guard.js hook.
# strict = every vendored opencode-policy pattern; balanced = drop the noisy
# cloud/dev false positives (default); off = vendored patterns disabled.
# setting.security_policy=balanced

# Optional container resource limits (docker --memory / --cpus). Empty = no limit.
# setting.memory=4g
# setting.cpus=2

# Built-in websearch provider: exa | firecrawl | parallel | tavily | random.
# Empty = ask once in the TUI. The provider API key must be in the env file.
# setting.websearch_provider=exa

# TUI theme (built-in, e.g. catppuccin). Empty = OpenCode default.
# setting.theme=catppuccin

# Custom volume mounts (read-only by default)
# Format: mount.<name>=<host_path>:<container_path>[:rw]
# Examples:
#   mount.gitconfig=~/.gitconfig:/home/coder/.gitconfig
#   mount.gitignore_global=~/.config/git/gitignore_global:/home/coder/.config/git/gitignore_global
# NOTE: do NOT mount ~/.ssh (it exposes private keys and is refused). Use
# setting.ssh_agent_support=true: the agent socket plus ~/.ssh/config and
# known_hosts are mounted read-only automatically.

EOF
    # Appended unquoted so the env-file example matches the active tree: with
    # --profile it must name the profile's own directory (an env file outside
    # the active CONFIG_DIR is refused at run time).
    cat >>"$CONFIG_FILE" <<EOF
# Secrets file (dotenv KEY=VALUE lines) loaded with docker --env-file.
# Must live under this config tree ($CONFIG_DIR/, never mounted). Create it
# with: install -m 600 /dev/null $CONFIG_DIR/env
# then add keys like EXA_API_KEY=... Empty = disabled. Use
# 'opencode-dockerized install' to add keys without ever printing them.
# setting.env_file=$CONFIG_DIR/env
EOF
    config_success "Created config file at $CONFIG_FILE"
}

# Load config file into arrays, preserving each entry's original key suffix so
# save_config can re-emit it unchanged (re-running setup never renames keys).
load_config() {
    if ! config_exists; then
        config_warning "Config file not found at $CONFIG_FILE"
        return 1
    fi

    CUSTOM_MOUNTS=()
    CUSTOM_MOUNT_KEYS=()

    # Read mounts (lines starting with "mount.")
    while IFS='=' read -r key value; do
        # Skip comments and non-mount lines
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ "$key" =~ ^[[:space:]]*mount\. ]] || continue
        # Trim whitespace around the key, then keep the suffix after "mount."
        key="${key#"${key%%[![:space:]]*}"}"
        key="${key%"${key##*[![:space:]]}"}"
        key="${key#mount.}"
        # Remove leading/trailing whitespace from the value
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        if [ -n "$value" ] && [ -n "$key" ]; then
            CUSTOM_MOUNT_KEYS+=("$key")
            CUSTOM_MOUNTS+=("$value")
        fi
    done <"$CONFIG_FILE"

    # Legacy env vars (lines starting with "env."): the host-environment
    # passthrough was removed; secrets now live in setting.env_file. Entries
    # are ignored with a warning telling how to migrate (see
    # migrate_legacy_env_vars for the interactive one-shot migration).
    while IFS='=' read -r key value; do
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ "$key" =~ ^[[:space:]]*env\. ]] || continue
        key="${key#"${key%%[![:space:]]*}"}"
        key="${key%"${key##*[![:space:]]}"}"
        key="${key#env.}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        if [ -n "$value" ] && [ -n "$key" ]; then
            config_warning "Ignoring legacy '$key' (env.* passthrough was removed); move the value to setting.env_file instead."
        fi
    done <"$CONFIG_FILE"

    # Read settings (lines starting with "setting.")
    SSH_AGENT_SUPPORT=false
    GPG_AGENT_SUPPORT=false
    GPG_ALLOW_MAIN_SOCKET=false
    GPG_AUTOSTART_AGENT=true
    GPG_RELAY=true
    DOCKER_SOCKET=false
    MOUNT_NPMRC=false
    NETWORK="host"
    SECURITY_POLICY="balanced"
    MEMORY=""
    CPUS=""
    PIDS_LIMIT=4096
    ENV_FILE=""
    WEBSEARCH_PROVIDER=""
    THEME=""
    while IFS='=' read -r key value; do
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ "$key" =~ ^[[:space:]]*setting\. ]] || continue
        # Trim whitespace and keep the suffix after "setting."
        key="${key#"${key%%[![:space:]]*}"}"
        key="${key%"${key##*[![:space:]]}"}"
        key="${key#setting.}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        case "$key" in
        ssh_agent_support) [[ "$value" == "true" ]] && SSH_AGENT_SUPPORT=true ;;
        gpg_agent_support) [[ "$value" == "true" ]] && GPG_AGENT_SUPPORT=true ;;
        gpg_allow_main_socket) [[ "$value" == "true" ]] && GPG_ALLOW_MAIN_SOCKET=true ;;
        gpg_autostart_agent) [[ "$value" == "false" ]] && GPG_AUTOSTART_AGENT=false ;;
        gpg_relay) [[ "$value" == "false" ]] && GPG_RELAY=false ;;
        docker_socket) [[ "$value" == "true" ]] && DOCKER_SOCKET=true ;;
        mount_npmrc) [[ "$value" == "true" ]] && MOUNT_NPMRC=true ;;
        network)
            case "$value" in
            "" | host | bridge) NETWORK="${value:-host}" ;;
            *) config_warning "Invalid network '$value' (use host|bridge); keeping host" ;;
            esac
            ;;
        env_file) ENV_FILE="$value" ;;
        websearch_provider)
            case "$value" in
            "" | exa | firecrawl | parallel | tavily | random) WEBSEARCH_PROVIDER="$value" ;;
            *) config_warning "Invalid websearch_provider '$value' (use exa|firecrawl|parallel|tavily|random); ignoring" ;;
            esac
            ;;
        theme)
            case "$value" in
            "") ;;
            *[!A-Za-z0-9_-]*) config_warning "Invalid theme '$value' (use letters, numbers, - or _); ignoring" ;;
            *) THEME="$value" ;;
            esac
            ;;
        memory)
            if [ -z "$value" ]; then
                MEMORY=""
            elif [[ "$value" =~ ^[0-9]+[bBkKmMgG]$ ]] && [[ "$value" =~ [1-9] ]]; then
                MEMORY="$value"
            else
                config_warning "Invalid memory '$value' (e.g. 4g); ignoring"
            fi
            ;;
        cpus)
            if [ -z "$value" ]; then
                CPUS=""
            elif [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                CPUS="$value"
            else
                config_warning "Invalid cpus '$value' (e.g. 2); ignoring"
            fi
            ;;
        pids_limit)
            if [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
                PIDS_LIMIT="$value"
            else
                config_warning "Invalid pids_limit '$value' (positive integer); keeping 4096"
            fi
            ;;
        security_policy)
            case "$value" in
            strict | balanced | off) SECURITY_POLICY="$value" ;;
            *) config_warning "Invalid security_policy '$value' (use strict|balanced|off); keeping balanced" ;;
            esac
            ;;
        esac
    done <"$CONFIG_FILE"

    return 0
}

# Allocate an unused "customN" key suffix for a new entry, avoiding collisions
# with already-used suffixes passed as arguments.
# Usage: key=$(next_custom_key "${CUSTOM_MOUNT_KEYS[@]}")
next_custom_key() {
    local n=1 existing
    while :; do
        local taken=false
        for existing in "$@"; do
            if [ "$existing" = "custom$n" ]; then
                taken=true
                break
            fi
        done
        if [ "$taken" = false ]; then
            echo "custom$n"
            return 0
        fi
        n=$((n + 1))
    done
}

# Save current arrays to config file, preserving original key names and
# skipping exact duplicate lines (idempotent across re-runs).
save_config() {
    mkdir -p "$CONFIG_DIR"

    {
        echo "# OpenCode Dockerized User Configuration"
        echo "# Generated by 'opencode-dockerized install' - edit manually or re-run 'opencode-dockerized install' to modify"
        echo ""
        echo "# Settings"
        echo "# SSH Agent Forwarding (enables git over SSH in container)"
        echo "# Automatically mounts SSH_AUTH_SOCK socket and passes the environment variable"
        echo "setting.ssh_agent_support=$SSH_AGENT_SUPPORT"
        echo "# GnuPG agent forwarding (public keyring + gpg-agent socket; enables git commit -S)"
        echo "setting.gpg_agent_support=$GPG_AGENT_SUPPORT"
        echo "# Allow GPG fallback to the full-control agent socket when the restricted"
        echo "# S.gpg-agent.extra is unavailable (NOT recommended)"
        echo "setting.gpg_allow_main_socket=$GPG_ALLOW_MAIN_SOCKET"
        echo "# Launch the host gpg-agent automatically when its socket is missing"
        echo "setting.gpg_autostart_agent=$GPG_AUTOSTART_AGENT"
        echo "# Relay the agent socket through a normal-filesystem socket (needed when"
        echo "# socketdir is on tmpfs, e.g. /run/user/<uid>/gnupg); requires socat"
        echo "setting.gpg_relay=$GPG_RELAY"
        echo "# Docker socket (opt-in; grants host Docker control — root-equivalent)"
        echo "setting.docker_socket=$DOCKER_SOCKET"
        echo "# Mount ~/.npmrc read-only (opt-in: it can hold registry auth tokens)"
        echo "setting.mount_npmrc=$MOUNT_NPMRC"
        echo "# Container network: host (default) | bridge (more isolated)"
        echo "setting.network=$NETWORK"
        echo "# Security policy mode: strict | balanced | off"
        echo "setting.security_policy=$SECURITY_POLICY"
        echo "# Optional container resource limits (empty = no limit)"
        echo "setting.memory=$MEMORY"
        echo "setting.cpus=$CPUS"
        echo "# Max processes in the container (default 4096)"
        echo "setting.pids_limit=$PIDS_LIMIT"
        echo "# Secrets file (dotenv KEY=VALUE lines) loaded with docker --env-file."
        echo "# Must live under $CONFIG_DIR (never mounted). Empty = disabled."
        echo "setting.env_file=$ENV_FILE"
        echo "# Built-in websearch provider: exa | firecrawl | parallel | tavily | random"
        echo "# (empty = ask once in the TUI). The provider API key comes from the"
        echo "# env file."
        echo "setting.websearch_provider=$WEBSEARCH_PROVIDER"
        echo "# TUI theme (built-in, e.g. catppuccin). Empty = OpenCode default."
        echo "setting.theme=$THEME"
        echo ""
        echo "# Custom volume mounts (read-only by default)"
        echo "# Format: mount.<name>=<host_path>:<container_path>[:rw]"
        echo "# NOTE: paths containing ':' are not supported (used as separator)"

        if [ ${#CUSTOM_MOUNTS[@]} -gt 0 ]; then
            local seen_m=""
            for i in "${!CUSTOM_MOUNTS[@]}"; do
                local line="mount.${CUSTOM_MOUNT_KEYS[$i]}=${CUSTOM_MOUNTS[$i]}"
                [[ "$seen_m" == *"|$line|"* ]] && continue
                seen_m="$seen_m|$line|"
                echo "$line"
            done
        fi
    } >"$CONFIG_FILE"

    config_success "Saved configuration to $CONFIG_FILE"
}

# ============================================
# CONFIG PARSING (used at runtime by all scripts)
# ============================================

# Parse config file into global arrays
parse_config() {
    load_config || return 0 # Continue even if load fails
}

# Add a bind mount for a socket/file/dir. Docker's `--mount` spec separates
# fields with commas, so fall back to `-v` when a path contains one.
# Usage: mount_bind <source> <target> [ro]
mount_bind() {
    local src="$1" dst="$2" mode="${3:-}"
    case "$src$dst" in
        *,*) DOCKER_MOUNT_ARGS+=(-v "$src:$dst${mode:+:$mode}") ;;
        *) DOCKER_MOUNT_ARGS+=(--mount "type=bind,source=$src,target=$dst${mode:+,readonly}") ;;
    esac
}

# Build docker volume mount arguments from CUSTOM_MOUNTS array
# Populates DOCKER_MOUNT_ARGS array with -v arguments
build_mount_args() {
    DOCKER_MOUNT_ARGS=()
    GPG_SOCKET=""
    # Stop a relay left over from a previous call in the same process.
    if [ -n "$GPG_RELAY_SOCKET" ]; then
        stop_gpg_relay "$GPG_RELAY_SOCKET"
    fi
    GPG_RELAY_SOCKET=""

    # Host-side preflight for the forwarded agents (no-op when disabled). It
    # launches the GPG agent if needed and reports why a socket is unusable.
    ensure_ssh_agent_ready
    ensure_gpg_agent_ready
    cleanup_stale_relays

    local mount spec colons
    for mount in "${CUSTOM_MOUNTS[@]}"; do
        # A mount entry must be host_path:container_path[:mode]; ':' inside a
        # path is unsupported, so more than three fields is malformed.
        colons="${mount//[^:]/}"
        if [ "${#colons}" -lt 1 ] || [ "${#colons}" -gt 2 ]; then
            config_error "Invalid mount '$mount': expected host_path:container_path[:mode]"
            exit 1
        fi

        local host_path="${mount%%:*}"
        local rest="${mount#*:}"
        local container_path="$rest" mode=""
        if [ "${#colons}" -eq 2 ]; then
            container_path="${rest%%:*}"
            mode="${rest#*:}"
            if [ -z "$mode" ]; then
                config_error "Invalid mount '$mount': empty mode (use ro or rw)"
                exit 1
            fi
        fi

        # Canonical host path, protected-location and container-path checks
        # (SSH/GnuPG homes, wrapper config, ~/.claude, Docker socket, "/",
        # $HOME; never over the read-only OpenCode config tree).
        if ! spec=$(validate_custom_mount "$host_path" "$container_path" "$mode"); then
            exit 1
        fi
        DOCKER_MOUNT_ARGS+=(-v "$spec")
    done

    # Handle SSH agent forwarding if enabled. ensure_ssh_agent_ready has already
    # reported why a socket is unusable, so only a valid socket is mounted here.
    if [ "$SSH_AGENT_SUPPORT" = true ]; then
        if [ -n "${SSH_AUTH_SOCK:-}" ] && [ -S "$SSH_AUTH_SOCK" ]; then
            # --mount (not -v) so a stale/missing source fails loudly instead
            # of Docker creating a directory at the host socket path, which
            # would break the real ssh-agent.
            mount_bind "$SSH_AUTH_SOCK" "$SSH_AUTH_SOCK"
        fi

        # Mount only the non-secret SSH files (read-only) so host-key
        # verification and host aliases keep working. Private keys (id_*,
        # *.pem, *.key) are never mounted; keys are used via the forwarded agent.
        local ssh_file
        for ssh_file in config known_hosts known_hosts2; do
            if [ -f "$HOME/.ssh/$ssh_file" ]; then
                DOCKER_MOUNT_ARGS+=(-v "$HOME/.ssh/$ssh_file:/home/coder/.ssh/$ssh_file:ro")
            fi
        done
    fi

    # Handle GnuPG agent forwarding if enabled: mount the mirrored public
    # keyring and the host agent socket. The private keys stay on the host;
    # only public material is shared. The mirror is shared by every session of
    # the profile, so it is mounted READ-ONLY as a seed: entrypoint.sh copies it
    # into a GNUPGHOME of the container's own, where keyboxd's socket, the agent
    # symlink and gpg's lock files live. A shared, writable home let concurrent
    # sessions reuse one container's keyboxd (dead once that container exits;
    # no-autostart keeps gpg from starting another) and each other's locks.
    # The socket is bind-mounted with --mount (a stale source fails loudly
    # instead of Docker creating a directory).
    if [ "$GPG_AGENT_SUPPORT" = true ]; then
        GPG_SOCKET=""
        ensure_gpg_mirror
        if [ -d "$OCODE_HOME/.gnupg" ]; then
            mount_bind "$OCODE_HOME/.gnupg" "$GPG_CONTAINER_SEED" ro
        else
            config_warning "GnuPG agent support enabled but $OCODE_HOME/.gnupg could not be prepared"
        fi

        local main_socket extra_socket gpg_socket
        main_socket=$(resolve_gpg_agent_socket)
        extra_socket=$(resolve_gpg_agent_extra_socket)

        # Prefer the restricted "extra" socket (sign/decrypt only) so the
        # container cannot reconfigure the host agent. The full-control main
        # socket is only used when explicitly opted in.
        if [ -n "$extra_socket" ] && [ -S "$extra_socket" ]; then
            gpg_socket="$extra_socket"
        elif [ -n "$main_socket" ] && [ -S "$main_socket" ] && [ "$GPG_ALLOW_MAIN_SOCKET" = true ]; then
            gpg_socket="$main_socket"
            config_warning "Using the full-control GnuPG agent socket (setting.gpg_allow_main_socket=true)"
        else
            gpg_socket=""
        fi

        if [ -n "$gpg_socket" ] && [ -S "$gpg_socket" ]; then
            GPG_SOCKET="$gpg_socket"
            local mount_socket="$gpg_socket"
            # Docker cannot bind a socket from a per-user tmpfs (/run/user/...):
            # it creates an empty directory instead. Relay it through a socket on
            # a normal filesystem and mount that.
            if { [[ "$gpg_socket" == /run/* ]] || [ "${GPG_RELAY_FORCE:-false}" = true ]; } && [ "$GPG_RELAY" = true ]; then
                local relay
                if relay=$(start_gpg_relay "$gpg_socket"); then
                    GPG_RELAY_SOCKET="$relay"
                    mount_socket="$relay"
                else
                    config_warning "Could not start the GnuPG relay; is 'socat' installed on the host?"
                fi
            fi
            if [[ "$mount_socket" == /run/* ]]; then
                config_warning "GnuPG agent socket is on tmpfs and no relay is available; Docker may not be able to bind it."
            fi
            # Mount the socket at a dedicated path OUTSIDE any other bind mount
            # (a nested socket mount can be shadowed by Docker). entrypoint.sh
            # links it into the container's own GNUPGHOME (gpg follows the link).
            mount_bind "$mount_socket" "$GPG_CONTAINER_AGENT_SOCK"
        else
            config_warning "GnuPG agent support enabled but no usable agent socket (extra socket missing and main fallback disabled)"
        fi
    fi
}

# Build docker environment variable arguments for automatic (non-secret)
# forwarding: agent sockets, terminal detection and doctor state flags.
# User secrets travel exclusively via setting.env_file (--env-file); the old
# env.* host passthrough was removed.
# Populates DOCKER_ENV_ARGS array with -e arguments
build_env_args() {
    DOCKER_ENV_ARGS=()

    # Handle SSH agent forwarding if enabled
    if [ "$SSH_AGENT_SUPPORT" = true ]; then
        if [ -n "$SSH_AUTH_SOCK" ]; then
            DOCKER_ENV_ARGS+=(-e "SSH_AUTH_SOCK=$SSH_AUTH_SOCK")
        fi
    fi

    # Handle GnuPG agent forwarding if enabled. GNUPGHOME is the container's own
    # home, seeded by entrypoint.sh from the read-only mirror; the agent socket
    # is announced only when one was mounted. XDG_RUNTIME_DIR is forwarded only
    # when the agent socket lives under it, so gpgconf inside the container
    # resolves the mounted path.
    if [ "$GPG_AGENT_SUPPORT" = true ]; then
        DOCKER_ENV_ARGS+=(-e "GNUPGHOME=$GPG_CONTAINER_HOME")
        DOCKER_ENV_ARGS+=(-e "OPENCODE_DOCKERIZED_GNUPG_SEED=$GPG_CONTAINER_SEED")
        if [ -n "${GPG_SOCKET:-}" ]; then
            DOCKER_ENV_ARGS+=(-e "OPENCODE_DOCKERIZED_GPG_AGENT_SOCK=$GPG_CONTAINER_AGENT_SOCK")
        fi

        if [ -n "${GPG_SOCKET:-}" ] && [ -n "${XDG_RUNTIME_DIR:-}" ] && [[ "$GPG_SOCKET" == "$XDG_RUNTIME_DIR"/* ]]; then
            DOCKER_ENV_ARGS+=(-e "XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR")
        fi
    fi

    # Forwarding state for `doctor` (non-secret): lets the in-container
    # diagnostics skip checks for forwardings the user disabled on purpose
    # instead of reporting them as failures. Websearch/theme/env-file state is
    # included so `doctor` can report the effective setup (key names only,
    # never values).
    DOCKER_ENV_ARGS+=(-e "OPENCODE_DOCKERIZED_SSH_AGENT=$SSH_AGENT_SUPPORT")
    DOCKER_ENV_ARGS+=(-e "OPENCODE_DOCKERIZED_GPG_AGENT=$GPG_AGENT_SUPPORT")
    DOCKER_ENV_ARGS+=(-e "OPENCODE_DOCKERIZED_WEBSEARCH=$WEBSEARCH_PROVIDER")
    DOCKER_ENV_ARGS+=(-e "OPENCODE_DOCKERIZED_THEME=$THEME")
    DOCKER_ENV_ARGS+=(-e "OPENCODE_DOCKERIZED_ENV_FILE=$([ -n "$ENV_FILE" ] && echo yes || echo no)")
    DOCKER_ENV_ARGS+=(-e "OPENCODE_DOCKERIZED_PROFILE=${OCD_PROFILE:-default}")
}

# Build the docker --env-file argument from setting.env_file.
# The file holds secrets (dotenv KEY=VALUE lines) and is consumed host-side by
# `docker run --env-file`, so values never appear on the wrapper command line.
# It must live under CONFIG_DIR, whose root is never mounted, and outside
# OCODE_HOME, whose subtrees are (config read-only; data, state and cache
# read-write). Both sides are canonicalized, so `..` segments or symlinks
# cannot escape the check and a symlinked CONFIG_DIR still works. This is the
# only way user secrets reach the container (the old env.* host passthrough
# was removed).
# Populates DOCKER_ENV_FILE_ARGS array.
# Usage: build_env_file_args
build_env_file_args() {
    DOCKER_ENV_FILE_ARGS=()

    [ -n "$ENV_FILE" ] || return 0

    local env_file cfg_c ocode_c
    env_file=$(expand_tilde "$ENV_FILE")
    if ! env_file=$(canonical_path "$env_file"); then
        config_error "env file must be an absolute path (or start with ~/): $ENV_FILE"
        exit 1
    fi
    cfg_c=$(canonical_path "$CONFIG_DIR") || cfg_c="$CONFIG_DIR"
    ocode_c=$(canonical_path "$OCODE_HOME") || ocode_c="$OCODE_HOME"

    case "$env_file" in
    "$cfg_c"/*) ;;
    *)
        config_error "Refusing env file outside \$CONFIG_DIR ($CONFIG_DIR): it could be mounted into the container."
        exit 1
        ;;
    esac
    if paths_overlap "$env_file" "$ocode_c"; then
        config_error "Refusing env file under \$OCODE_HOME ($OCODE_HOME): that tree is mounted into the container."
        exit 1
    fi

    if [ ! -f "$env_file" ]; then
        config_error "env file not found: $env_file"
        exit 1
    fi

    # A secrets file readable by group/others defeats its purpose.
    local mode=""
    mode=$(stat -c '%a' "$env_file" 2>/dev/null || stat -f '%Lp' "$env_file" 2>/dev/null || true)
    if [ -n "$mode" ] && [ $((8#$mode & 8#044)) -ne 0 ]; then
        config_warning "env file is readable by group/others ($env_file); run: chmod 600 \"$env_file\""
    fi

    # Light format check (never prints values, only line numbers): docker
    # ignores blank lines and `#` comments, needs KEY=VALUE otherwise, does
    # not understand an `export ` prefix, and may choke on CRLF line endings.
    local line lineno=0 CR
    CR=$(printf '\r')
    while IFS= read -r line || [ -n "$line" ]; do
        lineno=$((lineno + 1))
        case "$line" in
        "" | \#*) continue ;;
        esac
        case "$line" in
        *"$CR"*) config_warning "env file line $lineno has CRLF line endings; use LF only" ;;
        esac
        case "$line" in
        *=*) ;;
        *)
            config_warning "env file line $lineno has no '=' and will be ignored by docker"
            continue
            ;;
        esac
        case "$line" in
        export\ * | export\	*)
            config_warning "env file line $lineno uses an 'export ' prefix, which docker does not strip"
            ;;
        esac
    done <"$env_file"

    # shellcheck disable=SC2034 # populated here, consumed by bin/opencode-dockerized and tests
    DOCKER_ENV_FILE_ARGS=(--env-file "$env_file")
}

# ============================================
# CONFIG MANAGEMENT (used by `opencode-dockerized install`)
# ============================================

# Add a mount entry to arrays and optionally save
# New entries get an unused "customN" key suffix, preserving existing key names.
# add_mount <host_path> <container_path> [mode]   (mode: "ro" or "rw", default ro)
add_mount() {
    local host_path="$1"
    local container_path="$2"
    local mode="${3:-}"

    if [ -z "$host_path" ] || [ -z "$container_path" ]; then
        config_error "add_mount requires host_path and container_path"
        return 1
    fi

    case "$host_path$container_path" in
    *:*)
        config_error "Mount paths must not contain ':'"
        return 1
        ;;
    esac

    if [ -n "$mode" ] && [ "$mode" != "ro" ] && [ "$mode" != "rw" ]; then
        config_error "Invalid mode: $mode (must be 'ro' or 'rw')"
        return 1
    fi

    # Same checks as build_mount_args: absolute host path (leading ~
    # expanded), canonicalized before the protected-location checks, and a
    # container path that never shadows the read-only config or SSH/GnuPG.
    validate_custom_mount "$host_path" "$container_path" "$mode" >/dev/null || return 1

    local expanded_path
    expanded_path=$(expand_tilde "$host_path")
    if [ ! -e "$expanded_path" ]; then
        config_warning "Host path does not exist: $expanded_path"
    fi

    local mount_entry="$host_path:$container_path"
    [ -n "$mode" ] && mount_entry="$mount_entry:$mode"

    local key
    key=$(next_custom_key "${CUSTOM_MOUNT_KEYS[@]}")
    CUSTOM_MOUNT_KEYS+=("$key")
    CUSTOM_MOUNTS+=("$mount_entry")
}

# ============================================
# INTERACTIVE PROMPTS (used by `opencode-dockerized install`)
# ============================================

# Suggest a container path based on host path
# suggest_container_path <host_path> [default]
suggest_container_path() {
    local host_path="$1"
    local default="${2:-/home/coder/$(basename "$host_path")}"

    # For common paths, suggest sensible defaults
    if [[ "$host_path" == *"/.gitconfig" ]]; then
        echo "/home/coder/.gitconfig"
    elif [[ "$host_path" == *"/.ssh" ]]; then
        echo "/home/coder/.ssh"
    elif [[ "$host_path" == *"/.config/git"* ]]; then
        echo "/home/coder/.config/git/$(basename "$host_path")"
    else
        echo "$default"
    fi
}

# Ask user how to handle existing config
# Sets global: CONFIG_MODE ("append", "overwrite", or "skip")
prompt_config_mode() {
    if ! config_exists; then
        CONFIG_MODE="new"
        return 0
    fi

    echo ""
    config_info "Configuration file already exists at $CONFIG_FILE"

    PS3="Choose an option: "
    select mode in "Append (add new entries)" "Overwrite (replace config)" "Skip (keep existing)"; do
        case "$mode" in
        "Append (add new entries)")
            CONFIG_MODE="append"
            config_success "Will append new entries to existing config"
            break
            ;;
        "Overwrite (replace config)")
            CONFIG_MODE="overwrite"
            config_warning "Will replace existing config"
            break
            ;;
        "Skip (keep existing)")
            CONFIG_MODE="skip"
            config_info "Skipping config setup"
            break
            ;;
        *)
            if [ -z "$mode" ]; then
                config_info "No selection (EOF); skipping setup."
                CONFIG_MODE="skip"
                break
            fi
            config_error "Invalid option"
            ;;
        esac
    done
    [ -n "${CONFIG_MODE:-}" ] || CONFIG_MODE="skip"
}

# Interactive mount addition
# Prompts user repeatedly until they enter a blank line
prompt_custom_mounts() {
    echo ""
    config_info "Configure custom volume mounts (optional)"
    echo "Enter host paths to mount in the container (read-only by default)"
    echo "Press Enter with empty input to finish"
    echo ""

    while true; do
        read -r -p "Host path: " host_path || host_path=""

        # Allow blank to exit
        if [ -z "$host_path" ]; then
            break
        fi

        # Expand a leading ~ for validation
        local expanded_path="$host_path"
        if [[ "$expanded_path" == "~"* ]]; then
            expanded_path="$HOME${expanded_path#"~"}"
        fi

        if [ ! -e "$expanded_path" ]; then
            config_warning "Path does not exist: $expanded_path"
            read -r -p "Continue anyway? (y/N): " proceed || proceed=""
            [[ "$proceed" =~ ^[Yy]$ ]] || continue
        fi

        # Suggest container path
        local suggested
        suggested=$(suggest_container_path "$host_path")
        read -r -p "Container path [$suggested]: " container_path || container_path=""
        container_path="${container_path:-$suggested}"

        # Ask about read-write
        read -r -p "Read-write? (y/N): " rw_mode || rw_mode=""
        local mode=""
        if [[ "$rw_mode" =~ ^[Yy]$ ]]; then
            mode="rw"
        fi

        # Add the mount
        add_mount "$host_path" "$container_path" "$mode"
        config_success "Added mount: $host_path -> $container_path${mode:+ ($mode)}"
        echo ""
    done
}

# Interactive environment variable addition
# Prompts user repeatedly until they enter a blank line
# Write or replace one KEY=VALUE line in a dotenv secrets file, preserving
# every other line byte-for-byte. Creates the file with mode 600 when missing
# and fixes group/other-readable permissions with a warning. The value is never
# printed (only the key name is reported by callers).
# Usage: env_file_upsert <file> <KEY> <VALUE>
env_file_upsert() {
    local file="$1" key="$2" value="$3"

    if [ -z "$key" ] || ! [[ "$key" =~ ^[A-Z_][A-Z0-9_]*$ ]]; then
        config_error "Invalid variable name: $key (must be uppercase with underscores)"
        return 1
    fi
    case "$value" in
    *$'\n'*)
        config_error "Value for $key spans multiple lines; only single-line values are supported"
        return 1
        ;;
    esac

    local dir
    dir=$(dirname "$file")
    mkdir -p "$dir" 2>/dev/null || return 1
    if [ ! -f "$file" ]; then
        install -m 600 /dev/null "$file" 2>/dev/null || : >"$file" 2>/dev/null || return 1
    fi
    chmod 600 "$file" 2>/dev/null || true

    local tmp replaced=false
    tmp=$(mktemp "${file}.tmp.XXXXXX" 2>/dev/null) || return 1
    if [ -s "$file" ]; then
        local line
        while IFS= read -r line || [ -n "$line" ]; do
            case "$line" in
            "$key"=*)
                if [ "$replaced" = false ]; then
                    printf '%s=%s\n' "$key" "$value" >>"$tmp"
                    replaced=true
                fi
                ;;
            *)
                printf '%s\n' "$line" >>"$tmp"
                ;;
            esac
        done <"$file"
    fi
    if [ "$replaced" = false ]; then
        printf '%s=%s\n' "$key" "$value" >>"$tmp"
    fi
    cat "$tmp" >"$file" 2>/dev/null || {
        rm -f "$tmp"
        return 1
    }
    rm -f "$tmp"
}

# One-shot migration of legacy env.* entries into the secrets file. Values are
# taken from the current host environment and never printed; entries whose
# variable is unset are reported and skipped. Silent when nothing to migrate.
# Usage: migrate_legacy_env_vars
migrate_legacy_env_vars() {
    [ -f "$CONFIG_FILE" ] || return 0
    local vars
    vars=$(sed -nE 's/^[[:space:]]*env\.[^=[:space:]]+[[:space:]]*=[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*$/\1/p' "$CONFIG_FILE" 2>/dev/null || true)
    [ -n "$vars" ] || return 0

    echo ""
    config_info "Legacy env.* entries found in $CONFIG_FILE."
    echo "Their values can be moved into the secrets file (setting.env_file)."
    read -r -p "Migrate now from the current host environment? (Y/n): " migrate || migrate=""
    [[ "$migrate" =~ ^[Nn]$ ]] && return 0

    [ -n "$ENV_FILE" ] || ENV_FILE="$CONFIG_DIR/env"
    local var_name var_value count=0 skipped=0
    while IFS= read -r var_name; do
        [ -n "$var_name" ] || continue
        var_value="${!var_name:-}"
        if [ -z "$var_value" ]; then
            config_warning "'$var_name' is not set in this shell; skipped (export it and re-run setup to migrate it)"
            skipped=$((skipped + 1))
            continue
        fi
        if env_file_upsert "$(env_file_path)" "$var_name" "$var_value"; then
            config_success "Migrated $var_name"
            count=$((count + 1))
        fi
        var_value=""
    done <<<"$vars"
    var_value=""
    config_info "Migrated $count variable(s), skipped $skipped."
}

prompt_env_vars() {
    echo ""
    config_info "Secrets and environment variables (optional)"
    echo "Values are stored in a secrets file (dotenv KEY=VALUE, mode 600) and"
    echo "loaded with docker --env-file. Nothing is ever printed back."
    echo "Press Enter with empty input to finish"
    echo ""

    echo "Common examples:"
    echo "  EXA_API_KEY - Exa websearch API key"
    echo "  OPENCODE_API_KEY - provider API key"
    echo ""

    # Default location on first use.
    if [ -z "$ENV_FILE" ]; then
        ENV_FILE="$CONFIG_DIR/env"
    fi

    local var_name var_value
    while true; do
        read -r -p "Variable name (e.g. EXA_API_KEY): " var_name || var_name=""

        # Allow blank to exit
        if [ -z "$var_name" ]; then
            break
        fi

        # Validate variable name (basic check)
        if ! [[ "$var_name" =~ ^[A-Z_][A-Z0-9_]*$ ]]; then
            config_error "Invalid variable name: $var_name (must be uppercase with underscores)"
            continue
        fi
        case "$var_name" in
        PATH | HOME | LD_PRELOAD | LD_LIBRARY_PATH | DOCKER_* | *_PROXY | *_proxy)
            config_warning "'$var_name' overrides container runtime behavior; prefer a narrower name unless intentional"
            ;;
        esac

        # Hidden input: never echoed, paste-friendly.
        read -r -s -p "Value for $var_name (hidden): " var_value || var_value=""
        echo ""
        if [ -z "$var_value" ]; then
            config_warning "Empty value; skipping $var_name"
            echo ""
            continue
        fi

        if env_file_upsert "$(env_file_path)" "$var_name" "$var_value"; then
            config_success "Saved $var_name to the secrets file"
        fi
        var_value=""
        echo ""
    done
    var_value=""
}

# Interactive SSH agent support prompt
# If SSH_AGENT_SUPPORT is already set (from a previous config), show current value
# and only ask if user wants to change it
prompt_ssh_agent_support() {
    echo ""
    config_info "SSH Agent Forwarding Support"

    if [ "$SSH_AGENT_SUPPORT" = true ]; then
        config_success "SSH agent forwarding is currently enabled"
        read -r -p "Keep SSH agent forwarding enabled? (Y/n): " ssh_agent || ssh_agent=""
        if [[ "$ssh_agent" =~ ^[Nn]$ ]]; then
            SSH_AGENT_SUPPORT=false
            config_info "SSH agent forwarding support disabled"
        else
            config_success "SSH agent forwarding support remains enabled"
        fi
    else
        echo "Enable this if you use SSH agent forwarding for git operations over SSH."
        echo "This mounts the SSH agent socket (private keys stay on the host) and the"
        echo "non-secret ~/.ssh/config and known_hosts files read-only."
        echo ""

        read -r -p "Enable SSH agent forwarding support? (y/N): " ssh_agent || ssh_agent=""
        if [[ "$ssh_agent" =~ ^[Yy]$ ]]; then
            SSH_AGENT_SUPPORT=true
            config_success "SSH agent forwarding support enabled"
        else
            SSH_AGENT_SUPPORT=false
            config_info "SSH agent forwarding support disabled"
        fi
    fi
}

# Interactive GnuPG agent forwarding prompt
# Shares only the public keyring and the host gpg-agent socket; private keys
# never enter the container.
prompt_gpg_agent_support() {
    echo ""
    config_info "GnuPG Agent Forwarding (git commit signing)"

    if [ "$GPG_AGENT_SUPPORT" = true ]; then
        config_success "GnuPG agent forwarding is currently enabled"
        read -r -p "Keep GnuPG agent forwarding enabled? (Y/n): " gpg_agent || gpg_agent=""
        if [[ "$gpg_agent" =~ ^[Nn]$ ]]; then
            GPG_AGENT_SUPPORT=false
            config_info "GnuPG agent forwarding disabled"
        else
            config_success "GnuPG agent forwarding remains enabled"
        fi
    else
        echo "Enable this to sign commits (git commit -S) with the keys held by your"
        echo "host gpg-agent. Only the public keyring and the agent socket are shared;"
        echo "your private keys never enter the container."
        echo ""

        read -r -p "Enable GnuPG agent forwarding? (y/N): " gpg_agent || gpg_agent=""
        if [[ "$gpg_agent" =~ ^[Yy]$ ]]; then
            GPG_AGENT_SUPPORT=true
            config_success "GnuPG agent forwarding enabled"
        else
            GPG_AGENT_SUPPORT=false
            config_info "GnuPG agent forwarding disabled"
        fi
    fi
}

# Interactive host Docker socket prompt
# Mounting the socket gives the container full control of the host Docker
# daemon (effectively root on the host), so it is opt-in.
prompt_docker_socket() {
    echo ""
    config_info "Host Docker Socket (opt-in)"

    if [ "$DOCKER_SOCKET" = true ]; then
        config_warning "Docker socket is currently mounted (container can control the host Docker daemon)"
        read -r -p "Keep the Docker socket mounted? (y/N): " keep_socket || keep_socket=""
        if [[ "$keep_socket" =~ ^[Yy]$ ]]; then
            config_success "Docker socket remains mounted"
        else
            DOCKER_SOCKET=false
            config_info "Docker socket disabled"
        fi
    else
        echo "Enable only if you need Docker-in-Docker or Testcontainers."
        echo "WARNING: it grants the container full control of the host Docker daemon."
        read -r -p "Mount the host Docker socket? (y/N): " enable_socket || enable_socket=""
        if [[ "$enable_socket" =~ ^[Yy]$ ]]; then
            DOCKER_SOCKET=true
            config_success "Docker socket mounted"
        else
            DOCKER_SOCKET=false
            config_info "Docker socket disabled"
        fi
    fi
}

# Interactive container network prompt
# host = simple (shares host network namespace); bridge = more isolated.
prompt_network() {
    echo ""
    config_info "Container Network"
    echo "  host   = shares the host network namespace (default, simple)"
    echo "  bridge = more isolated (reach host services via host.docker.internal)"
    read -r -p "Container network (host|bridge) [$NETWORK]: " network || network=""
    case "$network" in
    host | bridge)
        NETWORK="$network"
        ;;
    "")
        ;;
    *)
        config_warning "Invalid network '$network' (use host|bridge); keeping $NETWORK"
        ;;
    esac
    config_success "Container network: $NETWORK"
}

# Interactive security policy prompt
# Selects which vendored opencode-policy pattern set the guard enforces.
prompt_security_policy() {
    echo ""
    config_info "Security Policy Mode"
    echo "Controls the vendored opencode-policy patterns enforced by security-guard.js:"
    echo "  strict   = every pattern (may flag legitimate commands)"
    echo "  balanced = drop cloud/multi-tenant rules and common dev false positives (default)"
    echo "  off      = vendored patterns disabled (built-in backstops still apply)"
    echo ""

    read -r -p "Security policy (strict|balanced|off) [$SECURITY_POLICY]: " security_policy || security_policy=""
    case "$security_policy" in
    strict | balanced | off)
        SECURITY_POLICY="$security_policy"
        ;;
    "")
        ;;
    *)
        config_warning "Invalid policy '$security_policy' (use strict|balanced|off); keeping $SECURITY_POLICY"
        ;;
    esac
    config_success "Security policy: $SECURITY_POLICY"
}

# Interactive container resource limit prompts (optional; empty = no limit).
prompt_memory() {
    echo ""
    config_info "Container Memory Limit (optional)"
    read -r -p "Memory limit, e.g. 4g (empty = no limit) [${MEMORY:-(none)}]: " memory || memory=""
    if [ -z "$memory" ]; then
        MEMORY=""
        config_info "No memory limit"
    elif [[ "$memory" =~ ^[0-9]+[bBkKmMgG]$ ]]; then
        MEMORY="$memory"
        config_success "Memory limit: $MEMORY"
    else
        config_warning "Invalid memory limit '$memory' (e.g. 4g); keeping ${MEMORY:-(none)}"
    fi
}

prompt_cpus() {
    echo ""
    config_info "Container CPU Limit (optional)"
    read -r -p "CPU limit, e.g. 2 (empty = no limit) [${CPUS:-(none)}]: " cpus || cpus=""
    if [ -z "$cpus" ]; then
        CPUS=""
        config_info "No CPU limit"
    elif [[ "$cpus" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        CPUS="$cpus"
        config_success "CPU limit: $CPUS"
    else
        config_warning "Invalid CPU limit '$cpus' (e.g. 2); keeping ${CPUS:-(none)}"
    fi
}

# Interactive websearch provider prompt. Empty means the TUI asks once per
# session. When a provider is chosen, its API key must reach the container
# through the secrets file (warns when the key is absent there).
prompt_websearch_provider() {
    echo ""
    config_info "Websearch Provider (optional)"
    echo "Built-in: exa | firecrawl | parallel | tavily | random."
    echo "Empty = the TUI asks once per session."
    echo ""
    read -r -p "Websearch provider [${WEBSEARCH_PROVIDER:-(ask once)}]: " ws_provider || ws_provider=""
    case "$ws_provider" in
    "")
        ;;
    exa | firecrawl | parallel | tavily | random)
        WEBSEARCH_PROVIDER="$ws_provider"
        config_success "Websearch provider: $ws_provider"
        local need=""
        case "$ws_provider" in
        exa) need=EXA_API_KEY ;;
        firecrawl) need=FIRECRAWL_API_KEY ;;
        parallel) need=PARALLEL_API_KEY ;;
        tavily) need=TAVILY_API_KEY ;;
        esac
        if [ -n "$need" ] && [ -n "${ENV_FILE:-}" ] && [ -f "$(env_file_path)" ] && ! grep -qE "^${need}=" "$(env_file_path)"; then
            config_warning "'$need' not found in the secrets file; add it via the env setup step"
        fi
        ;;
    *)
        config_warning "Invalid provider '$ws_provider' (use exa|firecrawl|parallel|tavily|random); keeping ${WEBSEARCH_PROVIDER:-(ask once)}"
        ;;
    esac
}

# Interactive TUI theme prompt. Empty means the OpenCode default.
prompt_theme() {
    echo ""
    config_info "TUI Theme (optional)"
    echo "Built-in: catppuccin, catppuccin-frappe, catppuccin-macchiato, ..."
    echo "Empty = OpenCode default."
    echo ""
    read -r -p "Theme [${THEME:-(default)}]: " theme_name || theme_name=""
    case "$theme_name" in
    "")
        ;;
    *[!A-Za-z0-9_-]*)
        config_warning "Invalid theme (letters, numbers, - or _ only); keeping ${THEME:-(default)}"
        ;;
    *)
        THEME="$theme_name"
        config_success "Theme: $theme_name"
        ;;
    esac
}

# Interactive GnuPG forwarding detail prompts (socket choice, autostart, relay).
# Only asked when GnuPG forwarding itself is enabled; otherwise the safe
# defaults from a fresh config apply.
prompt_gpg_agent_options() {
    [ "$GPG_AGENT_SUPPORT" = true ] || return 0
    echo ""
    config_info "GnuPG Agent Details"

    if [ "$GPG_ALLOW_MAIN_SOCKET" = true ]; then
        read -r -p "Keep allowing fallback to the full-control agent socket? (y/N): " gpg_main || gpg_main=""
        if [[ "$gpg_main" =~ ^[Yy]$ ]]; then
            config_success "Full-control socket fallback remains allowed"
        else
            GPG_ALLOW_MAIN_SOCKET=false
            config_info "Full-control socket fallback disabled"
        fi
    else
        echo "The restricted S.gpg-agent.extra socket is preferred; the full-control"
        echo "main socket is never used unless you opt in (NOT recommended)."
        echo ""
        read -r -p "Allow fallback to the full-control agent socket? (y/N): " gpg_main || gpg_main=""
        if [[ "$gpg_main" =~ ^[Yy]$ ]]; then
            GPG_ALLOW_MAIN_SOCKET=true
            config_warning "Full-control agent socket fallback enabled"
        else
            GPG_ALLOW_MAIN_SOCKET=false
            config_info "Full-control socket fallback disabled"
        fi
    fi

    if [ "$GPG_AUTOSTART_AGENT" = true ]; then
        read -r -p "Keep starting the host gpg-agent automatically when its socket is missing? (Y/n): " gpg_auto || gpg_auto=""
        if [[ "$gpg_auto" =~ ^[Nn]$ ]]; then
            GPG_AUTOSTART_AGENT=false
            config_info "GPG agent autostart disabled"
        else
            config_success "GPG agent autostart remains enabled"
        fi
    else
        read -r -p "Start the host gpg-agent automatically when its socket is missing? (y/N): " gpg_auto || gpg_auto=""
        if [[ "$gpg_auto" =~ ^[Yy]$ ]]; then
            GPG_AUTOSTART_AGENT=true
            config_success "GPG agent autostart enabled"
        else
            config_info "GPG agent autostart disabled"
        fi
    fi

    if [ "$GPG_RELAY" = true ]; then
        echo "The relay forwards the agent socket through a normal filesystem when"
        echo "socketdir is on tmpfs (requires socat on the host)."
        read -r -p "Keep the GPG socket relay enabled? (Y/n): " gpg_relay || gpg_relay=""
        if [[ "$gpg_relay" =~ ^[Nn]$ ]]; then
            GPG_RELAY=false
            config_info "GPG socket relay disabled"
        else
            config_success "GPG socket relay remains enabled"
        fi
    else
        read -r -p "Relay the agent socket through a normal filesystem when needed? (y/N): " gpg_relay || gpg_relay=""
        if [[ "$gpg_relay" =~ ^[Yy]$ ]]; then
            GPG_RELAY=true
            config_success "GPG socket relay enabled"
        else
            config_info "GPG socket relay disabled"
        fi
    fi
}

# Print current configuration (for debugging/info)
print_config() {
    echo ""
    echo "Current configuration:"
    echo "  Config file: $CONFIG_FILE"
    echo "  SSH agent forwarding: $SSH_AGENT_SUPPORT"
    echo "  GnuPG agent forwarding: $GPG_AGENT_SUPPORT"
    echo "  GPG main-socket fallback: $GPG_ALLOW_MAIN_SOCKET"
    echo "  GPG agent autostart: $GPG_AUTOSTART_AGENT"
    echo "  GPG socket relay: $GPG_RELAY"
    echo "  Docker socket: $DOCKER_SOCKET"
    if [ "$DOCKER_SOCKET" = true ]; then
        echo "  Docker socket WARNING: root-equivalent on the host (Docker-in-Docker only)"
    fi
    echo "  Container network: $NETWORK"
    echo "  Security policy: $SECURITY_POLICY"
    echo "  Memory limit: ${MEMORY:-(none)}"
    echo "  CPU limit: ${CPUS:-(none)}"
    if [ -n "$ENV_FILE" ]; then
        local env_key_count="?" env_path
        env_path=$(env_file_path)
        if [ -f "$env_path" ]; then
            env_key_count=$(grep -cE '^[A-Za-z_][A-Za-z0-9_]*=' "$env_path" 2>/dev/null || true)
        fi
        echo "  Env file: $ENV_FILE ($env_key_count keys)"
    else
        echo "  Env file: (none)"
    fi
    echo "  Websearch provider: ${WEBSEARCH_PROVIDER:-(ask once)}"
    echo "  Theme: ${THEME:-(default)}"

    if [ ${#CUSTOM_MOUNTS[@]} -gt 0 ]; then
        echo ""
        echo "  Custom mounts:"
        for i in "${!CUSTOM_MOUNTS[@]}"; do
            echo "    [$i] mount.${CUSTOM_MOUNT_KEYS[$i]}=${CUSTOM_MOUNTS[$i]}"
        done
    else
        echo ""
        echo "  Custom mounts: (none)"
    fi
    echo ""
}

# Print a docker command for DRY_RUN with secret-bearing values redacted:
# OPENCODE_CONFIG_CONTENT carries the permission rules. Secrets themselves
# travel via --env-file (path only, safe to show); all other -e values (TERM,
# policy mode, …) stay visible for debugging. One flag per line for readability.
# Usage: dry_run_print <docker args...>
dry_run_print() {
    [ $# -ge 2 ] || {
        printf '%s\n' "$@"
        return 0
    }
    local arg name mask_next=false
    printf '%s %s\n' "$1" "$2"
    shift 2
    for arg in "$@"; do
        if [ "$mask_next" = true ]; then
            name="${arg%%=*}"
            if [ "$name" = "OPENCODE_CONFIG_CONTENT" ]; then
                printf '  %s\n' "<redacted>"
            else
                printf '  %s\n' "$arg"
            fi
            mask_next=false
            continue
        fi
        if [ "$arg" = "-e" ] || [ "$arg" = "--env" ]; then
            printf '  %s\n' "$arg"
            mask_next=true
            continue
        fi
        printf '  %s\n' "$arg"
    done
}

# ============================================
# SETUP ORCHESTRATION (used by `opencode-dockerized install`)
# ============================================

# Main entry point for interactive configuration setup
# Handles: mode selection, prompts, config persistence
interactive_config_setup() {
    prompt_config_mode

    case "$CONFIG_MODE" in
    skip)
        echo ""
        echo "Skipping custom configuration setup."
        echo "You can run 'opencode-dockerized install' again later to configure custom mounts and environment variables."
        ;;
    append | overwrite)
        [ "$CONFIG_MODE" = "append" ] && load_config
        migrate_legacy_env_vars
        prompt_ssh_agent_support
        prompt_gpg_agent_support
        prompt_gpg_agent_options
        prompt_docker_socket
        prompt_network
        prompt_security_policy
        prompt_memory
        prompt_cpus
        prompt_websearch_provider
        prompt_theme
        prompt_custom_mounts
        prompt_env_vars
        save_config
        print_config
        ;;
    new)
        migrate_legacy_env_vars
        read -r -p "Would you like to configure custom mounts and environment variables now? (y/N): " setup_custom || setup_custom=""
        if [[ "$setup_custom" =~ ^[Yy]$ ]]; then
            prompt_ssh_agent_support
            prompt_gpg_agent_support
            prompt_gpg_agent_options
            prompt_docker_socket
            prompt_network
            prompt_security_policy
            prompt_memory
            prompt_cpus
            prompt_websearch_provider
            prompt_theme
            prompt_custom_mounts
            prompt_env_vars
            if [ ${#CUSTOM_MOUNTS[@]} -gt 0 ] || [ "$SSH_AGENT_SUPPORT" = true ] || [ "$GPG_AGENT_SUPPORT" = true ] || [ "$DOCKER_SOCKET" = true ] || [ "$NETWORK" != "host" ] || [ -n "$MEMORY" ] || [ -n "$CPUS" ] || [ "$SECURITY_POLICY" != "balanced" ] || [ -n "$ENV_FILE" ] || [ -n "$WEBSEARCH_PROVIDER" ] || [ -n "$THEME" ]; then
                save_config
                print_config
            else
                config_info "No custom configuration added."
            fi
        else
            init_config_file
            config_info "You can run 'opencode-dockerized install' again later to configure custom mounts and environment variables."
        fi
        ;;
    esac
}
