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

# Self-contained OpenCode state tree. The wrapper owns all of OpenCode's runtime
# state (config, data, state, cache) under this single host directory instead of
# spreading it across the host XDG dirs, so the setup is portable and replaces
# native host usage. It mirrors the container home layout and is mounted 1:1.
OCODE_HOME="${OCODE_HOME:-$CONFIG_DIR/home}"

# Directory holding active GPG relay sockets (one subdir per session). The relay
# lives on a normal filesystem so Docker can bind it (it cannot bind sockets
# under the per-user /run/user tmpfs).
GPG_RELAY_DIR="${GPG_RELAY_DIR:-$CONFIG_DIR/gnupg-relay}"

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

: "${RED:='\033[0;31m'}"
: "${GREEN:='\033[0;32m'}"
: "${YELLOW:='\033[1;33m'}"
: "${BLUE:='\033[0;34m'}"
: "${NC:='\033[0m'}"

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
NETWORK="host"                  # Container network: host (default, simple) | bridge (more isolated)
SECURITY_POLICY="balanced"      # Security policy mode: strict | balanced | off
MEMORY=""                       # Optional container memory limit (docker --memory), e.g. 4g
CPUS=""                         # Optional container CPU limit (docker --cpus), e.g. 2
ENV_FILE=""                     # Optional dotenv file with secrets (docker --env-file), must live under CONFIG_DIR
WEBSEARCH_PROVIDER=""           # Optional built-in websearch provider: exa | firecrawl | parallel | tavily | random
THEME=""                        # Optional TUI theme name (built-in, e.g. catppuccin); empty = OpenCode default
GPG_SOCKET=""                   # Resolved host agent socket (set by build_mount_args)

# ============================================
# SHARED HELPERS
# ============================================

# Compute the container mount path for a project directory.
# Strips $HOME prefix so the path is portable across machines/users.
# Example: /home/user/projects/acme/frontend -> /projects/acme/frontend
#          /opt/work/myproject                -> /opt/work/myproject (unchanged)
# Usage: container_path=$(compute_container_path "/home/user/projects/myapp")
compute_container_path() {
    local host_path="$1"

    if [[ "$host_path" == "$HOME"/* ]]; then
        echo "${host_path#"$HOME"}"
    else
        echo "$host_path"
    fi
}

# Reject project directories that would expose the host home or the whole
# filesystem to the sandbox: "/", $HOME, and any ancestor of $HOME (e.g. /home)
# are refused. Only a project subdirectory is allowed.
# Usage: validate_project_dir "/abs/path" || exit 1
validate_project_dir() {
    local project_dir="$1"

    if [ -z "$project_dir" ]; then
        config_error "A project directory is required."
        return 1
    fi

    if [ "$project_dir" = "/" ]; then
        config_error "Refusing to run with '/' as the project."
        config_info "Pass a project subdirectory instead (e.g. ~/projects/my-app)."
        return 1
    fi

    if [ "$project_dir" = "$HOME" ]; then
        config_error "Refusing to run with the home directory ($HOME) as the project."
        config_info "Pass a project subdirectory instead."
        return 1
    fi

    # Any ancestor of $HOME (e.g. /home) would expose the home through the mount.
    case "$HOME" in
    "$project_dir"/*)
        config_error "Refusing to run with '$project_dir' as the project: it contains your home directory."
        config_info "Pass a project subdirectory instead (e.g. ~/projects/my-app)."
        return 1
        ;;
    esac

    return 0
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

# Merge user-added permission rules into a fresh opencode.json template.
# Rules are flat single-key objects matched by (action,resource): template rules
# win conflicts (reported via MERGED_OVERRIDDEN), unknown user rules are
# preserved (counted in MERGED_ADDED). Single-line, minified and multi-line
# hand-written rules all work (extracted as escaped one-liners, joined back per
# object); rules with nested braces are left to the replace path.
# The result is JSON-validated before use; on failure nothing is written.
# Usage: merge_opencode_permissions <installed> <template> <output>
# Sets: MERGED_ADDED (count), MERGED_OVERRIDDEN ("action:resource ..." list)
merge_opencode_permissions() {
    local installed="$1" template="$2" output="$3"
    MERGED_ADDED=0
    MERGED_OVERRIDDEN=""

    cp "$template" "$output" 2>/dev/null || return 1

    local t_norm t_keys
    t_norm=$(grep -oE '\{[^{}]*"action"[^{}]*\}' "$template" 2>/dev/null | tr -d '[:space:]' || true)
    t_keys=$(grep -oE '\{[^{}]*"action"[^{}]*\}' "$template" 2>/dev/null | while IFS= read -r o; do
        printf '%s|%s\n' "$(printf '%s' "$o" | grep -oE '"action"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)" "$(printf '%s' "$o" | grep -oE '"resource"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)"
    done || true)

    # Extract flat rule objects as single escaped lines (backslash-escaped, real
    # newlines as literal \n), so multi-line hand-written rules survive the
    # pipeline. Objects with nested braces are skipped here and fall back to
    # the replace path via validation below. Portable awk (no gawk-isms).
    # Extract flat rule objects as single escaped lines (backslash-escaped, real
    # newlines as literal \n). Buffers are kept per nesting level so inner rule
    # objects emit on their own closing brace; the document wrapper (which also
    # mentions "action") is excluded via its "permissions" key. Braces inside
    # JSON strings still confuse counting — validation below is the backstop.
    local -a user_objs=()
    local esc obj norm a r seen="" examined=0
    while IFS= read -r esc; do
        [ -n "$esc" ] || continue
        obj=$(printf '%b' "$esc")
        examined=$((examined + 1))
        norm=$(printf '%s' "$obj" | tr -d '[:space:]')
        if grep -qxF -- "$norm" <<<"$t_norm"; then
            continue
        fi
        case "$seen" in
        *"|$norm|"*) continue ;;
        esac
        a=$(printf '%s' "$obj" | grep -oE '"action"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)
        r=$(printf '%s' "$obj" | grep -oE '"resource"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)
        if [ -z "$a" ] || [ -z "$r" ]; then
            continue
        fi
        if grep -qxF -- "$a|$r" <<<"$t_keys"; then
            MERGED_OVERRIDDEN="$MERGED_OVERRIDDEN $a:$r"
            continue
        fi
        user_objs+=("$obj")
        seen="$seen|$norm|"
        MERGED_ADDED=$((MERGED_ADDED + 1))
    done < <(awk '
        BEGIN { depth = 0 }
        function emit_if_rule(text) {
            if (text ~ /"action"/ && text !~ /"permissions"[ \t\r\n]*:/) {
                gsub(/\\/, "\\\\", text)
                gsub(/\n/, "\\n", text)
                print text
            }
        }
        {
            line = $0 "\n"
            for (i = 1; i <= length(line); i++) {
                c = substr(line, i, 1)
                if (c == "{") {
                    depth++
                    stack[depth] = ""
                }
                if (depth >= 1) {
                    for (d = 1; d <= depth; d++) stack[d] = stack[d] c
                }
                if (c == "}") {
                    emit_if_rule(stack[depth])
                    delete stack[depth]
                    depth--
                    if (depth < 0) depth = 0
                }
            }
        }' "$installed" 2>/dev/null || true)

    # Coverage sanity: every "action" key should have been examined; otherwise
    # some custom rule evaded parsing and stays only in the backup.
    local wanted
    wanted=$(grep -oE '"action"[[:space:]]*:' "$installed" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$examined" -lt "$wanted" ]; then
        config_warning "Some custom rules could not be parsed and were left in the backup"
    fi

    local new_tmp
    new_tmp=$(mktemp 2>/dev/null) || return 1

    if [ "$MERGED_ADDED" -gt 0 ]; then
        # Comma-terminate every rule object except the last (per object, so
        # multi-line rules keep their interior commas), give the template's
        # last rule a trailing comma, and insert before the closing bracket.
        local idx total=${#user_objs[@]}
        : >"$new_tmp" || {
            rm -f "$new_tmp"
            return 1
        }
        for ((idx = 0; idx < total; idx++)); do
            printf '%s' "${user_objs[$idx]}" | sed 's/^/    /' >>"$new_tmp" || {
                rm -f "$new_tmp"
                return 1
            }
            [ "$idx" -lt $((total - 1)) ] && printf ',' >>"$new_tmp"
            printf '\n' >>"$new_tmp"
        done
        local last_rule close_at
        last_rule=$(grep -n '"action"' "$output" | tail -1 | cut -d: -f1)
        close_at=$(grep -n '^  \]$' "$output" | head -1 | cut -d: -f1)
        if [ -z "$last_rule" ] || [ -z "$close_at" ]; then
            rm -f "$new_tmp"
            return 1
        fi
        sed "${last_rule}s/}[[:space:]]*$/},/" "$output" >"$new_tmp.merged" 2>/dev/null || {
            rm -f "$new_tmp" "$new_tmp.merged"
            return 1
        }
        head -n $((close_at - 1)) "$new_tmp.merged" >"$new_tmp.out" 2>/dev/null || {
            rm -f "$new_tmp" "$new_tmp.merged"
            return 1
        }
        cat "$new_tmp" >>"$new_tmp.out"
        tail -n +"$close_at" "$new_tmp.merged" >>"$new_tmp.out"
        cat "$new_tmp.out" >"$output"
        rm -f "$new_tmp.merged" "$new_tmp.out"
    fi
    rm -f "$new_tmp"

    # Validate before the caller moves anything into place.
    local v=0
    json_valid "$output" || v=$?
    [ "$v" -eq 1 ] && return 1
    return 0
}

ensure_opencode_dockerized_config() {
    mkdir -p "$CONFIG_DIR/plugins" 2>/dev/null || return 0

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
        template_tmp=$(mktemp 2>/dev/null) || return 0
        merged_tmp=$(mktemp 2>/dev/null) || {
            rm -f "$template_tmp"
            return 0
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
        if [ "$had_file" = true ] && merge_opencode_permissions "$CONFIG_DIR/opencode.json.bak" "$template_tmp" "$merged_tmp"; then
            cat "$merged_tmp" >"$CONFIG_DIR/opencode.json" 2>/dev/null || true
            [ "$MERGED_ADDED" -gt 0 ] && config_success "Preserved $MERGED_ADDED custom rule(s) in $CONFIG_DIR/opencode.json"
            [ -n "$MERGED_OVERRIDDEN" ] && config_warning "Template overrode custom rule(s):$MERGED_OVERRIDDEN"
        else
            if [ "$had_file" = true ]; then
                config_warning "Could not merge custom rules; keeping your backed-up opencode.json unchanged"
            else
                cat "$template_tmp" >"$CONFIG_DIR/opencode.json" 2>/dev/null || true
            fi
        fi
        rm -f "$template_tmp" "$merged_tmp"
        config_success "Refreshed security permissions at $CONFIG_DIR/opencode.json"
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
    # the rest of the code. When the installed copy predates the current guard
    # version (marker string below), it is backed up and refreshed — never
    # silently overwritten.
    local guard_src="$repo_dir/plugins/security-guard.js"
    local installed_guard_ver repo_guard_ver
    installed_guard_ver=$(grep -oE 'OPENCODE_DOCKERIZED_GUARD_VERSION=[0-9]+' "$CONFIG_DIR/plugins/security-guard.js" 2>/dev/null | head -1)
    repo_guard_ver=$(grep -oE 'OPENCODE_DOCKERIZED_GUARD_VERSION=[0-9]+' "$guard_src" 2>/dev/null | head -1)
    if [ ! -f "$CONFIG_DIR/plugins/security-guard.js" ] || [ "$installed_guard_ver" != "$repo_guard_ver" ]; then
        if [ -f "$guard_src" ]; then
            if [ -f "$CONFIG_DIR/plugins/security-guard.js" ]; then
                cp "$CONFIG_DIR/plugins/security-guard.js" "$CONFIG_DIR/plugins/security-guard.js.bak" 2>/dev/null || true
                config_warning "Backed up previous security-guard.js to security-guard.js.bak"
            fi
            if cp "$guard_src" "$CONFIG_DIR/plugins/security-guard.js" 2>/dev/null; then
                config_success "Installed security hooks at $CONFIG_DIR/plugins/security-guard.js"
            else
                config_warning "Could not install security hooks (copy failed; base rules still active)"
            fi
        else
            config_warning "Security hooks source not found at $guard_src (base rules still active)"
        fi
    fi

    # Seed/refresh the ported opencode-policy pattern data. The vendored set is
    # versioned (policies/VERSION): when the repo version differs from the
    # installed one, or any rule file (or the marker) is missing, the copies are
    # refreshed (existing files backed up first). The source lives next to this
    # library in the repo (policies/); the copies are mounted read-only into the
    # container (see build_standard_volume_args).
    local policy_src policy_dest
    policy_src="$repo_dir/policies"
    policy_dest="$CONFIG_DIR/plugins/policies"
    mkdir -p "$policy_dest" 2>/dev/null || true

    local -a policy_files=(unsafe-tool-patterns.json prompt-injection-patterns.json allow-patterns.json)
    local src_ver inst_ver pf policy_refresh=false
    src_ver=""
    inst_ver=""
    [ -f "$policy_src/VERSION" ] && src_ver=$(cat "$policy_src/VERSION" 2>/dev/null || true)
    [ -f "$policy_dest/VERSION" ] && inst_ver=$(cat "$policy_dest/VERSION" 2>/dev/null || true)
    [ ! -f "$policy_dest/VERSION" ] && policy_refresh=true
    [ "$src_ver" != "$inst_ver" ] && policy_refresh=true
    for pf in "${policy_files[@]}"; do
        [ -f "$policy_dest/$pf" ] || policy_refresh=true
    done

    if [ "$policy_refresh" = true ]; then
        for pf in "${policy_files[@]}"; do
            if [ -f "$policy_dest/$pf" ] && [ -f "$policy_src/$pf" ]; then
                cp "$policy_dest/$pf" "$policy_dest/$pf.bak" 2>/dev/null || true
            fi
        done
        for pf in "${policy_files[@]}"; do
            if [ -f "$policy_src/$pf" ]; then
                if cp "$policy_src/$pf" "$policy_dest/$pf" 2>/dev/null; then
                    config_success "Installed policy patterns at $policy_dest/$pf"
                else
                    config_warning "Could not install $pf (copy failed; base rules still active)"
                fi
            else
                config_warning "Policy source not found at $policy_src/$pf (base rules still active)"
            fi
        done
        if [ -f "$policy_src/VERSION" ]; then
            cp "$policy_src/VERSION" "$policy_dest/VERSION" 2>/dev/null || true
        fi
    fi

    # Mirror the security layer into the OpenCode config tree, which is bind
    # mounted read-only into the container. A single read-only directory mount is
    # used because Docker cannot create nested mountpoints under a read-only
    # parent. These copies are wrapper-managed and overwritten on every run, so
    # edit the sources in "$CONFIG_DIR" instead.
    local oc_dir="$OCODE_HOME/.config/opencode"
    if [ -d "$oc_dir" ]; then
        mkdir -p "$oc_dir/plugins/policies" 2>/dev/null || true
        if [ -f "$guard_src" ]; then
            cp "$guard_src" "$oc_dir/plugins/security-guard.js" 2>/dev/null || true
        fi
        for pf in unsafe-tool-patterns.json prompt-injection-patterns.json allow-patterns.json; do
            if [ -f "$CONFIG_DIR/plugins/policies/$pf" ]; then
                cp "$CONFIG_DIR/plugins/policies/$pf" "$oc_dir/plugins/policies/$pf" 2>/dev/null || true
            fi
        done
        # Global rules: back up a user-authored AGENTS.md (not one of ours) once,
        # then keep the managed rules in place.
        if [ -f "$CONFIG_DIR/AGENTS.md" ]; then
            if [ -f "$oc_dir/AGENTS.md" ] && ! grep -q "Security Rules — opencode-dockerized" "$oc_dir/AGENTS.md" 2>/dev/null; then
                cp "$oc_dir/AGENTS.md" "$oc_dir/AGENTS.md.user.bak" 2>/dev/null || true
                config_warning "Backed up your AGENTS.md to AGENTS.md.user.bak (replaced by the read-only security rules)"
            fi
            cp "$CONFIG_DIR/AGENTS.md" "$oc_dir/AGENTS.md" 2>/dev/null || true
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

    local repo_guard inst_guard
    repo_guard=$(grep -oE 'OPENCODE_DOCKERIZED_GUARD_VERSION=[0-9]+' "$repo_dir/plugins/security-guard.js" 2>/dev/null | head -1)
    inst_guard=$(grep -oE 'OPENCODE_DOCKERIZED_GUARD_VERSION=[0-9]+' "$CONFIG_DIR/plugins/security-guard.js" 2>/dev/null | head -1)
    if [ -n "$repo_guard" ] && [ "$repo_guard" = "$inst_guard" ]; then
        config_success "security-guard.js $repo_guard (in sync)"
    else
        config_warning "security-guard.js stale (repo ${repo_guard:-missing} vs installed ${inst_guard:-missing})"
        stale=true
    fi

    local src_ver inst_ver
    src_ver=$(cat "$repo_dir/policies/VERSION" 2>/dev/null || true)
    inst_ver=$(cat "$CONFIG_DIR/plugins/policies/VERSION" 2>/dev/null || true)
    if [ -n "$src_ver" ] && [ "$src_ver" = "$inst_ver" ]; then
        config_success "policy patterns v$src_ver (in sync)"
    else
        config_warning "policy patterns stale (repo ${src_ver:-missing} vs installed ${inst_ver:-missing})"
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
    local mirror_guard
    mirror_guard=$(grep -oE 'OPENCODE_DOCKERIZED_GUARD_VERSION=[0-9]+' "$oc_dir/plugins/security-guard.js" 2>/dev/null | head -1)
    if [ -n "$inst_guard" ] && [ "$mirror_guard" = "$inst_guard" ]; then
        config_success "config-tree mirror $mirror_guard (in sync)"
    else
        config_warning "config-tree mirror stale (installed ${inst_guard:-missing} vs mirror ${mirror_guard:-missing})"
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
        if [ ! -f "$ENV_FILE" ]; then
            config_warning "env file not found: $ENV_FILE"
            stale=true
        else
            local mode=""
            mode=$(stat -c '%a' "$ENV_FILE" 2>/dev/null || stat -f '%Lp' "$ENV_FILE" 2>/dev/null || true)
            if [ -n "$mode" ] && [ $((8#$mode & 8#044)) -ne 0 ]; then
                config_warning "env file is readable by group/others ($ENV_FILE); run: chmod 600"
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
#   - GPG_AGENT_PROBE_CMD replaces the probe with an arbitrary command.
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

    if [ -n "${GPG_AGENT_PROBE_CMD:-}" ]; then
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
    if [ -n "${GPG_AGENT_LAUNCH_CMD:-}" ]; then
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

# Mirror the host's *public* GnuPG material into $OCODE_HOME/.gnupg so the
# container can use the host gpg-agent (forwarded via its socket) without ever
# receiving the private keys. Only public files are copied; private-keys-v1.d,
# the agent sockets and random_seed are deliberately excluded.
# Usage: ensure_gpg_mirror
ensure_gpg_mirror() {
    local host_gpg_home="${GNUPGHOME:-$HOME/.gnupg}"
    local dest="$OCODE_HOME/.gnupg"

    if [ ! -d "$host_gpg_home" ]; then
        config_warning "GnuPG agent support enabled but no GnuPG home found at $host_gpg_home"
        return 0
    fi

    mkdir -p "$dest" 2>/dev/null || return 0
    chmod 700 "$dest" 2>/dev/null || true

    # Public keyring (GnuPG 2.x keybox) plus its lock/trust files. With keyboxd
    # the database can also live under public-keys.d/, so mirror that too.
    # Private keys (private-keys-v1.d) are never copied.
    local f
    for f in pubring.kbx trustdb.gpg sshcontrol; do
        if [ -f "$host_gpg_home/$f" ]; then
            install -m 600 "$host_gpg_home/$f" "$dest/$f" 2>/dev/null ||
                cp "$host_gpg_home/$f" "$dest/$f" 2>/dev/null || true
        fi
    done
    if [ -f "$host_gpg_home/public-keys.d/pubring.db" ]; then
        mkdir -p "$dest/public-keys.d" 2>/dev/null || true
        install -m 600 "$host_gpg_home/public-keys.d/pubring.db" "$dest/public-keys.d/pubring.db" 2>/dev/null ||
            cp "$host_gpg_home/public-keys.d/pubring.db" "$dest/public-keys.d/pubring.db" 2>/dev/null || true
    fi

    # Mirror the config verbatim, including `use-keyboxd`: on such hosts GnuPG
    # keeps the public keyring in the keyboxd database (public-keys.d/), so the
    # container must run keyboxd to read it. entrypoint.sh launches it at boot;
    # `no-autostart` (below) still prevents a keyless local gpg-agent. Stale
    # mirrored config is removed when the host has none.
    local conf
    for conf in gpg.conf common.conf; do
        if [ -f "$host_gpg_home/$conf" ]; then
            install -m 600 "$host_gpg_home/$conf" "$dest/$conf" 2>/dev/null ||
                cp "$host_gpg_home/$conf" "$dest/$conf" 2>/dev/null || true
        else
            rm -f "$dest/$conf" 2>/dev/null || true
        fi
    done

    # Never let the container's gpg auto-start a keyless local agent: the real
    # agent is the host's, reached through the forwarded socket.
    if [ -f "$dest/gpg.conf" ]; then
        grep -qE '^[[:space:]]*no-autostart([[:space:]]|$)' "$dest/gpg.conf" 2>/dev/null ||
            echo "no-autostart" >>"$dest/gpg.conf" 2>/dev/null || true
    else
        echo "no-autostart" >"$dest/gpg.conf" 2>/dev/null || true
    fi

    # Without a public keyring gpg cannot build a signature even when the agent
    # socket is forwarded: warn instead of failing silently later.
    if [ ! -f "$dest/pubring.kbx" ] && [ ! -f "$dest/public-keys.d/pubring.db" ]; then
        config_warning "No public GnuPG keyring found in $host_gpg_home (commit signing will not work)"
    fi

    # Clear any stale agent entry from earlier versions: the socket is
    # bind-mounted by the wrapper, never linked. A previous `-v` mount or a
    # Docker run with a missing source can leave a directory here, which would
    # block the socket mount and the real host agent.
    if [ -d "$dest/S.gpg-agent" ] && [ ! -S "$dest/S.gpg-agent" ]; then
        rmdir "$dest/S.gpg-agent" 2>/dev/null ||
            config_warning "Stray directory at $dest/S.gpg-agent; remove it on the host before mounting the agent socket"
    fi
    rm -f "$dest/S.gpg-agent" 2>/dev/null || true

    # Clear a stale keyboxd socket/lock from a previous run: the container starts
    # a fresh keyboxd, and a dead socket file would otherwise confuse gpgconf.
    rm -f "$dest/S.keyboxd" "$dest/S.keyboxd.lock" 2>/dev/null || true
}

# True when GPG_RELAY_DIR is a safe, non-root location to manage relays in.
# Usage: relay_dir_ok && ...
relay_dir_ok() {
    [ -n "$GPG_RELAY_DIR" ] || return 1
    case "$GPG_RELAY_DIR" in
        / | "") return 1 ;;
    esac
    case "$GPG_RELAY_DIR" in
        "$CONFIG_DIR"/* | "$HOME"/*) return 0 ;;
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
        rm -rf "$d" 2>/dev/null || true
    done
}

# Relay a GnuPG agent socket through a socket on a normal filesystem so Docker
# can bind it. One process per session; the wrapper stops it when the container
# exits. Uses `socat` by default; GPG_RELAY_CMD overrides the command for tests
# (it receives RELAY_SOCK and RELAY_REAL in its environment).
# Usage: relay_socket=$(start_gpg_relay <real_socket>)
start_gpg_relay() {
    local real="$1"
    [ -n "$real" ] && [ -S "$real" ] || return 1
    relay_dir_ok || return 1

    local template="${GPG_RELAY_CMD:-}"
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
# A worktree has a .git FILE (not directory) containing "gitdir: <path>"
# Returns (via stdout): "<git_common_dir>" if worktree, empty string otherwise
# Usage: main_git_dir=$(detect_git_worktree "/path/to/worktree")
detect_git_worktree() {
    local project_dir="$1"

    # Quick check: if .git is a directory (normal repo) or doesn't exist, not a worktree
    if [ ! -f "$project_dir/.git" ]; then
        return 0
    fi

    # Use git to reliably resolve paths (handles relative/absolute gitdir pointers)
    if ! command -v git >/dev/null 2>&1; then
        config_warning "Git worktree detected but 'git' is not installed on the host — git info will be unavailable in container"
        return 0
    fi

    # git rev-parse --git-common-dir gives us the shared .git directory
    local git_common_dir
    git_common_dir=$(git -C "$project_dir" rev-parse --git-common-dir 2>/dev/null) || return 0

    # Resolve to absolute path
    if [[ "$git_common_dir" != /* ]]; then
        git_common_dir=$(cd "$project_dir" && cd "$git_common_dir" && pwd)
    else
        git_common_dir=$(cd "$git_common_dir" && pwd)
    fi

    # Sanity check: the common dir should be a real .git directory
    if [ ! -d "$git_common_dir/objects" ] || [ ! -d "$git_common_dir/refs" ]; then
        return 0
    fi

    echo "$git_common_dir"
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
        --network "$NETWORK"
        --user "$(id -u):$(id -g)"
        --group-add coder
        --security-opt no-new-privileges:true
        --cap-drop=ALL
        -e "TERM=${TERM:-xterm-256color}"
    )

    # Optional resource limits (setting.memory / setting.cpus).
    [ -n "$MEMORY" ] && DOCKER_COMMON_ARGS+=(--memory "$MEMORY")
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
    # mounted as a read-only file into the config plugins dir instead
    # (see build_standard_volume_args).
    if [ -f "$CONFIG_DIR/opencode.json" ]; then
        local sandbox_rule_json
        if sandbox_rule_json=$(tr -d '\n' <"$CONFIG_DIR/opencode.json" 2>/dev/null) && [ -n "$sandbox_rule_json" ]; then
            # Optional built-in websearch provider (setting.websearch_provider).
            # Merged into the inline config alongside the permissions; the file
            # keeps its known shape (a single object ending in `}`), so a suffix
            # strip plus append is exact. The provider id is allowlisted at parse
            # time and re-checked here, so no JSON injection is possible.
            if [ -n "$WEBSEARCH_PROVIDER" ]; then
                case "$WEBSEARCH_PROVIDER" in
                exa | firecrawl | parallel | tavily | random)
                    if [[ "$sandbox_rule_json" == *"}" ]]; then
                        sandbox_rule_json="${sandbox_rule_json%\}},\"websearch\":{\"provider\":\"$WEBSEARCH_PROVIDER\"}}"
                    else
                        config_warning "Cannot merge websearch provider into sandbox rules (unexpected shape); skipping"
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

    # NPM configuration (optional)
    if [ -f "$HOME/.npmrc" ]; then
        VOLUME_ARGS+=(-v "$HOME/.npmrc:/home/coder/.npmrc:ro")
    fi

    # Claude Code compatibility directory (optional)
    # Provides fallback CLAUDE.md rules and ~/.claude/skills/ when no opencode equivalents exist
    if [ -d "$HOME/.claude" ]; then
        VOLUME_ARGS+=(-v "$HOME/.claude:/home/coder/.claude:ro")
    fi

    # Agent-compatible skills directory (optional)
    # OpenCode reads skills from ~/.agents/skills/<name>/SKILL.md
    if [ -d "$HOME/.agents" ]; then
        VOLUME_ARGS+=(-v "$HOME/.agents:/home/coder/.agents:ro")
    fi

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

# Secrets file (dotenv KEY=VALUE lines) loaded with docker --env-file.
# Must live under ~/.config/opencode-dockerized/ (never mounted). Create it with
# `install -m 600 /dev/null ~/.config/opencode-dockerized/env` and add keys like
# EXA_API_KEY=... Empty = disabled.
# setting.env_file=~/.config/opencode-dockerized/env

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

# Secrets live in setting.env_file (dotenv KEY=VALUE, never mounted).
# Use `opencode-dockerized install` to add keys without ever printing them.
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
    NETWORK="host"
    SECURITY_POLICY="balanced"
    MEMORY=""
    CPUS=""
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
            elif [[ "$value" =~ ^[0-9]+[bBkKmMgG]$ ]]; then
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
        echo "# Container network: host (default) | bridge (more isolated)"
        echo "setting.network=$NETWORK"
        echo "# Security policy mode: strict | balanced | off"
        echo "setting.security_policy=$SECURITY_POLICY"
        echo "# Optional container resource limits (empty = no limit)"
        echo "setting.memory=$MEMORY"
        echo "setting.cpus=$CPUS"
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

# Add a bind mount for a socket/file. Docker's `--mount` spec separates fields
# with commas, so fall back to `-v` when a path contains one.
# Usage: mount_bind <source> <target>
mount_bind() {
    local src="$1" dst="$2"
    case "$src$dst" in
        *,*) DOCKER_MOUNT_ARGS+=(-v "$src:$dst") ;;
        *) DOCKER_MOUNT_ARGS+=(--mount "type=bind,source=$src,target=$dst") ;;
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

    for mount in "${CUSTOM_MOUNTS[@]}"; do
        # Expand a leading ~ to the home directory (only at the start of the
        # host path; ':' inside paths is the field separator and unsupported)
        if [[ "$mount" == "~"* ]]; then
            mount="$HOME${mount#"~"}"
        fi

        # Extract host_path, container_path, and mode
        local host_path="${mount%%:*}"
        local rest="${mount#*:}"
        local container_path="${rest%:*}"
        local mode="${rest##*:}"

        # A mount entry must be host_path:container_path[:mode].
        if [[ "$mount" != *:* ]]; then
            config_error "Invalid mount '$mount': expected host_path:container_path"
            exit 1
        fi

        # Never expose the host SSH private material: agent forwarding is the
        # supported path (config/known_hosts are mounted read-only automatically).
        if [ "$host_path" = "$HOME/.ssh" ] || [[ "$host_path" == "$HOME/.ssh/"* ]]; then
            config_error "Refusing to mount $host_path: it would expose SSH private keys."
            config_info "Use setting.ssh_agent_support=true instead (config/known_hosts are mounted read-only automatically)."
            exit 1
        fi

        # Never expose the host GnuPG private material either: agent forwarding
        # mirrors only the public keyring and forwards the agent socket.
        if [ "$host_path" = "$HOME/.gnupg" ] || [[ "$host_path" == "$HOME/.gnupg/"* ]]; then
            config_error "Refusing to mount $host_path: it would expose GnuPG private keys."
            config_info "Use setting.gpg_agent_support=true instead (only the public keyring and the agent socket are shared)."
            exit 1
        fi

        # A malformed entry must not reach docker as `-v host::mode`.
        if [ -z "$container_path" ] || [[ "$container_path" != /* ]]; then
            config_error "Invalid mount '$mount': container path must be absolute"
            exit 1
        fi

        # Validate mode is either not set or "rw"
        if [ "$mode" = "$container_path" ]; then
            # No mode specified, default to read-only
            DOCKER_MOUNT_ARGS+=(-v "$host_path:$container_path:ro")
        elif [ "$mode" = "rw" ]; then
            DOCKER_MOUNT_ARGS+=(-v "$host_path:$container_path:rw")
        else
            # Mode was specified, use it as-is
            DOCKER_MOUNT_ARGS+=(-v "$host_path:$container_path:$mode")
        fi
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
    # keyring (rw so GPG can write lock files) and the host agent socket. The
    # private keys stay on the host; only public material is shared. The socket
    # is bind-mounted with --mount (a stale source fails loudly instead of Docker
    # creating a directory) at the container's GNUPGHOME path (and at its own XDG
    # path when applicable) so GPG discovers it without any host symlink.
    if [ "$GPG_AGENT_SUPPORT" = true ]; then
        GPG_SOCKET=""
        ensure_gpg_mirror
        if [ -d "$OCODE_HOME/.gnupg" ]; then
            mount_bind "$OCODE_HOME/.gnupg" "/home/coder/.gnupg"
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
            # Mount the socket at a dedicated path OUTSIDE the mirror. A socket
            # mounted *inside* another bind mount (the mirror) can be shadowed by
            # Docker, which left the agent socket invisible to gpg.
            mount_bind "$mount_socket" "/home/coder/.gnupg-agent/S.gpg-agent"
            # Expose it to gpg through GNUPGHOME with a symlink (gpg follows it).
            # ensure_gpg_mirror clears any previous link before each run.
            if [ -d "$OCODE_HOME/.gnupg" ]; then
                ln -sfn "/home/coder/.gnupg-agent/S.gpg-agent" "$OCODE_HOME/.gnupg/S.gpg-agent" 2>/dev/null ||
                    config_warning "Could not create the GnuPG agent socket symlink in $OCODE_HOME/.gnupg"
            fi
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

    # Handle GnuPG agent forwarding if enabled. GNUPGHOME points at the mirrored
    # public keyring; XDG_RUNTIME_DIR is forwarded only when the agent socket
    # lives under it, so gpgconf inside the container resolves the mounted path.
    if [ "$GPG_AGENT_SUPPORT" = true ]; then
        DOCKER_ENV_ARGS+=(-e "GNUPGHOME=/home/coder/.gnupg")

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
}

# Build the docker --env-file argument from setting.env_file.
# The file holds secrets (dotenv KEY=VALUE lines) and is consumed host-side by
# `docker run --env-file`, so values never appear on the wrapper command line.
# The file itself is never mounted: it must live under CONFIG_DIR, which no
# mount ever serves. This is the only way user secrets reach the container
# (the old env.* host passthrough was removed).
# Populates DOCKER_ENV_FILE_ARGS array.
# Usage: build_env_file_args
build_env_file_args() {
    DOCKER_ENV_FILE_ARGS=()

    [ -n "$ENV_FILE" ] || return 0

    # Expand a leading ~, then canonicalize so `..` segments cannot escape the
    # containment check below (readlink -m needs no existing file; fall back to
    # the literal path where it is unavailable, e.g. macOS).
    local env_file="$ENV_FILE"
    if [[ "$env_file" == "~"* ]]; then
        env_file="$HOME${env_file#"~"}"
    fi
    local canonical
    if canonical=$(readlink -m "$env_file" 2>/dev/null) && [ -n "$canonical" ]; then
        env_file="$canonical"
    fi

    case "$env_file" in
    "$CONFIG_DIR" | "$CONFIG_DIR"/*) ;;
    *)
        config_error "Refusing env file outside \$CONFIG_DIR ($CONFIG_DIR): it could be mounted into the container."
        exit 1
        ;;
    esac

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

    # Container path must be absolute (relative paths resolve unpredictably)
    if [[ "$container_path" != /* ]]; then
        config_error "Container path must be absolute: $container_path"
        return 1
    fi

    # Validate host path exists (leading ~ expanded for the check)
    local expanded_path="$host_path"
    if [[ "$expanded_path" == "~"* ]]; then
        expanded_path="$HOME${expanded_path#"~"}"
    fi

    # Never expose the host SSH private material via a custom mount.
    if [ "$expanded_path" = "$HOME/.ssh" ] || [[ "$expanded_path" == "$HOME/.ssh/"* ]]; then
        config_error "Refusing to mount $expanded_path: it would expose SSH private keys."
        config_info "Use setting.ssh_agent_support=true instead (config/known_hosts are mounted read-only automatically)."
        return 1
    fi

    # Never expose the host GnuPG private material via a custom mount.
    if [ "$expanded_path" = "$HOME/.gnupg" ] || [[ "$expanded_path" == "$HOME/.gnupg/"* ]]; then
        config_error "Refusing to mount $expanded_path: it would expose GnuPG private keys."
        config_info "Use setting.gpg_agent_support=true instead (only the public keyring and the agent socket are shared)."
        return 1
    fi

    if [ ! -e "$expanded_path" ]; then
        config_warning "Host path does not exist: $expanded_path"
    fi

    if [ -n "$mode" ] && [ "$mode" != "ro" ] && [ "$mode" != "rw" ]; then
        config_error "Invalid mode: $mode (must be 'ro' or 'rw')"
        return 1
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
        if env_file_upsert "$ENV_FILE" "$var_name" "$var_value"; then
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

        if env_file_upsert "$ENV_FILE" "$var_name" "$var_value"; then
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
        if [ -n "$need" ] && [ -n "${ENV_FILE:-}" ] && [ -f "$ENV_FILE" ] && ! grep -qE "^${need}=" "$ENV_FILE"; then
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
        local env_key_count="?"
        if [ -f "$ENV_FILE" ]; then
            env_key_count=$(grep -cE '^[A-Za-z_][A-Za-z0-9_]*=' "$ENV_FILE" 2>/dev/null || true)
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
