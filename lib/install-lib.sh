#!/bin/bash

# install-lib.sh - First-time install / repair wizard for opencode-dockerized.
# Sourced by bin/opencode-dockerized (the `install` command) and never executed
# directly. bin/ contains only the `opencode-dockerized` binary; there is no
# second `install` binary.
#
# NOTE: Do not use "set -e" here — this is a library file sourced by callers.

# Ensure the <install>/bin PATH export exists in an rc file.
# Returns 0 when added, 1 when already present, 2 on error.
# Usage: ensure_path_in_rc <rcfile>
ensure_path_in_rc() {
    local rc_file="$1"
    # Single quotes are intentional: $HOME/$PATH must stay unexpanded in the rc line.
    # shellcheck disable=SC2016
    local path_line='export PATH="$HOME/.local/share/opencode-dockerized/bin:$PATH"'
    [ -f "$rc_file" ] || : >"$rc_file" 2>/dev/null || return 2
    if grep -qF -- 'opencode-dockerized/bin' "$rc_file" 2>/dev/null; then
        return 1
    fi
    {
        echo ""
        echo "# Added by opencode-dockerized install"
        echo "$path_line"
    } >>"$rc_file" || return 2
    return 0
}

# Replace lines starting with PREFIX that also mention NEEDLE with REPLACEMENT
# (first match; later matching dupes dropped; all other lines preserved).
# Returns 0 when it replaced, 1 when nothing matched.
# Usage: replace_rc_line <file> <prefix> <needle> <replacement>
replace_rc_line() {
    local file="$1" prefix="$2" needle="$3" replacement="$4"
    local tmp replaced=false line
    tmp=$(mktemp "${file}.tmp.XXXXXX" 2>/dev/null) || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
        "$prefix"*)
            case "$line" in
            *"$needle"*)
                if [ "$replaced" = false ]; then
                    printf '%s\n' "$replacement" >>"$tmp" || {
                        rm -f "$tmp"
                        return 2
                    }
                    replaced=true
                fi
                ;;
            *)
                printf '%s\n' "$line" >>"$tmp" || {
                    rm -f "$tmp"
                    return 2
                }
                ;;
            esac
            ;;
        *)
            printf '%s\n' "$line" >>"$tmp" || {
                rm -f "$tmp"
                return 2
            }
            ;;
        esac
    done <"$file" || {
        rm -f "$tmp"
        return 2
    }
    if [ "$replaced" = false ]; then
        rm -f "$tmp"
        return 1
    fi
    cat "$tmp" >"$file" 2>/dev/null || {
        rm -f "$tmp"
        return 2
    }
    rm -f "$tmp"
}

# Ensure the three managed alias lines exist, pointing at the global command
# on PATH (never at an absolute repo path, which goes stale on repo moves).
# Returns 0 when it changed anything, 1 when already ok, 2 on error.
# Usage: ensure_aliases_in_rc <rcfile>
ensure_aliases_in_rc() {
    local rc_file="$1"
    local marker="# OpenCode Dockerized aliases"
    local a1="alias ocd='opencode-dockerized'"
    local a2="alias ocd-run='opencode-dockerized run'"
    local a3="alias ocd-auth='opencode-dockerized auth'"
    local changed=false line key existing
    [ -f "$rc_file" ] || : >"$rc_file" 2>/dev/null || return 2
    if ! grep -qF -- "$marker" "$rc_file" 2>/dev/null; then
        {
            echo ""
            echo "$marker"
            echo "$a1"
            echo "$a2"
            echo "$a3"
        } >>"$rc_file" || return 2
        return 0
    fi
    for line in "$a1" "$a2" "$a3"; do
        if grep -qxF -- "$line" "$rc_file" 2>/dev/null; then
            continue
        fi
        key="${line%%=*}"
        existing=$(grep -E -- "^${key}=" "$rc_file" 2>/dev/null | head -1 || true)
        if [ -n "$existing" ]; then
            case "$existing" in
            *opencode-dockerized*)
                replace_rc_line "$rc_file" "$key=" "opencode-dockerized" "$line" || return 2
                ;;
            *)
                printf '%s\n' "$line" >>"$rc_file" || return 2
                echo "Kept your custom '${key}' line; added ours after it (last definition wins)"
                ;;
            esac
        else
            printf '%s\n' "$line" >>"$rc_file" || return 2
        fi
        changed=true
    done
    [ "$changed" = true ]
}

# True when all three managed alias lines exist exactly (global command form).
# Usage: aliases_configured <rcfile>
aliases_configured() {
    local rc_file="$1" a
    for a in "alias ocd='opencode-dockerized'" "alias ocd-run='opencode-dockerized run'" "alias ocd-auth='opencode-dockerized auth'"; do
        grep -qxF -- "$a" "$rc_file" 2>/dev/null || return 1
    done
    return 0
}

# True when NAME is one of the enabled --only sections.
# Uses the global SETUP_ONLY (comma-separated).
wants_section() {
    case ",$SETUP_ONLY," in
    *",$1,"*) return 0 ;;
    esac
    return 1
}

# Ensure this checkout's bin/ is executable and on PATH in both shells,
# and drop the legacy ~/.local/bin symlink (nothing lives there anymore).
# Usage: ensure_global_command
ensure_global_command() {
    local repo_dir target ok=true
    repo_dir="$(install_root 2>/dev/null || true)"
    target="${repo_dir}/bin/opencode-dockerized"
    [ -n "$repo_dir" ] || target=""
    if [ -n "$target" ] && [ ! -x "$target" ]; then
        if chmod +x "$target" 2>/dev/null; then
            echo "Made the opencode-dockerized binary executable"
        else
            echo "Could not make $target executable"
            ok=false
        fi
    fi
    if [ -L "$HOME/.local/bin/opencode-dockerized" ]; then
        rm -f "$HOME/.local/bin/opencode-dockerized" 2>/dev/null || true
        echo "Removed legacy symlink ~/.local/bin/opencode-dockerized (now via PATH)"
    elif [ -e "$HOME/.local/bin/opencode-dockerized" ]; then
        echo "$HOME/.local/bin/opencode-dockerized exists and is not a symlink; left untouched (remove it manually)"
    fi
    # Drop the obsolete second binary from canonical installs (bin/ holds only
    # the opencode-dockerized binary now).
    if [ -e "$OCODE_BIN_DIR/install" ]; then
        rm -f "$OCODE_BIN_DIR/install" 2>/dev/null || true
        echo "Removed obsolete $OCODE_BIN_DIR/install (use 'opencode-dockerized install')"
    fi
    local rc
    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
        [ -f "$rc" ] || continue
        if ensure_path_in_rc "$rc"; then
            echo "Added opencode-dockerized/bin to PATH in $rc"
        fi
    done
    if command -v opencode-dockerized >/dev/null 2>&1; then
        echo "Command on PATH: $(command -v opencode-dockerized)"
    else
        echo "Restart your shell (or source ~/.bashrc) for PATH to take effect"
    fi
    [ "$ok" = true ]
}

_install_bash_completion() {
    local repo_dir="$1"
    local bash_rc="$HOME/.bashrc"
    local completion_line="[ -f \"$repo_dir/completions/bash.sh\" ] && source \"$repo_dir/completions/bash.sh\""
    if grep -qF -- "$completion_line" "$bash_rc" 2>/dev/null; then
        echo "Bash completion already configured in ~/.bashrc"
    else
        {
            echo ""
            echo "# OpenCode Dockerized completion"
            echo "$completion_line"
        } >>"$bash_rc"
        echo "Added bash completion to ~/.bashrc"
        echo "  Run: source ~/.bashrc"
    fi
}

_install_zsh_completion() {
    local repo_dir="$1"
    local zsh_rc="$HOME/.zshrc"
    local completion_line="[ -f \"$repo_dir/completions/zsh.sh\" ] && source \"$repo_dir/completions/zsh.sh\""
    if grep -qF -- "$completion_line" "$zsh_rc" 2>/dev/null; then
        echo "Zsh completion already configured in ~/.zshrc"
    else
        {
            echo ""
            echo "# OpenCode Dockerized completion"
            echo "$completion_line"
        } >>"$zsh_rc"
        echo "Added zsh completion to ~/.zshrc"
        echo "  Run: source ~/.zshrc"
    fi
}

_install_bash_aliases() {
    ensure_global_command || true
    local rc=0
    ensure_aliases_in_rc "$HOME/.bashrc" || rc=$?
    if [ "$rc" -eq 2 ]; then
        echo "Could not update aliases in ~/.bashrc"
    elif [ "$rc" -eq 0 ]; then
        echo "Added aliases to ~/.bashrc"
        echo "  Run: source ~/.bashrc"
    else
        echo "Bash aliases already configured in ~/.bashrc"
    fi
}

_install_zsh_aliases() {
    ensure_global_command || true
    local rc=0
    ensure_aliases_in_rc "$HOME/.zshrc" || rc=$?
    if [ "$rc" -eq 2 ]; then
        echo "Could not update aliases in ~/.zshrc"
    elif [ "$rc" -eq 0 ]; then
        echo "Added aliases to ~/.zshrc"
        echo "  Run: source ~/.zshrc"
    else
        echo "Zsh aliases already configured in ~/.zshrc"
    fi
}

_install_usage() {
    echo "Usage: opencode-dockerized install [--yes] [--only config,completions,aliases,global[,path][,build]] [-h|--help]"
    echo "  'global' and 'path' are aliases: both ensure <install>/bin is on PATH."
}

# Ensure the checkout tracks its upstream branch so `update`/`upgrade`
# work. `git clone` normally sets this, but manual checkouts
# (init + remote add + checkout) don't. Idempotent, never fails.
# Usage: ensure_git_upstream <repo_dir>
ensure_git_upstream() {
    local dir="$1" branch
    [ -d "$dir/.git" ] || return 0
    command -v git >/dev/null 2>&1 || return 0
    branch=$(git -C "$dir" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
    [ -n "$branch" ] && [ "$branch" != "HEAD" ] || return 0
    if git -C "$dir" rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1; then
        return 0
    fi
    if git -C "$dir" rev-parse --verify "refs/remotes/origin/$branch" >/dev/null 2>&1; then
        if git -C "$dir" branch --set-upstream-to="origin/$branch" "$branch" >/dev/null 2>&1; then
            echo "Tracking upstream: $branch -> origin/$branch (self-update enabled)"
            return 0
        fi
    fi
    echo "Could not set upstream tracking for '$branch' (no origin/$branch found); set it manually with 'git branch --set-upstream-to=origin/<branch>'"
    return 0
}

# First-time install / repair wizard. Idempotent.
# Non-interactive (piped stdin, no TTY) defaults to --yes so a single
# `curl .../install.sh | bash` performs the full setup (config, PATH,
# completions, aliases) without requiring a second manual run.
# Usage: run_install_main [--yes] [--only ...]
run_install_main() {
    SETUP_YES=false
    SETUP_ONLY="config,completions,aliases,global"
    while [ $# -gt 0 ]; do
        case "$1" in
        --yes) SETUP_YES=true ;;
        --only)
            [ -n "${2:-}" ] || {
                echo "Missing value for --only" >&2
                _install_usage
                return 1
            }
            SETUP_ONLY="$2"
            shift
            ;;
        --only=*) SETUP_ONLY="${1#--only=}" ;;
        -h | --help)
            _install_usage
            return 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            _install_usage
            return 1
            ;;
        esac
        shift
    done

    local _normalized=",$SETUP_ONLY,"
    _normalized="${_normalized//,path/,global}"
    SETUP_ONLY="${_normalized#,}"
    SETUP_ONLY="${SETUP_ONLY%,}"
    unset _normalized
    local _residue=",$SETUP_ONLY,"
    _residue="${_residue//,config/}"
    _residue="${_residue//,completions/}"
    _residue="${_residue//,aliases/}"
    _residue="${_residue//,global/}"
    _residue="${_residue//,build/}"
    if [ "$_residue" != "," ]; then
        echo "Unknown section in --only: $SETUP_ONLY (use config,completions,aliases,global[,path][,build])" >&2
        _install_usage
        return 1
    fi
    unset _residue

    # Piped/curl installs have no TTY for prompts: apply recommended defaults
    # instead of stopping after the core directories.
    if [ ! -t 0 ] && [ "$SETUP_YES" != true ]; then
        SETUP_YES=true
        config_info "Non-interactive install detected: applying recommended defaults (--yes)."
    fi

    local REPO_ROOT
    REPO_ROOT="$(install_root 2>/dev/null || true)"
    [ -n "$REPO_ROOT" ] || {
        config_error "Could not locate the checkout root."
        return 1
    }
    ensure_git_upstream "$REPO_ROOT" || true
    if [ "$(readlink -f "$REPO_ROOT" 2>/dev/null || echo "$REPO_ROOT")" != "$(readlink -f "$OCODE_INSTALL_DIR" 2>/dev/null || echo "$OCODE_INSTALL_DIR")" ] && [ -d "$OCODE_INSTALL_DIR/.git" ]; then
        ensure_git_upstream "$OCODE_INSTALL_DIR" || true
    fi

    export TMPDIR="${TMPDIR:-/tmp/opencode}"
    mkdir -p "$TMPDIR" 2>/dev/null || export TMPDIR="/tmp"

    echo "OpenCode Docker Install"
    echo "================================"
    echo ""
    echo "Checking OpenCode configuration..."
    echo ""

    mkdir -p "$OCODE_HOME/.config/opencode/agents" "$OCODE_HOME/.config/opencode/plugins" \
        "$OCODE_HOME/.config/opencode/commands" "$OCODE_HOME/.config/opencode/skills" \
        "$OCODE_HOME/.local/share/opencode" "$OCODE_HOME/.local/state/opencode" \
        "$OCODE_HOME/.cache/opencode" "$HOME/.mcp-auth" 2>/dev/null || true
    # Single quotes are intentional: the JSON $schema key must stay literal.
    # shellcheck disable=SC2016
    [ -f "$OCODE_HOME/.config/opencode/opencode.json" ] || echo '{"$schema": "https://opencode.ai/config.json"}' >"$OCODE_HOME/.config/opencode/opencode.json" 2>/dev/null || true
    [ -f "$OCODE_HOME/.config/opencode/cli.json" ] || echo '{}' >"$OCODE_HOME/.config/opencode/cli.json" 2>/dev/null || true
    ensure_opencode_dockerized_config

    if wants_section config; then
        if [ "$SETUP_YES" = true ]; then
            if config_exists; then
                config_info "Non-interactive defaults: keeping existing config."
            else
                init_config_file
            fi
        else
            interactive_config_setup
        fi
    fi

    if wants_section completions; then
        echo ""
        echo "Shell Completions Setup"
        local bash_completion_line="[ -f \"$REPO_ROOT/completions/bash.sh\" ] && source \"$REPO_ROOT/completions/bash.sh\""
        local zsh_completion_line="[ -f \"$REPO_ROOT/completions/zsh.sh\" ] && source \"$REPO_ROOT/completions/zsh.sh\""
        local bash_completion_installed=false zsh_completion_installed=false
        if [ -f "$HOME/.bashrc" ] && grep -qF -- "$bash_completion_line" "$HOME/.bashrc" 2>/dev/null; then
            bash_completion_installed=true
        fi
        if [ -f "$HOME/.zshrc" ] && grep -qF -- "$zsh_completion_line" "$HOME/.zshrc" 2>/dev/null; then
            zsh_completion_installed=true
        fi
        if [ "$SETUP_YES" = true ]; then
            echo "Non-interactive defaults: installing for shells with existing rc files."
            [ -f "$HOME/.bashrc" ] && _install_bash_completion "$REPO_ROOT"
            [ -f "$HOME/.zshrc" ] && _install_zsh_completion "$REPO_ROOT"
        else
            local install_completions=""
            if [ "$bash_completion_installed" = true ] && [ "$zsh_completion_installed" = true ]; then
                echo "Shell completions already configured (bash + zsh)"
                local reconfigure_completions=""
                read -r -p "Reconfigure completions? (y/N): " reconfigure_completions || reconfigure_completions=""
                [[ "$reconfigure_completions" =~ ^[Yy]$ ]] || install_completions="skip"
            elif [ "$bash_completion_installed" = true ]; then
                echo "Bash completion already configured"
                echo "Would you like to also install zsh completions?"
                local install_zsh_only=""
                read -r -p "Install zsh completions? (y/N): " install_zsh_only || install_zsh_only=""
                if [[ "$install_zsh_only" =~ ^[Yy]$ ]]; then
                    _install_zsh_completion "$REPO_ROOT"
                fi
                install_completions="skip"
            elif [ "$zsh_completion_installed" = true ]; then
                echo "Zsh completion already configured"
                echo "Would you like to also install bash completions?"
                local install_bash_only=""
                read -r -p "Install bash completions? (y/N): " install_bash_only || install_bash_only=""
                if [[ "$install_bash_only" =~ ^[Yy]$ ]]; then
                    _install_bash_completion "$REPO_ROOT"
                fi
                install_completions="skip"
            fi
            if [ "${install_completions:-}" != "skip" ]; then
                echo "Would you like to install shell completions? (enables tab completion for commands)"
                read -r -p "Install completions? (y/n): " install_completions || install_completions=""
                if [[ "$install_completions" =~ ^[Yy]$ ]]; then
                    echo ""
                    echo "Available completions:"
                    echo "  1) bash"
                    echo "  2) zsh"
                    echo "  3) both"
                    echo "  4) skip"
                    local shell_choice=""
                    read -r -p "Select option (1-4): " shell_choice || shell_choice=""
                    case "$shell_choice" in
                    1) _install_bash_completion "$REPO_ROOT" ;;
                    2) _install_zsh_completion "$REPO_ROOT" ;;
                    3)
                        _install_bash_completion "$REPO_ROOT"
                        _install_zsh_completion "$REPO_ROOT"
                        ;;
                    4) echo "Skipping completions installation." ;;
                    *) echo "Invalid choice, skipping completions." ;;
                    esac
                else
                    echo "Skipping completions installation."
                fi
            fi
        fi
    fi

    if wants_section aliases; then
        echo ""
        echo "Shell Aliases Setup"
        local bash_aliases_installed=false zsh_aliases_installed=false
        if [ -f "$HOME/.bashrc" ] && aliases_configured "$HOME/.bashrc"; then
            bash_aliases_installed=true
        fi
        if [ -f "$HOME/.zshrc" ] && aliases_configured "$HOME/.zshrc"; then
            zsh_aliases_installed=true
        fi
        local setup_aliases="ask"
        if [ "$SETUP_YES" = true ]; then
            echo "Non-interactive defaults: installing for shells with existing rc files."
            [ -f "$HOME/.bashrc" ] && _install_bash_aliases
            [ -f "$HOME/.zshrc" ] && _install_zsh_aliases
        else
            if [ "$bash_aliases_installed" = true ] && [ "$zsh_aliases_installed" = true ]; then
                echo "Shell aliases already configured (bash + zsh)"
                local reconfigure_aliases=""
                read -r -p "Reconfigure aliases? (y/N): " reconfigure_aliases || reconfigure_aliases=""
                [[ "$reconfigure_aliases" =~ ^[Yy]$ ]] || setup_aliases="skip"
            elif [ "$bash_aliases_installed" = true ]; then
                echo "Bash aliases already configured"
                echo "Would you like to also install zsh aliases?"
                local install_zsh_aliases_only=""
                read -r -p "Install zsh aliases? (y/N): " install_zsh_aliases_only || install_zsh_aliases_only=""
                if [[ "$install_zsh_aliases_only" =~ ^[Yy]$ ]]; then
                    _install_zsh_aliases
                fi
                setup_aliases="skip"
            elif [ "$zsh_aliases_installed" = true ]; then
                echo "Zsh aliases already configured"
                echo "Would you like to also install bash aliases?"
                local install_bash_aliases_only=""
                read -r -p "Install bash aliases? (y/N): " install_bash_aliases_only || install_bash_aliases_only=""
                if [[ "$install_bash_aliases_only" =~ ^[Yy]$ ]]; then
                    _install_bash_aliases
                fi
                setup_aliases="skip"
            fi
            if [ "$setup_aliases" != "skip" ]; then
                echo "Would you like to set up convenient aliases for opencode-dockerized?"
                echo "This will create short aliases like 'ocd' for easier command access."
                read -r -p "Setup aliases? (y/n): " setup_aliases || setup_aliases=""
                if [[ "$setup_aliases" =~ ^[Yy]$ ]]; then
                    echo ""
                    echo "Recommended aliases:"
                    echo "  ocd       -> opencode-dockerized"
                    echo "  ocd-run   -> opencode-dockerized run"
                    echo "  ocd-auth  -> opencode-dockerized auth"
                    echo ""
                    echo "Available shells:"
                    echo "  1) bash"
                    echo "  2) zsh"
                    echo "  3) both"
                    echo "  4) skip"
                    local alias_shell_choice=""
                    read -r -p "Select option (1-4): " alias_shell_choice || alias_shell_choice=""
                    case "$alias_shell_choice" in
                    1) _install_bash_aliases ;;
                    2) _install_zsh_aliases ;;
                    3)
                        _install_bash_aliases
                        _install_zsh_aliases
                        ;;
                    4) echo "Skipping aliases installation." ;;
                    *) echo "Invalid choice, skipping aliases." ;;
                    esac
                else
                    echo "Skipping aliases installation."
                fi
            fi
        fi
    fi

    if wants_section global; then
        echo ""
        echo "PATH Installation"
        local path_already_ok=false
        if command -v opencode-dockerized >/dev/null 2>&1; then
            path_already_ok=true
        fi
        if [ -L "$HOME/.local/bin/opencode-dockerized" ]; then
            rm -f "$HOME/.local/bin/opencode-dockerized" 2>/dev/null || true
            echo "Removed legacy symlink ~/.local/bin/opencode-dockerized"
        elif [ -e "$HOME/.local/bin/opencode-dockerized" ]; then
            echo "$HOME/.local/bin/opencode-dockerized exists and is not a symlink; left untouched (remove it manually)"
        fi
        # Obsolete second binary: bin/ holds only opencode-dockerized now.
        if [ -e "$OCODE_BIN_DIR/install" ]; then
            rm -f "$OCODE_BIN_DIR/install" 2>/dev/null || true
            echo "Removed obsolete $OCODE_BIN_DIR/install (use 'opencode-dockerized install')"
        fi
        if [ "$path_already_ok" = true ]; then
            echo "Already on PATH: $(command -v opencode-dockerized)"
            local rc
            for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
                [ -f "$rc" ] || continue
                if ensure_path_in_rc "$rc"; then
                    echo "Added opencode-dockerized/bin to PATH in $rc"
                fi
            done
        else
            echo "Put this checkout's bin/ on PATH so 'opencode-dockerized' works anywhere."
            echo "No symlink, stub or copy is created in ~/.local/bin."
            local install_global=""
            if [ "$SETUP_YES" = true ]; then
                echo "Non-interactive defaults: adding to PATH."
                install_global="y"
            else
                read -r -p "Add to PATH? (y/n): " install_global || install_global=""
            fi
            if [[ "$install_global" =~ ^[Yy]$ ]]; then
                local bin_target="$REPO_ROOT/bin/opencode-dockerized"
                if [ ! -x "$bin_target" ] && ! chmod +x "$bin_target" 2>/dev/null; then
                    echo "Could not make $bin_target executable"
                fi
                local added_to_rc=false rc_file
                for rc_file in "$HOME/.zshrc" "$HOME/.bashrc"; do
                    [ -f "$rc_file" ] || continue
                    if ensure_path_in_rc "$rc_file"; then
                        echo "Added opencode-dockerized/bin to PATH in $rc_file"
                        added_to_rc=true
                    fi
                done
                if [ "$added_to_rc" = true ]; then
                    echo "  Restart your shell or run: source ~/.bashrc (or ~/.zshrc)"
                else
                    echo "  Add this to your shell rc file:"
                    echo "    $OCODE_BIN_PATH_LINE"
                fi
                echo ""
                echo "  You can now run 'opencode-dockerized' from any directory:"
                echo "    opencode-dockerized run"
                echo "    opencode-dockerized build"
                echo "    opencode-dockerized auth"
            else
                echo "Skipping PATH installation."
                echo "  You can always run it directly: $REPO_ROOT/bin/opencode-dockerized"
            fi
        fi
        if [ "$(readlink -f "$REPO_ROOT")" != "$(readlink -f "$OCODE_INSTALL_DIR")" ] && [ -d "$OCODE_INSTALL_DIR/.git" ]; then
            echo "Note: running from $REPO_ROOT (canonical: $OCODE_INSTALL_DIR)"
        fi
    fi

    if wants_section build; then
        echo ""
        echo "Docker Image"
        if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
            echo "Docker is not running; skipping build (run 'opencode-dockerized build' later)"
        else
            local build_answer=""
            if [ "$SETUP_YES" = true ]; then
                build_answer="y"
            else
                read -r -p "Build the Docker image now? (Y/n): " build_answer || build_answer=""
                build_answer="${build_answer:-y}"
            fi
            if [[ "$build_answer" =~ ^[Yy]$ ]]; then
                docker build -t "opencode-dockerized:latest" "$REPO_ROOT" || echo "Build failed; run 'opencode-dockerized build' later"
            else
                echo "Skipping build (run 'opencode-dockerized build' later)."
            fi
        fi
    fi

    echo ""
    echo "Install complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Build the Docker image:"
    echo "     opencode-dockerized build"
    echo ""
    echo "  2. Authenticate with your LLM provider (no local OpenCode needed!):"
    echo "     opencode-dockerized auth"
    echo ""
    echo "  3. Run OpenCode in your project:"
    echo "     opencode-dockerized run /path/to/your/project"
    echo ""
    return 0
}
