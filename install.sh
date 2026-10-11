#!/bin/bash
# Bootstrap installer: clone (or reuse) the self-contained checkout at
# ${XDG_DATA_HOME:-$HOME/.local/share}/opencode-dockerized, then run the
# built-in `opencode-dockerized install` wizard. bin/ holds only the
# `opencode-dockerized` binary; there is no second `install` binary.
# Doom-style one-liner (does everything: download, config, PATH, completions,
# aliases — no second manual install needed):
#   curl -fsSL https://raw.githubusercontent.com/yukiteruamano/opencode-dockerized/master/install.sh | bash
#   curl -fsSL .../install.sh | bash -s -- --yes --only config,completions,aliases,global
#
# Environment:
#   OCODE_REPO_URL          source repository (default: the GitHub repo)
#   OCODE_INSTALL_DIR       target checkout (default: $XDG_DATA_HOME/opencode-dockerized)
#   OCODE_REF               branch or tag to install (default: the remote's default branch)
#   OCD_VERIFY_SIGNATURES   true = refuse a checkout whose signature does not verify
#                           (signed tag when OCODE_REF is a tag, else the HEAD commit)
#
# Inspect before running if you prefer: download the script, read it, then run it.
set -euo pipefail

# Everything lives in functions and the only top-level statement is the final
# `main "$@"`: bash must read the whole file before running anything, so a
# truncated `curl | bash` download executes nothing.

install_warn() { echo "warning: $1" >&2; }
install_die() {
    echo "error: $1" >&2
    exit 1
}

# True when OCD_VERIFY_SIGNATURES=true and the checkout at $1 does not verify.
# Usage: signature_rejected <dir> <ref>
signature_rejected() {
    [ "${OCD_VERIFY_SIGNATURES:-false}" = true ] || return 1
    if [ -n "$2" ] && git -C "$1" rev-parse --verify -q "refs/tags/$2" >/dev/null 2>&1; then
        git -C "$1" verify-tag "$2" >/dev/null 2>&1 && return 1
    else
        git -C "$1" verify-commit HEAD >/dev/null 2>&1 && return 1
    fi
    return 0
}

# Fresh clone, optionally pinned to a ref, verified when requested.
# Usage: clone_checkout <repo_url> <install_dir> <ref>
clone_checkout() {
    local repo_url="$1" install_dir="$2" ref="$3"
    local -a clone_args=()
    [ -n "$ref" ] && clone_args=(--branch "$ref")
    echo "Cloning opencode-dockerized into $install_dir ..."
    git clone ${clone_args[@]+"${clone_args[@]}"} "$repo_url" "$install_dir"
    if signature_rejected "$install_dir" "$ref"; then
        rm -rf "$install_dir"
        install_die "signature verification failed (OCD_VERIFY_SIGNATURES=true); the checkout was removed"
    fi
}

# Bring a reused checkout up to date without ever hiding a failure.
# Usage: refresh_checkout <install_dir> <ref>
refresh_checkout() {
    local install_dir="$1" ref="$2" branch local_rev remote_rev base

    # Manual checkouts (init + remote add) lack @{u}, which breaks
    # `update`/`upgrade`: set it when origin/<branch> exists.
    branch=$(git -C "$install_dir" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
    if [ -n "$branch" ] && [ "$branch" != "HEAD" ] &&
        ! git -C "$install_dir" rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1 &&
        git -C "$install_dir" rev-parse --verify "refs/remotes/origin/$branch" >/dev/null 2>&1; then
        if git -C "$install_dir" branch --set-upstream-to="origin/$branch" "$branch" >/dev/null 2>&1; then
            echo "Tracking upstream: $branch -> origin/$branch (self-update enabled)"
        else
            install_warn "could not set upstream tracking in $install_dir"
        fi
    fi

    if ! git -C "$install_dir" fetch --tags origin >/dev/null 2>&1; then
        install_warn "could not fetch from origin; installing the existing checkout (offline?)"
        return 0
    fi

    if [ -n "$ref" ]; then
        git -C "$install_dir" checkout -q "$ref" 2>/dev/null ||
            install_die "could not check out $ref in $install_dir"
    else
        local_rev=$(git -C "$install_dir" rev-parse HEAD 2>/dev/null || true)
        remote_rev=$(git -C "$install_dir" rev-parse '@{u}' 2>/dev/null || true)
        base=$(git -C "$install_dir" merge-base HEAD '@{u}' 2>/dev/null || true)
        if [ -z "$remote_rev" ] || [ "$local_rev" = "$remote_rev" ]; then
            :
        elif [ "$local_rev" = "$base" ]; then
            git -C "$install_dir" merge --ff-only "$remote_rev" >/dev/null 2>&1 ||
                install_warn "could not fast-forward $install_dir; installing the existing checkout"
        else
            install_warn "$install_dir has local commits or diverged from upstream; not updated"
        fi
    fi

    if signature_rejected "$install_dir" "$ref"; then
        install_die "signature verification failed (OCD_VERIFY_SIGNATURES=true) for $install_dir"
    fi
}

main() {
    local repo_url="${OCODE_REPO_URL:-https://github.com/yukiteruamano/opencode-dockerized.git}"
    local install_dir="${OCODE_INSTALL_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/opencode-dockerized}"
    local ref="${OCODE_REF:-}"

    # Forwarded install args. A piped `curl | bash` has no TTY for prompts, so
    # default to --yes (full setup) unless the caller already passed --yes or
    # asks for help. Explicit `bash -s -- --yes ...` keeps working.
    local -a forward_args=("$@")
    local has_yes=false has_help=false arg
    for arg in "$@"; do
        case "$arg" in
        --yes) has_yes=true ;;
        -h | --help) has_help=true ;;
        esac
    done
    if [ "$has_help" = false ] && [ "$has_yes" = false ] && [ ! -t 0 ]; then
        forward_args=(--yes "$@")
    fi

    # Running from a local checkout (./install.sh): use it directly, no cloning.
    # When piped via curl BASH_SOURCE is empty/a pipe, so skip this branch.
    local script_src="${BASH_SOURCE[0]:-}" own_root=""
    if [ -n "$script_src" ] && [ -f "$script_src" ]; then
        own_root="$(cd "$(dirname "$(readlink -f "$script_src")")" && pwd)"
    fi
    if [ -n "$own_root" ] && [ -x "$own_root/bin/opencode-dockerized" ]; then
        exec "$own_root/bin/opencode-dockerized" install ${forward_args[@]+"${forward_args[@]}"}
    fi

    command -v git >/dev/null 2>&1 || install_die "git is required to install opencode-dockerized"
    if [ -d "$install_dir" ] && [ ! -d "$install_dir/.git" ]; then
        install_die "$install_dir exists and is not a git checkout (remove it or set OCODE_INSTALL_DIR)"
    fi

    if [ ! -d "$install_dir" ]; then
        clone_checkout "$repo_url" "$install_dir" "$ref"
    else
        refresh_checkout "$install_dir" "$ref"
    fi

    [ -x "$install_dir/bin/opencode-dockerized" ] ||
        install_die "$install_dir/bin/opencode-dockerized not found or not executable"

    echo "Installing opencode-dockerized $(git -C "$install_dir" rev-parse --short HEAD) from $install_dir"
    exec "$install_dir/bin/opencode-dockerized" install ${forward_args[@]+"${forward_args[@]}"}
}

main "$@"
