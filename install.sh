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
#                           (signed tag when OCODE_REF is a tag, else the target
#                           commit); checked BEFORE the checkout moves
#   OCD_SIGNING_FINGERPRINTS space-separated key fingerprints to pin (recommended
#                           with OCD_VERIFY_SIGNATURES): only signatures from these
#                           keys are trusted, not any key in your keyring
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

# Uppercase a fingerprint for comparison. Usage: upper <text>
upper() { tr '[:lower:]' '[:upper:]' <<<"$1"; }

# True when one of the words in "$2" is a pinned fingerprint (OCD_SIGNING_FINGERPRINTS).
# Usage: fingerprint_pinned <pins> <candidate fingerprints...>
fingerprint_pinned() {
    local pins="$1" pin candidate
    shift
    for pin in $pins; do
        for candidate in "$@"; do
            [ -n "$candidate" ] && [ "$(upper "$pin")" = "$(upper "$candidate")" ] && return 0
        done
    done
    return 1
}

# True when commit <rev> carries a trusted signature: any valid signature from
# the keyring, or with OCD_SIGNING_FINGERPRINTS a good one (%G? G, or U: good
# but key validity unset, which the pin replaces) from a pinned key (%GF signing
# key or %GP primary key). Mirrors commit_signature_trusted in the wrapper.
# Usage: commit_trusted <dir> <rev>
commit_trusted() {
    local dir="$1" rev="$2" pins="${OCD_SIGNING_FINGERPRINTS:-}" info status
    if [ -z "$pins" ]; then
        git -C "$dir" verify-commit "$rev" >/dev/null 2>&1
        return
    fi
    info=$(git -C "$dir" log -1 --format='%G?%n%GF%n%GP' "$rev" 2>/dev/null) || return 1
    status=$(sed -n 1p <<<"$info")
    case "$status" in G | U) ;; *) return 1 ;; esac
    fingerprint_pinned "$pins" "$(sed -n 2p <<<"$info")" "$(sed -n 3p <<<"$info")"
}

# True when tag <tag> carries a trusted signature (see commit_trusted). With
# pins, the signing/primary fingerprints come from the GnuPG status lines
# (VALIDSIG) or, for SSH signatures, the SHA256: key fingerprint.
# Usage: tag_trusted <dir> <tag>
tag_trusted() {
    local dir="$1" tag="$2" pins="${OCD_SIGNING_FINGERPRINTS:-}" raw
    raw=$(git -C "$dir" verify-tag --raw "$tag" 2>&1) || return 1
    [ -n "$pins" ] || return 0
    # shellcheck disable=SC2046 # one word per fingerprint
    fingerprint_pinned "$pins" $(awk '$2 == "VALIDSIG" { print $3; print $NF }' <<<"$raw") \
        $(grep -oE 'SHA256:[A-Za-z0-9+/=]+' <<<"$raw" || true)
}

# True when OCD_VERIFY_SIGNATURES=true and <rev> (or the signed tag <tag>) is
# not trusted. Always called BEFORE the checkout moves to <rev>.
# Usage: signature_rejected <dir> <rev> [tag]
signature_rejected() {
    [ "${OCD_VERIFY_SIGNATURES:-false}" = true ] || return 1
    if [ -n "${3:-}" ]; then
        tag_trusted "$1" "$3" && return 1
    else
        commit_trusted "$1" "$2" && return 1
    fi
    return 0
}

# Name of <ref> when it is a tag in <dir>, else empty. Usage: tag_name <dir> <ref>
tag_name() {
    if [ -n "$2" ] && git -C "$1" rev-parse --verify -q "refs/tags/$2" >/dev/null 2>&1; then
        printf '%s\n' "$2"
    fi
}

# Fresh clone, optionally pinned to a ref, verified when requested. The clone
# is made without a working tree, so nothing unverified is ever checked out.
# Usage: clone_checkout <repo_url> <install_dir> <ref>
clone_checkout() {
    local repo_url="$1" install_dir="$2" ref="$3" head
    local -a clone_args=(--no-checkout)
    [ -n "$ref" ] && clone_args+=(--branch "$ref")
    echo "Cloning opencode-dockerized into $install_dir ..."
    git clone "${clone_args[@]}" "$repo_url" "$install_dir"
    head=$(git -C "$install_dir" rev-parse HEAD)
    if signature_rejected "$install_dir" "$head" "$(tag_name "$install_dir" "$ref")"; then
        rm -rf "$install_dir"
        install_die "signature verification failed (OCD_VERIFY_SIGNATURES=true); the checkout was removed"
    fi
    git -C "$install_dir" reset -q --hard "$head" ||
        install_die "could not check out $head in $install_dir"
}

# Move a reused checkout to OCODE_REF: a branch follows origin/<ref> (created
# as a tracking branch, or fast-forwarded), a tag or commit is checked out
# detached. The final commit is verified before anything moves.
# Usage: switch_to_ref <install_dir> <ref>
switch_to_ref() {
    local install_dir="$1" ref="$2" target tag local_rev
    if git -C "$install_dir" rev-parse --verify -q "refs/remotes/origin/$ref" >/dev/null 2>&1; then
        target=$(git -C "$install_dir" rev-parse "refs/remotes/origin/$ref")
        if local_rev=$(git -C "$install_dir" rev-parse --verify -q "refs/heads/$ref" 2>/dev/null) &&
            ! git -C "$install_dir" merge-base --is-ancestor "$local_rev" "$target" 2>/dev/null; then
            install_warn "local branch $ref has commits not on origin/$ref; installing it as is"
            target="$local_rev"
        fi
        signature_rejected "$install_dir" "$target" &&
            install_die "signature verification failed (OCD_VERIFY_SIGNATURES=true) for $ref ($target); checkout unchanged"
        git -C "$install_dir" checkout -q -B "$ref" "$target" 2>/dev/null ||
            install_die "could not check out $ref in $install_dir"
        git -C "$install_dir" branch -q --set-upstream-to="origin/$ref" "$ref" >/dev/null 2>&1 ||
            install_warn "could not set upstream tracking for $ref"
        return 0
    fi
    target=$(git -C "$install_dir" rev-parse --verify -q "$ref^{commit}" 2>/dev/null) ||
        install_die "unknown ref $ref in $install_dir (not a branch on origin, tag or commit)"
    tag=$(tag_name "$install_dir" "$ref")
    signature_rejected "$install_dir" "$target" "$tag" &&
        install_die "signature verification failed (OCD_VERIFY_SIGNATURES=true) for $ref; checkout unchanged"
    git -C "$install_dir" checkout -q "$target" 2>/dev/null ||
        install_die "could not check out $ref in $install_dir"
}

# Fast-forward the current branch to its upstream, verifying the upstream head
# first. A checkout that is up to date or diverged keeps (and verifies) HEAD.
# Usage: follow_upstream <install_dir>
follow_upstream() {
    local install_dir="$1" local_rev remote_rev base
    local_rev=$(git -C "$install_dir" rev-parse HEAD 2>/dev/null || true)
    remote_rev=$(git -C "$install_dir" rev-parse '@{u}' 2>/dev/null || true)
    base=$(git -C "$install_dir" merge-base HEAD '@{u}' 2>/dev/null || true)
    if [ -n "$remote_rev" ] && [ "$local_rev" != "$remote_rev" ] && [ "$local_rev" = "$base" ]; then
        signature_rejected "$install_dir" "$remote_rev" &&
            install_die "signature verification failed (OCD_VERIFY_SIGNATURES=true) for upstream ${remote_rev:0:12}; checkout unchanged"
        git -C "$install_dir" merge --ff-only "$remote_rev" >/dev/null 2>&1 ||
            install_warn "could not fast-forward $install_dir; installing the existing checkout"
        return 0
    fi
    if [ -n "$remote_rev" ] && [ "$local_rev" != "$remote_rev" ]; then
        install_warn "$install_dir has local commits or diverged from upstream; not updated"
    fi
    if signature_rejected "$install_dir" HEAD; then
        install_die "signature verification failed (OCD_VERIFY_SIGNATURES=true) for $install_dir"
    fi
}

# Bring a reused checkout up to date without ever hiding a failure.
# Usage: refresh_checkout <install_dir> <ref>
refresh_checkout() {
    local install_dir="$1" ref="$2" branch

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
        if signature_rejected "$install_dir" HEAD "$(tag_name "$install_dir" "$ref")"; then
            install_die "signature verification failed (OCD_VERIFY_SIGNATURES=true) for $install_dir"
        fi
        return 0
    fi

    if [ -n "$ref" ]; then
        switch_to_ref "$install_dir" "$ref"
    else
        follow_upstream "$install_dir"
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
