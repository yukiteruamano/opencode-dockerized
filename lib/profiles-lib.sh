#!/bin/bash

# profiles-lib.sh - Profile naming and the one-time layout migration for
# opencode-dockerized. Sourced by bin/opencode-dockerized BEFORE config-lib.sh,
# because every state path derives from CONFIG_DIR when config-lib loads.
#
# Layout (base = ~/.config/opencode-dockerized, or $CONFIG_DIR when exported):
#   <base>/profiles/<name>/   one self-contained tree per account: config, env
#                             file, generated permissions, security layer and
#                             the OpenCode home (auth, sessions, state, cache)
#   <base>/profiles/default/  the profile used when none is selected
#   <base>/{.lock,.lock.d,.previous-rev,gnupg-relay}
#                             install-wide state shared by every profile
#
# Releases before profiles kept the default tree directly in <base>. The first
# run of this code moves it into profiles/default (ocd_migrate_legacy_layout).

# NOTE: Do not use "set -e" here — this is a library file sourced by callers.

# Same form as the callers' definitions (literal escapes `echo -e` interprets).
: "${RED:=\033[0;31m}"
: "${GREEN:=\033[0;32m}"
: "${YELLOW:=\033[1;33m}"
: "${BLUE:=\033[0;34m}"
: "${NC:=\033[0m}"

# Honor NO_COLOR / dumb terminals here too: the migration messages print
# before config-lib.sh (which applies the same rule) is loaded.
if [ -n "${NO_COLOR:-}" ] || [ "${TERM:-}" = "dumb" ]; then
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

OCD_DEFAULT_PROFILE="default"

# Entries of <base> that belong to the installation, not to a profile.
OCD_BASE_GLOBAL_ENTRIES=(profiles .lock .lock.d .previous-rev gnupg-relay)

# Staging directory of an in-progress migration (a dot name is never a valid
# profile, so `profile list` and --profile cannot pick it up).
OCD_MIGRATION_STAGE=".default.migrating"

# Seconds to wait for another wrapper holding the install lock (update,
# install, clean) before deferring the migration to a later run. Tests may
# shorten it, but only with OPENCODE_DOCKERIZED_TEST_HOOKS=1.
OCD_MIGRATION_LOCK_WAIT=30
if [ "${OPENCODE_DOCKERIZED_TEST_HOOKS:-}" = 1 ] && [[ "${OCD_TEST_MIGRATION_LOCK_WAIT:-}" =~ ^[0-9]+$ ]]; then
    OCD_MIGRATION_LOCK_WAIT="$OCD_TEST_MIGRATION_LOCK_WAIT"
fi

# Names become path components and container-name parts.
# Usage: ocd_valid_profile_name NAME && ...
ocd_valid_profile_name() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]]
}

_ocd_mig_info() { echo -e "${BLUE}ℹ${NC} $1" >&2; }
_ocd_mig_success() { echo -e "${GREEN}✓${NC} $1" >&2; }
_ocd_mig_warning() { echo -e "${YELLOW}⚠${NC} $1" >&2; }
_ocd_mig_error() { echo -e "${RED}✗${NC} $1" >&2; }

# Physical path of an existing directory (no output when it does not exist).
# Usage: dir=$(_ocd_canon_dir DIR)
_ocd_canon_dir() {
    (cd -P -- "$1" 2>/dev/null && pwd -P)
}

# Fill OCD_LEGACY_ENTRIES with the names in <base> that belong to the old
# default tree: everything except the install-wide entries.
# Usage: _ocd_collect_legacy BASE
_ocd_collect_legacy() {
    local base="$1" entry name global keep
    OCD_LEGACY_ENTRIES=()
    for entry in "$base"/* "$base"/.[!.]* "$base"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        name="${entry##*/}"
        keep=true
        for global in "${OCD_BASE_GLOBAL_ENTRIES[@]}"; do
            if [ "$name" = "$global" ]; then
                keep=false
                break
            fi
        done
        [ "$keep" = true ] && OCD_LEGACY_ENTRIES+=("$name")
    done
}

# True when a wrapper of the old layout still runs a container: its session
# markers (files named after the PID, holding it) live in <base>/sessions.
# Moving the tree under a live session would break its GnuPG mirror cleanup.
# Usage: _ocd_legacy_session_alive BASE && ...
_ocd_legacy_session_alive() {
    local marker pid
    [ -d "$1/sessions" ] || return 1
    for marker in "$1/sessions"/*; do
        [ -f "$marker" ] || continue
        pid=$(cat "$marker" 2>/dev/null || true)
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        [ "$pid" != "$$" ] && kill -0 "$pid" 2>/dev/null && return 0
    done
    return 1
}

# Map a setting.env_file value that points into the old tree (under <base> but
# not under <base>/profiles) to the same file inside DEST, keeping a leading
# `~/` form. Prints the new value; returns 1 when the value needs no change.
# Usage: new=$(_ocd_relocate_env_value VALUE BASE DEST)
_ocd_relocate_env_value() {
    local value="$1" base="$2" dest="$3" expanded tilde=false dir dir_c base_c root candidate rel=""
    expanded="$value"
    case "$value" in
    \~/*)
        expanded="$HOME/${value#\~/}"
        tilde=true
        ;;
    esac
    [[ "$expanded" == /* ]] || return 1
    base_c=$(_ocd_canon_dir "$base")
    dir=$(dirname -- "$expanded")
    dir_c=$(_ocd_canon_dir "$dir")
    # Compare the resolved form (symlinked base or env dir) and the literal one.
    for root in ${base_c:+"$base_c"} "$base"; do
        for candidate in ${dir_c:+"$dir_c/${expanded##*/}"} "$expanded"; do
            case "$candidate" in
            "$root"/profiles | "$root"/profiles/*) return 1 ;;
            "$root"/*)
                rel="${candidate#"$root"/}"
                break 2
                ;;
            esac
        done
    done
    [ -n "$rel" ] || return 1
    local new="$dest/$rel"
    if [ "$tilde" = true ] && [[ "$new" == "$HOME"/* ]]; then
        printf '%s/%s\n' '~' "${new#"$HOME"/}"
    else
        printf '%s\n' "$new"
    fi
}

# Repoint setting.env_file in CONFIG (when it names a file of the old tree) at
# DEST, atomically and keeping the file mode. A no-op when nothing changes, so
# a resumed migration does not rewrite it twice.
# Usage: _ocd_rewrite_env_setting CONFIG BASE DEST
_ocd_rewrite_env_setting() {
    local cfg="$1" base="$2" dest="$3" line key value new tmp changed=false
    [ -f "$cfg" ] || return 0
    tmp=$(mktemp "$cfg.migrate.XXXXXX") || return 1
    cp -p "$cfg" "$tmp" 2>/dev/null || true
    while IFS= read -r line || [ -n "$line" ]; do
        if [[ "$line" == *=* ]]; then
            key="${line%%=*}"
            key="${key#"${key%%[![:space:]]*}"}"
            key="${key%"${key##*[![:space:]]}"}"
            if [ "$key" = "setting.env_file" ]; then
                value="${line#*=}"
                value="${value#"${value%%[![:space:]]*}"}"
                value="${value%"${value##*[![:space:]]}"}"
                if new=$(_ocd_relocate_env_value "$value" "$base" "$dest"); then
                    line="setting.env_file=$new"
                    changed=true
                fi
            fi
        fi
        printf '%s\n' "$line"
    done <"$cfg" >"$tmp" || {
        rm -f "$tmp"
        return 1
    }
    if [ "$changed" = true ]; then
        mv -f "$tmp" "$cfg" || {
            rm -f "$tmp"
            return 1
        }
        _ocd_mig_info "setting.env_file now points at the default profile's copy"
    else
        rm -f "$tmp"
    fi
}

# Take the install lock (the same file update/install/clean use) for the
# migration; released by _ocd_migration_unlock so those commands can take it
# again later in this process. Skipped when a parent already holds it (the
# re-exec after an update pull). Returns 1 on timeout.
# Usage: _ocd_migration_lock BASE
_ocd_migration_lock() {
    OCD_MIGRATION_LOCKED=""
    [ -n "${OCD_LOCK_HELD:-}" ] && return 0
    if command -v flock >/dev/null 2>&1; then
        exec 8>"$1/.lock" || return 1
        if ! flock -w "$OCD_MIGRATION_LOCK_WAIT" 8; then
            exec 8>&-
            return 1
        fi
        OCD_MIGRATION_LOCKED=flock
        return 0
    fi
    local waited=0
    until mkdir "$1/.lock.d" 2>/dev/null; do
        [ "$waited" -ge "$OCD_MIGRATION_LOCK_WAIT" ] && return 1
        sleep 1
        waited=$((waited + 1))
    done
    OCD_MIGRATION_LOCKED="$1/.lock.d"
}

_ocd_migration_unlock() {
    case "${OCD_MIGRATION_LOCKED:-}" in
    "") ;;
    flock) exec 8>&- ;;
    *) rmdir "$OCD_MIGRATION_LOCKED" 2>/dev/null || true ;;
    esac
    OCD_MIGRATION_LOCKED=""
}

# Move the pre-profiles default tree from BASE into BASE/profiles/default.
# Each entry is renamed into a staging dir (same filesystem, so every move is
# atomic), then the staging dir is renamed into place: an interrupted run
# leaves the stage behind and the next run resumes it. Install-wide entries
# stay in BASE.
# Returns 0 (migrated, or nothing to do), 2 (deferred: a session of the old
# layout is running or the install lock is busy; the caller keeps using the
# old tree for this run) or 1 (failed; the caller must not start).
# Usage: ocd_migrate_legacy_layout BASE
ocd_migrate_legacy_layout() {
    local base="$1"
    local dest="$base/profiles/$OCD_DEFAULT_PROFILE" stage="$base/profiles/$OCD_MIGRATION_STAGE"
    [ -d "$base" ] || return 0
    _ocd_collect_legacy "$base"
    [ "${#OCD_LEGACY_ENTRIES[@]}" -eq 0 ] && [ ! -d "$stage" ] && return 0

    if [ -d "$dest" ]; then
        # Never merge into an existing default profile: report the leftovers.
        if [ "${#OCD_LEGACY_ENTRIES[@]}" -gt 0 ]; then
            _ocd_mig_warning "Files from the pre-profiles layout remain in $base (${OCD_LEGACY_ENTRIES[*]}), but $dest already exists, so they are not migrated."
            _ocd_mig_info "Move what you need into $dest (or another profile) and delete the rest from $base."
        fi
        return 0
    fi

    if _ocd_legacy_session_alive "$base"; then
        _ocd_mig_warning "An OpenCode session from the previous layout is still running; the move to profiles/$OCD_DEFAULT_PROFILE is deferred to the next run."
        return 2
    fi
    if ! _ocd_migration_lock "$base"; then
        _ocd_mig_warning "Another opencode-dockerized command holds the install lock; the move to profiles/$OCD_DEFAULT_PROFILE is deferred to the next run."
        return 2
    fi

    # Re-check under the lock: a concurrent run may have finished it.
    _ocd_collect_legacy "$base"
    if [ -d "$dest" ]; then
        _ocd_migration_unlock
        return 0
    fi

    _ocd_mig_info "Migrating your configuration to the profile layout: $base -> $dest"
    if ! mkdir -p "$stage"; then
        _ocd_mig_error "Could not create $stage"
        _ocd_migration_unlock
        return 1
    fi
    chmod 700 "$stage" 2>/dev/null || true

    # Rewrite the env-file setting before the files move (the config may
    # already sit in the stage when resuming).
    local cfg="$base/config"
    [ -f "$stage/config" ] && cfg="$stage/config"
    if ! _ocd_rewrite_env_setting "$cfg" "$base" "$dest"; then
        _ocd_mig_error "Could not update setting.env_file in $cfg"
        _ocd_migration_unlock
        return 1
    fi

    local name
    for name in "${OCD_LEGACY_ENTRIES[@]}"; do
        if [ -e "$stage/$name" ] || [ -L "$stage/$name" ]; then
            _ocd_mig_error "Cannot migrate $base/$name: $stage/$name already exists (from an interrupted migration). Merge or remove one of them, then re-run."
            _ocd_migration_unlock
            return 1
        fi
        if ! mv -- "$base/$name" "$stage/$name"; then
            _ocd_mig_error "Could not move $base/$name into $stage"
            _ocd_migration_unlock
            return 1
        fi
    done
    if ! mv -- "$stage" "$dest"; then
        _ocd_mig_error "Could not move $stage to $dest"
        _ocd_migration_unlock
        return 1
    fi
    _ocd_migration_unlock
    _ocd_mig_success "Configuration migrated to the '$OCD_DEFAULT_PROFILE' profile ($dest)"
    return 0
}
