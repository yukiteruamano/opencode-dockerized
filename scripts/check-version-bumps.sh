#!/bin/bash
# Fail when files that define the security layer changed without bumping the
# marker installs use to notice the change (CI runs this on pull requests):
#   plugins/security-guard.js        -> OPENCODE_DOCKERIZED_GUARD_VERSION=<n>
#   policies/*-patterns.json         -> policies/VERSION
# The new marker must exist and be numerically greater than the base one: a
# missing or decreased marker would make installs skip (or never notice) the
# refresh.
# Usage: scripts/check-version-bumps.sh <base-ref>
set -euo pipefail

base="${1:?usage: check-version-bumps.sh <base-ref>}"
changed="$(git diff --name-only "$base" HEAD)"
status=0

guard_marker() { grep -oE 'OPENCODE_DOCKERIZED_GUARD_VERSION=[0-9]+' | head -n 1 | cut -d= -f2 || true; }
policy_marker() { tr -d '[:space:]' | grep -xE '[0-9]+' || true; }

# Usage: check_bump <label> <old> <new> <hint>
check_bump() {
    local label="$1" old="$2" new="$3" hint="$4"
    if [ -z "$new" ]; then
        echo "$label: the version marker is missing or not numeric in the new file. $hint" >&2
        status=1
    elif [ -z "$old" ]; then
        return 0 # newly introduced marker: nothing to compare against
    elif [ "$((10#$new))" -eq "$((10#$old))" ]; then
        echo "$label changed but the version is still $new. $hint" >&2
        status=1
    elif [ "$((10#$new))" -lt "$((10#$old))" ]; then
        echo "$label: the version decreased ($old -> $new); it must only increase. $hint" >&2
        status=1
    fi
}

if grep -qx 'plugins/security-guard.js' <<<"$changed"; then
    old="$(git show "$base:plugins/security-guard.js" 2>/dev/null | guard_marker)"
    new="$( { cat plugins/security-guard.js 2>/dev/null || true; } | guard_marker)"
    check_bump "plugins/security-guard.js" "$old" "$new" \
        "Bump OPENCODE_DOCKERIZED_GUARD_VERSION so installs refresh."
fi

if grep -qE '^policies/([a-z-]+-patterns\.json|VERSION)$' <<<"$changed"; then
    old="$(git show "$base:policies/VERSION" 2>/dev/null | policy_marker)"
    new="$( { cat policies/VERSION 2>/dev/null || true; } | policy_marker)"
    check_bump "policies/*-patterns.json" "$old" "$new" \
        "Bump policies/VERSION (and policies/SHA256SUMS, SOURCE.json)."
fi

exit "$status"
