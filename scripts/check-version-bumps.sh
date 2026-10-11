#!/bin/bash
# Fail when files that define the security layer changed without bumping the
# marker installs use to notice the change (CI runs this on pull requests):
#   plugins/security-guard.js        -> OPENCODE_DOCKERIZED_GUARD_VERSION=<n>
#   policies/*-patterns.json         -> policies/VERSION
# Usage: scripts/check-version-bumps.sh <base-ref>
set -euo pipefail

base="${1:?usage: check-version-bumps.sh <base-ref>}"
changed="$(git diff --name-only "$base" HEAD)"
status=0

guard_marker() { grep -oE 'OPENCODE_DOCKERIZED_GUARD_VERSION=[0-9]+' | head -n 1 || true; }

if grep -qx 'plugins/security-guard.js' <<<"$changed"; then
    old="$(git show "$base:plugins/security-guard.js" 2>/dev/null | guard_marker)"
    new="$(guard_marker <plugins/security-guard.js)"
    if [ -n "$old" ] && [ "$old" = "$new" ]; then
        echo "plugins/security-guard.js changed but still says $new: bump OPENCODE_DOCKERIZED_GUARD_VERSION so installs refresh." >&2
        status=1
    fi
fi

if grep -qE '^policies/[a-z-]+-patterns\.json$' <<<"$changed"; then
    old="$(git show "$base:policies/VERSION" 2>/dev/null || true)"
    new="$(cat policies/VERSION)"
    if [ "$old" = "$new" ]; then
        echo "policies/*-patterns.json changed but policies/VERSION is still $new: bump it (and policies/SHA256SUMS, SOURCE.json)." >&2
        status=1
    fi
fi

exit "$status"
