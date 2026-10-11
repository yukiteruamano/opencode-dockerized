#!/bin/bash
# Report which pinned inputs of the Dockerfile have a newer release, and print the
# sha256 of the newer installers so a bump is a reviewed copy-paste, not a guess.
# Read-only: it never edits the Dockerfile. Needs network access and curl; python3
# is used only to read JSON.
#
# Usage: scripts/pins-report.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
DOCKERFILE="$ROOT/Dockerfile"
work="$(mktemp -d)"
trap 'rm -r "$work" 2>/dev/null || true' EXIT

arg() { sed -n "s/^ARG $1=\(.*\)$/\1/p" "$DOCKERFILE" | head -n 1; }
fetch() { curl -fsSL --max-time 30 "$@"; }
json_field() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d}))' "$1"; }
sha256_of() { sha256sum "$1" | cut -d' ' -f1; }

changes=0
# Usage: report <name> <current> <latest> [note]
report() {
    if [ -z "$3" ]; then
        printf '%-14s %-34s (could not resolve the latest)\n' "$1" "$2"
    elif [ "$2" = "$3" ]; then
        printf '%-14s %-34s up to date\n' "$1" "$2"
    else
        printf '%-14s %-34s -> %s %s\n' "$1" "$2" "$3" "${4:-}"
        changes=$((changes + 1))
    fi
}

echo "Pinned inputs of $DOCKERFILE"
echo

# Base image digest
token="$(fetch "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/debian:pull" | json_field 'd["token"]' 2>/dev/null || true)"
latest_digest=""
if [ -n "$token" ]; then
    latest_digest="$(curl -fsSI --max-time 30 -H "Authorization: Bearer $token" \
        -H "Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json" \
        https://registry-1.docker.io/v2/library/debian/manifests/trixie-slim 2>/dev/null |
        tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: //p' || true)"
fi
current_digest="$(sed -n 's/^FROM debian:trixie-slim@\(sha256:[0-9a-f]*\)$/\1/p' "$DOCKERFILE")"
report "base image" "${current_digest:0:26}…" "${latest_digest:+${latest_digest:0:26}…}" "(update the FROM digest)"

# Node.js LTS
latest_node="$(fetch https://nodejs.org/dist/index.json | python3 -c 'import json,sys; print(next(x["version"] for x in json.load(sys.stdin) if x["lts"]).lstrip("v"))' 2>/dev/null || true)"
report "node (LTS)" "$(arg NODE_VERSION)" "$latest_node" "(ARG NODE_VERSION)"

# OpenCode and pnpm from the npm registry
latest_oc="$(fetch https://registry.npmjs.org/@opencode/cli/latest | json_field 'd["version"]' 2>/dev/null || true)"
report "opencode" "$(arg OPENCODE_VERSION)" "$latest_oc" "(ARG OPENCODE_VERSION)"
latest_pnpm="$(fetch https://registry.npmjs.org/pnpm/latest | json_field 'd["version"]' 2>/dev/null || true)"
report "pnpm" "$(arg PNPM_VERSION)" "$latest_pnpm" "(ARG PNPM_VERSION)"

# nvm and uv from GitHub releases
latest_nvm="$(fetch https://api.github.com/repos/nvm-sh/nvm/releases/latest | json_field 'd["tag_name"]' 2>/dev/null || true)"
report "nvm" "$(arg NVM_VERSION)" "$latest_nvm" "(ARG NVM_VERSION + NVM_INSTALL_SHA256)"
latest_uv="$(fetch https://api.github.com/repos/astral-sh/uv/releases/latest | json_field 'd["tag_name"]' 2>/dev/null || true)"
report "uv" "$(arg UV_VERSION)" "$latest_uv" "(ARG UV_VERSION + UV_INSTALL_SHA256)"

# Docker CLI packages (identical versions for amd64 and arm64)
if fetch https://download.docker.com/linux/debian/dists/trixie/stable/binary-amd64/Packages -o "$work/Packages" 2>/dev/null; then
    for pair in docker-ce-cli:DOCKER_CLI_VERSION docker-buildx-plugin:DOCKER_BUILDX_VERSION docker-compose-plugin:DOCKER_COMPOSE_VERSION; do
        pkg="${pair%%:*}"
        latest_pkg="$(awk -v p="$pkg" '$1=="Package:"{cur=$2} $1=="Version:" && cur==p{v=$2} END{print v}' "$work/Packages")"
        report "$pkg" "$(arg "${pair##*:}")" "$latest_pkg" "(ARG ${pair##*:})"
    done
fi

# Installer hashes for the pinned versions, and for the newer ones when they differ.
echo
echo "Installer sha256 (paste into the matching *_INSTALL_SHA256 ARG after reviewing the script):"
hash_installer() {
    local label="$1" url="$2" pinned="$3" file="$work/$1.sh" actual
    if ! fetch "$url" -o "$file" 2>/dev/null; then
        printf '  %-18s could not download %s\n' "$label" "$url"
        return 0
    fi
    actual="$(sha256_of "$file")"
    if [ "$actual" = "$pinned" ]; then
        printf '  %-18s %s (matches the pin)\n' "$label" "$actual"
    else
        printf '  %-18s %s (PIN MISMATCH: pinned %s)\n' "$label" "$actual" "${pinned:0:16}…"
        changes=$((changes + 1))
    fi
}
hash_installer "nvm $(arg NVM_VERSION)" "https://raw.githubusercontent.com/nvm-sh/nvm/$(arg NVM_VERSION)/install.sh" "$(arg NVM_INSTALL_SHA256)"
hash_installer "uv $(arg UV_VERSION)" "https://astral.sh/uv/$(arg UV_VERSION)/install.sh" "$(arg UV_INSTALL_SHA256)"
hash_installer "pnpm (get.pnpm.io)" "https://get.pnpm.io/install.sh" "$(arg PNPM_INSTALL_SHA256)"
if [ -n "$latest_nvm" ] && [ "$latest_nvm" != "$(arg NVM_VERSION)" ]; then
    hash_installer "nvm $latest_nvm" "https://raw.githubusercontent.com/nvm-sh/nvm/$latest_nvm/install.sh" ""
fi
if [ -n "$latest_uv" ] && [ "$latest_uv" != "$(arg UV_VERSION)" ]; then
    hash_installer "uv $latest_uv" "https://astral.sh/uv/$latest_uv/install.sh" ""
fi

echo
if [ "$changes" -eq 0 ]; then
    echo "Everything is up to date."
else
    echo "$changes item(s) to review. Bump in small commits (chore(deps): ...) and run tests/dockerfile-lint.test.sh."
fi
