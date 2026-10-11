#!/bin/bash
# Static checks for the image definition. Nothing here needs Docker: it pins the
# supply-chain properties (digest, checksums, key fingerprint, no moving
# versions) and keeps the docs in step with the Dockerfile.
#
# Usage: bash tests/dockerfile-lint.test.sh

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKERFILE="$REPO_DIR/Dockerfile"

fail() {
    echo "FAIL: $1"
    exit 1
}

arg_default() { sed -n "s/^ARG $1=\(.*\)$/\1/p" "$DOCKERFILE" | head -1; }

# Base image: tag AND digest.
grep -qE '^FROM debian:trixie-slim@sha256:[0-9a-f]{64}$' "$DOCKERFILE" ||
    fail "FROM must pin debian:trixie-slim by digest"

# Tool versions are concrete (no `latest`, no empty pins).
for arg in NVM_VERSION NODE_VERSION UV_VERSION PNPM_VERSION OPENCODE_VERSION \
    DOCKER_CLI_VERSION DOCKER_BUILDX_VERSION DOCKER_COMPOSE_VERSION; do
    value="$(arg_default "$arg")"
    [ -n "$value" ] || fail "ARG $arg must have a pinned default"
    [ "$value" != latest ] || fail "ARG $arg must not default to latest"
done

# Every downloaded installer is verified against a pinned sha256 before it runs.
for arg in NVM_INSTALL_SHA256 UV_INSTALL_SHA256 PNPM_INSTALL_SHA256; do
    arg_default "$arg" | grep -qE '^[0-9a-f]{64}$' || fail "ARG $arg must be a sha256"
    grep -q "\${$arg}" "$DOCKERFILE" || fail "ARG $arg is declared but never checked"
done
grep -q 'sha256sum -c' "$DOCKERFILE" || fail "installers must be verified with sha256sum -c"

# No pipe-to-shell of a remote script, and every curl fails on HTTP errors.
if grep -vE '^[[:space:]]*#' "$DOCKERFILE" | grep -nE 'curl[^|]*\|[[:space:]]*(ba)?sh'; then
    fail "never pipe curl into a shell: download, verify, then run"
fi
while IFS= read -r line; do
    case "$line" in
    *curl*) grep -qE 'curl[^|&;]*-[a-zA-Z]*f' <<<"$line" || fail "curl without -f: $line" ;;
    esac
done < <(grep -E '^[^#]*\bcurl +-' "$DOCKERFILE")

# The Docker apt key is checked against its published fingerprint.
arg_default DOCKER_GPG_FINGERPRINT | grep -qE '^[0-9A-F]{40}$' || fail "DOCKER_GPG_FINGERPRINT must be a 40-hex fingerprint"
grep -q '\${DOCKER_GPG_FINGERPRINT}' "$DOCKERFILE" || fail "the Docker key fingerprint must be verified"

# Provenance labels, so the wrapper can detect drift between checkout and image.
for label in org.opencontainers.image.source org.opencontainers.image.revision \
    dev.opencode-dockerized.opencode-version dev.opencode-dockerized.dockerfile-sha256; do
    grep -q "$label" "$DOCKERFILE" || fail "missing image label $label"
done

# Runs as a non-root user and never installs sudo or the daemon.
grep -q '^USER coder' "$DOCKERFILE" || fail "the image must switch to the coder user"
if grep -qE 'apt-get install[^\n]*\b(sudo|docker-ce |containerd)' "$DOCKERFILE"; then
    fail "the image must not install sudo, the Docker daemon or containerd"
fi

# .dockerignore is an allowlist: only what the Dockerfile COPYs enters the context.
first_rule="$(grep -vE '^[[:space:]]*(#|$)' "$REPO_DIR/.dockerignore" | head -1)"
[ "$first_rule" = '*' ] || fail ".dockerignore must start by excluding everything (*)"
for src in $(sed -n 's/^COPY \([^ ]*\) .*/\1/p' "$DOCKERFILE"); do
    grep -qx "!$src" "$REPO_DIR/.dockerignore" || fail ".dockerignore must re-include COPY source $src"
done

# Documentation quotes the Dockerfile's versions (it drifted once: pnpm).
for arg in NVM_VERSION PNPM_VERSION; do
    value="$(arg_default "$arg")"
    grep -q "$arg=$value" "$REPO_DIR/AGENTS.md" || fail "AGENTS.md must quote $arg=$value (as in the Dockerfile)"
done

echo "dockerfile-lint test passed"
