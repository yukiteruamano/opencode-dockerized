#!/bin/bash

# Alternative simple runner for OpenCode Docker.
# Delegates to bin/opencode-dockerized so there is a single code path.

set -e

ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
IMAGE_NAME="opencode-dockerized:latest"

# Source the shared config module (provides colors, logging, config functions)
# shellcheck source=lib/config-lib.sh
source "$ROOT/lib/config-lib.sh"

# Refuse to run as root: the wrapper maps the invoking user into the container,
# and building the image as root would create root-owned layers.
if [ "$(id -u)" -eq 0 ]; then
    config_error "Do not run this script as root."
    exit 1
fi

# Show help if requested
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "help" ]; then
    cat << EOF
OpenCode Docker Simple Runner

Usage: $(basename "$0") [DIR]

Runs OpenCode in a Docker container with a simplified setup.
Delegates to 'opencode-dockerized run', so it shares the full feature set.

Arguments:
    DIR     Project directory to mount (default: current directory)

Options:
    --help, -h    Show this help message

For the full command set, use opencode-dockerized instead.
EOF
    exit 0
fi

# Get project directory (default to current directory)
PROJECT_DIR="${1:-$(pwd)}"

# Validate project directory exists
if [ ! -d "$PROJECT_DIR" ]; then
    config_error "Project directory does not exist: $PROJECT_DIR"
    exit 1
fi

PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd -P)"

# Build the image if it doesn't exist (the main runner expects it to exist)
if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    config_info "Docker image not found, building..."
    docker build -t "$IMAGE_NAME" "$ROOT"
fi

# Single code path: hand off to the main runner
exec "$ROOT/bin/opencode-dockerized" run "$PROJECT_DIR"
