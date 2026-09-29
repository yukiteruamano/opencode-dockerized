#!/bin/bash
# Compat shim: the binary moved to bin/opencode-dockerized (no symlink in ~/.local/bin).
set -e
ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
echo "opencode-dockerized.sh is deprecated; use 'opencode-dockerized' on PATH (bin/opencode-dockerized)" >&2
exec "$ROOT/bin/opencode-dockerized" "$@"
