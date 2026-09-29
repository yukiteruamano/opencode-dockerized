#!/bin/bash
# Compat shim: setup.sh moved to `opencode-dockerized install` (lib/install-lib.sh).
set -e
ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
echo "setup.sh is deprecated; use 'opencode-dockerized install'" >&2
exec "$ROOT/bin/opencode-dockerized" install "$@"
