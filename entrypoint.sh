#!/bin/bash
set -e

# This script runs as a non-root user. There is no privilege dropping and no
# UID/GID remapping: the wrapper starts the container with
# `--user <host uid>:<host gid>`, so every process already runs as the host
# user. Docker socket access is granted at run time with `--group-add`
# (see config-lib.sh), not by editing /etc/group here.

# Resolve the project working directory (set by bin/opencode-dockerized via
# OPENCODE_WORKDIR). Falls back to the container's Docker --workdir ($PWD) so
# one-off CLI commands that only pass --workdir still run in the project.
# Exported (not interpolated into the command string) so paths containing quotes
# or shell metacharacters are safe.
WORKDIR="${OPENCODE_WORKDIR:-$PWD}"
export WORKDIR

# Set HOME explicitly to ensure it points to /home/coder
export HOME=/home/coder
export USER=coder

# Ensure user-installed CLIs are on PATH for OpenCode and every process it
# spawns (e.g. composio installed under ~/.local/bin). Kept explicit here so it
# holds even if the image PATH changes.
export PATH="/home/coder/.local/bin:$PATH"

# Source NVM to make Node.js available
export NVM_DIR="/home/coder/.nvm"

# With GnuPG agent forwarding, start the local keyboxd so gpg can read the
# mirrored public keyring (public-keys.d/). The mirrored gpg.conf sets
# no-autostart, which only blocks on-demand autostart, not this explicit launch;
# the private-key operations still go to the host agent via the mounted socket.
# Best-effort: never block the container on it.
if [ -n "${GNUPGHOME:-}" ] && command -v gpgconf >/dev/null 2>&1; then
    gpgconf --launch keyboxd >/dev/null 2>&1 || true
fi

# cd into the project working directory before executing. The script is single
# quoted so $WORKDIR is expanded by the child bash from the environment, not
# spliced into the command text.
exec bash -c 'source "$NVM_DIR/nvm.sh" && cd "$WORKDIR" && exec "$@"' \
    -- "$@"
