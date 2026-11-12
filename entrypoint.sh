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

# With GnuPG agent forwarding, give this container a GnuPG home of its own:
# copy the public material from the read-only mirror the wrapper mounts at
# OPENCODE_DOCKERIZED_GNUPG_SEED and link the forwarded host agent socket
# (OPENCODE_DOCKERIZED_GPG_AGENT_SOCK) into it. The mirror is shared by every
# session of a profile; keyboxd's socket and gpg's lock files must not be, or
# one container's exit leaves the others with a dead keyboxd. GNUPGHOME sits on
# the container's own layer (/home/coder is group-writable), so it vanishes
# with the container. Only the files the wrapper mirrors are copied.
seed_gnupg_home() {
    local seed="${OPENCODE_DOCKERIZED_GNUPG_SEED:-}" agent="${OPENCODE_DOCKERIZED_GPG_AGENT_SOCK:-}" f
    [ -n "$seed" ] && [ -d "$seed" ] || return 0
    mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME" || return 1
    for f in pubring.kbx trustdb.gpg sshcontrol common.conf gpg.conf; do
        if [ -f "$seed/$f" ]; then
            cp -- "$seed/$f" "$GNUPGHOME/$f" && chmod 600 "$GNUPGHOME/$f"
        fi
    done
    if [ -f "$seed/public-keys.d/pubring.db" ]; then
        mkdir -p "$GNUPGHOME/public-keys.d" && chmod 700 "$GNUPGHOME/public-keys.d" &&
            cp -- "$seed/public-keys.d/pubring.db" "$GNUPGHOME/public-keys.d/pubring.db" &&
            chmod 600 "$GNUPGHOME/public-keys.d/pubring.db"
    fi
    if [ -n "$agent" ] && [ -S "$agent" ]; then
        ln -sfn "$agent" "$GNUPGHOME/S.gpg-agent"
    fi
}

# Then start this container's keyboxd so gpg can read the public keyring
# (public-keys.d/). The mirrored gpg.conf sets no-autostart, which only blocks
# on-demand autostart, not this explicit launch; the private-key operations
# still go to the host agent via the linked socket.
# Best-effort: never block the container on either step.
if [ -n "${GNUPGHOME:-}" ]; then
    seed_gnupg_home || echo "opencode-dockerized: could not prepare GNUPGHOME ($GNUPGHOME); GnuPG signing may fail" >&2
    if command -v gpgconf >/dev/null 2>&1; then
        gpgconf --launch keyboxd >/dev/null 2>&1 || true
    fi
fi

# cd into the project working directory before executing. The script is single
# quoted so $WORKDIR is expanded by the child bash from the environment, not
# spliced into the command text.
exec bash -c 'source "$NVM_DIR/nvm.sh" && cd "$WORKDIR" && exec "$@"' \
    -- "$@"
