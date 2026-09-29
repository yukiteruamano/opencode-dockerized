# Use Debian slim as lightweight Linux base
# Note: We only install Docker CLI to use host's Docker daemon via mounted socket
FROM debian:trixie-slim

# Fail fast inside RUN pipelines (curl | sh, | tee, …)
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Parameterize tool versions for easier updates
ARG NVM_VERSION=v0.40.8
ARG PNPM_VERSION=12.5.1
# OpenCode CLI release; override with --build-arg OPENCODE_VERSION=x.y.z
ARG OPENCODE_VERSION=latest

# Install base dependencies and useful CLI tools for coding agents
RUN apt-get update && apt-get install -y \
    git \
    curl \
    bash \
    ca-certificates \
    zip \
    unzip \
    wget \
    gnupg \
    lsb-release \
    apt-transport-https \
    ripgrep \
    fd-find \
    jq \
    tree \
    less \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI only (uses host Docker daemon via mounted socket)
# We don't need docker-ce (daemon) or containerd.io since we use the host's Docker
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc && \
    chmod a+r /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y docker-ce-cli docker-buildx-plugin docker-compose-plugin && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
# Note: Docker socket group membership is granted at run time by the wrapper
# (config-lib.sh) with `--group-add <socket GID>`; the entrypoint never runs as
# root and does not edit /etc/group.
# There is intentionally no sudo: the agent must never gain root, so neither a
# sudoers entry nor the sudo binary (a setuid-root vector) is installed.
RUN useradd -m -s /bin/bash -u 1000 coder

# Install NVM and Node.js LTS as coder user
USER coder
WORKDIR /home/coder
ENV NVM_DIR="/home/coder/.nvm"
RUN curl -o- "https://raw.githubusercontent.com/nvm-sh/nvm/${NVM_VERSION}/install.sh" | bash && \
    bash -c "source $NVM_DIR/nvm.sh && \
    nvm install --lts && \
    nvm alias default node && \
    nvm use default && \
    ln -sf \$(dirname \$(which node)) $NVM_DIR/default"

# Install uv (Python package manager) as coder user
# See: https://docs.astral.sh/uv/getting-started/installation/
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Install pnpm via the official standalone installer (native binary, no Node needed)
# The script installs to $PNPM_HOME (default: ~/.local/share/pnpm) and appends a
# PATH snippet to ~/.bashrc; we wire PATH via ENV below so it works non-interactively.
# PNPM_VERSION pins the installed release (override with --build-arg PNPM_VERSION=x.y.z).
# SHELL/ENV must be set explicitly in Docker builds (documented by pnpm.io) because
# the installer cannot infer the shell and otherwise fails with ERR_PNPM_UNKNOWN_SHELL.
# See: https://pnpm.io/installation (sections "POSIX systems", "In a Docker container",
# "Installing a specific version")
ENV PNPM_HOME="/home/coder/.local/share/pnpm"
RUN curl -fsSL https://get.pnpm.io/install.sh | env PNPM_VERSION="${PNPM_VERSION}" ENV="$HOME/.bashrc" SHELL="$(which bash)" sh - && "$PNPM_HOME/bin/pnpm" --version

# Add pnpm, nvm, node, uv, ~/.composio and ~/.local/bin to PATH
# Node.js is available via the NVM default symlink created above.
# ~/.local/bin holds user-installed CLIs (uv tools, pipx apps).
# ~/.composio holds the Composio CLI and its login, mounted read-write from the
# host via mount.composio in the wrapper config, so `composio` resolves on PATH.
ENV PATH="$PNPM_HOME/bin:$NVM_DIR/default:/home/coder/.composio:/home/coder/.local/bin:$PATH"

# Install OpenCode V2 globally with pnpm
# The package postinstall selects the native binary for the platform and refuses
# to run without it, so --allow-build is required (pnpm blocks scripts by default)
# ARG OPENCODE_BUILD_TIME is only passed during 'update' to bust cache
# ARG OPENCODE_VERSION pins the release; defaults to latest for regular builds
ARG OPENCODE_BUILD_TIME=0
RUN pnpm add -g @opencode/cli@"${OPENCODE_VERSION}" --allow-build=@opencode/cli && opencode --version

# Create the writable home tree, owned by coder and group-writable (g+rwX) so
# the wrapper can grant any host UID access with `--group-add coder` (a name
# resolved against the container's /etc/group, hence gid 1000). Runs as coder:
# it owns the tree, so no root step is needed and the image stays non-root.
RUN mkdir -p /home/coder/.config/opencode && \
    mkdir -p /home/coder/.local/bin && \
    mkdir -p /home/coder/.local/share/opencode && \
    mkdir -p /home/coder/.local/state/opencode && \
    mkdir -p /home/coder/.cache/opencode && \
    mkdir -p /home/coder/.npm && \
    chown -R coder:coder /home/coder && \
    chmod -R g+rwX /home/coder

# Default working directory; entrypoint.sh cd's into the project (OPENCODE_WORKDIR,
# falling back to the Docker --workdir set by the wrapper).
WORKDIR /

# Copy entrypoint script. COPY is not subject to USER (files are created
# root-owned) and preserves the source mode, and entrypoint.sh is committed as
# 0755, so no root step and no chmod are required. The script stays root-owned
# in root-owned /usr/local/bin, so the runtime user cannot modify it.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# entrypoint.sh performs no privilege changes.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Default command is to run opencode
CMD ["opencode"]
