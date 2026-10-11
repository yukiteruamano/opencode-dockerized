# Use Debian slim as lightweight Linux base, pinned by tag AND digest so a
# rebuilt/moved tag cannot change the image under us. To refresh: resolve the new
# digest of debian:trixie-slim (docker buildx imagetools inspect) and update it.
# Note: We only install Docker CLI to use host's Docker daemon via mounted socket
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

# Fail fast inside RUN pipelines (curl | sh, | tee, …)
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Every moving part is pinned to a concrete release (override with --build-arg);
# remote installers are downloaded to a file, verified against a pinned sha256 and
# only then run. When an installer changes upstream the build stops on purpose:
# review the new script, then bump the matching *_SHA256.
ARG NVM_VERSION=v0.40.8
ARG NVM_INSTALL_SHA256=48a0eee9a60e07422dce0eb5774754c83889570ca1ee2566c516acbe8af03a9e
# Node.js LTS ("Krypton", 24.x) installed through nvm
ARG NODE_VERSION=24.21.0
ARG UV_VERSION=0.13.0
ARG UV_INSTALL_SHA256=283cbef4bdaca819bd896b0dacb8a085c4c05dbc880642aa5001d97bc4db74ba
ARG PNPM_VERSION=12.11.2
ARG PNPM_INSTALL_SHA256=a5cb30faa96ded2937d60f80041e9d47b5280b224fbdcd9d3b136000a8edabf8
# OpenCode CLI release. `opencode-dockerized update` resolves the newest release
# from the npm registry and passes it here; a plain build uses this pin.
ARG OPENCODE_VERSION=2.0.26
# Docker CLI packages from Docker's apt repository (versions exist for amd64 and
# arm64 alike) and the fingerprint the repository key must have.
ARG DOCKER_CLI_VERSION=5:29.9.0-1~debian.13~trixie
ARG DOCKER_BUILDX_VERSION=0.38.0-1~debian.13~trixie
ARG DOCKER_COMPOSE_VERSION=5.6.0-1~debian.13~trixie
ARG DOCKER_GPG_FINGERPRINT=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
# Changing this value invalidates every layer below it. The wrapper passes the ISO
# week on `update`, so system packages and the toolchain are refreshed at most
# weekly without losing the cache on every rebuild; a plain build keeps it at 0.
ARG APT_REFRESH=0
# Optional: build from a frozen Debian archive (e.g. APT_SNAPSHOT=20261010T000000Z)
# for package-level reproducibility. Empty = the live mirror. Not exercised by CI.
ARG APT_SNAPSHOT=""

RUN : "apt refresh ${APT_REFRESH}" && \
    if [ -n "${APT_SNAPSHOT}" ]; then \
        sed -i \
            -e "s|http://deb.debian.org/debian-security|https://snapshot.debian.org/archive/debian-security/${APT_SNAPSHOT}|g" \
            -e "s|http://deb.debian.org/debian|https://snapshot.debian.org/archive/debian/${APT_SNAPSHOT}|g" \
            /etc/apt/sources.list.d/debian.sources && \
        echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/10snapshot; \
    fi

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
    ncurses-term \
    ripgrep \
    fd-find \
    jq \
    tree \
    less \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI only (uses host Docker daemon via mounted socket)
# We don't need docker-ce (daemon) or containerd.io since we use the host's Docker.
# The repository key is accepted only when it has the published fingerprint.
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc && \
    actual_fingerprint="$(gpg --show-keys --with-colons /etc/apt/keyrings/docker.asc | awk -F: '/^fpr/ && !seen {print $10; seen=1}')" && \
    { [ "${actual_fingerprint}" = "${DOCKER_GPG_FINGERPRINT}" ] || \
        { echo "Docker apt key fingerprint mismatch: got ${actual_fingerprint}" >&2; exit 1; }; } && \
    chmod a+r /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y \
        "docker-ce-cli=${DOCKER_CLI_VERSION}" \
        "docker-buildx-plugin=${DOCKER_BUILDX_VERSION}" \
        "docker-compose-plugin=${DOCKER_COMPOSE_VERSION}" && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
# Note: Docker socket group membership is granted at run time by the wrapper
# (config-lib.sh) with `--group-add <socket GID>`; the entrypoint never runs as
# root and does not edit /etc/group.
# There is intentionally no sudo: the agent must never gain root, so neither a
# sudoers entry nor the sudo binary (a setuid-root vector) is installed.
RUN useradd -m -s /bin/bash -u 1000 coder

# Install NVM and Node.js (pinned LTS) as coder user
USER coder
WORKDIR /home/coder
ENV NVM_DIR="/home/coder/.nvm"
RUN curl -fsSL "https://raw.githubusercontent.com/nvm-sh/nvm/${NVM_VERSION}/install.sh" -o /tmp/nvm-install.sh && \
    echo "${NVM_INSTALL_SHA256}  /tmp/nvm-install.sh" | sha256sum -c - && \
    bash /tmp/nvm-install.sh && \
    rm -f /tmp/nvm-install.sh && \
    bash -c "source $NVM_DIR/nvm.sh && \
    nvm install ${NODE_VERSION} && \
    nvm alias default ${NODE_VERSION} && \
    nvm use default && \
    ln -sf \$(dirname \$(which node)) $NVM_DIR/default"

# Install uv (Python package manager) as coder user, from the pinned release's
# installer (which in turn verifies the binary it downloads).
# See: https://docs.astral.sh/uv/getting-started/installation/
RUN curl -fsSL "https://astral.sh/uv/${UV_VERSION}/install.sh" -o /tmp/uv-install.sh && \
    echo "${UV_INSTALL_SHA256}  /tmp/uv-install.sh" | sha256sum -c - && \
    sh /tmp/uv-install.sh && \
    rm -f /tmp/uv-install.sh

# Install pnpm via the official standalone installer (native binary, no Node needed)
# The script installs to $PNPM_HOME (default: ~/.local/share/pnpm) and appends a
# PATH snippet to ~/.bashrc; we wire PATH via ENV below so it works non-interactively.
# PNPM_VERSION pins the installed release (override with --build-arg PNPM_VERSION=x.y.z).
# SHELL/ENV must be set explicitly in Docker builds (documented by pnpm.io) because
# the installer cannot infer the shell and otherwise fails with ERR_PNPM_UNKNOWN_SHELL.
# See: https://pnpm.io/installation (sections "POSIX systems", "In a Docker container",
# "Installing a specific version")
ENV PNPM_HOME="/home/coder/.local/share/pnpm"
RUN curl -fsSL https://get.pnpm.io/install.sh -o /tmp/pnpm-install.sh && \
    echo "${PNPM_INSTALL_SHA256}  /tmp/pnpm-install.sh" | sha256sum -c - && \
    env PNPM_VERSION="${PNPM_VERSION}" ENV="$HOME/.bashrc" SHELL="$(which bash)" sh /tmp/pnpm-install.sh && \
    rm -f /tmp/pnpm-install.sh && \
    "$PNPM_HOME/bin/pnpm" --version

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
# ARG OPENCODE_VERSION pins the release (the wrapper resolves the newest on update)
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

# Provenance labels (last, so changing them never invalidates the layers above).
# The wrapper passes GIT_SHA, DOCKERFILE_SHA256 and BUILD_DATE; it reads the
# Dockerfile hash back to warn when the image is older than the checkout.
ARG GIT_SHA=unknown
ARG DOCKERFILE_SHA256=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="opencode-dockerized" \
      org.opencontainers.image.source="https://github.com/yukiteruamano/opencode-dockerized" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      dev.opencode-dockerized.opencode-version="${OPENCODE_VERSION}" \
      dev.opencode-dockerized.dockerfile-sha256="${DOCKERFILE_SHA256}"

# entrypoint.sh performs no privilege changes.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Default command is to run opencode
CMD ["opencode"]
