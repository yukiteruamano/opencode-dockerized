# OpenCode Dockerized - Secure Sandbox Environment

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Fork of [glennvdv/opencode-dockerized](https://github.com/glennvdv/opencode-dockerized),
> rebuilt around OpenCode V2** with a hardened security model, tighter Docker
> isolation, and deeper host integration (SSH and GPG agent forwarding, plugin
> hooks, managed config sync and more). See
> [About this fork](#about-this-fork) for the full list of improvements.

Run OpenCode in a secure, isolated Docker container with controlled access to your projects. This setup provides OpenCode with just enough access to be useful while maintaining strong security boundaries.

## Table of Contents

- [Security Features](#-security-features)
- [About This Fork](#-about-this-fork)
- [Prerequisites](#-prerequisites)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [Portability & Sharing](#-portability--sharing)
- [Advanced Usage](#-advanced-usage)
- [Performance Optimizations](#-performance-optimizations)
- [Testcontainers Support](#-testcontainers-support)
- [Troubleshooting](#-troubleshooting)
- [File Reference](#-file-reference)

## 🔒 Security Features

- **Isolated Environment** - OpenCode only has access to the mounted project directory
- **Persistent Configuration** - All OpenCode state lives self-contained under `~/.config/opencode-dockerized/home/`, so MCP servers, sessions and auth survive container restarts and image rebuilds. The OpenCode config directory itself is mounted **read-only**: edit it on the host
- **Security Layer** - A generated `~/.config/opencode-dockerized/` directory (permission rules, `AGENTS.md` rules, plugin hooks plus the ported `opencode-policy` unsafe/injection patterns) is never mounted as a directory: the permission rules are passed inline (`OPENCODE_CONFIG_CONTENT`) and the rules/hooks/policies are mirrored into the read-only config tree, so every session receives them and cannot relax them
- **Configurable policy** - `setting.security_policy` selects `strict`, `balanced` (default, drops the noisy cloud/multi-tenant false positives) or `off`
- **No host Docker control by default** - The host Docker socket is **not** mounted unless you opt in with `setting.docker_socket=true` (it is root-equivalent on the host; see [SECURITY.md](SECURITY.md))
- **Session Persistence** - Logs and project session data persist across container restarts
- **Non-root User** - Runs as the host user via `--user <uid>:<gid>`; no root process ever starts in the container (plus `--cap-drop=ALL` and `no-new-privileges`)
- **Limited Blast Radius** - Commands like `rm -rf .` only affect the project directory, not your entire system

## 🍴 About This Fork

This is a fork of [glennvdv/opencode-dockerized](https://github.com/glennvdv/opencode-dockerized),
rebuilt around **OpenCode V2** (native `permissions`, plugin hooks, `OPENCODE_CONFIG_CONTENT`).
Everything below is on top of what upstream provides.

### Hardened security
- **Rootless by design** - the container starts as your host UID/GID (`--user`), with no `sudo` binary, `--cap-drop=ALL` and `no-new-privileges`; no root process ever runs.
- **Read-only OpenCode config** - a single ro directory mount delivers config, plugins and rules; sandbox permissions travel inline (`OPENCODE_CONFIG_CONTENT`), never from a writable file, so a session cannot relax its own rules.
- **Versioned V2 security hooks** (`plugins/security-guard.js`, auto-refreshed with backup) evaluating the ported `opencode-policy` unsafe/injection pattern sets in `strict`, `balanced` (default, drops cloud/dev false positives) or `off` modes.
- **Symlink-escape resolution** - `read`/`grep`/`glob` and `edit`/`write` confinement resolve symlinks (plus real parents), and `/` can never become a writable root.
- **Secret backstops beyond the pattern sets** - shell references to `.env` (except `.env.example`), `*.pem`, `*.key`, key-like names (incl. bare `*key`), `auth.json`, `credentials*`, `.npmrc`, `.mcp-auth/`, `.ssh/`, `.gitconfig`, `.composio/`, SSH keys and GnuPG private material are denied via shell and file tools alike; `openssl` key readers, `ssh-keygen -y`, bare environment dumps (`env`, `printenv`, `set`, `export` without arguments) and host-agent control (`ssh-add -D/-e`, `gpgconf --kill/--reload`, secret-key export) are blocked in every mode.
- **SSH/GPG agent hardening** - only the agent socket plus non-secret `config`/`known_hosts` (ro) is shared; `~/.ssh` and `~/.gnupg` as custom mounts are refused; the restricted `S.gpg-agent.extra` socket is preferred with no silent fallback to the full-control socket; only the public keyring is mirrored (`private-keys-v1.d` never copied or mounted).
- **Project confinement** - `/`, `$HOME` and ancestors of `$HOME` are refused as projects, with symlink-resolved paths (`pwd -P`); custom mounts default to read-only and validate absolute container paths.
- **Fail-closed conventions** - `docker --env-file` for secrets (never `-e KEY=value` on the command line), `DRY_RUN` redaction, `--mount` (not `-v`) for agent sockets so stale sources fail loudly, `commit.gpgsign`-compatible signing without private keys in the container.

### Usability and host integration
- **Self-contained state tree** (`~/.config/opencode-dockerized/home/`) - config, auth, sessions and caches survive rebuilds without touching host XDG dirs.
- **`doctor` command** - in-container diagnosis of guard version, SSH/GPG agents, websearch provider/key presence, theme, env file and inline-secret scans.
- **`config sync [--check]`** - refreshes the versioned security layer, merges custom permission rules (template wins conflicts, everything reported), repairs `cli.json` and removes the legacy symlink; `--check` is read-only (CI-ready).
- **Secrets file workflow** - `setting.env_file` (`600`, under the config dir, never mounted) with hidden-value `install` prompts, format/permission validation and one-shot migration of legacy entries.
- **Built-in websearch provider** (`exa | firecrawl | parallel | tavily | random`) merged into the inline config, key via env file.
- **Catppuccin theme** (and variants) via inline CLI config.
- **Global install + aliases guaranteed** - `install.sh` puts `<install>/bin` on `PATH` (no symlink/stub/copy in `~/.local/bin`, legacy symlink auto-removed), ensures `PATH` in bash/zsh, and verifies/repairs the `ocd`, `ocd-run`, `ocd-auth` aliases, which point at the command on `PATH` rather than an absolute repo path (immune to repo moves; `sync --check` watches PATH health).
- **Non-interactive setup** (`--yes`, `--only`, `NO_COLOR`, multiline redacted `DRY_RUN`) and private-server readiness for `models`/`stats`/`exec`/`debug`.
- **Git worktree support**, container resource limits, drift hints in `config show`, and a contract test suite (`bash` + `node`) covering mounts, permissions, policies and sync.

## 📋 Prerequisites

1. **Docker** installed and running
2. **Optional configuration files** (if you have them):
   - `~/.npmrc` - NPM configuration

**No local OpenCode installation required!** Authentication and all OpenCode operations run through Docker.

## 🚀 Quick Start

### First-Time Setup

```bash
# Option A: one-liner (clones to ~/.local/share/opencode-dockerized)
curl -fsSL https://raw.githubusercontent.com/yukiteruamano/opencode-dockerized/master/install.sh | bash

# Option B: from a local clone
./install.sh
# Non-interactive (recommended defaults, ideal for automation):
./install.sh --yes
# Only some sections (config,completions,aliases,global,path,build):
./install.sh --only completions,aliases

# 3. Build the Docker image
opencode-dockerized build

# 4. Authenticate with your LLM provider (no local OpenCode needed!)
opencode-dockerized auth

# 5. Run OpenCode in your project (from any directory!)
opencode-dockerized run
# or
opencode-dockerized run /path/to/your/project
```

### Authentication

**No local OpenCode installation required!** You can authenticate directly through Docker:

```bash
# Authenticate with your LLM provider (Anthropic, OpenAI, etc.)
opencode-dockerized auth

# This will:
# - Run 'opencode auth login' inside the container
# - Save credentials to ~/.config/opencode-dockerized/home/.local/share/opencode on your host
# - Make authentication available to all future OpenCode runs
```

Your authentication is stored on the host machine and persists across container restarts.

### Daily Usage

```bash
# Run in current directory (works from anywhere after setup)
opencode-dockerized run

# Run in specific project
opencode-dockerized run ~/projects/my-app

# Check version
opencode-dockerized version

# Update OpenCode
opencode-dockerized update
```

### Global Installation

No symlink, stub or copy is ever created in `~/.local/bin`. The binary lives
in `bin/` of the self-contained checkout (`~/.local/share/opencode-dockerized`
by default) and is reached via `PATH`:

```bash
export PATH="$HOME/.local/share/opencode-dockerized/bin:$PATH"
```

`install.sh` (via `opencode-dockerized install`) adds that line to `~/.bashrc`/`~/.zshrc` for you
(idempotent, never duplicated). Re-running `install` (or `config sync --check`)
verifies the integration: a legacy `~/.local/bin/opencode-dockerized` symlink
left by older versions is removed automatically (a real file is never touched),
and missing PATH lines are reported (re-run `install` to repair them; `sync`
never edits rc files).

### Shell Aliases (Automatic)

`install.sh` installs these aliases automatically (in both `~/.bashrc` and `~/.zshrc` when those files exist, repaired on re-runs). They point at the command on `PATH` — never at an absolute repo path, so they survive repo moves (PATH health is watched by `config sync --check`):

```bash
alias ocd='opencode-dockerized'
alias ocd-run='opencode-dockerized run'
alias ocd-auth='opencode-dockerized auth'

# Then use them anywhere (after `source ~/.bashrc` or a new shell)
cd ~/my-project
ocd run
```

### Shell Completion (Optional)

Autocompletion support is available for both Bash and Zsh:

**For Bash:**
```bash
# Source the completion file
source /path/to/opencode-dockerized/completions/bash.sh

# Or add to ~/.bashrc for permanent installation
echo "source /path/to/opencode-dockerized/completions/bash.sh" >> ~/.bashrc
```

**For Zsh:**
```bash
# Source the completion file
source /path/to/opencode-dockerized/completions/zsh.sh

# Or add to ~/.zshrc for permanent installation
echo "source /path/to/opencode-dockerized/completions/zsh.sh" >> ~/.zshrc

# For system-wide installation (requires sudo)
sudo cp /path/to/opencode-dockerized/completions/zsh.sh /usr/local/share/zsh/site-functions/_opencode-dockerized
```

After installation, you'll get:
- Command completion (`run`, `build`, `update`, `version`, `auth`, `models`, `exec`, `mcp`, `plugin`, `stats`, `debug`, `doctor`, `config`, `clean`, `help`)
- Subcommand completion for `config` (`show`, `edit`, `path`)
- Directory completion for the `run` command
- Helpful descriptions for each command
- Works with the `opencode-dockerized` command on PATH and the `ocd` alias

## 📖 Usage

### Available Commands

```bash
opencode-dockerized build          # Build Docker image
opencode-dockerized auth           # Authenticate with LLM provider
opencode-dockerized run [DIR]      # Run OpenCode (default: current dir)
opencode-dockerized models         # List available models
opencode-dockerized exec "..."     # Non-interactive prompt
opencode-dockerized mcp list       # MCP servers and their status
opencode-dockerized plugin list    # Loaded plugins
opencode-dockerized stats --days 7 # Usage statistics
opencode-dockerized debug paths    # Resolved data/config/cache paths
opencode-dockerized doctor         # Diagnose install, guard, SSH/GPG, websearch, theme and env file
opencode-dockerized install        # Install / repair PATH, config, completions, aliases
opencode-dockerized upgrade --check # Check for updates from GitHub
opencode-dockerized upgrade        # Full upgrade: git pull + sync + image rebuild
opencode-dockerized update         # Full upgrade: git pull + sync + image rebuild
opencode-dockerized version        # Show wrapper, guard and OpenCode versions
opencode-dockerized config show    # Show parsed configuration
opencode-dockerized config edit    # Edit wrapper config in $EDITOR
opencode-dockerized config path    # Print wrapper config file path
opencode-dockerized config sync [--check]  # Refresh security layer (guard/policies) from repo
opencode-dockerized config opencode path   # Print OpenCode config path
opencode-dockerized config opencode edit   # Edit OpenCode config (MCP, models)
opencode-dockerized clean          # Remove the Docker image
opencode-dockerized help           # Show help
```

### Dry Run Mode

Preview the `docker run` command without executing it:

```bash
DRY_RUN=true opencode-dockerized run /path/to/project
```

This prints the full Docker command with all volume mounts, environment variables, and flags — one flag per line — useful for debugging configuration issues.

Note: dry-run still prepares host-side state (keyring mirror, agent autostart/relay checks) so the printed command is accurate, but it never starts a container and stops any relay it started. The inline permission rules are redacted in the output; secrets travel via `--env-file` (only the file path is shown).

Set `NO_COLOR=1` (or `TERM=dumb`) for plain output without ANSI colors.

### Alternative Runners

**Simple Runner**:
```bash
./run-simple.sh /path/to/your/project
```

### Inside the Container

Once OpenCode starts:

```bash
# Initialize OpenCode for the project
/init

# Ask questions about your code
How is authentication handled in @src/auth.ts

# Make changes
Add error handling to the login function

# Create plans before implementing
<TAB>  # Switch to Plan mode
Let's add a new feature for user profiles
```

## 🔧 Configuration

### Configuration File

The wrapper is configured through `~/.config/opencode-dockerized/config`
(INI-style, created by `./install.sh`). It holds the `setting.*` and `mount.*`
directives described under
[Custom Global Configuration](#custom-global-configuration-optional).

There is **no `.env` file**: secrets live in `setting.env_file` (a dotenv file
under `~/.config/opencode-dockerized/`, loaded with `docker --env-file`), and
`TERM` is forwarded automatically. The
container runs as your host UID/GID (`--user`), so no `HOST_UID`/`HOST_GID`
mapping is needed.

### Volume Mounts

| Host Path | Container Path | Mode | Purpose |
|-----------|---------------|------|---------|
| `$PROJECT_DIR` | `$PROJECT_DIR` (with `$HOME` stripped) | read-write | Your project files |
| `~/.config/opencode-dockerized/home/.config/opencode/` | `/home/coder/.config/opencode/` | **read-only** | Self-contained OpenCode config: MCP servers, models, `cli.json`, skills, agents, commands, plugins. The security files (`AGENTS.md`, `plugins/security-guard.js`, `plugins/policies/`) are mirrored into this tree on the host |
| `~/.config/opencode-dockerized/home/.local/share/opencode/` | `/home/coder/.local/share/opencode/` | read-write | Auth database (API keys, MCP OAuth), logs, sessions, storage |
| `~/.config/opencode-dockerized/home/.local/state/opencode/` | `/home/coder/.local/state/opencode/` | read-write | Selected model, prompt history, locks |
| `~/.config/opencode-dockerized/home/.cache/opencode/` | `/home/coder/.cache/opencode/` | read-write | Provider package cache |
| `~/.npmrc` | `/home/coder/.npmrc` | read-only | NPM config (optional) |
| `~/.mcp-auth/` | `/home/coder/.mcp-auth/` | **read-write** | MCP OAuth store for `mcp-remote` servers (optional) |
| `~/.composio/` | `/home/coder/.composio/` | read-write | Composio CLI binary + login (optional custom `mount.composio`) |
| `~/.config/opencode-dockerized/home/.gnupg/` | `/home/coder/.gnupg/` | read-write | Mirrored **public** GnuPG material (pubring/trustdb/gpg.conf) + agent socket (only with `setting.gpg_agent_support=true`); `private-keys-v1.d/` is never copied |

The wrapper's own directory (`~/.config/opencode-dockerized/`) is **not** mounted at all: its permission rules are read on the host and passed inline, and its security files are mirrored into the config tree above.

### Persistent Configuration & Security Layer

The wrapper is **self-contained and replaces native host usage**: all of OpenCode's
state lives under a single host directory (`~/.config/opencode-dockerized/home/`,
override with `OCODE_HOME`), mirroring the container home layout 1:1. Back up or move
that one directory and the whole setup travels with it. The host XDG dirs
(`~/.config/opencode`, `~/.local/...`) are never touched.

```text
~/.config/opencode-dockerized/
│   config                          ← wrapper INI config (mounts, env vars, settings)
│   opencode.json                   ← sandbox permission rules (deny rm -rf/sudo,
│                                      ask git push, deny reading .env/keys, ...);
│                                      passed inline via OPENCODE_CONFIG_CONTENT
│   AGENTS.md                       ← security rules source
│   plugins/security-guard.js       ← guard source (versioned in the repo)
│   plugins/policies/*.json         ← opencode-policy pattern sets + local allowlist
│
└── home/                            ← mirrors /home/coder, mounted piece by piece
    └── .config/opencode/            ← mounted READ-ONLY
    │   AGENTS.md                   ← security rules (mirrored from the source above)
    │   opencode.json               ← YOUR config: MCP servers, models (seeded minimal)
    │   cli.json                    ← V2 terminal client settings (seeded `{}`)
    │   plugins/                    ← your plugins + mirrored guard + policies/
    │   agents/ commands/ skills/   ← seeded empty (V2 plural layout)
    └── .local/share|state/opencode/ ← auth, sessions, history (rw)
    └── .cache/opencode/ ← caches (rw)
```

Because everything lives on the host, all state persists across `docker` up/down
cycles **and** image rebuilds:

- **Editing config / adding MCP servers:** the config dir is mounted **read-only**,
  so edit it on the host — either the JSON file directly or with
  `opencode-dockerized config opencode edit`. `opencode mcp add` and
  `opencode plugin add/update/remove` are intentionally disabled inside the
  container. Provider auth and MCP OAuth tokens live in `.local/share/opencode`
  (read-write), so `opencode-dockerized auth` and `opencode mcp auth` keep working.
- **Security layer:** generated on the host and mirrored into the config tree on
  every run (wrapper-managed; a user-authored `AGENTS.md` is backed up once to
  `AGENTS.md.user.bak`). The guard is versioned in the repo
  (`plugins/security-guard.js`); bumping `OPENCODE_DOCKERIZED_GUARD_VERSION`
  refreshes installs (the previous copy is backed up to `.bak`).
- **Policy mode:** `setting.security_policy` (default `balanced`) selects which
  `opencode-policy` patterns the hook enforces. `balanced` drops cloud/multi-tenant
  rules and common false positives while keeping the dangerous ones; `strict` enforces
  everything; `off` disables the vendored patterns but keeps the built-in backstops.
  Local exceptions live in `plugins/policies/allow-patterns.json`.

The security layer is activated through environment variables the wrapper injects:

| Variable | Value | Purpose |
|----------|-------|---------|
| `OPENCODE_CONFIG_CONTENT` | inline JSON | Injects the sandbox permission rules (merged like a config document) |
| `OPENCODE_DOCKERIZED_POLICY` | `strict` \| `balanced` \| `off` | Selects which `opencode-policy` pattern sets the security hook enforces (from `setting.security_policy`) |
| `OPENCODE_DISABLE_AUTOUPDATE` | `true` | Always set: prevents OpenCode from self-updating inside the container |

> Note: the wrapper deliberately does **not** set `OPENCODE_CONFIG` or
> `OPENCODE_CONFIG_DIR`. `OPENCODE_CONFIG_DIR` replaces the global config directory
> (breaking the self-contained config); `OPENCODE_CONFIG` would require mounting a
> file. The permissions are passed inline via `OPENCODE_CONFIG_CONTENT` instead.

**Known precedence caveats** (see the [OpenCode config docs](https://opencode.ai/docs/config/)):

- A project-level `opencode.json` can override `permissions` keys — but it **cannot remove
  the plugin hooks**, which are the hard enforcement layer.
- The global `AGENTS.md` rules are provided read-only in the config tree and combined
  with any project `AGENTS.md`/`CLAUDE.md`; the hooks and deny-rules still apply.

The V2 terminal client settings live in `cli.json` next to `opencode.json`. The wrapper
seeds an empty `cli.json` on first run (mounted read-write, so the client persists its
settings there across restarts).

### Custom Global Configuration (Optional)

**Advanced Users:** You can configure custom volume mounts and environment variables to be automatically mounted in the container for all projects. This is useful for:

- **SSH agent forwarding**: Enable `setting.ssh_agent_support=true` for secure git over SSH (recommended). Forwards only the host `SSH_AUTH_SOCK` and mounts `~/.ssh/config` + `known_hosts` read-only; private keys are never mounted.
- **GnuPG agent forwarding**: Enable `setting.gpg_agent_support=true` to sign commits (`git commit -S`) with the keys held by your host gpg-agent (private keys never enter the container; the restricted agent socket is preferred). Run `opencode-dockerized doctor` to verify the socket and keyring from inside the container.
- **Global git configuration**: Mount `~/.gitconfig` and global gitignore
- **Environment variables**: API keys and other credentials live in the secrets file (`setting.env_file`)
- **Websearch provider**: Set `setting.websearch_provider=exa` to use Exa without the TUI prompt (needs `EXA_API_KEY` in the container)
- **TUI theme**: Set `setting.theme=catppuccin` for the Catppuccin look

#### Getting Started with Custom Global Config

```bash
# During install, you'll be prompted to add custom mounts and env vars
./install.sh

# Or manually edit the config file
~/.config/opencode-dockerized/config
```

#### Config Format

Configuration is stored in `~/.config/opencode-dockerized/config` (INI format):

```ini
# Settings (built-in features)
# Format: setting.<name>=<value>
setting.ssh_agent_support=true
setting.gpg_agent_support=true
setting.gpg_allow_main_socket=false
setting.gpg_autostart_agent=true
setting.memory=4g
setting.cpus=2
setting.env_file=~/.config/opencode-dockerized/env
setting.websearch_provider=exa
setting.theme=catppuccin

# Custom volume mounts (read-only by default)
# Format: mount.<name>=<host_path>:<container_path>[:rw]
mount.gitconfig=~/.gitconfig:/home/coder/.gitconfig

# Environment variables are passed from the secrets file only
# (setting.env_file, dotenv KEY=VALUE lines loaded with docker --env-file).
# There is no per-variable passthrough: put every key in that file.
```

Secrets file format (`setting.env_file`, dotenv `KEY=VALUE` lines, `chmod 600`):
```ini
EXA_API_KEY=...
OPENCODE_API_KEY=...
```

#### Examples

**Example 1: Git configuration with SSH agent forwarding (Recommended)**
```ini
setting.ssh_agent_support=true
mount.gitconfig=~/.gitconfig:/home/coder/.gitconfig
```

Your private keys never enter the container: only `SSH_AUTH_SOCK` and the non-secret `~/.ssh/config`/`known_hosts` are shared (read-only). Do not mount `~/.ssh` — it is refused. If your `~/.ssh/config` sets `IdentitiesOnly yes` with an `IdentityFile`, make sure that key is loaded in the host `ssh-agent` (the key file itself is not mounted).

**Example 2: Commit signing with the host GnuPG agent (Recommended for signed commits)**
```ini
setting.gpg_agent_support=true
mount.gitconfig=~/.gitconfig:/home/coder/.gitconfig
```
Inside the container, configure git to use your signing key (e.g. `git config --global user.signingkey <KEYID>` and `git config --global commit.gpgsign true`, or set it per project). Only the public keyring and the host `gpg-agent` socket are shared; private keys stay on the host. The wrapper mirrors `pubring.kbx` (or `public-keys.d/pubring.db`), keeps `use-keyboxd` and sets `no-autostart` in the mirrored config, and the container starts keyboxd at boot so gpg can read the mirrored key database while private-key operations go to the host agent. The agent socket is mounted at a dedicated path (`/home/coder/.gnupg-agent/S.gpg-agent`) and exposed through a symlink in the keyring — a socket mounted inside another bind mount can be shadowed by Docker. It prefers the restricted `S.gpg-agent.extra` socket; if that socket is missing it warns and skips instead of silently using the full-control main socket, and set `setting.gpg_allow_main_socket=true` only if you accept that risk.

Verify the setup with `opencode-dockerized doctor`. If the host agent socket is missing, `run` starts it automatically (`setting.gpg_autostart_agent=true`, the default); before launching it probes whether the agent already answers (`gpg-connect-agent` with a 2 s timeout), so a live agent is never relaunched and a stale socket is replaced. Set `gpg_autostart_agent=false` to only warn and never launch anything.

**Important:** many Docker setups cannot bind a socket under a per-user tmpfs (`/run/user/<uid>/gnupg/…`) — they create an empty directory instead. The wrapper transparently relays the agent socket through a socket on a normal filesystem (under `~/.config/opencode-dockerized/gnupg-relay/`) using `socat`, and mounts that. Install `socat` on the host; if it is missing the wrapper warns and skips GPG forwarding. Only the restricted `S.gpg-agent.extra` socket is relayed, and the relay exists only while the container runs (`setting.gpg_relay=true`, the default; `clean` purges leftovers).

Pinentry runs on the **host** agent, so it is independent of the container's desktop: install a suitable `pinentry` for your session (KDE/LXQt → `pinentry-qt`; GNOME → `pinentry-gnome3`; sway/i3/awesome → `pinentry-gtk`/`pinentry-qt` or `pinentry-rofi`). With a terminal-only pinentry, run `gpg-connect-agent updatestartuptty /bye` on the host so prompts appear in your terminal.

**Example 3: API keys and credentials (secrets file recommended)**
```ini
setting.env_file=~/.config/opencode-dockerized/env
```

Create the file with `install -m 600 /dev/null ~/.config/opencode-dockerized/env`, then add one `KEY=VALUE` per line. It must live under `~/.config/opencode-dockerized/` (anywhere else is refused) and is passed with `docker --env-file`, so values never appear on the command line; the file itself is never mounted.

**Never write secrets inline in `opencode.json`** — use `{env:VARNAME}` references instead (e.g. `"apiKey": "{env:EXA_API_KEY}"`). The wrapper aborts the run if it finds inline secrets there; `doctor` reports them too.

**Example 4: Websearch with Exa**
```ini
setting.websearch_provider=exa
setting.env_file=~/.config/opencode-dockerized/env
```
With `EXA_API_KEY=...` in the env file, web search uses Exa without asking. Supported ids: `exa | firecrawl | parallel | tavily | random`; empty means the TUI asks once per session.

**Example 5: Catppuccin theme**
```ini
setting.theme=catppuccin
```
Built-in variants: `catppuccin`, `catppuccin-frappe`, `catppuccin-macchiato`. Empty means the OpenCode default.

**Note:** 
- **SSH Agent Support**: Use `setting.ssh_agent_support=true` instead of mounting `~/.ssh` (refused) or passing `SSH_AUTH_SOCK` manually
- **GnuPG Agent Support**: Use `setting.gpg_agent_support=true` instead of mounting `~/.gnupg` (refused); it requires a running `gpg-agent` on the host and mirrors only public material (restricted socket preferred; `setting.gpg_allow_main_socket=true` opts into the full-control socket)
- Mounts are **read-only by default** (append `:rw` for read-write)
- Paths use `~` which is expanded to your home directory at runtime
- Environment variables must be set in your host environment to be passed
- Re-run `./install.sh` anytime to update your custom configuration

## 🌍 Portability & Sharing

**This setup is fully portable!** It uses `$HOME` instead of hardcoded paths and works across different users and systems.

### How to Share

**Method 1: Git Repository (Recommended)**

```bash
git init
git add .
git commit -m "Initial OpenCode Docker setup"
git remote add origin <your-repo-url>
git push -u origin master
```

Users can then:
```bash
curl -fsSL https://raw.githubusercontent.com/yukiteruamano/opencode-dockerized/master/install.sh | bash
opencode-dockerized build
opencode-dockerized run
```
Or manually:
```bash
git clone <your-repo-url> ~/.local/share/opencode-dockerized
~/.local/share/opencode-dockerized/install.sh   # adds bin/ to PATH + config
opencode-dockerized build
opencode-dockerized run
```

**Method 2: Archive Distribution**

```bash
tar -czf opencode-docker.tar.gz opencode-dockerized/
```

Users extract and run:
```bash
tar -xzf opencode-docker.tar.gz
cd opencode-dockerized
./install.sh              # Sets up config + PATH
opencode-dockerized build
```

### Platform Compatibility

- **Linux**: Works out of the box
- **macOS**: Works with Docker Desktop
- **Windows (WSL2)**: Works in WSL2 terminal
- **Windows (Native)**: Use WSL2 instead

### What to Share

✅ Safe to share:
- Dockerfile
- Shell scripts
- Documentation
- .gitignore

❌ Never share:
- `.env` file with secrets
- Personal `auth.json`
- Personal `opencode.json` (may contain API keys)
- Personal `.npmrc`

## 🔍 Advanced Usage

### Python Development with uv

The container includes [uv](https://docs.astral.sh/uv/), a fast Python package manager and project manager. Use it for:

```bash
# Inside the container or via OpenCode commands
uv init my-project              # Create a new Python project
uv add requests                 # Add dependencies
uv run python script.py         # Run scripts in isolated environment
uv pip install package          # Install packages (pip-compatible)
uv venv                         # Create virtual environments
uv python install 3.12          # Install specific Python versions
```

**Benefits:**
- ✅ 10-100x faster than pip
- ✅ Deterministic dependency resolution
- ✅ Built-in virtual environment management
- ✅ Works seamlessly with existing pip workflows

For more information, see the [uv documentation](https://docs.astral.sh/uv/).

### Adding Additional Tools

Edit `Dockerfile`:

```dockerfile
RUN apt-get update && apt-get install -y \
    git \
    curl \
    bash \
    ca-certificates \
    python3 \
    python3-pip \
    jq \
    && rm -rf /var/lib/apt/lists/*
```

### Using Different Base Images

```dockerfile
# For Alpine (smaller size)
FROM node:20-alpine

# For specific Node version
FROM node:22-slim

# For Ubuntu-based
FROM ubuntu:22.04
# (then install Node.js manually)
```

## 🐛 Troubleshooting

### Permission Denied on Scripts

```bash
chmod +x bin/opencode-dockerized install.sh entrypoint.sh
```

### Config Files Not Found

```bash
# Run install script
./install.sh

# Or manually create the self-contained tree
mkdir -p ~/.config/opencode-dockerized/home/.config/opencode ~/.config/opencode-dockerized/home/.local/share/opencode
echo '{"$schema": "https://opencode.ai/config.json"}' > ~/.config/opencode-dockerized/home/.config/opencode/opencode.json
```

### Permission Issues with Files

```bash
# The container runs as your host user; check it
echo "Host UID: $(id -u), GID: $(id -g)"

# Rebuild image
opencode-dockerized build
```

### Container Won't Start

```bash
# Check Docker is running
docker info

# View container logs
docker logs opencode-dockerized

# Remove and rebuild
docker rm -f opencode-dockerized
opencode-dockerized build
```

### OpenCode Not Updating

```bash
# Force rebuild without cache
docker build --no-cache -t opencode-dockerized:latest .

# Or use update command
opencode-dockerized update
```

## 📁 File Reference

### Core Files

- **`Dockerfile`** - Container image definition (Debian + Node.js/NVM + pnpm + OpenCode, no sudo)
- **`entrypoint.sh`** - Container entrypoint (resolves the workdir, sets up NVM/Node and execs the command; runs unprivileged, no UID/GID mapping)

### User Scripts

- **`bin/opencode-dockerized`** - Main wrapper, no extension (build, run, auth, install, upgrade, update, version, config, clean, help). Reached via `<install>/bin` on `PATH`; `bin/` holds only this binary
- **`install.sh`** - Curl-able bootstrap (runs the local `bin/opencode-dockerized install`, or clones to `~/.local/share/opencode-dockerized` first; full setup in one shot)
- **`run-simple.sh`** - Simplified runner script (delegates to `opencode-dockerized run`)
- **`opencode-dockerized.sh`, `setup.sh`** - Deprecated compat shims (forward to `bin/`)

### Shared Modules

- **`lib/config-lib.sh`** - Shared configuration library (sourced by other scripts, handles mounts and env vars)

### Security Layer

- **`plugins/security-guard.js`** - Versioned OpenCode V2 hooks (permission evaluation, policy modes, backstops)
- **`policies/unsafe-tool-patterns.json`**, **`policies/prompt-injection-patterns.json`** - Vendored `opencode-policy` pattern sets
- **`policies/allow-patterns.json`** - Local allowlist (e.g. `.env.example`)
- **`policies/README.md`** - Provenance and refresh instructions

### Tests

- **`tests/security-guard.test.mjs`** - Policy regression tests (`node tests/security-guard.test.mjs`)

### Shell Completion (`completions/`)

- **`completions/bash.sh`** - Bash shell completion script
- **`completions/zsh.sh`** - Zsh shell completion script

### Examples (`examples/`)

- **`examples/config.example`** - Example custom configuration file

### Documentation & Meta

- **`SECURITY.md`** - Security model, enforced controls and known limitations
- **`CONTRIBUTING.md`** - Contribution workflow and local checks (CI parity)
- **`.shellcheckrc`**, **`.hadolint.yaml`**, **`.editorconfig`** - Linter/formatter configuration

### Configuration
- **`.gitignore`** - Excludes sensitive files from Git
- **`.dockerignore`** - Excludes non-essential files from Docker build context

### How It Works

1. **Base Image**: Uses Debian Trixie slim for minimal footprint
2. **Docker CLI Only**: Installs only Docker CLI (uses host's Docker daemon via the opt-in socket)
3. **Development Tools**: Includes Node.js (via NVM), pnpm, Python tooling (via uv), Git, and essential CLI tools
4. **OpenCode Installation**: Installs the configured OpenCode V2 release (`@opencode/cli`, pinned via `ARG OPENCODE_VERSION`) via pnpm
5. **User Management**: Creates non-root `coder` user; the wrapper runs the container as your host UID/GID with `--user` and joins the image's `coder` group with `--group-add coder` (group-writable home), so no root process and no runtime remapping
6. **Entrypoint**: Resolves the project workdir, loads NVM/Node and execs OpenCode as the unprivileged user
7. **Volume Mounting**: Mounts only necessary directories with appropriate permissions

### The Blast Radius Concept

If OpenCode runs a dangerous command like `rm -rf .`:

- ❌ **Without Docker**: Could delete your entire home directory
- ✅ **With Docker**: Only affects the mounted project directory

This significantly reduces risk while maintaining full functionality.

## 📚 Additional Resources

- [OpenCode Documentation](https://opencode.ai/docs)
- [OpenCode GitHub Repository](https://github.com/sst/opencode)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)

## ⚠️ Important Notes

1. **Docker Socket (opt-in)**: Not mounted by default. Set `setting.docker_socket=true` to use the host's Docker daemon (no privileged mode needed) — it is root-equivalent on the host, so enable it only when required.
2. **Network Access**: Container uses host network mode by default for convenience
3. **Configuration Updates**: The OpenCode config is self-contained under `~/.config/opencode-dockerized/home/.config/opencode/` and mounted **read-only**; modify it on the host (`config opencode edit`) and restart. Auth/MCP-OAuth live in the read-write data dir, so `auth`/`mcp auth` keep working
4. **Persistent Data**: Project files plus the whole `~/.config/opencode-dockerized/home/` state tree persist across restarts and rebuilds
5. **No sudo/apt inside**: The image ships no sudo (no sudoers entry, no binary) — the agent runs as the host user, never as root, with all Linux capabilities dropped and `no-new-privileges` set, so it cannot escalate by design
6. **Not a Replacement for Caution**: Review OpenCode's actions, especially with `--allow-all-tools`

## 🚀 Performance Optimizations

This setup is optimized for minimal overhead:

- **Docker CLI Only**: Only installs Docker CLI (not the full daemon), saving ~200MB
- **Host Docker Daemon (opt-in)**: Uses your existing Docker daemon via socket mounting when `setting.docker_socket=true`
- **No Privileged Mode**: No need for `--privileged` flag or Docker-in-Docker
- **Shared Resources**: Shares Docker images/containers with host (no duplication)
- **Fast Startup**: No daemon initialization delay

## 🧪 Testcontainers Support

**Testcontainers support is available** (opt-in). Enable the host Docker socket first:

```ini
# ~/.config/opencode-dockerized/config
setting.docker_socket=true
```

Then your integration tests can spin up Docker containers.

### How It Works

When you run tests with Testcontainers (Node.js, Python, etc.):

1. Testcontainers library detects the Docker socket at `/var/run/docker.sock`
2. Containers are created on your **host's Docker daemon** (not inside the OpenCode container)
3. Test containers appear in `docker ps` on your host machine
4. Containers are automatically cleaned up after tests complete

### Example Use Cases

```python
# Python with Testcontainers
from testcontainers.postgres import PostgresContainer

with PostgresContainer("postgres:15-alpine") as postgres:
    url = postgres.get_connection_url()
```

```javascript
// Node.js with Testcontainers
const { GenericContainer } = require("testcontainers");

const container = await new GenericContainer("postgres:15-alpine")
  .withExposedPorts(5432)
  .start();
```

### Benefits

✅ **Works out of the box** - No special configuration needed  
✅ **Fast performance** - Containers run directly on host (no nested virtualization)  
✅ **Shared images** - Downloaded images are shared with your host Docker  
✅ **Easy debugging** - Use `docker ps` and `docker logs` on your host to inspect test containers  
✅ **Network access** - Test containers can communicate with your application  

### Important Notes

- Test containers run on the **host**, not inside the OpenCode container
- Cleanup happens automatically via Testcontainers' cleanup hooks
- Volume mounts in test containers use host paths, not container paths
- Network modes (bridge, host) work as expected

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Software

This project uses and packages the following third-party software:

- **[OpenCode](https://github.com/sst/opencode)** - Apache 2.0 License (packaged in container)
- **[opencode-policy](https://github.com/tjvjk/opencode-policy)** - MIT License (pattern sets adapted into our V2 security hooks; upstream package itself is V1-only and does not load on V2 — see `policies/README.md`)
- **Docker CLI** - Apache 2.0 License (packaged in container)
- **Node.js** - MIT License (packaged in container)

Each component retains its original license. This wrapper script and configuration are provided under the MIT License.

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes** and test them
4. **Commit your changes** (`git commit -m 'Add amazing feature'`)
5. **Push to the branch** (`git push origin feature/amazing-feature`)
6. **Open a Pull Request**

### Guidelines

- Follow existing shell script style (see [AGENTS.md](AGENTS.md) for conventions)
- Test changes with both `opencode-dockerized` and `run-simple.sh`
- Update documentation for new features
- Keep security as a priority

### Reporting Issues

Found a bug or have a suggestion? Please [open an issue](../../issues) with:
- Clear description of the problem/suggestion
- Steps to reproduce (for bugs)
- Your environment (OS, Docker version)

---

**Made with 🔒 by developers who like AI but trust carefully**
