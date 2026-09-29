# Agent Guidelines for OpenCode Dockerized

## Project Overview

Shell script-based Docker wrapper for running [OpenCode](https://opencode.ai) in secure, isolated containers. Sandboxes OpenCode so its blast radius is limited to the mounted project directory. Source is Bash scripts, a Dockerfile, one small Node.js V2 plugin (`plugins/security-guard.js`) with vendored JSON policy data (`policies/`), and Node-based policy tests (`tests/`). No package manager files and no build step.

**Key files:**
- `bin/opencode-dockerized` — Main wrapper, no extension (build, run, auth, models, exec, mcp, plugin, stats, debug, doctor, install, upgrade, update, config, clean commands). Reached via `<install>/bin` on PATH; nothing lives in `~/.local/bin`. `bin/` holds only this binary.
- `install.sh` — Curl-able bootstrap: runs the local `bin/opencode-dockerized install` when present, else clones to `~/.local/share/opencode-dockerized` and runs it there (full setup in one shot, no second manual install)
- `lib/config-lib.sh` — Shared library sourced by other scripts (config parsing, mount/env arg building, shared volume logic, interactive prompts, installs the security layer). **Not executable directly.**
- `lib/install-lib.sh` — Install wizard library sourced by the wrapper's `install` command (`--yes`, `--only config,completions,aliases,global[,path][,build]`). **Not executable directly.**
- `opencode-dockerized.sh`, `setup.sh` (root) — Compat shims forwarding to `bin/`+`lib/`
- `Dockerfile` — Container image (Debian trixie-slim + Node.js/NVM + pnpm + OpenCode V2 (`@opencode/cli`), no sudo)
- `entrypoint.sh` — Container entrypoint (unprivileged; resolves workdir, loads NVM, execs the command)
- `run-simple.sh` — Simplified alternative runner (delegates to `opencode-dockerized run`)
- `plugins/security-guard.js` — Versioned OpenCode V2 hooks (source of truth; copied into the user config by `lib/config-lib.sh`)
- `policies/` — Vendored `opencode-policy` pattern sets + local `allow-patterns.json` (see `policies/README.md`)
- `tests/security-guard.test.mjs` — Security-policy regression tests
- `SECURITY.md`, `CONTRIBUTING.md` — Security model and contribution guide
- `config.example` — Example user config (INI-style), in `examples/`
- `.dockerignore` — Excludes non-essential files from Docker build context
- Completion scripts: `completions/{bash,zsh}.sh`

## Build / Test / Lint Commands

```bash
# Core operations
./install.sh                              # install bin/ on PATH + config (or: curl .../install.sh | bash)
bin/opencode-dockerized build             # Build Docker image (uses layer cache)
bin/opencode-dockerized run [DIR]         # Run OpenCode (default: current dir)
bin/opencode-dockerized auth              # Authenticate OpenCode
bin/opencode-dockerized upgrade --check   # Check for updates from GitHub (full upgrade: git pull + sync + rebuild)
bin/opencode-dockerized update [--check|--yes|--no-build]  # Full upgrade: git pull + sync + image rebuild
opencode-dockerized models [DIR]      # List models available to configured providers
opencode-dockerized exec MSG          # Non-interactive prompt (opencode run)
opencode-dockerized mcp [ARGS]        # Manage MCP servers (default: list)
opencode-dockerized plugin [ARGS]     # Manage plugins (default: list)
opencode-dockerized stats [OPTS]      # Usage statistics
opencode-dockerized debug [ARGS]      # Debug tools (default: paths)
opencode-dockerized doctor            # Diagnose install, guard, SSH and GPG forwarding
opencode-dockerized version           # Show OpenCode version
opencode-dockerized config show       # Show parsed configuration
opencode-dockerized config edit       # Edit config in $EDITOR
opencode-dockerized config path       # Print config file path
opencode-dockerized clean             # Remove Docker image
opencode-dockerized help              # Show help
DRY_RUN=true opencode-dockerized run  # Print docker command without running

# Validation
bash -n bin/opencode-dockerized install.sh  # Syntax-check key scripts
bash -n lib/*.sh completions/*.sh                       # Syntax-check lib + completions
shellcheck -x -S warning bin/* lib/*.sh install.sh completions/*.sh   # Lint (config in .shellcheckrc)
cat Dockerfile | docker run --rm -i hadolint/hadolint:latest hadolint -   # Lint Dockerfile
node --check plugins/security-guard.js  # Syntax-check the V2 hooks
node tests/security-guard.test.mjs      # Security-policy regression tests (Node 22+)
bash tests/wrapper-args.test.sh         # Wrapper mount/env contract test (no Docker)

# Docker operations
docker build -t opencode-dockerized:latest .                    # Manual build
docker build --no-cache -t opencode-dockerized:latest .         # Force rebuild (no cache)
docker run --rm opencode-dockerized:latest opencode --version   # Verify version
```

`bash -n`, `shellcheck`, `hadolint` and the policy test are the checks CI runs (`.github/workflows/ci.yml`). `shellcheck` is not installed in the container — run it via the `koalaman/shellcheck` image or install it on your host.

## Code Style Guidelines

### File Header

Every executable shell script starts with:
```bash
#!/bin/bash
set -e  # Exit on first error
```

**Exception:** `lib/config-lib.sh` and `lib/install-lib.sh` are libraries sourced by callers — they must **not** use `set -e` to avoid affecting callers' error handling.

### Script Initialization

Binaries resolve their own dir, derive the repo root, then source the lib:

```bash
BIN_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_ROOT="$(cd "$BIN_DIR/.." && pwd)"
source "$REPO_ROOT/lib/config-lib.sh"
```

### Naming Conventions

| Type              | Convention         | Examples                                      |
|-------------------|--------------------|-----------------------------------------------|
| Shell scripts     | kebab-case / no ext in bin/ | `bin/opencode-dockerized`, `run-simple.sh` |
| Functions         | snake_case         | `check_docker()`, `build_image()`             |
| Constants         | UPPER_SNAKE        | `IMAGE_NAME`, `REPO_ROOT`, `CONFIG_DIR`       |
| Local variables   | lower_snake        | `project_dir`, `container_name`               |
| Global arrays     | UPPER_SNAKE        | `CUSTOM_MOUNTS=()`, `DOCKER_MOUNT_ARGS=()`   |
| Booleans          | UPPER_SNAKE=false  | `SSH_AGENT_SUPPORT=false` |
| Docker images     | kebab-case:tag     | `opencode-dockerized:latest`                  |
| Container names   | kebab-case-suffix  | `opencode-myproject-abc123`                   |

### Variable Handling

- **Always quote variables:** `"$variable"` not `$variable`
- **Command substitution:** `$()` not backticks
- **Declare and assign separately:** `local dir_name; dir_name=$(...)` (SC2155)
- **Absolute paths:** `BIN_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"` + `REPO_ROOT="$(cd "$BIN_DIR/.." && pwd)"`
- **Defaults with `:=`:** `CONFIG_DIR="${CONFIG_DIR:-$HOME/.config/opencode-dockerized}"`
- **Color defaults in modules:** `: "${RED:='\033[0;31m'}"` (avoid overwriting caller-defined values)
- **Use arrays for Docker args:** Never build docker args as strings — use arrays and `"${array[@]}"`

### Color Output / Logging

```bash
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
print_error()   { echo -e "${RED}✗${NC} $1"; }
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_info()    { echo -e "${BLUE}ℹ${NC} $1"; }
```

In `lib/config-lib.sh`, use fallback wrappers that delegate to caller's functions if defined:
```bash
config_info() {
    if type print_info >/dev/null 2>&1; then print_info "$1"
    else echo -e "${BLUE}ℹ${NC} $1"; fi
}
```

### Error Handling

- Check prerequisites before operations (e.g., `check_docker`, `check_image` before Docker commands)
- Validate project directory exists before `cd`: `if [ ! -d "$dir" ]; then print_error ...; exit 1; fi`
- Print explicit error with `print_error()` then `exit 1`
- Suppress expected failures: `2>/dev/null || true`
- Graceful fallback in parsers: `load_config || return 0`
- Wrap `docker run` in error-handling: `if ! docker run ...; then print_error ...; exit 1; fi`
- Always use `read -r` to prevent backslash interpretation (SC2162)
- Validate env var names from config: `[[ "$var_name" =~ ^[A-Z_][A-Z0-9_]*$ ]]`

### Shared Logic (lib/config-lib.sh)

All volume mount logic lives in `lib/config-lib.sh` to eliminate duplication:
- `OCODE_HOME` (`~/.config/opencode-dockerized/home`) — self-contained OpenCode state root mirroring the container home; all OpenCode mounts source from here, never from host XDG dirs
- `build_standard_volume_args "$project_dir" [include_docker_socket]` — populates `VOLUME_ARGS` array (socket is passed from `setting.docker_socket`; OpenCode config dir mounted `:ro`)
- `build_common_docker_args` — populates `DOCKER_COMMON_ARGS` array (--rm, --network host, `--user <host uid>:<host gid>`, `--group-add coder`, `--cap-drop=ALL`, `--security-opt no-new-privileges:true`, TERM, `OPENCODE_DOCKERIZED_POLICY`, `OPENCODE_CONFIG_CONTENT`, `OPENCODE_DISABLE_AUTOUPDATE`)
- `ensure_opencode_dirs` — creates required host directories, seeds the state tree and installs the versioned security layer (`ensure_opencode_dockerized_config`: `plugins/security-guard.js` from the repo + `policies/*.json` with their `policies/VERSION` marker, mirrored into `$OCODE_HOME/.config/opencode`)
- `check_image "$IMAGE_NAME"` — validates Docker image exists
- `sanitize_container_name "$name"` — strips invalid Docker container name characters
- `generate_random_suffix` — produces random hex for unique container names
- `ensure_gpg_mirror` / `resolve_gpg_agent_socket` / `resolve_gpg_agent_extra_socket` — mirror the host's public GnuPG material into `$OCODE_HOME/.gnupg` (adding `no-autostart` to the mirrored `gpg.conf`) and locate the gpg-agent socket, preferring the restricted `S.gpg-agent.extra`; `build_mount_args`/`build_env_args` mount the mirror plus socket and set `GNUPGHOME` when `setting.gpg_agent_support=true` (private keys never shared)

### Main Entry Point Pattern

```bash
main() {
    check_docker
    local command="${1:-run}"
    shift || true
    case "$command" in
        run)    check_config; run_opencode "$@" ;;
        build)  build_image ;;
        config) show_config "$@" ;;
        clean)  clean_image ;;
        help|--help|-h) show_help ;;
        *)      print_error "Unknown command: $command"; show_help; exit 1 ;;
    esac
}
main "$@"
```

### Config File Format

INI-style (`key.name=value`), parsed with `while IFS='=' read -r key value` loops:
```ini
setting.ssh_agent_support=true
setting.gpg_agent_support=false
setting.docker_socket=false
setting.security_policy=balanced
setting.memory=4g
setting.cpus=2
setting.env_file=~/.config/opencode-dockerized/env
setting.websearch_provider=exa
setting.theme=catppuccin
mount.gitconfig=~/.gitconfig:/home/coder/.gitconfig
```

Secrets only travel via `setting.env_file` (dotenv file under `~/.config/opencode-dockerized/`,
`docker --env-file`, never mounted). The old `env.*` host passthrough was removed.

### Dockerfile Conventions

- Base image: `debian:trixie-slim` (pinned, not `latest`)
- Set `SHELL ["/bin/bash", "-o", "pipefail", "-c"]` so RUN pipelines fail fast
- Parameterize tool versions via `ARG`: `ARG NVM_VERSION=v0.40.8`, `ARG PNPM_VERSION=12.5.1`, `ARG OPENCODE_VERSION=latest`
- Install pnpm with the official standalone script (`curl -fsSL https://get.pnpm.io/install.sh | env PNPM_VERSION="${PNPM_VERSION}" ENV="$HOME/.bashrc" SHELL="$(which bash)" sh -` — `SHELL`/`ENV` are required in Docker builds) and put `$PNPM_HOME/bin` on `PATH` via `ENV`
- Install global packages with `pnpm add -g` (never `npm install -g`), passing `--allow-build=<pkg>` since pnpm blocks lifecycle scripts by default; keep npm/npx available for `npx`-based MCP servers
- Clean apt cache in same RUN layer: `&& rm -rf /var/lib/apt/lists/*`
- Install Docker CLI only (`docker-ce-cli`), never the daemon
- No sudo: neither a sudoers entry nor the `sudo` binary (the agent must never gain root; the container starts as the host user via `--user`, `--cap-drop=ALL` and `no-new-privileges`, Docker access via `--group-add`)
- System packages as root; dev tools (NVM, uv) as non-root `coder` user
- Non-root user: `useradd -m -s /bin/bash -u 1000 coder`
- Create NVM default symlink for PATH: `ln -sf $(dirname $(which node)) $NVM_DIR/default`
- Cache-busting `ARG OPENCODE_BUILD_TIME` only used by `update`, not regular `build`
- Use official installers from trusted sources

### Security Rules

- OpenCode config tree (`$OCODE_HOME/.config/opencode`) mounted **read-only**; the security layer is mirrored into it on the host and delivered by that single mount. Sandbox permissions go inline via `OPENCODE_CONFIG_CONTENT`. The wrapper's `$CONFIG_DIR` is never mounted. Data/state/cache dirs are read-write; `~/.mcp-auth` is read-write
- **Never commit:** `.env`, `auth.json`, `*.pem`, `*.key`, credentials
- Docker socket is **opt-in** (`setting.docker_socket`, default `false`): mount the host socket only on request, no privileged mode, grant the socket GID via `--group-add` (no root step). It is root-equivalent on the host.
- SSH agent forwarding is **opt-in** (`setting.ssh_agent_support`, default `false`): forwards only `SSH_AUTH_SOCK` and mounts `~/.ssh/config`/`known_hosts` read-only; private keys are never mounted and a custom mount of `~/.ssh` is refused
- GnuPG agent forwarding is **opt-in** (`setting.gpg_agent_support`, default `false`): mirrors only public material, prefers the restricted `S.gpg-agent.extra` socket, and sets `no-autostart`; private keys are never copied
- Security policy is configurable (`setting.security_policy`, default `balanced`) and passed to the hook as `OPENCODE_DOCKERIZED_POLICY`
- Sandbox permission rules are generated at `$CONFIG_DIR/opencode.json` (host-only) and passed inline via `OPENCODE_CONFIG_CONTENT`; `$CONFIG_DIR` itself is never mounted
- The OpenCode config tree is mounted **read-only**; the security files are mirrored into it on the host by `ensure_opencode_dockerized_config`. A non-managed `AGENTS.md` is backed up to `AGENTS.md.user.bak` before the rules are installed
- `plugins/security-guard.js` is the guard source of truth; bump `OPENCODE_DOCKERIZED_GUARD_VERSION` when changing its behavior so installs refresh (previous copy backed up to `.bak`)
- Prefer `policies/allow-patterns.json` or a policy mode over editing the vendored `policies/*.json`
- In `balanced` mode the guard drops broad, whole-string false positives (e.g. `history-1`, `dns-exfil-3`, `exec-builtin`, `fork-bomb-2`, `env-direct-2`) via `BALANCED_EXCLUDED_IDS`; `strict` keeps them all
- Writes are allowed only inside the project directory and `/tmp/opencode` (the advertised scratch dir); the generated `opencode.json` allowlists `/tmp/opencode/*` for writes and the guard mirrors that root
- OpenCode self-update is disabled in the container via `OPENCODE_DISABLE_AUTOUPDATE=true`
- Run as non-root `coder` inside container; the wrapper maps the host user with `--user <host uid>:<host gid>` so no root process runs
- Use `--rm` for automatic container cleanup; `--network host` for simplicity
- Custom user mounts default to read-only
- Only pass environment variables explicitly listed in config
- Container names sanitized to prevent injection via directory names

## Volume Mounts Reference

| Host Path | Container Path | Mode | Purpose |
|-----------|---------------|------|---------|
| `$PROJECT_DIR` | `$PROJECT_DIR` (with `$HOME` stripped) | rw | Project files |
| `~/.config/opencode-dockerized/home/.config/opencode/` | `/home/coder/.config/opencode/` | ro | Self-contained config: MCP servers, `cli.json`, skills, agents, commands, plugins. The security files (`AGENTS.md`, `plugins/security-guard.js`, `plugins/policies/`) are mirrored into this tree on the host by `ensure_opencode_dockerized_config` |
| `~/.config/opencode-dockerized/home/.local/share/opencode/` | `/home/coder/.local/share/opencode/` | rw | Auth database, sessions |
| `~/.config/opencode-dockerized/home/.local/state/opencode/` | `/home/coder/.local/state/opencode/` | rw | Selected model, prompt history, locks |
| `~/.config/opencode-dockerized/home/.cache/opencode/` | `/home/coder/.cache/opencode/` | rw | Provider cache |
| `~/.mcp-auth/` | `/home/coder/.mcp-auth/` | rw | MCP OAuth store (`mcp-remote`) |
| `~/.claude/` | `/home/coder/.claude/` | ro | Claude Code compat: CLAUDE.md rules, skills/ |
| `~/.agents/` | `/home/coder/.agents/` | ro | Agent-compatible skills (skills/<name>/SKILL.md) |
| `~/.composio/` | `/home/coder/.composio/` | rw | Composio CLI binary + login (custom `mount.composio`) — treat `user_data.json`/`config.json` as credentials |
| `~/.config/opencode-dockerized/home/.gnupg/` | `/home/coder/.gnupg/` | rw (opt-in) | Mirrored **public** GnuPG material (pubring/trustdb/gpg.conf) + agent socket, only when `setting.gpg_agent_support=true`; `private-keys-v1.d/` is never copied |
| `/var/run/docker.sock` | `/var/run/docker.sock` | rw (opt-in) | Docker socket, only when `setting.docker_socket=true` |

The wrapper's own directory (`~/.config/opencode-dockerized/`) is **never** mounted. Its `opencode.json` (sandbox permissions) is read on the host and passed inline via `OPENCODE_CONFIG_CONTENT`; its `AGENTS.md`, guard and policies are sourced from there and mirrored into the config tree.
