# Security Model

`opencode-dockerized` sandboxes an autonomous coding agent. It reduces blast
radius; it is **not** a hard security boundary against a determined attacker.
This document states what it does and does not protect against.

## Threat model

The agent is untrusted code execution: it may run arbitrary shell commands,
edit files, and fetch URLs, and it may be steered by untrusted content (prompt
injection). The wrapper's job is to keep that activity inside a container with
the least access it needs to be useful.

## What is enforced

| Control | How |
|---------|-----|
| Non-root execution | Image has no `sudo` (no binary, no sudoers); the wrapper starts the container with `--user <host uid>:<host gid>` and `--cap-drop=ALL`, so no root process runs at any point and `entrypoint.sh` performs no privilege changes |
| Project-only writes | Only the project directory and the self-contained state tree are mounted; a plugin hook denies edits whose absolute path is outside the project (resolving symlinks via `realpath`, so a link inside the project cannot be used to escape) |
| Secret reads | Generated `permissions` deny rules plus the security hook refuse reads of `.env` (except `.env.example`), `*.pem`, `*.key`, `auth.json`, `credentials*`, `~/.npmrc`, `~/.mcp-auth/`, `~/.ssh/`, SSH keys (`id_rsa`, `id_eddsa`, `id_ecdsa`, `id_dsa`) and `private-keys-v1.d/` — both via the `read` tool and from shell commands |
| GnuPG agent forwarding (opt-in) | `setting.gpg_agent_support=true` mirrors only the public keyring (`pubring.kbx` / `public-keys.d`) and forwards the host `gpg-agent` socket (preferring the restricted `S.gpg-agent.extra`), mounted at a dedicated path and exposed through a symlink in the mirrored keyring (a nested bind mount could be shadowed by Docker); the host agent is started on demand unless `setting.gpg_autostart_agent=false` (after a `gpg-connect-agent` liveness probe, so a live agent is not relaunched); the mirrored config keeps `use-keyboxd` and sets `no-autostart`, and the container starts keyboxd at boot so gpg can read the mirrored keyboxd database; the full-control main socket is only used with `setting.gpg_allow_main_socket=true`; `private-keys-v1.d/` is never copied or mounted, and a custom mount of `~/.gnupg` is refused |
| SSH agent forwarding (opt-in) | `setting.ssh_agent_support=true` forwards only the host `SSH_AUTH_SOCK` and mounts `~/.ssh/config`/`known_hosts` read-only; private keys (`id_*`, `*.pem`, `*.key`) are never mounted, and a custom mount of `~/.ssh` is refused |
| Dangerous commands | Deny rules + hook backstops for `sudo`, `rm -rf /`, `mkfs`, `dd of=/dev/…`, `shutdown`/`reboot`; `git push` requires approval |
| Self-protection | The OpenCode config tree is mounted **read-only**; the security files (`AGENTS.md`, `security-guard.js`, `policies/`) are mirrored into it on the host by the wrapper, so a session cannot relax its own rules or add a persistent plugin/MCP server. Sandbox permission rules are passed inline (`OPENCODE_CONFIG_CONTENT`), not from a writable file |
| Policy patterns | The vendored `opencode-policy` pattern sets, evaluated by `plugins/security-guard.js` (see `policies/README.md`) |

## Known limitations

- **Docker socket is opt-in but root-equivalent.** With
  `setting.docker_socket=true` the container gets the host Docker socket, which
  allows mounting `/` and escaping to host root. It is **off by default**;
  enable it only for Docker-in-Docker / Testcontainers.
- **`--network host`.** The container shares the host network namespace, so it
  can reach host services and the internet without restrictions.
- **GnuPG agent forwarding is a signing oracle.** With
  `setting.gpg_agent_support=true` the container can ask the host `gpg-agent` to
  sign arbitrary data while it runs; it cannot read the private keys. Pinentry
  runs on the host agent, so it is independent of the container's desktop
  environment (KDE/GNOME/sway/i3/awesome/LXQt); a terminal-only pinentry needs
  `gpg-connect-agent updatestartuptty /bye` on the host. It is **off by default**;
  enable it only when you need signed commits/tags.
- **SSH agent forwarding is a signing oracle.** With
  `setting.ssh_agent_support=true` the container can authenticate/sign with the
  host agent while it runs; it cannot read the private keys. Destructive agent
  operations (`ssh-add -D/-d/-x/-X/-e`) and host-agent control
  (`gpgconf --kill/--reload`) are blocked, but anything the agent is authorised
  for can be used from the container. **Off by default.**
- **Agent sockets are bind-mounted, not created.** The SSH/GPG agent sockets are
  attached with `--mount type=bind`, so a stale or missing source fails instead
  of Docker creating a directory at the host socket path (which would break the
  real agent). If a previous run left a directory at
  `$XDG_RUNTIME_DIR/gnupg/S.gpg-agent*`, remove it on the host.
- **GPG needs a mirrored public keyring.** If no `pubring.kbx` /
  `public-keys.d/pubring.db` exists in the host `GNUPGHOME`, signed commits fail;
  the wrapper warns instead of failing silently, and `opencode-dockerized doctor`
  reports it from inside the container.
- **`config sync` writes host state (by design).** Only `config sync --check` is
  side-effect free: plain `sync` creates missing directories, refreshes the
  versioned layer (backing up replaced files) and reseeds a broken `cli.json`.
  User files (`config`, env file, MCP/servers config) are never modified.
- **GPG socket relay.** Many Docker setups cannot bind a socket under a per-user
  tmpfs (`/run/user/<uid>/gnupg/…`) — they create an empty directory instead. The
  wrapper relays the restricted `S.gpg-agent.extra` socket through a socket on a
  normal filesystem (`socat`, under the wrapper config dir) for the lifetime of
  the session; only that socket is relayed, never the main one. Install `socat`;
  without it GPG forwarding is skipped with a warning (`setting.gpg_relay=false`
  disables the relay).
- **No read-only root filesystem.** `--cap-drop=ALL` and
  `--security-opt no-new-privileges:true` are enabled, but the rootfs stays
  writable (the image's `/home/coder` is owned by the `coder` group and
  group-writable, and the wrapper joins that group with `--group-add coder`, so
  an arbitrary host UID can use the non-mounted caches). Adding `--read-only`
  with tmpfs mounts is future hardening work.
- **Policy patterns are heuristics.** They can both miss traffic and (in
  `strict` mode) flag legitimate commands. `balanced` mode drops the most
  common false positives; `off` disables the vendored patterns while keeping
  the built-in backstops. Commands are evaluated per shell segment, so an
  anchored pattern can fire on a segment (`cmd --yes && ...` trips `dos-yes`,
  which is why `balanced` drops the `dos-yes*` rules while `strict` keeps them).
- **Project mount is read-write and shares the host filesystem.** The agent can
  modify (or delete) anything inside the mounted project directory.
- **Config runtime files are read-only.** `service.json`/`cli.json` in the
  (read-only) config dir are not written back, so any in-session change to them
  does not persist. The CLI and local server were verified to start and run with
  the config dir read-only.
- **MCP auth store is read-write.** `~/.mcp-auth` is mounted read-write so
  `mcp-remote` OAuth tokens persist; the agent can read or alter those tokens.
- **Config is read-only, so config changes are host-only.** `opencode mcp add`
  and `opencode plugin add/update/remove` do not work from the container; edit
  the OpenCode config on the host (`opencode-dockerized config opencode edit`).
- **Environment variables in the container are visible to the agent.** Provider
  keys from the secrets file (e.g. `OPENCODE_API_KEY`, `EXA_API_KEY`) end up in
  the container environment and in `docker inspect` on the host. This is
  intentional (it is how OpenCode is configured) but means a session can read
  its own provider credentials; keep unrelated host secrets out of the env file.
- **Secret reads are heuristic.** Reads of `.env` (except `.env.example`),
  `*.pem`, `*.key`, key-like file names (including bare `*key`), `auth.json`,
  `credentials*`, `~/.npmrc`, `~/.mcp-auth/`, `~/.ssh/`, `~/.gitconfig` and
  `~/.composio/` are denied via the `read`/`grep`/`glob` actions and the shell
  backstops; an obfuscated command could still reach data that is not mounted at
  all. The bare `*key` heuristic also blocks unrelated names ending in "key"
  (e.g. `monkey`).
- **Inline secrets in `opencode.json` abort the run.** Credentials in the user
  OpenCode config must use `{env:VAR}` (or `{file:path}`) substitution; literal
  `apiKey`/`token`/`secret`/`password` values are rejected by the wrapper and
  reported by `doctor`. Keep the values in `setting.env_file` (never mounted,
  passed via `docker --env-file`).
- **Bare environment dumps are denied.** `env`, `printenv`, `set`, `export`,
  `declare` and `typeset` with no arguments (plus `export -p`, `declare -p`,
  `typeset -p`, `compgen -e`, `compgen -v`, `declare -x`, `typeset -x`) are
  blocked in every policy mode; scoped uses (`printenv PATH`,
  `env FOO=1 cmd`, `set -e`, `declare -A map`) stay allowed. Targeted reads of
  secret-like names (`printenv SECRET`, `printenv *_KEY`, `*_TOKEN`,
  `*_PASSWORD`, `*CREDENTIAL*`) are denied; `echo $VAR` expansion stays allowed
  by design (blocking it would break ordinary scripting).
- **Bulk interpreter dumps are denied, member access stays allowed.**
  `console.log(process.env)`, `print(os.environ)`, `puts ENV`, `print %ENV`,
  `print_r($_ENV)` and `Deno.env.toObject()` dumps are blocked in every mode;
  single-variable reads (`process.env.PATH`, `os.environ.get("X")`,
  `ENV["X"]`, `$ENV{X}`, `getenv("X")`) stay allowed — they are normal config
  reads, and blocking them would break ordinary apps. Staged copies
  (`x = {...process.env}` printed later) remain a documented residual.
- **Destructive root targets are denied.** `rm -rf /`, `rm -rf /*` and `rm`
  with `/..` traversals, `chmod 777 /|/*|traversal` and `chown /|traversal`,
  `mkfs`, `dd of=/dev/…` and `>/dev/sd*` are blocked in every mode.
  Project-scoped deletion (`rm -rf dist/*`, `rm -rf .`) stays allowed: the
  project mount is read-write by design.
- **Proc/metadata/docker-escape backstops are mode-independent.** Reads of
  `/proc/*/environ`, the cloud metadata IP (literal, decimal, hex and octal
  forms) and `docker -v /:/`, `--volume /:/` and `--mount …,source=/,…`
  mounts plus `docker --privileged` are blocked even with
  `setting.security_policy=off` (the vendored patterns alone only cover them in
  `balanced`/`strict`). Named volumes and host subdirectories stay allowed.
- **Git exfiltration over key material is denied.** `show`/`cat-file` of
  `rev:path` key paths, `log -p`, non-`--stat` `diff`, `grep` and `archive`
  over `*.key`/`*.pem`/key-like names are blocked in every mode; `git log
  --oneline`, `git show HEAD:README.md` and `git diff --stat` stay allowed.
- **Renamed extractor binaries are denied (token-gated).** A local executable
  (`./k`, `/tmp/…`) with `ssh-keygen -y -f` or `openssl … -in/-text` flag
  shapes over a key-like target is blocked; the same flags over ordinary files
  (`./backup.sh -y -f /tmp/bak`) stay allowed. Plain renamed readers without
  extraction flags (a copied `cat` reading `deploy_key`) remain a documented
  heuristic residual — like staged copies, they cannot be closed without
  breaking legitimate file management (`ls`/`rm`/`chmod` over key files).
- **Write confinement depends on the hook.** The generated `permissions` cannot
  encode a project-scoped write rule (the project path is dynamic), so edits are
  confined by the `security-guard` hook — including relative targets, which are
  resolved against the project directory; if the plugin fails to load, writes fall
  back to the runtime default. The config tree is mounted read-only and the guard
  is delivered read-only, so a session cannot relax it.
- **Prompt injection is only partly mitigated.** Rules and hooks reduce the
  impact; they do not make the agent trustworthy. Review its actions.

## Reporting a vulnerability

Open a private security advisory on the repository, or email the maintainers.
Please include a reproduction (command, `DRY_RUN=true` output, and container
configuration) and the expected vs. observed behavior. Do not open a public
issue for exploitable findings before a fix is available.
