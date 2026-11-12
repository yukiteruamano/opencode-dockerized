# Changelog

All notable changes to opencode-dockerized. Versions follow `WRAPPER_VERSION`;
the guard (`OPENCODE_DOCKERIZED_GUARD_VERSION`) and the policy set
(`policies/VERSION`) carry their own counters.

## 0.16.0 (unreleased) — profile layout, multi-account profiles and balanced-mode false positives

### Layout change (migrated automatically)
- Profiles are now the only layout: every run uses a profile, `default` when
  no `--profile` is given, at `~/.config/opencode-dockerized/profiles/default/`.
  The base keeps only install-wide state: the update/install lock
  (`.lock`/`.lock.d`), `.previous-rev` (rollback) and `gnupg-relay/`.
- On the first run of 0.16 (normally the `update` that installs it), a
  pre-0.16 setup — config, secrets file, generated permissions, security
  layer, sessions and the OpenCode home with its auth database — is moved
  from the base into `profiles/default` (`lib/profiles-lib.sh`). Each entry
  is renamed into a stage that is renamed into place at the end, so an
  interrupted move resumes on the next run; `setting.env_file` pointing into
  the old tree follows the move (keeping its `~/` form, mode 600 preserved).
  The move runs under the install lock (and under the parent's lock in the
  post-pull re-exec of `update`), waits while a session started by the old
  version is still running (that run keeps the old tree), never merges into
  an existing `profiles/default` (leftovers are reported, not deleted), and
  fails closed — no container starts — on a conflict.
- `profile remove default` is refused; `profile create --from default` copies
  the default profile like any other; `profile list` shows only real profiles.
- `--profile=` with an empty name is refused instead of falling back.
- A `~/` form of `setting.env_file` (written by the migration and shown in
  the docs) is now expanded by every reader, not only by `docker --env-file`:
  the layer check no longer reports it "not found" (which made `update` end
  as INCOMPLETE), `config show` counts its keys, and adding keys through
  `install` no longer creates a literal `~` directory in the current dir.

### Profiles (multi-account)
- `--profile NAME` (or `OPENCODE_DOCKERIZED_PROFILE=NAME`) selects a
  self-contained state tree under `~/.config/opencode-dockerized/profiles/NAME`:
  its own wrapper config (e.g. one profile `security_policy=strict`, another
  `balanced`), env file (provider account), generated permissions, security
  layer and OpenCode home (auth database, sessions, state, cache).
- New `profile` command: `list`, `current`, `path`,
  `create NAME [--from NAME]`, `remove NAME [--yes]`; plus a
  non-interactive `config init`.
- The profiles base is a protected location: a session in one profile cannot
  mount or open another profile's tree (credentials, auth database).
- Secrets are per profile: `setting.env_file` must live under the active
  profile's tree (the existing containment check now anchors there), the
  generated config template points its env-file example at the profile's own
  directory, and `profile create --from` repoints the copied `env_file` at
  the new tree, seeds an empty mode-600 file and never copies the source
  account's secrets.
- Container names and the `OPENCODE_DOCKERIZED_PROFILE` indicator carry the
  profile; `config show` and `doctor` print it.

### Command surface and documentation sync
- New `tests/commands-smoke.test.sh`: every command's happy path, its
  documented refusals (`mcp add`, `plugin add/remove`, extra `run` args,
  invalid profile names, unconfirmed `profile remove`) and help drift are
  exercised against a stub docker; `tests/completions.test.sh` now covers
  `profile <TAB>`, `config init` and `--profile <TAB>` profile-name completion.
- `profile create` seeds the config template before syncing the security
  layer, so the first sync no longer warns about a missing config.
- Documentation synced with behavior: the removed `env.*` passthrough no
  longer appears as a config format, the completion feature list, command
  lists, file reference and troubleshooting names match the real commands and
  container names, and `policies/README.md` documents the mandatory
  classification of new vendored injection rules.
- `tests/policy-lint.test.mjs` timing budgets re-measure (min of three) only
  when over budget, so scheduler noise on a loaded host no longer flakes the
  suite while real quadratic blowups still fail (guard v21 already flaked).

### Guard (v22) — balanced mode stops flagging everyday development
- Verified false positives dropped from `balanced` (kept in `strict`):
  `.env` reader rules without a word boundary (matched `process.env`), Python
  idiom heuristics (`re.compile(`, `getattr`, `importlib`, `[::-1]`),
  `for`/`while` loops containing `&&`, `LD_LIBRARY_PATH`/`LD_PRELOAD`,
  `xxd <file>`, `JSON.stringify`+`process`, `sleep NNNN`, and the blanket
  `ln -s` rules. These also blocked *writing* ordinary source files.
- Prompt-injection prose rules (role-play, "ignore instructions",
  decode-and-run wording) now apply only to `webfetch`/`websearch` in
  `balanced`: on shell they scanned the agent's own commit messages and
  searches. Literal base64 payload rules still apply to shell;
  `strict` keeps everything everywhere. `tests/policy-lint.test.mjs` forces a
  classification for every vendored injection rule.
- New targeted builtins (every mode): `ln -s` targets are resolved and denied
  when they alias `$HOME` outside the writable roots or a sensitive system
  tree (in-project symlinks and `/usr/...` links stay allowed), and
  `printf`/`echo` hex escapes are denied only inside a command substitution
  (ANSI color output stays allowed).

## Unreleased — security audit fixes

### Guard (v21)
- Persistence through git config and git hooks is blocked.
- Environment dumps get an additional backstop, and `/proc/<pid>/task/<tid>/environ`
  is treated like `/proc/<pid>/environ`.
- Write confinement follows symlinks.
- The read tool covers `.env*` files and relative paths.
- False positives reduced; cloud metadata endpoints covered more broadly;
  regex evaluation bounded against ReDoS.

### Config library
- Git worktree trust, a canonicalised mount guard, project dir validation,
  fail-closed permission refresh, `setting.env_file` containment, GnuPG mirror
  symlink handling, and test-only hooks gated behind
  `OPENCODE_DOCKERIZED_TEST_HOOKS=1`.

### Wrapper and installer
- `install.sh` verifies the target commit (upstream head, branch tip, tag or
  SHA) **before** fast-forwarding or checking out, so a refused signature never
  moves HEAD; fresh clones are made without a working tree until verified, and
  an offline refresh still verifies HEAD.
- `OCODE_REF=<branch>` on a reused checkout follows `origin/<branch>` (tracking
  branch created or fast-forwarded); tags and SHAs are checked out as before.
- New `OCD_SIGNING_FINGERPRINTS` (space-separated) pins the trusted signing
  keys for `update`/`upgrade` and `install.sh` (`%G?` G or U, `%GF`/`%GP` in the
  list). Without it a valid signature from any keyring key is accepted, as before
  (docs now say so).
- `update` flags incoming host-executed code (`bin/`, `lib/`, `install.sh`,
  `scripts/`, `completions/`) and asks for confirmation on a TTY (`--yes` skips).
- `:previous` is only re-tagged when the rebuild produced a different image ID,
  so repeated updates keep the good rollback target; `rollback` reminds to run
  `config sync` after the printed `git reset`.
- The drift label hashes `Dockerfile` + `entrypoint.sh`, so entrypoint changes
  mark the image stale.
- Dockerfile: the Docker apt key file must contain exactly one primary key with
  the pinned fingerprint.
- `run DIR extra…` now fails instead of silently ignoring the extra arguments
  (`run -- DIR` still works).
- `doctor` warns when no memory limit applies.
- The installer refuses install paths containing `$`, backtick, `"`, `\` or a
  newline (they would be evaluated in rc files); completion lines now live in a
  marked block that a re-install from a moved checkout replaces.
- Completions: `--full` for `update`/`upgrade`; bash no longer offers config
  subcommands after `debug config`; zsh `config opencode <TAB>` offers
  `path|edit`.
- `scripts/check-version-bumps.sh` fails when the guard marker or
  `policies/VERSION` is missing or decreased (numeric compare).
- Docs: what is and is not pinned in the image, `--pull` vs. the digest-pinned
  base, the `--network host` exposure of abstract unix sockets (prefer
  `setting.network=bridge`), resource limits and the corrected colour-default
  snippet in `AGENTS.md`.

## 0.15.0 (unreleased)

### Security
- Guard v20: shell obfuscation (quotes, escapes, ANSI-C, `$IFS`, braces, globs)
  is normalised before matching; env dumps, destructive targets and egress of
  secrets are caught behind wrappers and equivalent paths; web fetch refuses
  non-http(s) and metadata targets and asks for loopback/private ones; writes to
  git hooks are denied and agent/CI/editor config asks; `git push` behind
  options asks; multi-resource, malformed and oversized inputs fail closed; an
  audit log records decisions without the command text.
- Skills are mounted read-only per path (`~/.claude/{skills,agents,commands,CLAUDE.md}`,
  `~/.agents/skills`); the rest of `~/.claude` is no longer visible. `~/.npmrc`
  is opt-in (`setting.mount_npmrc`). Custom mount modes are validated.
- Policies v4: two vendored patterns with catastrophic backtracking were
  rewritten (documented in `policies/README.md`); `SOURCE.json` and
  `SHA256SUMS` record provenance and integrity.
- The security layer is verified and installed by content, atomically, with
  rotated backups; a failed install stops the wrapper instead of running unguarded.

### Reproducibility and updates
- Image: base by digest; Node, uv, pnpm, nvm, OpenCode and the Docker CLI pinned;
  installers verified by sha256; Docker repository fingerprint checked; provenance
  labels; allowlist `.dockerignore`.
- `update`: no longer exits early when up to date; `--full`; always pulls the base;
  weekly package refresh; newest OpenCode release resolved from npm; merges the
  exact SHA shown; lists incoming changes; opt-in signature check; re-executes
  the pulled code; keeps `:previous`; `rollback`; locking; `--check --json` with
  exit codes 0/10/1 that also compare the OpenCode release.
- `install.sh`: strict mode, truncation-safe, `OCODE_REF`, opt-in signature check;
  the installer is idempotent, follows custom install dirs and fails loudly.
- CI: SHA-pinned actions, weekly schedule, Node matrix, image build + smoke +
  Trivy + SBOM, version-bump enforcement, all wrapper tests; Dependabot.

### Integration
- `docker run`: `--init`, pids/memory limits, scratch tmpfs, locale, label,
  `host.docker.internal` on bridge; exit codes propagate; INT/TERM exit.
- Private per-user temp dir; relay cleanup spares live sessions; the GnuPG
  mirror is not reset under a live session.
- `doctor` checks the host side, read-only mounts, skills, scratch and limits.
- Completions and help cover every command; the private-server script fails fast.

### Not done / needs a real environment
- The image has not been built in this environment (no Docker daemon): the
  `image` CI job is the first full build of the new Dockerfile.
- Whether OpenCode V2 loads project-level plugins from `.opencode/` and the exact
  names of its tool actions are unverified (the guard logs unknown actions).
