# Changelog

All notable changes to opencode-dockerized. Versions follow `WRAPPER_VERSION`;
the guard (`OPENCODE_DOCKERIZED_GUARD_VERSION`) and the policy set
(`policies/VERSION`) carry their own counters.

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
