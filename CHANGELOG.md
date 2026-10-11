# Changelog

All notable changes to opencode-dockerized. Versions follow `WRAPPER_VERSION`;
the guard (`OPENCODE_DOCKERIZED_GUARD_VERSION`) and the policy set
(`policies/VERSION`) carry their own counters.

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
