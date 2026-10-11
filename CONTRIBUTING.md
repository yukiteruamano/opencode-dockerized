# Contributing

Thanks for helping improve `opencode-dockerized`. This project is pure Bash
plus one small Node.js security plugin and vendored JSON policy data.

## Before you start

```bash
./install.sh          # installs bin/ on PATH, creates ~/.config/opencode-dockerized + security layer
opencode-dockerized build
```

## Checks (run before opening a PR)

CI runs all of these; you can run them locally:

```bash
# 1. Syntax
bash -n bin/opencode-dockerized install.sh opencode-dockerized.sh setup.sh run-simple.sh
for f in lib/*.sh completions/*.sh scripts/*.sh tests/*.sh; do bash -n "$f"; done

# 2. ShellCheck (any of these)
shellcheck -x -S warning bin/* lib/*.sh install.sh setup.sh opencode-dockerized.sh run-simple.sh completions/*.sh scripts/*.sh tests/*.sh
# …or without a local install:
uvx --from shellcheck-py shellcheck -x -S warning bin/* lib/*.sh scripts/*.sh tests/*.sh install.sh

# 3. Dockerfile
cat Dockerfile | docker run --rm -i hadolint/hadolint:latest hadolint -
# …or: uvx --from hadolint-py hadolint --config .hadolint.yaml Dockerfile

# 4. Every test (Node.js 20+; none of them needs Docker)
node --check plugins/security-guard.js
for t in tests/*.test.mjs; do node "$t"; done
for t in tests/*.test.sh; do bash "$t"; done
```

The wrapper tests drive the real binary against a throw-away HOME, a local git
origin and a stub `docker` that records its arguments, so update, install, run,
clean, doctor and the image build flags are covered without a daemon.
`tests/dockerfile-lint.test.sh` pins the image's supply-chain properties
statically. The image itself is built and smoke-tested by the `image` CI job.

## Style

- Follow the conventions in [AGENTS.md](AGENTS.md) (kebab-case scripts,
  snake_case functions, UPPER_SNAKE constants, quoted variables, `$()`, arrays
  for Docker arguments).
- Every executable script starts with `#!/bin/bash` + `set -e`;
  `lib/config-lib.sh` and `lib/install-lib.sh` are sourced libraries and must **not** use `set -e`.
- The binary is `bin/opencode-dockerized` (no extension), reached via
  `<install>/bin` on PATH. Nothing is ever placed in `~/.local/bin`
  (no symlink, stub or copy).
- Keep security the priority: never weaken a deny rule without a documented
  reason and a test.

## Security layer changes

- **`plugins/security-guard.js` is the source of truth.** It is copied into
  `~/.config/opencode-dockerized/plugins/` by `lib/config-lib.sh`, which compares
  file content; still bump `OPENCODE_DOCKERIZED_GUARD_VERSION` on any behavior
  change (CI enforces it on pull requests via `scripts/check-version-bumps.sh`).
  The replaced copy is kept as a timestamped `.bak.<stamp>`.
- **`policies/*.json` are vendored** from opencode-policy (`policies/README.md`),
  with the local patches listed in `policies/SOURCE.json`. To change behavior for
  local use, prefer the policy mode (`strict` / `balanced` / `off`) or
  `policies/allow-patterns.json` over editing them. After an intentional edit,
  bump `policies/VERSION`, refresh `policies/SHA256SUMS` (`cd policies && sha256sum
  *-patterns.json > SHA256SUMS`) and keep `tests/policy-lint.test.mjs` green: it
  fuzzes every rule against a time budget (no catastrophic backtracking).
- Add a case to `tests/security-guard-adversarial.test.mjs` (or
  `tests/security-guard.test.mjs`) for every new deny/allow behavior — both that
  the dangerous thing is blocked and that normal development is not.

## Updating pinned inputs

Everything the image installs is pinned (see AGENTS.md, "Dockerfile
Conventions"). `scripts/pins-report.sh` lists which pins have a newer release and
prints the sha256 of the current installers. Bump in small `chore(deps): …`
commits, review a changed installer before updating its hash, and run
`tests/dockerfile-lint.test.sh`. Dependabot handles the base-image digest and the
GitHub Actions SHAs.

## Releases

Releases are signed tags `vX.Y.Z` on `master` whose `WRAPPER_VERSION` matches;
`opencode-dockerized version` shows `git describe`, and `install.sh` can install
a tag (`OCODE_REF=v0.15.0`, optionally with `OCD_VERIFY_SIGNATURES=true`).
Describe user-visible changes in `CHANGELOG.md`.

## Docs

Update `README.md` (and `SECURITY.md` where relevant) for user-visible
changes. The wrapper config lives at `~/.config/opencode-dockerized/config`.
