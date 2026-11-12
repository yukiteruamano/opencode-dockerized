#!/bin/bash
# Contract test for multi-account profiles: --profile / OPENCODE_DOCKERIZED_PROFILE
# select a self-contained state tree under <config>/profiles/<name> (own config,
# env file, security layer, OpenCode home), the profiles base stays protected
# from mounts and project dirs, and the profile subcommands manage the trees.
# Uses a throw-away HOME and a stub docker (no daemon needed).
#
# Usage: bash tests/profile-flow.test.sh

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export TMPDIR="${TMPDIR:-/tmp/opencode}"
mkdir -p "$TMPDIR" 2>/dev/null || export TMPDIR="/tmp"
TMP="$(mktemp -d -p "$TMPDIR")"
trap 'rm -r "$TMP" 2>/dev/null || true' EXIT

fail() {
    echo "FAIL: $1"
    [ -n "${OUT:-}" ] && printf '%s\n' "$OUT" | tail -15
    exit 1
}

export HOME="$TMP/home"
export CONFIG_DIR="$TMP/cfg"
# OCODE_HOME is deliberately NOT exported: it must derive from the profile's
# CONFIG_DIR, which is the whole point of the profile mechanism.
export OPENCODE_DOCKERIZED_ALLOW_CONTAINER_SYNC=1
mkdir -p "$HOME" "$TMP/proj" "$TMP/bin"
export PATH="$REPO_DIR/bin:$TMP/bin:$PATH"

export DOCKER_STUB_LOG="$TMP/docker.log"
cat >"$TMP/bin/docker" <<'STUB'
#!/bin/bash
echo "$*" >>"$DOCKER_STUB_LOG"
case "$1" in
run) exit "${DOCKER_STUB_RC:-0}" ;;
*) exit 0 ;;
esac
STUB
chmod +x "$TMP/bin/docker"

WRAPPER="$REPO_DIR/bin/opencode-dockerized"
run_wrapper() {
    : >"$DOCKER_STUB_LOG"
    OUT="$("$WRAPPER" "$@" 2>&1 </dev/null)"
    RC=$?
}
docker_run_line() { grep -m1 '^run ' "$DOCKER_STUB_LOG"; }

# 1. Path derivation: the whole tree moves under profiles/<name>.
run_wrapper --profile dev config path
[ "$RC" -eq 0 ] || fail "--profile dev config path must succeed (got $RC)"
[ "$OUT" = "$CONFIG_DIR/profiles/dev/config" ] || fail "profile config path must derive from the base (got $OUT)"

run_wrapper config path
[ "$OUT" = "$CONFIG_DIR/config" ] || fail "without a profile the classic path must be unchanged (got $OUT)"

# 1b. The environment variable selects the same tree; the flag wins over it.
OUT="$(OPENCODE_DOCKERIZED_PROFILE=dev "$WRAPPER" config path 2>&1)" || fail "env-var profile selection failed"
[ "$OUT" = "$CONFIG_DIR/profiles/dev/config" ] || fail "OPENCODE_DOCKERIZED_PROFILE must select the profile (got $OUT)"
OUT="$(OPENCODE_DOCKERIZED_PROFILE=other "$WRAPPER" --profile dev profile current 2>&1)" || fail "flag+env failed"
[ "$OUT" = "dev" ] || fail "--profile must win over the environment (got $OUT)"

# 1c. The flag is recognised anywhere before a literal `--`.
run_wrapper profile current --profile=dev
[ "$OUT" = "dev" ] || fail "--profile=NAME after the command must still select it (got $OUT)"

# 1d. Invalid names are refused before any path is derived.
run_wrapper --profile '../escape' config path
[ "$RC" -ne 0 ] || fail "a path-traversal profile name must be refused"
run_wrapper --profile '.hidden' config path
[ "$RC" -ne 0 ] || fail "a profile name must start with a letter or digit"
run_wrapper --profile '' config path
[ "$RC" -ne 0 ] || fail "an empty profile name must be refused"

# 2. profile create: seeds the tree, the security layer and a config template.
run_wrapper profile create dev
[ "$RC" -eq 0 ] || fail "profile create dev failed: $OUT"
[ -f "$CONFIG_DIR/profiles/dev/config" ] || fail "create must seed the profile config template"
[ -f "$CONFIG_DIR/profiles/dev/home/.config/opencode/plugins/security-guard.js" ] ||
    fail "create must install the security layer into the profile's OpenCode home"
# The template's env-file example must name the profile's own tree, not the
# default one (an env file outside the active CONFIG_DIR is refused at run time).
grep -q "# setting.env_file=$CONFIG_DIR/profiles/dev/env" "$CONFIG_DIR/profiles/dev/config" ||
    fail "the generated template must point its env-file example at the profile tree"
run_wrapper profile create dev
[ "$RC" -ne 0 ] || fail "creating an existing profile must fail"
run_wrapper profile create 'bad/name'
[ "$RC" -ne 0 ] || fail "an invalid profile name must be refused by create"

# 2b. list / current reflect the active profile.
run_wrapper profile list
grep -q '^default \*' <<<"$OUT" || fail "list must mark default as active without --profile: $OUT"
grep -q '^dev (' <<<"$OUT" || fail "list must show the created profile: $OUT"
run_wrapper --profile dev profile list
grep -q '^dev \*' <<<"$OUT" || fail "list must mark the selected profile: $OUT"
run_wrapper profile current
[ "$OUT" = "default" ] || fail "current must print default without --profile (got $OUT)"

# 3. Per-profile configuration: one profile strict, the default balanced.
printf 'setting.security_policy=strict\n' >"$CONFIG_DIR/profiles/dev/config"
run_wrapper --profile dev config show
grep -q 'strict' <<<"$OUT" || fail "profile config must drive config show: $OUT"
grep -q 'Profile: dev' <<<"$OUT" || fail "config show must name the active profile: $OUT"
run_wrapper config show
grep -q 'strict' <<<"$OUT" && fail "the default profile must not see the dev config"

# 3b. The profile's policy, state tree and name reach the container.
run_wrapper --profile dev run "$TMP/proj"
[ "$RC" -eq 0 ] || fail "--profile dev run must succeed with a stub docker: $OUT"
line="$(docker_run_line)"
grep -q -- ' -e OPENCODE_DOCKERIZED_POLICY=strict ' <<<"$line" || fail "profile policy must reach the container"
grep -q -- ' -e OPENCODE_DOCKERIZED_PROFILE=dev ' <<<"$line" || fail "profile indicator must reach the container"
grep -q -- "--name opencode-dev-" <<<"$line" || fail "the container name must carry the profile"
grep -q -- "$CONFIG_DIR/profiles/dev/home/.local/share/opencode" <<<"$line" ||
    fail "the auth/data mount must come from the profile's own home"
run_wrapper run "$TMP/proj"
line="$(docker_run_line)"
grep -q -- ' -e OPENCODE_DOCKERIZED_POLICY=balanced ' <<<"$line" || fail "default profile must stay balanced"
grep -q -- ' -e OPENCODE_DOCKERIZED_PROFILE=default ' <<<"$line" || fail "default indicator must be 'default'"

# 4. Isolation: another profile's state must be unreachable as mount or project.
run_wrapper profile create other
[ "$RC" -eq 0 ] || fail "profile create other failed: $OUT"
printf 'setting.security_policy=strict\nmount.leak=%s:/leak:ro\n' "$CONFIG_DIR/profiles/other" \
    >"$CONFIG_DIR/profiles/dev/config"
run_wrapper --profile dev run "$TMP/proj"
[ "$RC" -ne 0 ] || fail "mounting another profile's tree must be refused"
grep -qi 'profile\|wrapper config' <<<"$OUT" || fail "the refusal must name the protected location: $OUT"
printf 'setting.security_policy=strict\n' >"$CONFIG_DIR/profiles/dev/config"
run_wrapper --profile dev run "$CONFIG_DIR/profiles/other/home"
[ "$RC" -ne 0 ] || fail "another profile's home must be refused as a project directory"

# 4b. Per-profile secrets: each profile's env_file lives in its own tree.
install -m 600 /dev/null "$CONFIG_DIR/profiles/dev/env"
printf 'A_KEY=1\n' >"$CONFIG_DIR/profiles/dev/env"
printf 'setting.security_policy=strict\nsetting.env_file=%s\n' "$CONFIG_DIR/profiles/dev/env" \
    >"$CONFIG_DIR/profiles/dev/config"
run_wrapper --profile dev run "$TMP/proj"
[ "$RC" -eq 0 ] || fail "an env file under the profile's own tree must be accepted: $OUT"
docker_run_line | grep -q -- "--env-file $CONFIG_DIR/profiles/dev/env" ||
    fail "the profile's own env file must reach docker --env-file"

# The default tree's env file is outside the profile and must be refused.
install -m 600 /dev/null "$CONFIG_DIR/env"
printf 'setting.env_file=%s\n' "$CONFIG_DIR/env" >"$CONFIG_DIR/profiles/dev/config"
run_wrapper --profile dev run "$TMP/proj"
[ "$RC" -ne 0 ] || fail "the default tree's env file must be refused from a profile"
grep -qi 'outside' <<<"$OUT" || fail "the env refusal must say it is outside the config dir: $OUT"

# Another profile's env file must be refused too.
install -m 600 /dev/null "$CONFIG_DIR/profiles/other/env"
printf 'setting.env_file=%s\n' "$CONFIG_DIR/profiles/other/env" >"$CONFIG_DIR/profiles/dev/config"
run_wrapper --profile dev run "$TMP/proj"
[ "$RC" -ne 0 ] || fail "another profile's env file must be refused"

# 5. create --from copies the source profile's config.
printf 'setting.security_policy=strict\nsetting.env_file=%s\n' "$CONFIG_DIR/profiles/dev/env" \
    >"$CONFIG_DIR/profiles/dev/config"
run_wrapper profile create lab --from dev
[ "$RC" -eq 0 ] || fail "profile create --from failed: $OUT"
grep -q 'strict' "$CONFIG_DIR/profiles/lab/config" || fail "--from must copy the source config"
# Secrets are per account: the env_file is repointed at the new tree, the
# source secrets are not copied, and an empty 600 env file is seeded.
grep -q "^setting.env_file=$CONFIG_DIR/profiles/lab/env$" "$CONFIG_DIR/profiles/lab/config" ||
    fail "--from must repoint setting.env_file at the new profile"
[ -f "$CONFIG_DIR/profiles/lab/env" ] || fail "--from must seed an empty env file"
grep -q 'A_KEY' "$CONFIG_DIR/profiles/lab/env" && fail "--from must NOT copy the source secrets"
env_mode="$(stat -c '%a' "$CONFIG_DIR/profiles/lab/env" 2>/dev/null || stat -f '%Lp' "$CONFIG_DIR/profiles/lab/env")"
[ "$env_mode" = "600" ] || fail "the seeded env file must be mode 600 (got $env_mode)"
grep -q 'NOT copied' <<<"$OUT" || fail "--from must warn that secrets were not copied: $OUT"
# The copied profile must run with its own (empty) env file.
run_wrapper --profile lab run "$TMP/proj"
[ "$RC" -eq 0 ] || fail "the copied profile must run with its own env file: $OUT"
docker_run_line | grep -q -- "--env-file $CONFIG_DIR/profiles/lab/env" ||
    fail "the copied profile must pass its own env file to docker"

# 6. remove: confirmation is required, the active profile is refused.
run_wrapper profile remove lab
[ "$RC" -ne 0 ] || fail "non-interactive remove without --yes must be refused"
[ -d "$CONFIG_DIR/profiles/lab" ] || fail "a refused remove must leave the profile in place"
run_wrapper --profile lab profile remove lab
[ "$RC" -ne 0 ] || fail "removing the selected profile must be refused"
run_wrapper profile remove lab --yes
[ "$RC" -eq 0 ] || fail "profile remove --yes failed: $OUT"
[ ! -d "$CONFIG_DIR/profiles/lab" ] || fail "remove --yes must delete the profile tree"
run_wrapper profile remove nope --yes
[ "$RC" -ne 0 ] || fail "removing a missing profile must fail"

# 7. config init is idempotent and never overwrites.
printf 'setting.security_policy=strict\n' >"$CONFIG_DIR/profiles/dev/config"
run_wrapper --profile dev config init
[ "$RC" -eq 0 ] || fail "config init on an existing config must succeed"
grep -q 'strict' "$CONFIG_DIR/profiles/dev/config" || fail "config init must not overwrite an existing config"

echo "PASS: profile-flow"
