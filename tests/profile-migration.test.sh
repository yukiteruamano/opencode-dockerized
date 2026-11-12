#!/bin/bash
# Contract test for the one-time move of a pre-profiles config tree into
# profiles/default (lib/profiles-lib.sh): what moves and what stays install-
# wide, the env-file rewrite, idempotency, deferral while an old-layout session
# runs or the install lock is busy, resume after an interruption, fail-closed
# conflicts, and leftovers next to an existing default profile.
# Uses throw-away HOMEs and a stub docker (no daemon needed).
#
# Usage: bash tests/profile-migration.test.sh

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export TMPDIR="${TMPDIR:-/tmp/opencode}"
mkdir -p "$TMPDIR" 2>/dev/null || export TMPDIR="/tmp"
TMP="$(mktemp -d -p "$TMPDIR")"
BG_PIDS=()
cleanup() {
    local p
    for p in "${BG_PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    rm -r "$TMP" 2>/dev/null || true
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1"
    [ -n "${OUT:-}" ] && printf '%s\n' "$OUT" | tail -15
    exit 1
}

export NO_COLOR=1
export OPENCODE_DOCKERIZED_ALLOW_CONTAINER_SYNC=1
unset CONFIG_DIR OCODE_HOME OPENCODE_DOCKERIZED_PROFILE OCD_LOCK_HELD
mkdir -p "$TMP/bin" "$TMP/proj"
export PATH="$REPO_DIR/bin:$TMP/bin:$PATH"
export DOCKER_STUB_LOG="$TMP/docker.log"
cat >"$TMP/bin/docker" <<'STUB'
#!/bin/bash
echo "$*" >>"$DOCKER_STUB_LOG"
exit 0
STUB
chmod +x "$TMP/bin/docker"

WRAPPER="$REPO_DIR/bin/opencode-dockerized"
run_wrapper() {
    : >"$DOCKER_STUB_LOG"
    OUT="$("$WRAPPER" "$@" 2>&1 </dev/null)"
    RC=$?
}

# A pre-profiles install: the default tree directly in the base, plus the
# install-wide entries and an already-created named profile.
# Usage: legacy_home NAME  (sets HOME, B)
legacy_home() {
    export HOME="$TMP/home-$1"
    B="$HOME/.config/opencode-dockerized"
    mkdir -p "$B/home/.local/share/opencode" "$B/home/.config/opencode" "$B/plugins/policies" \
        "$B/sessions" "$B/gnupg-relay/4242" "$B/profiles/work" "$B/vault"
    printf 'setting.security_policy=strict\nsetting.env_file=~/.config/opencode-dockerized/env\n' >"$B/config"
    chmod 600 "$B/config"
    install -m 600 /dev/null "$B/env"
    printf 'PROVIDER_KEY=default-account\n' >"$B/env"
    printf '{"token":"t"}\n' >"$B/home/.local/share/opencode/auth.json"
    printf '{"permissions":[]}\n' >"$B/opencode.json"
    printf 'rules\n' >"$B/AGENTS.md"
    printf 'abc123\n' >"$B/.previous-rev"
    : >"$B/.lock"
    printf 'setting.theme=catppuccin\n' >"$B/profiles/work/config"
}

# 1. The first run moves the tree; install-wide entries stay in the base.
legacy_home basic
run_wrapper config path
[ "$RC" -eq 0 ] || fail "the migrating run must succeed (got $RC)"
grep -q "migrated to the 'default' profile" <<<"$OUT" || fail "the migration must be reported"
grep -qx "$B/profiles/default/config" <<<"$OUT" || fail "the command must run against the migrated profile"
D="$B/profiles/default"
for moved in config env opencode.json AGENTS.md plugins sessions home vault; do
    [ -e "$D/$moved" ] || fail "$moved must move into profiles/default"
    [ ! -e "$B/$moved" ] || fail "$moved must not remain in the base"
done
for kept in .previous-rev .lock gnupg-relay profiles; do
    [ -e "$B/$kept" ] || fail "install-wide $kept must stay in the base"
done
[ ! -e "$D/.previous-rev" ] || fail ".previous-rev is install-wide and must not move"
grep -qx 'abc123' "$B/.previous-rev" || fail ".previous-rev must be untouched"
grep -q '"token":"t"' "$D/home/.local/share/opencode/auth.json" || fail "the auth database must keep its content"
grep -qx 'PROVIDER_KEY=default-account' "$D/env" || fail "the secrets must move with the profile"
[ "$(stat -c %a "$D/env" 2>/dev/null || stat -f %Lp "$D/env")" = 600 ] || fail "the env file must keep mode 600"
[ "$(stat -c %a "$D/config" 2>/dev/null || stat -f %Lp "$D/config")" = 600 ] || fail "the config must keep its mode"
grep -qx 'setting.env_file=~/.config/opencode-dockerized/profiles/default/env' "$D/config" ||
    fail "setting.env_file must follow the move and keep the ~/ form: $(cat "$D/config")"
grep -qx 'setting.security_policy=strict' "$D/config" || fail "other settings must be preserved"
grep -qx 'setting.theme=catppuccin' "$B/profiles/work/config" || fail "an existing named profile must be untouched"
[ ! -e "$B/profiles/.default.migrating" ] || fail "the staging dir must be gone after a migration"

# 1a. The rewritten `~/` env_file resolves everywhere: the layer check finds
# it (no "not found", which would mark the upgrade incomplete).
run_wrapper config sync --check
grep -q 'env file not found' <<<"$OUT" && fail "a ~/ env_file must be expanded by the layer check: $OUT"
grep -q 'env file permissions ok' <<<"$OUT" || fail "the layer check must find the migrated env file: $OUT"

# 1b. Idempotent: the next run is silent and changes nothing.
run_wrapper config path
[ "$OUT" = "$D/config" ] || fail "a migrated install must not migrate again (got: $OUT)"

# 1c. The migrated profile runs with its own env file and data mount.
run_wrapper run "$TMP/proj"
[ "$RC" -eq 0 ] || fail "run after the migration must succeed: $OUT"
line="$(grep -m1 '^run ' "$DOCKER_STUB_LOG")"
grep -q -- "--env-file $D/env" <<<"$line" || fail "run must use the migrated env file"
grep -q -- "$D/home/.local/share/opencode" <<<"$line" || fail "run must mount the migrated auth/data dir"
grep -q -- ' -e OPENCODE_DOCKERIZED_POLICY=strict ' <<<"$line" || fail "run must use the migrated policy"

# 2. Absolute env-file paths (also custom names) are rewritten too.
legacy_home absolute
printf 'K=1\n' >"$B/secrets.env"
chmod 600 "$B/secrets.env"
printf 'setting.env_file=%s\n' "$B/secrets.env" >"$B/config"
run_wrapper config path
grep -qx "setting.env_file=$B/profiles/default/secrets.env" "$B/profiles/default/config" ||
    fail "an absolute env_file must be rewritten: $(cat "$B/profiles/default/config")"
[ -f "$B/profiles/default/secrets.env" ] || fail "a custom-named env file must move"

# 2b. An env_file that already points into a profile is left alone.
legacy_home prepointed
printf 'setting.env_file=%s\n' "$B/profiles/work/env" >"$B/config"
run_wrapper config path
grep -qx "setting.env_file=$B/profiles/work/env" "$B/profiles/default/config" ||
    fail "an env_file already inside profiles/ must not be rewritten"

# 3. A live session of the old layout defers the move; the default profile
# keeps the old tree for that run, named profiles are unaffected.
legacy_home live
sleep 60 &
live_pid=$!
BG_PIDS+=("$live_pid")
echo "$live_pid" >"$B/sessions/$live_pid"
run_wrapper config path
[ "$RC" -eq 0 ] || fail "a deferred migration must not block the command (got $RC)"
grep -q 'deferred' <<<"$OUT" || fail "the deferral must be reported: $OUT"
grep -qx "$B/config" <<<"$OUT" || fail "while deferred the default profile must use the old tree: $OUT"
[ -f "$B/config" ] && [ ! -e "$B/profiles/default" ] || fail "nothing may move while an old session runs"
run_wrapper --profile work config path
grep -qx "$B/profiles/work/config" <<<"$OUT" || fail "named profiles must work while the migration waits"
kill "$live_pid" 2>/dev/null
wait "$live_pid" 2>/dev/null
run_wrapper config path
grep -qx "$B/profiles/default/config" <<<"$OUT" || fail "the migration must run once the old session ended: $OUT"

# 4. A busy install lock (an update/install elsewhere) defers it as well...
if command -v flock >/dev/null 2>&1; then
    legacy_home locked
    (
        exec 7>"$B/.lock"
        flock 7
        sleep 60
    ) &
    lock_pid=$!
    BG_PIDS+=("$lock_pid")
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        flock -n "$B/.lock" true 2>/dev/null || break
        sleep 0.2
    done
    OUT="$(OPENCODE_DOCKERIZED_TEST_HOOKS=1 OCD_TEST_MIGRATION_LOCK_WAIT=1 "$WRAPPER" config path 2>&1 </dev/null)"
    grep -q 'install lock' <<<"$OUT" || fail "a busy lock must defer the migration: $OUT"
    [ -f "$B/config" ] || fail "nothing may move while the lock is held"
    # ...unless this process runs under that lock (the re-exec after a pull).
    OUT="$(OCD_LOCK_HELD=1 "$WRAPPER" config path 2>&1 </dev/null)"
    grep -qx "$B/profiles/default/config" <<<"$OUT" ||
        fail "the post-pull re-exec (OCD_LOCK_HELD) must migrate under the parent's lock: $OUT"
    kill "$lock_pid" 2>/dev/null
fi

# 5. An interrupted migration (stage left behind) is resumed.
legacy_home resume
mkdir -p "$B/profiles/.default.migrating"
mv "$B/home" "$B/profiles/.default.migrating/home"
run_wrapper config path
[ "$RC" -eq 0 ] || fail "resuming a migration must succeed: $OUT"
[ -f "$B/profiles/default/home/.local/share/opencode/auth.json" ] || fail "the staged part must land in the profile"
[ -f "$B/profiles/default/config" ] || fail "the remaining part must land in the profile"
[ ! -e "$B/profiles/.default.migrating" ] || fail "the stage must be consumed on resume"

# 6. A name clash between the stage and the base fails closed: nothing starts.
legacy_home clash
mkdir -p "$B/profiles/.default.migrating"
printf 'other\n' >"$B/profiles/.default.migrating/config"
run_wrapper run "$TMP/proj"
[ "$RC" -ne 0 ] || fail "a clashing resume must fail closed"
grep -q 'already exists' <<<"$OUT" || fail "the clash must be explained: $OUT"
grep -q '^run ' "$DOCKER_STUB_LOG" && fail "no container may start after a failed migration"
[ -f "$B/config" ] || fail "a failed migration must not lose the base config"

# 7. An existing default profile is never merged into: leftovers are reported.
legacy_home leftovers
mkdir -p "$B/profiles/default"
printf 'setting.theme=x\n' >"$B/profiles/default/config"
run_wrapper config path
grep -q 'remain in' <<<"$OUT" || fail "leftovers next to an existing default profile must be reported: $OUT"
grep -qx "$B/profiles/default/config" <<<"$OUT" || fail "the existing default profile must be used"
grep -qx 'setting.theme=x' "$B/profiles/default/config" || fail "the existing default profile must be untouched"
[ -f "$B/config" ] || fail "leftovers must not be deleted"

# 8. A fresh install has nothing to migrate and creates the default profile.
export HOME="$TMP/home-fresh"
mkdir -p "$HOME"
run_wrapper config init
[ "$RC" -eq 0 ] || fail "config init on a fresh install must succeed: $OUT"
grep -q 'Migrating' <<<"$OUT" && fail "a fresh install must not report a migration"
[ -f "$HOME/.config/opencode-dockerized/profiles/default/config" ] ||
    fail "a fresh install must create the default profile"
[ ! -e "$HOME/.config/opencode-dockerized/config" ] || fail "a fresh install must not use the old layout"

# 8b. Only install-wide entries in the base: nothing to migrate, no warning.
export HOME="$TMP/home-globalonly"
mkdir -p "$HOME/.config/opencode-dockerized/gnupg-relay"
: >"$HOME/.config/opencode-dockerized/.lock"
run_wrapper config path
[ "$OUT" = "$HOME/.config/opencode-dockerized/profiles/default/config" ] ||
    fail "install-wide entries alone must not trigger a migration or warning (got: $OUT)"

echo "PASS: profile-migration"
