#!/bin/bash
# Contract test for the self-update flow (`upgrade`/`update`). No Docker needed:
# a throwaway checkout of this repo is cloned from a local bare origin and the
# wrapper runs from that clone with `--check` / `--no-build`.
#
# Usage: bash tests/update-flow.test.sh

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
# CONFIG_DIR is the base: the lock and .previous-rev are install-wide and stay
# there; per-profile state lives in profiles/default.
export CONFIG_DIR="$TMP/cfg"
export OCODE_HOME="$CONFIG_DIR/profiles/default/home"
export OPENCODE_DOCKERIZED_ALLOW_CONTAINER_SYNC=1
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid
export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
mkdir -p "$HOME"

# Seed repo = tracked files of this checkout (working-tree content, so the test
# exercises uncommitted wrapper changes too).
SEED="$TMP/seed"
mkdir -p "$SEED"
(cd "$REPO_DIR" && git ls-files -z | xargs -0 -I{} cp --parents {} "$SEED/") ||
    fail "could not stage the seed tree"
git -C "$SEED" init -q -b master
git -C "$SEED" add -A
git -C "$SEED" commit -q -m seed
git clone -q --bare "$SEED" "$TMP/origin.git"
git clone -q "$TMP/origin.git" "$TMP/install"
git clone -q "$TMP/origin.git" "$TMP/other"
# Simulate an installed user: the clone's bin/ is on PATH (check_global_install).
export PATH="$TMP/install/bin:$PATH"
WRAPPER="$TMP/install/bin/opencode-dockerized"

run() {
    OUT="$("$@" 2>&1)"
    RC=$?
    # The ERR trap must stay quiet when the wrapper handles a result itself.
    if grep -q 'unexpected failure' <<<"$OUT" && [ "$RC" -le 10 ]; then
        fail "spurious 'unexpected failure' report (rc $RC)"
    fi
}

push_upstream_commit() {
    (cd "$TMP/other" && git pull -q --ff-only && echo "$1" >>CHANGELOG.test && git add -A &&
        git commit -q -m "$1" && git push -q origin HEAD:master)
}

# 1. Up to date: --check must succeed (exit 0), not abort under `set -e`.
run "$WRAPPER" upgrade --check
[ "$RC" -eq 0 ] || fail "upgrade --check on an up-to-date checkout must exit 0 (got $RC)"
grep -q 'Already up to date' <<<"$OUT" || fail "up-to-date message missing"

# 1b. --check also compares the OpenCode release baked into the image with the
# newest one on the registry (only when the image carries its version label).
CHECK_STUB="$TMP/check-stub"
mkdir -p "$CHECK_STUB" "$TMP/reg/@opencode/cli"
cat >"$CHECK_STUB/docker" <<'STUB'
#!/bin/bash
if [ "$1" = image ] && [ "$2" = inspect ] && [ "$3" = --format ]; then
    echo "${DOCKER_STUB_VERSION_LABEL:-}"
fi
exit 0
STUB
chmod +x "$CHECK_STUB/docker"
printf '{"name":"@opencode/cli","version":"2.9.9"}' >"$TMP/reg/@opencode/cli/latest"
check_with() {
    PATH="$CHECK_STUB:$PATH" OCD_NPM_REGISTRY="file://$TMP/reg" DOCKER_STUB_VERSION_LABEL="$1" run "$WRAPPER" upgrade --check "${@:2}"
}
check_with 2.0.26
[ "$RC" -eq 10 ] || fail "an older OpenCode in the image must report an update (exit 10, got $RC)"
grep -q 'OpenCode: image 2.0.26, newest 2.9.9' <<<"$OUT" || fail "the OpenCode versions must be shown"
check_with 2.9.9
[ "$RC" -eq 0 ] || fail "an image on the newest OpenCode must be current (got $RC)"
check_with 2.0.26 --json
[ "$RC" -eq 10 ] || fail "--json must keep exit code 10 for an OpenCode update (got $RC)"
grep -q '"opencode":{"image":"2.0.26","latest":"2.9.9","status":"available"}' <<<"$OUT" ||
    fail "--json must carry the OpenCode comparison (got: $OUT)"
check_with ""
[ "$RC" -eq 0 ] || fail "an image without a version label must not trigger an OpenCode update (got $RC)"

# 2. Up to date: update --no-build must still sync the security layer and finish.
run "$WRAPPER" update --no-build
[ "$RC" -eq 0 ] || fail "update --no-build on an up-to-date checkout must exit 0 (got $RC)"
grep -q 'Upgrade complete' <<<"$OUT" || fail "update must report completion when already up to date"

# 3. Behind upstream: --check reports it with the documented exit code (10).
push_upstream_commit one
run "$WRAPPER" upgrade --check
[ "$RC" -eq 10 ] || fail "upgrade --check with an update available must exit 10 (got $RC)"
grep -q 'Update available' <<<"$OUT" || fail "update-available message missing"
[ "$(git -C "$TMP/install" rev-parse HEAD)" != "$(git -C "$TMP/origin.git" rev-parse master)" ] ||
    fail "--check must not modify the checkout"

# 4. Behind upstream: update --no-build pulls exactly the upstream head.
run "$WRAPPER" update --no-build
[ "$RC" -eq 0 ] || fail "update --no-build must succeed when behind (got $RC)"
[ "$(git -C "$TMP/install" rev-parse HEAD)" = "$(git -C "$TMP/origin.git" rev-parse master)" ] ||
    fail "update must fast-forward to the upstream head"

# 4b. A pull shows what it brings (U6), warns when the security layer changes,
# records the previous revision for rollback (U5) and re-executes the freshly
# pulled script instead of continuing with the old one (U3).
prev_head="$(git -C "$TMP/install" rev-parse HEAD)"
(cd "$TMP/other" && git pull -q --ff-only && echo '// touched' >>plugins/security-guard.js &&
    git add -A && git commit -q -m "tweak guard three" && git push -q origin HEAD:master)
run "$WRAPPER" update --no-build
[ "$RC" -eq 0 ] || fail "update --no-build must succeed with a guard change (got $RC)"
grep -q 'tweak guard three' <<<"$OUT" || fail "the incoming commit subjects must be listed"
grep -q 'security layer' <<<"$OUT" || fail "a change under plugins/ must be flagged as touching the security layer"
grep -q 'Restarting with the updated code' <<<"$OUT" || fail "update must re-exec the pulled wrapper"
[ "$(cat "$CONFIG_DIR/.previous-rev" 2>/dev/null)" = "$prev_head" ] ||
    fail "the pre-pull revision must be saved for rollback"

# 4c. Signature verification is opt-in and fails closed (the seed commits are unsigned).
push_upstream_commit four
before="$(git -C "$TMP/install" rev-parse HEAD)"
OCD_VERIFY_SIGNATURES=true run "$WRAPPER" update --no-build
[ "$RC" -eq 1 ] || fail "unsigned upstream commit must be refused with OCD_VERIFY_SIGNATURES=true (got $RC)"
[ "$(git -C "$TMP/install" rev-parse HEAD)" = "$before" ] ||
    fail "a refused pull must not move HEAD"

# 4c2. Pinned maintainer keys: with OCD_SIGNING_FINGERPRINTS only a signature
# from a pinned key is trusted, not any key in the keyring.
if command -v gpg >/dev/null 2>&1; then
    export GNUPGHOME="$TMP/gnupg"
    mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"
    gen_key() {
        gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "$1 <$1@example.invalid>" ed25519 sign never >/dev/null 2>&1
        gpg --list-keys --with-colons "$1@example.invalid" 2>/dev/null | awk -F: '/^fpr/ {print $10; exit}'
    }
    MAINT_FPR="$(gen_key maint)"
    OTHER_FPR="$(gen_key other)"
    if [ -n "$MAINT_FPR" ] && [ -n "$OTHER_FPR" ]; then
        push_signed() { (cd "$TMP/other" && git pull -q --ff-only && echo "$1" >>CHANGELOG.test && git add -A &&
            git -c gpg.program=gpg -c user.signingkey="$2" commit -q -S -m "$1" && git push -q origin HEAD:master); }
        push_signed signed-by-other "$OTHER_FPR"
        before="$(git -C "$TMP/install" rev-parse HEAD)"
        OCD_VERIFY_SIGNATURES=true OCD_SIGNING_FINGERPRINTS="$MAINT_FPR" run "$WRAPPER" update --no-build
        [ "$RC" -eq 1 ] || fail "a head signed by a key that is not pinned must be refused (got $RC)"
        grep -q 'pinned to OCD_SIGNING_FINGERPRINTS' <<<"$OUT" || fail "the refusal must mention the pinned keys"
        [ "$(git -C "$TMP/install" rev-parse HEAD)" = "$before" ] || fail "a non-pinned signature must not move HEAD"
        push_signed signed-by-maint "$MAINT_FPR"
        OCD_VERIFY_SIGNATURES=true OCD_SIGNING_FINGERPRINTS="${MAINT_FPR,,}" run "$WRAPPER" update --no-build
        [ "$RC" -eq 0 ] || fail "a head signed by a pinned key must be accepted (got $RC)"
        [ "$(git -C "$TMP/install" rev-parse HEAD)" = "$(git -C "$TMP/origin.git" rev-parse master)" ] ||
            fail "a pinned signature must fast-forward to the upstream head"
    else
        echo "note: could not create throwaway GnuPG keys; skipping the pinned-key scenario"
    fi
    gpgconf --kill gpg-agent >/dev/null 2>&1 || true
    unset GNUPGHOME
fi

# 4c3. Host-executed code (bin/, install.sh, scripts/, completions/, lib/) is
# flagged, and `update` asks before pulling it when interactive (a TTY via
# `script`); --yes skips the question, and other changes are pulled silently.
if command -v script >/dev/null 2>&1 && script -qec true /dev/null </dev/null >/dev/null 2>&1; then
    tty_update() {
        OUT="$(printf '%s\n' "$1" | SHELL=/bin/bash script -qec "$WRAPPER update --no-build ${2:-}" /dev/null 2>&1)"
        RC=$?
    }
    (cd "$TMP/other" && git pull -q --ff-only && echo '# touched' >>scripts/pins-report.sh &&
        git add -A && git commit -q -m "host script change" && git push -q origin HEAD:master)
    before="$(git -C "$TMP/install" rev-parse HEAD)"
    tty_update n
    grep -q 'runs on the HOST' <<<"$OUT" || fail "a change under scripts/ must be flagged as host-executed code"
    grep -q 'Pull 1 commit(s)?' <<<"$OUT" || fail "update must ask before pulling host-code changes on a TTY"
    [ "$(git -C "$TMP/install" rev-parse HEAD)" = "$before" ] || fail "declining the prompt must not move HEAD"
    tty_update "" --yes
    if grep -q 'Pull 1 commit(s)?' <<<"$OUT"; then fail "update --yes must not ask"; fi
    [ "$(git -C "$TMP/install" rev-parse HEAD)" = "$(git -C "$TMP/origin.git" rev-parse master)" ] ||
        fail "update --yes must pull the host-code change"
    push_upstream_commit docs-only
    tty_update n
    if grep -q 'Pull 1 commit(s)?' <<<"$OUT"; then fail "update must not ask when no host code changes"; fi
    [ "$(git -C "$TMP/install" rev-parse HEAD)" = "$(git -C "$TMP/origin.git" rev-parse master)" ] ||
        fail "update must pull a change that touches no host code without asking"
else
    echo "note: script(1) cannot allocate a pty here; skipping the interactive update prompt scenario"
fi
for f in install.sh bin/opencode-dockerized completions/bash.sh; do
    (cd "$TMP/other" && git pull -q --ff-only && echo '# touched' >>"$f" &&
        git add -A && git commit -q -m "touch $f" && git push -q origin HEAD:master)
    run "$WRAPPER" upgrade --check
    grep -q 'runs on the HOST' <<<"$OUT" || fail "a change to $f must be flagged as host-executed code"
    grep -qF "    $f" <<<"$OUT" || fail "the flagged host-code list must name $f"
    run "$WRAPPER" update --no-build --yes
    [ "$RC" -eq 0 ] || fail "update --yes after touching $f must succeed (got $RC)"
done
push_upstream_commit five # leave the checkout behind for the scenarios below

# 4d. Machine-readable --check.
run "$WRAPPER" upgrade --check --json
[ "$RC" -eq 10 ] || fail "--check --json must keep exit code 10 (got $RC)"
grep -q '"status":"available"' <<<"$OUT" || fail "--json must report status available"

# 4e. Concurrent runs are refused while the lock is held.
if command -v flock >/dev/null 2>&1; then
    mkdir -p "$CONFIG_DIR"
    (
        exec 8>"$CONFIG_DIR/.lock"
        flock -n 8 && sleep 4
    ) &
    holder=$!
    sleep 1
    run "$WRAPPER" update --no-build
    [ "$RC" -eq 1 ] || fail "update must refuse to run while another instance holds the lock (got $RC)"
    grep -q 'already running' <<<"$OUT" || fail "lock refusal message missing"
    wait "$holder" 2>/dev/null
fi

# 4f. Without flock (macOS) an atomic mkdir lock is used and released on exit.
NOFLOCK="$TMP/noflock-bin"
mkdir -p "$NOFLOCK"
for f in /usr/bin/* /bin/*; do
    [ "${f##*/}" = flock ] || ln -sf "$f" "$NOFLOCK/${f##*/}" 2>/dev/null
done
PATH_BACKUP="$PATH"
export PATH="$TMP/install/bin:$NOFLOCK"
run "$WRAPPER" update --no-build
[ "$RC" -eq 0 ] || fail "update --no-build without flock must succeed (got $RC)"
[ ! -d "$CONFIG_DIR/.lock.d" ] || fail "the mkdir lock must be released on exit"
mkdir "$CONFIG_DIR/.lock.d"
run "$WRAPPER" update --no-build
[ "$RC" -eq 1 ] || fail "a held mkdir lock must refuse a second run (got $RC)"
grep -q 'already running' <<<"$OUT" || fail "mkdir-lock refusal message missing"
rmdir "$CONFIG_DIR/.lock.d"
export PATH="$PATH_BACKUP"

# 4g. The rebuild refreshes what a cached build never would: base image (--pull),
# the weekly package/toolchain layers (APT_REFRESH), the newest OpenCode release,
# and with --full the whole cache. The replaced image is kept as :previous.
# The stub keeps the current image ID in a file; `build` switches it to
# $DOCKER_STUB_BUILD_ID when set (a changed image), else leaves it (a no-op).
STUB_BIN="$TMP/stub-bin"
mkdir -p "$STUB_BIN" "$TMP/reg/@opencode/cli"
export DOCKER_STUB_LOG="$TMP/docker.log"
export DOCKER_STUB_ID_FILE="$TMP/docker.id"
echo sha256:aaa >"$DOCKER_STUB_ID_FILE"
cat >"$STUB_BIN/docker" <<'STUB'
#!/bin/bash
echo "$*" >>"$DOCKER_STUB_LOG"
if [ "$1" = image ] && [ "$2" = inspect ] && [ "$3" = --format ] && [ "$4" = '{{.Id}}' ]; then
    cat "$DOCKER_STUB_ID_FILE"
fi
if [ "$1" = build ] && [ -n "${DOCKER_STUB_BUILD_ID:-}" ]; then
    echo "$DOCKER_STUB_BUILD_ID" >"$DOCKER_STUB_ID_FILE"
fi
exit 0
STUB
chmod +x "$STUB_BIN/docker"
printf '{"name":"@opencode/cli","version":"2.9.9"}' >"$TMP/reg/@opencode/cli/latest"
: >"$DOCKER_STUB_LOG"
PATH="$STUB_BIN:$PATH" OCD_NPM_REGISTRY="file://$TMP/reg" DOCKER_STUB_BUILD_ID=sha256:bbb run "$WRAPPER" update --full
[ "$RC" -eq 0 ] || fail "update --full against a stub docker must succeed (got $RC)"
build_line="$(grep -m1 '^build ' "$DOCKER_STUB_LOG")"
for needle in ' --pull ' ' --no-cache ' '--build-arg APT_REFRESH=' '--build-arg OPENCODE_BUILD_TIME=' '--build-arg OPENCODE_VERSION=2.9.9'; do
    grep -qF -- "$needle" <<<"$build_line" || fail "update --full build line lacks '$needle'"
done
grep -qx 'tag sha256:aaa opencode-dockerized:previous' "$DOCKER_STUB_LOG" ||
    fail "the replaced image (by ID) must be tagged :previous after a rebuild that changed it"
: >"$DOCKER_STUB_LOG"
# A rebuild that yields the same image must keep the existing rollback target.
PATH="$STUB_BIN:$PATH" OCD_NPM_REGISTRY="file://$TMP/reg" run "$WRAPPER" update
build_line="$(grep -m1 '^build ' "$DOCKER_STUB_LOG")"
if grep -qF -- ' --no-cache ' <<<"$build_line"; then fail "a plain update must keep the Docker cache"; fi
grep -qF -- ' --pull ' <<<"$build_line" || fail "a plain update must still pass --pull"
if grep -q 'opencode-dockerized:previous' "$DOCKER_STUB_LOG"; then
    fail "a rebuild that produced the same image must not overwrite :previous"
fi
grep -q 'same image' <<<"$OUT" || fail "an unchanged rebuild must say :previous was kept"

# 4h. rollback restores :previous and prints the git reset plus the config sync.
: >"$DOCKER_STUB_LOG"
PATH="$STUB_BIN:$PATH" run "$WRAPPER" rollback
[ "$RC" -eq 0 ] || fail "rollback must succeed (got $RC)"
grep -qx 'tag opencode-dockerized:previous opencode-dockerized:latest' "$DOCKER_STUB_LOG" ||
    fail "rollback must restore :previous"
grep -q 'reset --hard' <<<"$OUT" || fail "rollback must print the git reset"
grep -q 'config sync' <<<"$OUT" || fail "rollback must tell the user to run config sync after the reset"

# 5. Diverged: refuse, leave the checkout untouched, exit 1.
push_upstream_commit two
(cd "$TMP/install" && echo local >LOCAL.test && git add -A && git commit -q -m local)
local_head="$(git -C "$TMP/install" rev-parse HEAD)"
run "$WRAPPER" upgrade --yes --no-build
[ "$RC" -eq 1 ] || fail "a diverged checkout must exit 1 (got $RC)"
[ "$(git -C "$TMP/install" rev-parse HEAD)" = "$local_head" ] ||
    fail "a diverged checkout must not be modified"

echo "update-flow test passed"
