#!/bin/bash
# Contract test for install.sh and the install wizard: fresh install from a
# local origin, idempotency, custom install dir, legacy rc migration, truncated
# download, pinned ref, opt-in signature check and failure propagation. No Docker.
#
# Usage: bash tests/install-flow.test.sh

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export TMPDIR="${TMPDIR:-/tmp/opencode}"
mkdir -p "$TMPDIR" 2>/dev/null || export TMPDIR="/tmp"
TMP="$(mktemp -d -p "$TMPDIR")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -r "$TMP" 2>/dev/null || true' EXIT

fail() {
    echo "FAIL: $1"
    [ -n "${OUT:-}" ] && printf '%s\n' "$OUT" | tail -15
    exit 1
}

# Isolate from the caller's git config (e.g. commit signing): the seed must be unsigned.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid
export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid

# Origin = tracked files of this checkout (working-tree content), with a tag on
# the first commit and a second commit on top.
SEED="$TMP/seed"
mkdir -p "$SEED"
(cd "$REPO_DIR" && git ls-files -z | xargs -0 -I{} cp --parents {} "$SEED/") ||
    fail "could not stage the seed tree"
git -C "$SEED" init -q -b master
git -C "$SEED" add -A
git -C "$SEED" commit -q -m seed
git -C "$SEED" tag v0
echo second >"$SEED/SECOND.test"
git -C "$SEED" add -A
git -C "$SEED" commit -q -m second
git clone -q --bare "$SEED" "$TMP/origin.git"
export OCODE_REPO_URL="$TMP/origin.git"

# Each scenario gets its own HOME so rc files and config never leak between them.
new_home() {
    export HOME="$TMP/home-$1"
    export CONFIG_DIR="$HOME/.config/opencode-dockerized"
    export OCODE_HOME="$CONFIG_DIR/home"
    export XDG_DATA_HOME="$HOME/.local/share"
    mkdir -p "$HOME"
    : >"$HOME/.bashrc"
    unset OCD_VERIFY_SIGNATURES OCODE_REF
}

# Run install.sh the way `curl | bash` does: from stdin.
piped_install() {
    OUT="$(bash -s -- "$@" <"$REPO_DIR/install.sh" 2>&1)"
    RC=$?
}

# 1. Fresh piped install: clones, configures, adds PATH once, exits 0.
new_home fresh
export OCODE_INSTALL_DIR="$HOME/.local/share/opencode-dockerized"
piped_install --yes --only config,global
[ "$RC" -eq 0 ] || fail "fresh piped install must succeed (got $RC)"
[ -x "$OCODE_INSTALL_DIR/bin/opencode-dockerized" ] || fail "the checkout must be cloned and executable"
grep -q '>>> opencode-dockerized >>>' "$HOME/.bashrc" || fail "rc must get a delimited PATH block"
[ "$(grep -c 'opencode-dockerized/bin' "$HOME/.bashrc")" -eq 1 ] || fail "PATH must be added exactly once"

# 2. Idempotent: a second run succeeds and leaves the rc byte-identical.
sum_before="$(cksum <"$HOME/.bashrc")"
piped_install --yes --only config,global
[ "$RC" -eq 0 ] || fail "second install must succeed (got $RC)"
[ "$sum_before" = "$(cksum <"$HOME/.bashrc")" ] || fail "second install must not touch the rc"
ls "$HOME"/.bashrc.bak.* >/dev/null 2>&1 && fail "an unchanged rc must not be backed up"

# 3. Custom install dir: the PATH block points at the real location.
new_home custom
export OCODE_INSTALL_DIR="$HOME/tools/ocd"
piped_install --yes --only config,global
[ "$RC" -eq 0 ] || fail "custom-dir install must succeed (got $RC)"
grep -qF 'tools/ocd/bin' "$HOME/.bashrc" || fail "PATH block must point at the custom install dir"
if grep -qF '.local/share/opencode-dockerized/bin' "$HOME/.bashrc"; then
    fail "PATH block must not hardcode the default install dir"
fi

# 4. Legacy rc lines are migrated to the delimited block (no duplicates).
new_home legacy
export OCODE_INSTALL_DIR="$HOME/.local/share/opencode-dockerized"
printf 'export FOO=1\n\n# Added by opencode-dockerized install\nexport PATH="$HOME/.local/share/opencode-dockerized/bin:$PATH"\nexport BAR=2\n' >"$HOME/.bashrc"
piped_install --yes --only config,global
[ "$RC" -eq 0 ] || fail "legacy migration must succeed (got $RC)"
if grep -q '# Added by opencode-dockerized install' "$HOME/.bashrc"; then
    fail "the legacy marker must be replaced"
fi
[ "$(grep -c 'opencode-dockerized/bin' "$HOME/.bashrc")" -eq 1 ] || fail "legacy migration must leave a single PATH line"
grep -q 'export FOO=1' "$HOME/.bashrc" && grep -q 'export BAR=2' "$HOME/.bashrc" ||
    fail "migration must keep the user's own lines"
ls "$HOME"/.bashrc.bak.* >/dev/null 2>&1 || fail "migration must back up the rc"

# 5. A truncated download must not run anything.
new_home trunc
export OCODE_INSTALL_DIR="$HOME/.local/share/opencode-dockerized"
OUT="$(head -c 1500 "$REPO_DIR/install.sh" | bash -s -- --yes 2>&1)"
[ ! -e "$OCODE_INSTALL_DIR" ] || fail "a truncated install.sh must not clone or install anything"

# 6. OCODE_REF pins a tag.
new_home ref
export OCODE_INSTALL_DIR="$HOME/.local/share/opencode-dockerized"
OCODE_REF=v0 piped_install --yes --only config
[ "$RC" -eq 0 ] || fail "install at a pinned ref must succeed (got $RC)"
[ "$(git -C "$OCODE_INSTALL_DIR" rev-parse HEAD)" = "$(git -C "$SEED" rev-parse v0)" ] ||
    fail "OCODE_REF=v0 must check out the tagged commit"

# 7. Signature verification is opt-in and fails closed (the seed is unsigned).
new_home sig
export OCODE_INSTALL_DIR="$HOME/.local/share/opencode-dockerized"
OCD_VERIFY_SIGNATURES=true piped_install --yes --only config
[ "$RC" -ne 0 ] || fail "an unsigned checkout must be refused with OCD_VERIFY_SIGNATURES=true"
[ ! -e "$OCODE_INSTALL_DIR" ] || fail "a refused checkout must be removed, not left installed"

# 8. A reused checkout whose fetch fails says so instead of staying silent.
new_home offline
export OCODE_INSTALL_DIR="$HOME/.local/share/opencode-dockerized"
piped_install --yes --only config
git -C "$OCODE_INSTALL_DIR" remote set-url origin "$TMP/missing.git"
piped_install --yes --only config
[ "$RC" -eq 0 ] || fail "an offline reinstall must still succeed (got $RC)"
grep -qi 'could not fetch' <<<"$OUT" || fail "a failed fetch must be reported"

# 9. A section that fails makes the whole install fail.
new_home failing
export OCODE_INSTALL_DIR="$HOME/.local/share/opencode-dockerized"
piped_install --yes --only config,global
printf 'export KEEP=1\n' >"$HOME/.bashrc"
chmod 444 "$HOME/.bashrc"
piped_install --yes --only config,global
chmod 644 "$HOME/.bashrc"
[ "$RC" -ne 0 ] || fail "install must exit non-zero when the PATH section cannot be written"
grep -qi 'could not update' <<<"$OUT" || fail "the failing section must be named"

echo "install-flow test passed"
