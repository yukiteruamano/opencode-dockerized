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
    export OCODE_HOME="$CONFIG_DIR/profiles/default/home"
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

# 9b. An install path the shell would evaluate inside the double-quoted rc
# lines (`$(...)`, backticks, quotes, backslashes) is refused, nothing is written.
new_home evil
export OCODE_INSTALL_DIR="$HOME/ocd\$(touch $HOME/PWNED)"
piped_install --yes --only config,global,completions
[ "$RC" -ne 0 ] || fail "an install path containing \$( must be refused"
grep -q 'Refusing to install from' <<<"$OUT" || fail "the refusal must explain the unsafe path"
if grep -qF 'touch' "$HOME/.bashrc"; then fail "an unsafe install path must never reach the rc file"; fi
[ ! -e "$HOME/PWNED" ] || fail "the unsafe path must not have been evaluated"
export OCODE_INSTALL_DIR="$HOME/ocd\"quote"
piped_install --yes --only config,global
[ "$RC" -ne 0 ] || fail "an install path containing a double quote must be refused"
grep -q 'Refusing to install from' <<<"$OUT" || fail "the double-quote refusal must explain the unsafe path"

# 9c. Completion lines live in a delimited block: re-installing from a moved
# checkout replaces the old line, legacy unmarked lines are migrated, other
# tools' completion lines are kept, and a repeat install changes nothing.
new_home completions
printf '%s\n' '[ -f "/opt/other/completions/bash.sh" ] && source "/opt/other/completions/bash.sh"' \
    '' '# OpenCode Dockerized completion' \
    '[ -f "/old/place/completions/bash.sh" ] && source "/old/place/completions/bash.sh"' >"$HOME/.bashrc"
export OCODE_INSTALL_DIR="$HOME/first"
piped_install --yes --only config,completions
[ "$RC" -eq 0 ] || fail "completion install must succeed (got $RC)"
grep -qxF '# >>> opencode-dockerized completion >>>' "$HOME/.bashrc" || fail "completion must be written in a delimited block"
if grep -qF '/old/place' "$HOME/.bashrc"; then fail "the legacy completion line must be migrated into the block"; fi
if grep -qxF '# OpenCode Dockerized completion' "$HOME/.bashrc"; then fail "the legacy completion marker must be removed"; fi
grep -qF '/opt/other/completions/bash.sh' "$HOME/.bashrc" || fail "another tool's completion line must be kept"
sum_before="$(cksum <"$HOME/.bashrc")"
piped_install --yes --only config,completions
[ "$sum_before" = "$(cksum <"$HOME/.bashrc")" ] || fail "a repeat completion install must not touch the rc"
export OCODE_INSTALL_DIR="$HOME/second"
piped_install --yes --only config,completions
[ "$RC" -eq 0 ] || fail "completion install from a moved checkout must succeed (got $RC)"
[ "$(grep -c 'completions/bash.sh' "$HOME/.bashrc")" -eq 2 ] ||
    fail "a moved checkout must replace its completion line, not add one ($(grep 'completions/bash.sh' "$HOME/.bashrc"))"
grep -qF "$HOME/second/completions/bash.sh" "$HOME/.bashrc" || fail "the completion line must point at the new checkout"
if grep -qF "$HOME/first/" "$HOME/.bashrc"; then fail "the stale completion line of the old checkout must be gone"; fi

# 10. A reused checkout verifies the upstream head BEFORE fast-forwarding: an
# unsigned new commit is refused and HEAD stays where it was.
new_home sig-reuse
export OCODE_INSTALL_DIR="$HOME/.local/share/opencode-dockerized"
piped_install --yes --only config
[ "$RC" -eq 0 ] || fail "baseline install for the reuse scenario must succeed (got $RC)"
WORK="$TMP/work-$RANDOM"
git clone -q "$TMP/origin.git" "$WORK"
push_origin() { (cd "$WORK" && echo "$1" >>"PUSH-$1.test" && git add -A && git commit -q -m "$1" && git push -q origin "HEAD:${2:-master}"); }
push_origin unsigned-upstream
before="$(git -C "$OCODE_INSTALL_DIR" rev-parse HEAD)"
OCD_VERIFY_SIGNATURES=true piped_install --yes --only config
[ "$RC" -ne 0 ] || fail "an unsigned upstream head must be refused on a reused checkout"
grep -qi 'signature verification failed' <<<"$OUT" || fail "the refusal must name the signature check"
[ "$(git -C "$OCODE_INSTALL_DIR" rev-parse HEAD)" = "$before" ] ||
    fail "a refused upstream head must not move HEAD (it moved to $(git -C "$OCODE_INSTALL_DIR" rev-parse HEAD))"

# 11. OCODE_REF=<branch> on a reused checkout follows origin/<branch>: the
# branch is created tracking origin, and later runs fast-forward it.
(cd "$WORK" && git checkout -q -b feature)
push_origin feature-one feature
OCODE_REF=feature piped_install --yes --only config
[ "$RC" -eq 0 ] || fail "OCODE_REF=<branch> on a reused checkout must succeed (got $RC)"
[ "$(git -C "$OCODE_INSTALL_DIR" rev-parse HEAD)" = "$(git -C "$TMP/origin.git" rev-parse feature)" ] ||
    fail "OCODE_REF=feature must check out origin/feature"
[ "$(git -C "$OCODE_INSTALL_DIR" rev-parse --abbrev-ref HEAD)" = feature ] || fail "OCODE_REF=feature must be on branch feature"
[ "$(git -C "$OCODE_INSTALL_DIR" rev-parse --abbrev-ref '@{u}')" = origin/feature ] ||
    fail "branch feature must track origin/feature"
push_origin feature-two feature
OCODE_REF=feature piped_install --yes --only config
[ "$(git -C "$OCODE_INSTALL_DIR" rev-parse HEAD)" = "$(git -C "$TMP/origin.git" rev-parse feature)" ] ||
    fail "a second OCODE_REF=feature run must fast-forward to the new origin/feature"
push_origin feature-three feature
before="$(git -C "$OCODE_INSTALL_DIR" rev-parse HEAD)"
OCODE_REF=feature OCD_VERIFY_SIGNATURES=true piped_install --yes --only config
[ "$RC" -ne 0 ] || fail "an unsigned origin/<branch> must be refused"
[ "$(git -C "$OCODE_INSTALL_DIR" rev-parse HEAD)" = "$before" ] || fail "a refused branch switch must not move HEAD"

# 12. Pinned maintainer keys (OCD_SIGNING_FINGERPRINTS): a commit signed by a
# pinned key is accepted, one signed by any other key in the keyring is not.
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
        push_signed() { (cd "$WORK" && git checkout -q master && git pull -q --ff-only origin master &&
            echo "$1" >>"SIGNED-$1.test" && git add -A &&
            git -c gpg.program=gpg -c user.signingkey="$2" commit -q -S -m "$1" && git push -q origin HEAD:master); }
        new_home pinned
        export OCODE_INSTALL_DIR="$HOME/.local/share/opencode-dockerized"
        export GNUPGHOME="$TMP/gnupg"
        piped_install --yes --only config
        push_signed by-other "$OTHER_FPR"
        before="$(git -C "$OCODE_INSTALL_DIR" rev-parse HEAD)"
        OCD_VERIFY_SIGNATURES=true OCD_SIGNING_FINGERPRINTS="$MAINT_FPR" piped_install --yes --only config
        [ "$RC" -ne 0 ] || fail "a commit signed by a key that is not pinned must be refused"
        [ "$(git -C "$OCODE_INSTALL_DIR" rev-parse HEAD)" = "$before" ] || fail "a non-pinned signature must not move HEAD"
        OCD_VERIFY_SIGNATURES=true piped_install --yes --only config
        [ "$RC" -eq 0 ] || fail "without pins, any valid keyring signature is accepted (got $RC)"
        push_signed by-maint "$MAINT_FPR"
        OCD_VERIFY_SIGNATURES=true OCD_SIGNING_FINGERPRINTS="0000 ${MAINT_FPR,,}" piped_install --yes --only config
        [ "$RC" -eq 0 ] || fail "a commit signed by a pinned key must be accepted (got $RC)"
        [ "$(git -C "$OCODE_INSTALL_DIR" rev-parse HEAD)" = "$(git -C "$TMP/origin.git" rev-parse master)" ] ||
            fail "a pinned signature must fast-forward to the upstream head"
    else
        echo "note: could not create throwaway GnuPG keys; skipping the pinned-key scenario"
    fi
    gpgconf --kill gpg-agent >/dev/null 2>&1 || true
    unset GNUPGHOME
else
    echo "note: gpg not installed; skipping the pinned-key scenario"
fi

echo "install-flow test passed"
