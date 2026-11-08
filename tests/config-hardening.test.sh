#!/bin/bash
# Regression tests for the config-lib.sh hardening (security audit 2026-11):
# git worktree trust, custom-mount and project-dir guards, fail-closed
# permission refresh, env_file containment, GnuPG mirror symlink safety,
# websearch merge, gated test hooks, colors, policy VERSION mirror, backup
# collisions and container path collisions. No Docker required: it sources
# config-lib.sh with an isolated HOME/CONFIG_DIR.
#
# Usage: bash tests/config-hardening.test.sh
# shellcheck disable=SC2034  # globals below are consumed by sourced config-lib.sh functions

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export TMPDIR="${TMPDIR:-/tmp/opencode}"
mkdir -p "$TMPDIR" 2>/dev/null || export TMPDIR="/tmp"
TMP="$(cd "$(mktemp -d -p "$TMPDIR")" && pwd -P)"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -r "$TMP" 2>/dev/null || true' EXIT

fail() {
    echo "FAIL: $1"
    exit 1
}

export HOME="$TMP/home"
export CONFIG_DIR="$TMP/cfg"
export OCODE_HOME="$CONFIG_DIR/home"
export OPENCODE_DOCKERIZED_ALLOW_CONTAINER_SYNC=1
unset DOCKER_HOST OPENCODE_DOCKERIZED_TEST_HOOKS
OC_CONFIG_DIR="$OCODE_HOME/.config/opencode"
mkdir -p "$HOME/.ssh" "$HOME/.gnupg" "$HOME/.claude/projects" "$HOME/.config/git" \
    "$HOME/.composio" "$HOME/code/foo" "$OC_CONFIG_DIR/plugins" \
    "$OCODE_HOME/.local/share/opencode"
: >"$HOME/.gitconfig"
: >"$HOME/.config/git/gitignore_global"

# A PATH without node/python3 (JSON parsers) for the fail-closed/fallback paths.
MINBIN="$TMP/minbin"
mkdir -p "$MINBIN"
for exe in /usr/local/bin/* /usr/bin/* /bin/*; do
    name="$(basename "$exe")"
    case "$name" in
    node | nodejs | python | python3*) continue ;;
    esac
    [ -x "$exe" ] && [ ! -e "$MINBIN/$name" ] && ln -s "$exe" "$MINBIN/$name"
done

# shellcheck source=/dev/null
source "$REPO_DIR/lib/config-lib.sh" >/dev/null 2>&1
ensure_opencode_dockerized_config >/dev/null 2>&1 || fail "initial security layer install must succeed"

# --- 9. Colors: no literal quotes stored, escapes work with echo -e ---------
red=$(env -u RED -u GREEN -u NC -u NO_COLOR TERM=xterm bash -c 'source "$0" >/dev/null 2>&1; printf "%s" "$RED"' "$REPO_DIR/lib/config-lib.sh")
[ "$red" = '\033[0;31m' ] || fail "default RED must be the bare escape, got: $red"
env -u RED -u NC -u NO_COLOR TERM=xterm bash -c 'source "$0" >/dev/null 2>&1; config_error x' "$REPO_DIR/lib/config-lib.sh" | grep -q "'" &&
    fail "colored output must not contain literal quotes"

# --- 10. Policy VERSION is mirrored into the read-only config tree ----------
[ -f "$OC_CONFIG_DIR/plugins/policies/VERSION" ] || fail "policy VERSION must be mirrored into the config tree"
cmp -s "$REPO_DIR/policies/VERSION" "$OC_CONFIG_DIR/plugins/policies/VERSION" ||
    fail "mirrored policy VERSION must match the repo"

# --- 11. Same-second backups never collide ----------------------------------
mkdir -p "$TMP/bk"
printf 'one\n' >"$TMP/bk/src1"
printf 'two\n' >"$TMP/bk/src2"
printf 'three\n' >"$TMP/bk/src3"
printf 'zero\n' >"$TMP/bk/dest"
install_managed_file "$TMP/bk/src1" "$TMP/bk/dest" t >/dev/null 2>&1 || fail "install 1"
install_managed_file "$TMP/bk/src2" "$TMP/bk/dest" t >/dev/null 2>&1 || fail "install 2"
install_managed_file "$TMP/bk/src3" "$TMP/bk/dest" t >/dev/null 2>&1 || fail "install 3"
[ "$(compgen -G "$TMP/bk/dest.bak.*" | wc -l)" -eq 3 ] || fail "three quick refreshes must leave three distinct backups"
grep -qx zero "$TMP/bk"/dest.bak.* || fail "the oldest backup must survive a same-second refresh"

# --- 12. Projects named like system dirs never land on them ------------------
[ "$(compute_container_path "$HOME/bin/tool")" = "/home/coder/bin/tool" ] || fail "~/bin must not map onto /bin"
[ "$(compute_container_path "$HOME/usr")" = "/home/coder/usr" ] || fail "~/usr must not map onto /usr"
for d in etc tmp lib proc sys dev var home opt sbin run root boot; do
    [ "$(compute_container_path "$HOME/$d/x")" = "/home/coder/$d/x" ] || fail "~/$d must not map onto /$d"
done
[ "$(compute_container_path "$HOME/projects/x")" = "/projects/x" ] || fail "regular projects keep the stripped path"
[ "$(compute_container_path "$HOME/binaries/x")" = "/binaries/x" ] || fail "only exact system dir names are remapped"
[ "$(compute_container_path /opt/work/p)" = "/opt/work/p" ] || fail "non-home paths stay unchanged"
ln -s "$HOME" "$TMP/homelink"
[ "$(HOME="$TMP/homelink" compute_container_path "$HOME/projects/x")" = "/projects/x" ] ||
    fail "a symlinked HOME must still be stripped from canonical project paths"

# --- 3. Project directory guard ----------------------------------------------
validate_project_dir "$HOME/code/foo" >/dev/null 2>&1 || fail "~/code/foo must be accepted"
for bad in "$HOME/.ssh" "$HOME/.gnupg" "$HOME/.config" "$HOME/.config/nvim" "$CONFIG_DIR" \
    "$OCODE_HOME" "$OC_CONFIG_DIR" "$HOME/.claude" "$HOME/.claude/projects" "$TMP" "/var/run" "/run"; do
    if validate_project_dir "$bad" >/dev/null 2>&1; then
        fail "project dir $bad must be refused"
    fi
done
if (HOME="$TMP/homelink" validate_project_dir "$HOME") >/dev/null 2>&1; then
    fail "the canonical home must be refused when HOME is a symlink"
fi
if (HOME="$TMP/homelink" validate_project_dir "$HOME/.ssh") >/dev/null 2>&1; then
    fail "the canonical ~/.ssh must be refused when HOME is a symlink"
fi

# --- 2. Custom mount guard -----------------------------------------------------
ln -s "$HOME/.ssh" "$HOME/sshlink"
ln -s "$CONFIG_DIR" "$HOME/cfglink"
: >"$TMP/dh.sock"
mount_refused() {
    CUSTOM_MOUNTS=("$1")
    CUSTOM_MOUNT_KEYS=(m)
    ! (build_mount_args) >/dev/null 2>&1
}
for bad in \
    "~/sshlink:/x" "~/sshlink/newfile:/x" "~/.ssh/../.ssh:/x" "~//.ssh:/x" "$HOME/./.ssh:/x" \
    "~:/x:rw" "/:/host:rw" "$TMP:/x" "$CONFIG_DIR:/c:rw" "~/cfglink:/c" "$OCODE_HOME/.local/share/opencode:/d:rw" \
    "~/.claude:/home/coder/.claude" "~/.claude/projects:/p" \
    "/var/run/docker.sock:/var/run/docker.sock" "/run/docker.sock:/s" "/var/run:/r" \
    "relative:/x" "~nobody/x:/x" \
    "~/.composio:/home/coder/.config/opencode/plugins:rw" "~/.composio:/home/coder/.config/opencode" \
    "~/.composio:/home/coder//.config/./opencode/x" "~/.composio:/home/coder/.ssh" "~/.composio:/home/coder/.gnupg/x" \
    "~/.composio:/" "~/.composio:/tmp/x:ro:rw" "~/.composio:/x:" "~/.composio"; do
    mount_refused "$bad" || fail "custom mount '$bad' must be refused"
done
if DOCKER_HOST="unix://$TMP/dh.sock" mount_refused "$TMP/dh.sock:/s"; then :; else
    fail "the DOCKER_HOST socket must not be mountable"
fi
for good in "~/.gitconfig:/home/coder/.gitconfig" \
    "~/.config/git/gitignore_global:/home/coder/.config/git/gitignore_global" \
    "~/.composio:/home/coder/.composio:rw" "~/.composio:/home/coder/.composio:ro,Z"; do
    CUSTOM_MOUNTS=("$good")
    CUSTOM_MOUNT_KEYS=(m)
    (build_mount_args) >/dev/null 2>&1 || fail "legit custom mount '$good' must be accepted"
done
CUSTOM_MOUNTS=("~/.gitconfig:/home/coder//.gitconfig")
CUSTOM_MOUNT_KEYS=(m)
build_mount_args >/dev/null 2>&1
grep -qxF -- "$HOME/.gitconfig:/home/coder/.gitconfig:ro" <<<"$(printf '%s\n' "${DOCKER_MOUNT_ARGS[@]}")" ||
    fail "custom mounts must pass the canonical host and normalized container path"
CUSTOM_MOUNTS=()
CUSTOM_MOUNT_KEYS=()
add_mount "~/sshlink" /home/coder/x >/dev/null 2>&1 && fail "add_mount must refuse a symlink to ~/.ssh"
add_mount "relative/dir" /home/coder/x >/dev/null 2>&1 && fail "add_mount must refuse relative host paths"
add_mount "~/.composio" /home/coder/.config/opencode/x rw >/dev/null 2>&1 && fail "add_mount must refuse the config tree"
add_mount "~/.claude" /home/coder/.claude >/dev/null 2>&1 && fail "add_mount must refuse ~/.claude"
add_mount "~/.composio" /home/coder/.composio rw >/dev/null 2>&1 || fail "add_mount must accept a legit mount"
CUSTOM_MOUNTS=()
CUSTOM_MOUNT_KEYS=()

# --- 1. Git worktree trust -----------------------------------------------------
if command -v git >/dev/null 2>&1; then
    g() { git -c user.name=t -c user.email=t@example.com -c init.defaultBranch=main "$@"; }
    g init -q "$TMP/wt-main" && g -C "$TMP/wt-main" commit -q --allow-empty -m init ||
        fail "could not create the test repo"
    g -C "$TMP/wt-main" worktree add -q "$TMP/wt-legit" -b legit >/dev/null 2>&1 ||
        fail "could not create a test worktree"
    build_git_worktree_args "$TMP/wt-legit" >/dev/null 2>&1
    [ "${GIT_WORKTREE_ARGS[*]}" = "-v $TMP/wt-main/.git:$TMP/wt-main/.git:ro" ] ||
        fail "a legit worktree must mount its common .git dir read-only (got: ${GIT_WORKTREE_ARGS[*]})"

    g init -q "$TMP/victim-repo"
    mkdir -p "$TMP/forged1" "$TMP/forged2"
    printf 'gitdir: %s\n' "$TMP/victim-repo/.git" >"$TMP/forged1/.git"
    build_git_worktree_args "$TMP/forged1" >/dev/null 2>&1
    [ "${#GIT_WORKTREE_ARGS[@]}" -eq 0 ] || fail "a .git pointing at another repo's .git must mount nothing"
    wt_name="$(basename "$(dirname "$(sed -n 's/^gitdir: //p' "$TMP/wt-legit/.git")/x")")"
    printf 'gitdir: %s\n' "$TMP/wt-main/.git/worktrees/$wt_name" >"$TMP/forged2/.git"
    build_git_worktree_args "$TMP/forged2" >/dev/null 2>&1
    [ "${#GIT_WORKTREE_ARGS[@]}" -eq 0 ] || fail "a .git borrowing another worktree's entry must mount nothing"
    out="$(detect_git_worktree "$TMP/forged1" 2>/dev/null)"
    [ -z "$out" ] || fail "warnings must not leak into detect_git_worktree's stdout"
fi

# --- 4. Permission refresh: real JSON merge, fail closed ------------------------
if command -v node >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
    cat >"$CONFIG_DIR/opencode.json" <<'EOF'
{
  "$schema": "https://opencode.ai/config.json",
  "model": "anthropic/claude",
  "share": { "mode": "disabled", "nested": { "a": "}" } },
  "permission": { "bash": "ask" },
  "permissions": [
    { "action": "read", "resource": "*.{env,pem}", "effect": "deny" },
    { "action": "shell", "resource": "echo }{", "effect": "ask" },
    { "action": "shell", "resource": "sudo", "effect": "allow" }
  ]
}
EOF
    out="$(ensure_opencode_dockerized_config 2>&1)" || fail "merge with braces in strings must succeed: $out"
    grep -q 'Refreshed security permissions' <<<"$out" || fail "a successful merge must report the refresh"
    json_valid "$CONFIG_DIR/opencode.json" || fail "merged opencode.json must be valid JSON"
    grep -qF '"resource": "*.{env,pem}"' "$CONFIG_DIR/opencode.json" || fail "a rule with braces must be preserved"
    grep -qF '"resource": "echo }{"' "$CONFIG_DIR/opencode.json" || fail "a rule with unbalanced braces must be preserved"
    grep -qF '"model": "anthropic/claude"' "$CONFIG_DIR/opencode.json" || fail "user top-level keys must be preserved"
    grep -qF '"nested"' "$CONFIG_DIR/opencode.json" || fail "nested user top-level values must be preserved"
    grep -qF '{ "action": "shell", "resource": "sudo", "effect": "deny" }' "$CONFIG_DIR/opencode.json" ||
        fail "the template must win conflicts"
    grep -qF '"permission"' "$CONFIG_DIR/opencode.json" && fail "the legacy V1 permission block must be dropped"
    grep -q 'overrode' <<<"$out" || fail "overridden rules must be reported"

    # Invalid JSON: nothing written, the layer fails (run blocked).
    printf '{ "permissions": [ { "action": "shell", "resource": "x" ' >"$CONFIG_DIR/opencode.json"
    cp "$CONFIG_DIR/opencode.json" "$TMP/broken.json"
    if out="$(ensure_opencode_dockerized_config 2>&1)"; then
        fail "an unparsable opencode.json must fail closed"
    fi
    grep -q 'Refreshed' <<<"$out" && fail "no refresh success may be reported when the merge fails"
    cmp -s "$TMP/broken.json" "$CONFIG_DIR/opencode.json" || fail "a failed merge must leave the user file untouched"
fi

# No JSON parser on the host: an outdated user file blocks instead of being mangled.
printf '{\n  "permissions": [ { "action": "shell", "resource": "mine", "effect": "ask" } ]\n}\n' >"$CONFIG_DIR/opencode.json"
cp "$CONFIG_DIR/opencode.json" "$TMP/mine.json"
if (PATH="$MINBIN" ensure_opencode_dockerized_config) >"$TMP/noparser.out" 2>&1; then
    fail "without a JSON parser an outdated opencode.json must fail closed"
fi
grep -q 'Refreshed' "$TMP/noparser.out" && fail "no refresh success may be reported without a parser"
cmp -s "$TMP/mine.json" "$CONFIG_DIR/opencode.json" || fail "the user file must stay untouched without a parser"
# A fresh install needs no parser.
rm -f "$CONFIG_DIR/opencode.json"
(PATH="$MINBIN" ensure_opencode_dockerized_config) >/dev/null 2>&1 || fail "a fresh install must not need a JSON parser"
grep -q 'private-keys-v1.d' "$CONFIG_DIR/opencode.json" || fail "a fresh install must write the template"

# --- 7. Websearch merge: {} and an existing key ----------------------------------
for impl in tool fallback; do
    run_ws() {
        if [ "$impl" = fallback ]; then
            (PATH="$MINBIN" merge_websearch_provider "$1" exa)
        else
            merge_websearch_provider "$1" exa
        fi
    }
    [ "$(run_ws '{}')" = '{"websearch":{"provider":"exa"}}' ] || fail "$impl: {} must merge to a valid object"
    [ "$(run_ws '{ }')" = '{"websearch":{"provider":"exa"}}' ] || fail "$impl: { } must merge to a valid object"
    out="$(run_ws '{"a":1}')" || fail "$impl: a regular object must merge"
    grep -qF '"websearch":{"provider":"exa"}' <<<"$out" || fail "$impl: provider missing"
    out="$(run_ws '{"websearch":{"provider":"tavily"},"a":1}')" && {
        [ "$(grep -o '"websearch"' <<<"$out" | wc -l)" -eq 1 ] || fail "$impl: duplicate websearch key"
        [ "$impl" = tool ] && ! grep -qF '"provider":"exa"' <<<"$out" && fail "$impl: the setting must win"
    }
done
if command -v node >/dev/null 2>&1; then
    printf '{}\n' >"$CONFIG_DIR/opencode.json"
    WEBSEARCH_PROVIDER=exa
    build_common_docker_args >/dev/null 2>&1
    for arg in "${DOCKER_COMMON_ARGS[@]}"; do
        case "$arg" in OPENCODE_CONFIG_CONTENT=*) inline="${arg#OPENCODE_CONFIG_CONTENT=}" ;; esac
    done
    printf '%s' "$inline" | node -e 'JSON.parse(require("fs").readFileSync(0,"utf8"))' ||
        fail "inline config built from {} must be valid JSON"
    WEBSEARCH_PROVIDER=""
fi

# --- 5. env_file containment -----------------------------------------------------
printf 'A=1\n' >"$CONFIG_DIR/env"
chmod 600 "$CONFIG_DIR/env"
ln -s "$CONFIG_DIR" "$TMP/cfglink"
(CONFIG_DIR="$TMP/cfglink" OCODE_HOME="$TMP/cfglink/home" ENV_FILE="$TMP/cfglink/env" build_env_file_args) >/dev/null 2>&1 ||
    fail "a symlinked CONFIG_DIR must accept a legit env file"
printf 'A=1\n' >"$OCODE_HOME/.local/share/opencode/secrets.env"
if (ENV_FILE="$OCODE_HOME/.local/share/opencode/secrets.env" build_env_file_args) >/dev/null 2>&1; then
    fail "an env file under OCODE_HOME (mounted) must be refused"
fi
printf 'A=1\n' >"$TMP/outside.env"
if (ENV_FILE="$CONFIG_DIR/../outside.env" build_env_file_args) >/dev/null 2>&1; then
    fail "an env file escaping CONFIG_DIR with .. must be refused"
fi
ln -s "$TMP/outside.env" "$CONFIG_DIR/link.env"
if (ENV_FILE="$CONFIG_DIR/link.env" build_env_file_args) >/dev/null 2>&1; then
    fail "an env file symlinked out of CONFIG_DIR must be refused"
fi

# --- 6. GnuPG mirror never writes through planted symlinks ------------------------
export GNUPGHOME="$TMP/hostgpg"
mkdir -p "$GNUPGHOME/public-keys.d" "$TMP/victimdir"
printf 'HOSTKBX\n' >"$GNUPGHOME/pubring.kbx"
printf 'HOSTDB\n' >"$GNUPGHOME/public-keys.d/pubring.db"
printf 'keyid-format long\n' >"$GNUPGHOME/gpg.conf"
printf 'VICTIMDB\n' >"$TMP/victimdir/pubring.db"
printf 'VICTIMFILE\n' >"$TMP/victim.txt"
printf 'VICTIMCONF\n' >"$TMP/victim.conf"
mirror="$OCODE_HOME/.gnupg"
mkdir -p "$mirror/trustdb.gpg"
ln -s "$TMP/victimdir" "$mirror/public-keys.d"
ln -s "$TMP/victim.txt" "$mirror/pubring.kbx"
ln -s "$TMP/victim.conf" "$mirror/gpg.conf"
ensure_gpg_mirror >/dev/null 2>&1
grep -qx VICTIMDB "$TMP/victimdir/pubring.db" || fail "a planted public-keys.d symlink must not be written through"
[ "$(ls -A "$TMP/victimdir")" = "pubring.db" ] || fail "nothing may be added to the symlink target"
grep -qx VICTIMFILE "$TMP/victim.txt" || fail "a planted pubring.kbx symlink must not be written through"
grep -qx VICTIMCONF "$TMP/victim.conf" || fail "a planted gpg.conf symlink must not be written through"
[ -d "$mirror/public-keys.d" ] && [ ! -L "$mirror/public-keys.d" ] || fail "public-keys.d must be a real directory again"
grep -qx HOSTDB "$mirror/public-keys.d/pubring.db" || fail "the keyboxd DB must be mirrored"
[ -f "$mirror/pubring.kbx" ] && [ ! -L "$mirror/pubring.kbx" ] || fail "pubring.kbx must be a regular file again"
[ ! -L "$mirror/gpg.conf" ] || fail "gpg.conf must be a regular file again"
ensure_gpg_mirror >/dev/null 2>&1
[ "$(grep -c '^no-autostart$' "$mirror/gpg.conf")" -eq 1 ] || fail "no-autostart must be added exactly once"
grep -qx 'keyid-format long' "$mirror/gpg.conf" || fail "the host gpg.conf must be mirrored"
compgen -G "$OCODE_HOME/.gnupg-stage.*" >/dev/null && fail "the mirror stage dir must be cleaned up"
unset GNUPGHOME

# --- 8. Command-override test hooks need the explicit opt-in ----------------------
if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$TMP/agent.sock"
    GPG_AGENT_EXTRA_SOCKET="$TMP/agent.sock"
    GPG_AGENT_PROBE_CMD="touch '$TMP/probe.marker'"
    gpg_agent_is_running >/dev/null 2>&1
    [ ! -e "$TMP/probe.marker" ] || fail "GPG_AGENT_PROBE_CMD must be ignored without OPENCODE_DOCKERIZED_TEST_HOOKS=1"
    OPENCODE_DOCKERIZED_TEST_HOOKS=1 gpg_agent_is_running >/dev/null 2>&1
    [ -e "$TMP/probe.marker" ] || fail "GPG_AGENT_PROBE_CMD must run with the explicit opt-in"
    unset GPG_AGENT_EXTRA_SOCKET GPG_AGENT_PROBE_CMD
fi

echo "config-hardening test passed"
