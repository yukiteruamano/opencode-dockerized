#!/bin/bash
# Consistency test: every command the wrapper's help lists must be completed by
# the bash and zsh scripts, and the subcommand/flag values must stay in sync.
#
# Usage: bash tests/completions.test.sh

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
export HOME="${TMPDIR:-/tmp}/completions-test-home-$$"
mkdir -p "$HOME"
trap 'rm -r "$HOME" 2>/dev/null || true' EXIT

fail() {
    echo "FAIL: $1"
    exit 1
}

bash -n "$REPO_DIR/completions/bash.sh" || fail "bash completion has a syntax error"
if command -v zsh >/dev/null 2>&1; then
    zsh -n "$REPO_DIR/completions/zsh.sh" || fail "zsh completion has a syntax error"
fi

# Commands listed by `help` (the indented "name  description" block).
help_out="$("$REPO_DIR/bin/opencode-dockerized" help 2>&1)"
commands="$(awk '/^Commands:/{f=1;next} /^[A-Z]/{f=0} f && /^    [a-z]/{print $1}' <<<"$help_out")"
[ -n "$commands" ] || fail "could not read the command list from help"

bash_opts="$(grep -m1 'opts="' "$REPO_DIR/completions/bash.sh")"
for cmd in $commands; do
    grep -qw -- "$cmd" <<<"$bash_opts" || fail "bash completion is missing the '$cmd' command"
    grep -q "^        '$cmd:" "$REPO_DIR/completions/zsh.sh" || fail "zsh completion is missing the '$cmd' command"
done

# Flag and value lists that changed over time.
for word in --json rollback; do
    grep -q -- "$word" "$REPO_DIR/completions/bash.sh" || fail "bash completion lacks $word"
    grep -q -- "$word" "$REPO_DIR/completions/zsh.sh" || fail "zsh completion lacks $word"
done
for section in config completions aliases global build; do
    grep -q "install)" "$REPO_DIR/completions/bash.sh" || fail "bash completion lacks install"
    grep -q -- "$section" "$REPO_DIR/completions/bash.sh" || fail "bash completion must offer the '$section' install section"
    grep -q -- "$section" "$REPO_DIR/completions/zsh.sh" || fail "zsh completion must offer the '$section' install section"
done

# Functional check: `install --only config,co<TAB>` completes the last section.
# shellcheck source=/dev/null
source "$REPO_DIR/completions/bash.sh"
COMP_WORDS=(opencode-dockerized install --only "config,co")
COMP_CWORD=3
_opencode_dockerized
[ "${COMPREPLY[*]}" = "config,completions" ] || fail "--only must complete the last section (got: ${COMPREPLY[*]})"
COMP_WORDS=(opencode-dockerized upgrade --)
COMP_CWORD=2
_opencode_dockerized
grep -qw -- "--json" <<<"${COMPREPLY[*]}" || fail "upgrade must complete --json"

echo "completions test passed"
