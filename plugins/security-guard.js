// opencode-dockerized security guard plugin
//
// opencode-dockerized security layer for OpenCode V2. Mounted read-only into the
// container config plugins dir (no host symlinks), so these hooks cannot be
// altered from within a session. Edit from the host at
// ~/.config/opencode-dockerized/plugins/security-guard.js instead.
// Only a Node.js builtin is imported ("node:fs") — no package.json needed.
//
// OPENCODE_DOCKERIZED_GUARD_VERSION=17
//
// Policy modes (env OPENCODE_DOCKERIZED_POLICY, set by the wrapper from
// `setting.security_policy`; default "balanced"):
//   strict   — every vendored opencode-policy pattern is enforced as-is.
//   balanced — cloud-tenant-specific rules, upstream `admin_bypass` rules and
//              patterns that fire on ordinary local development are dropped,
//              while the genuinely dangerous ones stay. (recommended)
//   off      — vendored patterns are disabled entirely; the built-in backstops
//              below and the generated opencode.json permission rules remain.
//
// opencode-policy patterns: the unsafe tool patterns and prompt-injection
// patterns in ./policies/*.json (ported from opencode-policy, MIT — see
// policies/README.md) are evaluated with the same first-match semantics as
// upstream (new RegExp(pattern, flags ?? "i")). Values matching an entry in
// ./policies/allow-patterns.json are skipped. The built-in DENY_* rules below
// stay active as a backstop even if the policy files are missing.

import { readFileSync, realpathSync } from "node:fs";

const POLICY_MODE = (
  process.env.OPENCODE_DOCKERIZED_POLICY || "balanced"
).toLowerCase();

const loadRules = (name) => {
  try {
    const url = new URL(`./policies/${name}`, import.meta.url);
    const parsed = JSON.parse(readFileSync(url, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    return [];
  }
};

const compile = (rules) =>
  rules
    .map((rule) => {
      if (!rule || typeof rule.pattern !== "string") return undefined;
      try {
        return {
          id: rule.id,
          reason: rule.reason,
          adminBypass: rule.admin_bypass === true,
          re: new RegExp(rule.pattern, rule.flags ?? "i"),
        };
      } catch (e) {
        return undefined;
      }
    })
    .filter(Boolean);

// Rules dropped in "balanced" mode. These are either specific to a shared,
// multi-tenant cloud sandbox (workspaces, /workspace, _shared) or patterns that
// fire on ordinary local development (shell/env parameter expansion, ecosystem
// env access, toolchain/pkg installs, hex tools, "stress"/"benchmark" words,
// "cd ..", `.git/hooks`, `sed -e`, …). Rules upstream marks `admin_bypass` are
// also dropped in balanced mode.
const BALANCED_EXCLUDED_IDS = new Set([
  // Shell/env expansion and access
  "env-var-ref",
  "shell-var-expansion",
  "bypass-var-substring",
  "bypass-var-replace",
  "bypass-ifs-1",
  "bypass-brace-cmd",
  "env-direct-1",
  "var-access-1",
  "var-access-2",
  "var-access-3",
  // Language ecosystem env access
  "dotenv-1",
  "dotenv-2",
  "node-dotenv",
  "python-env-1",
  "python-env-2",
  "python-import-environ",
  "python-subprocess-env",
  "node-env",
  "pythonpath",
  "node-path",
  // Broad npx/npm patterns
  "npx-test-json",
  "npx-env",
  "npx-dump",
  "npx-leak",
  "npx-secret",
  "npx-config",
  "npx-diag",
  "npx-debug",
  "npm-run-env",
  "node-p-process",
  "node-print-process",
  // Process management
  "kill-9",
  "kill-system-1",
  "kill-system-2",
  // Shell/exec idioms
  "sed-exec",
  "eval-cmd",
  "git-hooks",
  "time-exfil-sleep",
  "bypass-nohup",
  "bypass-disown",
  "bypass-setsid",
  // Resource-abuse wording that matches normal test names
  "stress-1",
  "stress-2",
  "stress-test",
  "cpu-stress",
  "thermal-test",
  "urandom-bzip",
  "sysbench",
  // Toolchain / package installs expected in a dev container
  "rustup",
  "go-install",
  "haskell",
  "pip-tensorflow",
  "pip-transformers",
  "pip-cuda",
  "pip-opencv",
  "npm-tensorflow",
  // Hex/base64 tools used in normal debugging
  "base64-pipe-2",
  "xxd-tool",
  "hexdump-tool",
  "od-tool",
  // Cloud multi-tenant workspace rules
  "cd-parent-workspace",
  "cd-dotdot-in-script",
  "workspace-root-direct",
  "workspace-root-ls",
  "shared-dir-access",
  "find-workspace",
  // Whole-string false positives. The guard scans the entire command text
  // (prose in commit messages, grep patterns, heredoc/script bodies), so these
  // match ordinary development rather than a real attack. Dropped in balanced,
  // kept in strict.
  "history-1", // any occurrence of the word "history" (e.g. a directory name)
  "dns-exfil-3", // "host" followed by any later "$" (e.g. --network host $(id -u))
  "exec-builtin", // `.exec(` in JS/Python snippets, not a shell exec
  "fork-bomb-2", // two "&&" anywhere in one command string
  "env-direct-2", // plain `printenv`
  "at-schedule", // `\bat\s+` matches any standalone word "at" (prose, commit messages)
  "base64-exfil-1", // any `base64 <file>`; targeted secret denies still apply
  // `yes`-anchored rules fire on any segment ending in "yes": commands are
  // evaluated per segment, so `--yes` flags (`cmd --yes && ...`,
  // `cmd --yes | ...`) and the legitimate `yes | head` idiom are blocked.
  // Kept in strict.
  "dos-yes",
  "dos-yes-pipe",
]);

const selectRules = (rules) => {
  if (POLICY_MODE === "off") return [];
  if (POLICY_MODE === "strict") return rules;
  return rules.filter(
    (rule) => !rule.adminBypass && !BALANCED_EXCLUDED_IDS.has(rule.id),
  );
};

const UNSAFE_PATTERNS = selectRules(compile(loadRules("unsafe-tool-patterns.json")));
const INJECTION_PATTERNS = selectRules(
  compile(loadRules("prompt-injection-patterns.json")),
);
const ALLOW_PATTERNS = compile(loadRules("allow-patterns.json"));

const matchRule = (rules, value) => {
  for (const rule of rules) {
    if (rule.re.test(value)) return rule;
  }
  return undefined;
};

const isAllowed = (value) => {
  // An allow rule never applies to a value that chains commands or spans lines:
  // `cat .env.example && cat .env` must not slip through on the `.env.example`.
  if (/[;&|\n\r]/.test(value)) return false;
  for (const rule of ALLOW_PATTERNS) {
    if (rule.re.test(value)) return true;
  }
  return false;
};

// Resolve a path to its real location (following symlinks). Returns undefined
// when the path does not exist or cannot be resolved.
const tryRealpath = (p) => {
  if (typeof p !== "string" || p === "") return undefined;
  try {
    return realpathSync.native(p);
  } catch (e) {
    return undefined;
  }
};

// Normalize shell obfuscation back to spaces before matching secret patterns
// (guard v15, H1). `${IFS}`, `$'\t'`/`$'\n'` are word separators for the shell
// but not for the boundary classes in DENY_SECRET_PATH, so `cat${IFS}.env`
// slipped through in balanced/off. Normalization is test-only: the original
// command is kept for the deny message.
const normalizeShell = (cmd) =>
  cmd
    .replace(/\$\{IFS[^}]*\}/gi, " ")
    .replace(/\$'\\t'/g, " ")
    .replace(/\$'\\n'/g, " ");

// Lexically normalize a path (resolve `.`/`..`/duplicate slashes) without
// touching the filesystem. Used for relative edit/write targets (guard v16,
// H11) and documented here so the rm/chmod traversal rules below stay in sync.
const normalizeLexical = (p) => {
  const absolute = p.startsWith("/");
  const parts = p.split("/");
  const stack = [];
  for (const part of parts) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      if (stack.length > 0) stack.pop();
      continue;
    }
    stack.push(part);
  }
  return (absolute ? "/" : "") + stack.join("/");
};

// Secret file names/paths referenced from a shell command (any tool).
// Provider/MCP credentials and SSH keys that need an explicit shell block so the
// agent cannot read/exfiltrate them via `cat`, `cp`, `curl`, etc.
const SECRET_PATH_RE =
  /(^|[\/\s'"=:(])auth\.json([\s'"\/):;,]|$)|(^|[\/\s'"=:(])credentials([\s'"\/.=:;,]|$)|(^|[\/\s'"=:(])\.npmrc([\s'"\/):;,]|$)|(^|[\/\s'"=:(])\.mcp-auth([\/\s'"=:;,]|$)|(^|[\/\s'"=:(])\.gitconfig([\s'"\/):;,]|$)|(^|[\/\s'"=:(])\.composio([\/\s'"=:;,]|$)|(^|[\/\s'"=:(])id_(rsa|dsa|ecdsa|ed25519|ed25519_sk|ecdsa_sk|eddsa)([\s'"\/):;,]|$)/i;

// Shell verbs capable of reading, encoding, copying or transmitting a file.
// Key/certificate *generators* (openssl genrsa, ssh-keygen, gpg --gen-key) are
// deliberately NOT listed, so creating a key is allowed while leaking one is not.
const LEAK_VERB =
  "cat|tac|less|more|head|tail|grep|egrep|fgrep|rg|sed|awk|cut|strings|xxd|od|" +
  "hexdump|base64|base32|cp|mv|install|scp|rsync|tar|zip|gzip|bzip2|xz|curl|wget|" +
  "nc|ncat|socat|telnet|python[0-9.]*|node|deno|bun|perl|ruby|php|" +
  "sort|nl|rev|tr|split|comm|join|paste|pr|fmt|expand|unexpand|fold|csplit|" +
  "diff|cmp|xargs|dd";

// Match a leak verb followed (within the same command segment) by a secret path.
const leakOf = (token) =>
  new RegExp(`\\b(?:${LEAK_VERB})\\b[^\\n|;&]*${token}`, "i");

// File-reading/transmitting verbs, excluding search/print-of-pattern tools
// (grep, sed, awk, …). Used for the bare `*key` heuristic so that grepping for
// the word "key" is not denied while `cat mykey` still is.
const READ_VERB =
  "cat|tac|less|more|head|tail|cp|mv|install|scp|rsync|tar|zip|gzip|bzip2|xz|" +
  "base64|base32|xxd|od|hexdump|strings|dd|python[0-9.]*|node|deno|bun|perl|ruby|php";

const leakReadOf = (token) =>
  new RegExp(`\\b(?:${READ_VERB})\\b[^\\n|;&]*${token}`, "i");

// Shell commands that name `*.env` are denied regardless of the program used, so
// indirect readers the vendored patterns miss are covered: `sort .env`,
// `nl .env`, `xargs -a .env`, `bash < .env`, `source .env`, `dd if=.env`,
// `while read … < .env`, `find … -execdir cat`. `.env.example` templates stay
// readable via the negative lookahead, and the boundary before `.env` avoids
// matching `process.env`-style member access in source code while still
// catching `./.env`, `--env-file=.env`, `"$PWD/.env"` and `>.env`.
const DENY_SECRET_PATH = [/(^|[\s'"=:(/@,<>\-])\.env(?!\.example\b)/i];

// Key-like file names not covered by the `.key`/`.pem` extension rule, e.g.
// `deploy_key`, `prod-key`, `vault_priv`. The `id_*` SSH keys are already in
// SECRET_PATH_RE; the negative lookahead keeps public `*.pub` files readable.
const KEY_FILE =
  "(?:[\\w.-]*(?:_key|-key|_priv)|id_(?:rsa|dsa|ecdsa|ed25519|eddsa))(?![A-Za-z0-9])(?!\\.pub\\b)";

// A bare file name ending in `key` (e.g. `mykey`, `deploykey`) is treated as a
// private key for file-reading verbs. The trailing boundary keeps public
// artifacts such as `public-keys.d`, `authorized_keys` and `*.pub` readable.
const BARE_KEY = "(?:[\\w.-]*key)(?![A-Za-z0-9])(?!\\.pub\\b)";

// Key-like tokens shared by the git-plumbing (N4) and renamed-extractor (N5)
// rules below: private extensions, extensionless key names and bare `*key`.
const KEY_TOKEN = `(?:\\.pem\\b(?!\\.pub\\b)|\\.key\\b(?!\\.pub\\b)|${KEY_FILE}|${BARE_KEY})`;

const DENY_BASH = [
  /\bsudo\b/,
  /\brm\s+(-[a-zA-Z]+\s+)*-[a-zA-Z]*[rf][a-zA-Z]*\s+\/(\s|$)/, // rm -rf /
  /\brm\s+.*\s+\/\s*$/, // rm ... /
  // (guard v16, H1): `rm -rf /*` and `/..` traversals (`/tmp/../`,
  // `/tmp/opencode/../../`) resolve to `/` but miss the bare-slash rules.
  // `rm -rf dist/*` (no leading slash) stays allowed.
  /\brm\s+[^\n|;&]*\s\/\*([\s;|&]|$)/,
  /\brm\s+[^\n|;&]*\/\.\.(\/|$)/,
  /\bmkfs(\.\w+)?\b/,
  /\bdd\b[^|;&]*\bof=\/(dev\/)?[a-z]/, // dd of=/dev/...
  /\b(shutdown|reboot|halt|poweroff)\b/,
  /\bchmod\s+(-[a-zA-Z]+\s+)*0?777\s+\/(\s|$)/,
  // (guard v16, H12): chmod traversals/globs and any chown of `/`.
  /\bchmod\s+[^\n|;&]*\s\/\*([\s;|&]|$)/,
  /\bchmod\s+[^\n|;&]*\/\.\.(\/|$)/,
  /\bchown\s+[^\n|;&]*\s\/([\s;|&*]|$)/,
  /\bchown\s+[^\n|;&]*\/\.\.(\/|$)/,
  />\s*\/dev\/(sd|nvme|hd)/,
  // (guard v16, H4): mode-independent backstops. The vendored patterns cover
  // these in balanced/strict, but `off` disables them entirely.
  /\/proc\/[^/\s]*\/environ\b/,
  /169\.254\.169\.254/,
  // (guard v17, N2): encoded metadata-IP forms. Decimal, dotted/packed hex
  // and octal all reach the same host; the trailing-dot form is already
  // caught by the literal above.
  /\b2852039166\b|\b0x[aA]9[fF][eE][aA]9[fF][eE]\b|0x[aA]9\s*\.\s*0x[fF][eE]\s*\.\s*0x[aA]9\s*\.\s*0x[fF][eE]\b|\b0251\.0376\.0251\.0376\b|::ffff:(a9fe:a9fe|169\.254\.169\.254)/i,
  /\bdocker\b[^\n|;&]*-v\s+\/:/,
  /\bdocker\b[^\n|;&]*--privileged\b/,
  // Secret files: block any command that references them (cat/grep/curl/...),
  // not only the `read` tool. Covers provider/MCP credentials and SSH keys.
  SECRET_PATH_RE,
  // Secret-file leaks the ported patterns miss (cp/scp/`curl -F`/`python open`):
  // a leak verb must precede the token. `.env.example` stays allowed, and key
  // generation is not a leak verb, so `openssl genrsa -out server.key` is fine.
  // `.pem`/`.key` keep the verb rule (now covering the readers that were
  // missing) plus input redirection and sourcing, which have no verb.
  leakOf("\\.pem\\b(?!\\.pub\\b)"),
  leakOf("\\.key\\b(?!\\.pub\\b)"),
  leakOf(KEY_FILE),
  leakReadOf(BARE_KEY),
  /(^|[;&|]\s*)(?:source|\.)\s+[^\s'"|;&<>]*\.(?:pem|key)\b(?!\.pub\b)/i,
  /<\s*[^\s'"|;&]*\.(?:pem|key)\b(?!\.pub\b)/i,
  // `openssl` reading a private key (-in/-inkey/-text, or asn1parse). Generation
  // commands (genrsa/genpkey/req/keygen) stay allowed.
  /\bopenssl\s+(?:rsa|pkey|ec|dsa|pkcs8|pkcs12|asn1parse)\b[^\n|;&]*(?:-inkey\b|-in\b|-text\b)/i,
  // Extract a public key from a private key file. Case-sensitive: `-Y sign`
  // (used by git SSH signing) must stay allowed.
  /\bssh-keygen\b[^\n|;&]*-y\b[^\n|;&]*-f\b/,
  // GnuPG private material and secret-key export (defense in depth; the private
  // keys are never copied into the container anyway).
  /\bprivate-keys-v1\.d\b/,
  /\bgpg\b[^\n|;&]*--export-secret(-keys|-subkeys)?\b/i,
  // Bare environment dumps (no arguments or assignments): `env`, `printenv`,
  // `set`, `export`, `declare` and `typeset` alone print the whole
  // environment, including provider keys from the env file. With arguments or
  // assignments (`printenv PATH`, `env FOO=1 cmd`, `set -e`, `export FOO=1`,
  // `declare -A map`) they stay allowed.
  /(^|[;|&(`\n])\s*\b(env|printenv|set|export|declare|typeset)\b\s*([;|&\n]|$)/i,
  // Dump switches that ignore arguments and always print the environment
  // (guard v16, H2): `declare -p`/`typeset -p` dump every variable with values,
  // bypassing the bare-dump rule above. Declaration flags (`-A/-a/-r/...`)
  // stay allowed.
  /\bexport\s+-p\b/i,
  /\bdeclare\s+-p\b/i,
  /\btypeset\s+-p\b/i,
  /\bcompgen\s+-e\b/i,
  /\bcompgen\s+-v\b/i,
  /\bdeclare\s+-x\b/i,
  /\btypeset\s+-x\b/i,
  // (guard v16, H3): targeted reads of secret-like variable names. `printenv
  // PATH` stays allowed (yellow-team requirement); `printenv SECRET`,
  // `printenv OPENCODE_API_KEY`, `printenv *_TOKEN`, etc. are denied in every
  // mode. `echo $VAR` expansion stays allowed by design (blocking it would
  // break ordinary scripting; see BALANCED_EXCLUDED_IDS).
  /\bprintenv\b\s+[^\n|;&]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH|API[_-]?KEY)\b/i,
  // Forwarded SSH agent is a signing oracle: forbid manipulating the host agent
  // (delete/lock identities, or remove a specific one with -e). Signing and
  // listing stay allowed.
  /\bssh-add\b[^\n|;&]*-[DdxXe]\b/,
  // Do not let the container stop or reconfigure the host gpg-agent.
  /\bgpgconf\b[^\n|;&]*--(?:kill|reload)\b/i,
];

// `*.env.example` templates stay readable (the generated config also allows
// them); a bare `.env`/`.env.local`/... is still denied. Also denies provider/MCP
// credentials, SSH private keys, GnuPG private keys, host git/Composio config
// that can carry tokens, and key-like file names (no extension).
const DENY_READ =
  /(^|\/)\.env(\.(?!example$)|$)|\.pem$|\.key$|(^|\/)auth\.json$|(^|\/)id_(rsa|dsa|ecdsa|ed25519|ed25519_sk|ecdsa_sk|eddsa)$|(^|\/)\.ssh(\/|$)|(^|\/)\.npmrc$|(^|\/)\.mcp-auth(\/|$)|(^|\/)credentials(\.|$)|(^|\/)private-keys-v1\.d(\/|$)|(^|\/)\.gitconfig$|(^|\/)\.composio(\/|$)|(^|\/)[\w.-]*(?:_key|-key|_priv)$|(^|\/)[\w.-]*key$/;

// Actions whose values are scanned against the vendored pattern sets.
const TOOL_ACTIONS = new Set([
  "bash",
  "shell",
  "read",
  "edit",
  "webfetch",
  "websearch",
]);
// Prompt-injection patterns only make sense for free-text inputs, not paths.
const INJECTION_ACTIONS = new Set(["bash", "shell", "webfetch", "websearch"]);

// Extra writable locations beyond the project root(s). The runtime advertises
// `/tmp/opencode` as an approved scratch directory, so writes there are allowed
// in every mode (the project directory itself is the other writable location).
const EXTRA_WRITE_ROOTS = ["/tmp/opencode"];

// OpenCode V2 plugin module: default export with id + setup. Blocking uses the
// permission "evaluate" hook: configured deny rules are final and skip the hook
// (first enforcement layer), while this hook upgrades allow/ask decisions to
// deny for anything the config patterns do not spell out (second layer).
export default {
  id: "opencode-dockerized.security-guard",
  async setup(ctx) {
    // Never treat "/" (or a non-absolute/empty value) as a writable root: a
    // session whose directory is "/" must not become a global write allow.
    const roots = [
      ctx.location && ctx.location.directory,
      ctx.location && ctx.location.project && ctx.location.project.directory,
      ctx.location && ctx.location.project && ctx.location.project.canonical,
      ...EXTRA_WRITE_ROOTS,
    ].filter((r) => typeof r === "string" && r.startsWith("/") && r !== "/");

    const denyPolicy = (event, rule) => {
      event.effect = "deny";
      event.message = `Blocked by workspace policy (opencode-policy/${rule.id}): ${rule.reason}`;
    };

    // Scan values against the ported patterns (first match wins). Returns true
    // when it denied.
    const scanValues = (event, values, rules) => {
      if (rules.length === 0) return false;
      for (const value of values) {
        if (typeof value !== "string" || value === "") continue;
        if (isAllowed(value)) continue;
        const rule = matchRule(rules, value);
        if (rule) {
          denyPolicy(event, rule);
          return true;
        }
      }
      return false;
    };

    await ctx.permission.hook("evaluate", (event) => {
      if (event.effect === "deny") return;
      const resources = event.resources || [];
      const action = event.action;

      if (TOOL_ACTIONS.has(action) && scanValues(event, resources, UNSAFE_PATTERNS)) {
        return;
      }
      if (
        INJECTION_ACTIONS.has(action) &&
        scanValues(event, resources, INJECTION_PATTERNS)
      ) {
        return;
      }

      // Built-in backstops, covering gaps the pattern sets may miss.
      // Shell command evaluations report action "shell" (observed at runtime);
      // "bash" is kept for flows that report the tool-level action instead.
      if (action === "bash" || action === "shell") {
        const command = resources.join(" ");
        const normalized = normalizeShell(command);
        for (const pattern of DENY_BASH) {
          if (pattern.test(command) || pattern.test(normalized)) {
            event.effect = "deny";
            event.message =
              "Blocked by opencode-dockerized security policy: " + command;
            return;
          }
        }
        // Path-reference secret checks are independent of the program used and
        // of the vendored policy mode (defense in depth, even in "off").
        for (const pattern of DENY_SECRET_PATH) {
          if (pattern.test(command) || pattern.test(normalized)) {
            event.effect = "deny";
            event.message =
              "Blocked by opencode-dockerized security policy: " + command;
            return;
          }
        }
      }

      if (action === "read" || action === "grep" || action === "glob") {
        const path = resources.join(" ");
        const real = resources.map(tryRealpath).filter(Boolean).join(" ");
        if (DENY_READ.test(path) || (real !== "" && DENY_READ.test(real))) {
          event.effect = "deny";
          event.message =
            "Blocked by opencode-dockerized security policy: refusing to read " +
            path;
          return;
        }
      }

      if ((action === "edit" || action === "write") && roots.length > 0) {
        for (const path of resources) {
          if (typeof path !== "string" || path === "") continue;
          // (guard v16, H11): resolve relative targets against the project
          // directory instead of skipping them. The runtime resolves relative
          // tool paths against the session directory, so `../outside.txt`
          // must not become a confinement bypass that relies solely on the
          // first-layer `permissions`. Absolute paths keep the previous
          // symlink-aware checks; `/tmp/opencode` stays writable.
          const absolute = path.startsWith("/")
            ? normalizeLexical(path)
            : normalizeLexical(roots[0] + "/" + path);
          // Resolve symlinks so a link inside the project cannot be used to
          // write outside it. Check both the literal path and its real target
          // (and the real parent, since the target may not exist yet).
          const candidates = [absolute];
          const real = tryRealpath(absolute);
          if (real) candidates.push(real);
          const parent = tryRealpath(absolute.replace(/\/[^/]*$/, "") || "/");
          if (parent)
            candidates.push(parent + "/" + absolute.replace(/.*\//, ""));
          const outside = candidates.some(
            (c) => !roots.some((r) => c === r || c.startsWith(r + "/")),
          );
          if (outside) {
            event.effect = "deny";
            event.message =
              "Blocked by opencode-dockerized security policy: write outside project directory: " +
              path;
            return;
          }
        }
      }
    });
  },
};
