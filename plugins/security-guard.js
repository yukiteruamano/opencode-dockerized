// opencode-dockerized security guard plugin
//
// opencode-dockerized security layer for OpenCode V2. Mounted read-only into the
// container config plugins dir (no host symlinks), so these hooks cannot be
// altered from within a session. The wrapper mirrors this file from the repo
// checkout into the config tree on every run (`config sync`); edit the repo copy.
// Only Node.js builtins are imported (node:fs, node:path, node:crypto) — no
// package.json needed. The version marker below is what the wrapper greps to
// decide whether the installed copy is stale: bump it on any behavior change.
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
// ./policies/allow-patterns.json have only the allowed token neutralised. The
// built-in DENY_* rules below stay active as a backstop even if the policy
// files are missing; in balanced/strict a policy set that fails to load makes
// shell commands fail closed instead of silently degrading to "off".

import {
  appendFileSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  renameSync,
  statSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";

const GUARD_VERSION_MARKER = "OPENCODE_DOCKERIZED_GUARD_VERSION=21";
const GUARD_VERSION = Number(GUARD_VERSION_MARKER.split("=")[1]);

const POLICY_MODE = (
  process.env.OPENCODE_DOCKERIZED_POLICY || "balanced"
).toLowerCase();

const HOME_DIR = process.env.HOME || "/home/coder";

// Values longer than this are refused instead of scanned: the vendored regexes
// contain `.*` chains whose worst case is quadratic, so an oversized command
// could freeze this synchronous hook. Use the write tool for large payloads.
const MAX_SCAN_LENGTH = 16 * 1024;

// Audit trail (JSONL) in the read-write state dir. It records decisions, never
// the command text: only its length and a short hash.
const AUDIT_PATH =
  process.env.OPENCODE_DOCKERIZED_GUARD_LOG ||
  join(HOME_DIR, ".local/state/opencode/guard-audit.jsonl");
const AUDIT_MAX_BYTES = 2 * 1024 * 1024;

const audit = (entry) => {
  try {
    mkdirSync(dirname(AUDIT_PATH), { recursive: true });
    try {
      if (statSync(AUDIT_PATH).size > AUDIT_MAX_BYTES) {
        renameSync(AUDIT_PATH, AUDIT_PATH + ".1");
      }
    } catch (e) {
      // no log yet
    }
    appendFileSync(
      AUDIT_PATH,
      JSON.stringify({
        ts: new Date().toISOString(),
        mode: POLICY_MODE,
        version: GUARD_VERSION,
        ...entry,
      }) + "\n",
    );
  } catch (e) {
    // Auditing must never change or break a decision.
  }
};

const loadRules = (name) => {
  try {
    const url = new URL(`./policies/${name}`, import.meta.url);
    const parsed = JSON.parse(readFileSync(url, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    audit({ event: "policy-load-failed", file: name });
    return [];
  }
};

const compile = (rules) =>
  rules
    .map((rule) => {
      if (!rule || typeof rule.pattern !== "string") return undefined;
      try {
        // `g`/`y` make RegExp.test stateful (lastIndex), which would alternate
        // results between calls: strip them from vendored flags.
        const flags =
          typeof rule.flags === "string" ? rule.flags.replace(/[gy]/g, "") : "i";
        return {
          id: rule.id,
          reason: rule.reason,
          adminBypass: rule.admin_bypass === true,
          re: new RegExp(rule.pattern, flags),
          reAll: new RegExp(rule.pattern, flags + "g"),
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

// balanced/strict without their vendored sets would silently behave like "off".
const POLICIES_DEGRADED =
  POLICY_MODE !== "off" &&
  (UNSAFE_PATTERNS.length === 0 || INJECTION_PATTERNS.length === 0);

const matchRule = (rules, value) => {
  for (const rule of rules) {
    if (rule.re.test(value)) return rule;
  }
  return undefined;
};

// Replace the allowed tokens (`.env.example`, `*.key.pub`) with a neutral word
// so the vendored rules still see the rest of the command. Skipping the whole
// value would let `nmap 10.0.0.1 .env.example` through. An allow rule never
// applies to a value that chains commands or spans lines: a template read
// chained with a real secret read must be scanned as written.
const stripAllowed = (value) => {
  if (/[;&|\n\r]/.test(value)) return value;
  let out = value;
  for (const rule of ALLOW_PATTERNS) {
    out = out.replace(rule.reAll, (_m, lead) => `${lead ?? ""}ALLOWED_TEMPLATE`);
  }
  return out;
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

// Decode the body of an ANSI-C quote (`$'...'`): `$'\x2e'` is `.`. Whitespace
// escapes become a plain space, the word separator they act as for the shell.
const decodeAnsiC = (body) =>
  body.replace(/\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|[0-7]{1,3}|[\s\S])/g, (_m, e) => {
    if (e[0] === "x" && e.length > 1) return String.fromCharCode(parseInt(e.slice(1), 16));
    if (e[0] === "u" && e.length > 1) return String.fromCharCode(parseInt(e.slice(1), 16));
    if (/^[0-7]+$/.test(e)) return String.fromCharCode(parseInt(e, 8) & 0xff);
    if (e === "t" || e === "n" || e === "r" || e === " ") return " ";
    return e;
  });

// Expand `{a,b}` brace groups inside one word, as the shell does before running
// it: `{cat,.env}` is the two words `cat` and `.env`. Bounded to 64 results.
const expandBraces = (word) => {
  const m = /^([\s\S]*?)\{([^{}]*,[^{}]*)\}([\s\S]*)$/.exec(word);
  if (!m) return [word];
  const out = [];
  for (const alt of m[2].split(",")) {
    for (const w of expandBraces(m[1] + alt + m[3])) {
      out.push(w);
      if (out.length >= 64) return out;
    }
  }
  return out;
};

// Normalize shell obfuscation before matching secret patterns: `${IFS}`/`$IFS`
// and ANSI-C quotes are word separators or literal characters for the shell
// but not for the boundary classes below, quotes and backslashes split or hide
// names (`.e""nv`, `.\env`), and `{cat,.env}` hides a word boundary. The
// normalization is test-only: the original command is kept for the message and
// every rule is tested against both forms.
const normalizeShell = (cmd) => {
  let out = cmd
    .replace(/\$'((?:[^'\\]|\\[\s\S])*)'/g, (_m, body) => decodeAnsiC(body))
    // Constructs that expand to nothing glue the surrounding characters back
    // together: `.e$""nv`, `.e$()nv`, `.e``nv` and `.e$@nv` are all `.env`.
    // A locale string `$"…"` is its plain double-quoted body.
    .replace(/\$"/g, '"')
    .replace(/\$\(\s*\)|``|\$\{[@*1-9]\}|\$[@*1-9]/g, "")
    .replace(
      /\$\{IFS[^}]*\}|\$IFS(?![A-Za-z0-9_])(?:\$\{?\d\}?|\$\d)?/gi,
      " ",
    )
    .replace(/\\\n/g, "")
    .replace(/\\([\s\S])/g, "$1")
    .replace(/["']/g, "");
  if (out.length <= 8192) {
    out = out.replace(/\S+/g, (w) =>
      w.includes("{") && w.includes(",") ? expandBraces(w).join(" ") : w,
    );
  }
  return out;
};

// Lexically normalize a path (resolve `.`/`..`/duplicate slashes) without
// touching the filesystem. Used for relative edit/write targets and by the
// destructive-target check below.
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

// Kernel-style resolution of an absolute path: components are walked left to
// right and every symlink is followed, including a dangling one (whose target
// does not exist yet but would be created by a write). A `..` after a symlink
// climbs from the link's real target, not lexically. The missing tail is
// appended as written. Returns undefined on a symlink loop or a read error so
// callers can fail closed.
const physicalPath = (path) => {
  let pending = path.split("/");
  let current = "/";
  let missing = false;
  let hops = 0;
  while (pending.length > 0) {
    const part = pending.shift();
    if (part === "" || part === ".") continue;
    if (part === "..") {
      current = dirname(current);
      continue;
    }
    const next = current === "/" ? "/" + part : current + "/" + part;
    if (missing) {
      current = next;
      continue;
    }
    let stats;
    try {
      stats = lstatSync(next);
    } catch (e) {
      missing = true;
      current = next;
      continue;
    }
    if (!stats.isSymbolicLink()) {
      current = next;
      continue;
    }
    if (++hops > 40) return undefined;
    let target;
    try {
      target = readlinkSync(next);
    } catch (e) {
      return undefined;
    }
    if (target.startsWith("/")) current = "/";
    pending = [...target.split("/"), ...pending];
  }
  return current;
};

// Ordered regex parts that must all match, left to right, inside one command
// segment (no newline, pipe, `;` or `&` between them by default). Equivalent to
// joining the parts with `[^\n|;&]*`, but linear: each part is searched once
// from where the previous one ended (lookbehinds still see the whole segment),
// instead of the quadratic backtracking such a gap causes on a 16 KB command
// that repeats the first part. `unless` vetoes a segment when it matches the
// text after the first part.
const SEGMENT_SEPARATORS = /[\n|;&]/;
const inSegment = (parts, { flags = "", split = SEGMENT_SEPARATORS, unless } = {}) => {
  const res = parts.map((p) => new RegExp(typeof p === "string" ? p : p.source, flags + "g"));
  const veto = unless && new RegExp(typeof unless === "string" ? unless : unless.source, flags);
  return {
    test(value) {
      for (const segment of value.split(split)) {
        let at = 0;
        let matched = true;
        for (const [i, re] of res.entries()) {
          re.lastIndex = at;
          const m = re.exec(segment);
          if (!m) {
            matched = false;
            break;
          }
          at = m.index + m[0].length;
          if (i === 0 && veto && veto.test(segment.slice(at))) {
            matched = false;
            break;
          }
        }
        if (matched) return true;
      }
      return false;
    },
  };
};

// Secret file names/paths referenced from a shell command (any tool).
// Provider/MCP credentials, SSH keys and other credential stores that need an
// explicit shell block so the agent cannot read/exfiltrate them via `cat`,
// `cp`, `curl`, etc. The bare word `credentials` only counts when it is
// path-like (`/credentials`, `~/.aws/credentials`, `.credentials*`,
// `credentials.json`), so searching code or writing commit messages that
// mention credentials stays allowed.
const SECRET_PATH_RE = new RegExp(
  [
    String.raw`(^|[\/\s'"=:(])auth\.json([\s'"\/):;,]|$)`,
    String.raw`(^|[\/\s'"=:(])mcp-auth\.json([\s'"\/):;,]|$)`,
    String.raw`(^|[\/\s'"=:(])opencode\.db(?:-wal|-shm|-journal)?([\s'"\/):;,]|$)`,
    // OpenCode's own data dir as a whole (recursive greps, archives).
    String.raw`\.local\/share\/opencode\/?([\s'"):;,]|$)`,
    String.raw`(^|[\/\s'"=:(])\.credentials([\s'"\/.=:;,]|$)`,
    String.raw`(^|[\s'"=:(])credentials\.json([\s'"\/):;,]|$)`,
    String.raw`[\/~]credentials([\s'"\/.=:;,)]|$)`,
    // The AWS config dir itself (`cd ~/.aws && cat credentials`).
    String.raw`(^|[\/\s'"=:(])\.aws\/?([\s'"):;,]|$)`,
    String.raw`(^|[\/\s'"=:(])\.npmrc([\s'"\/):;,]|$)`,
    String.raw`(^|[\/\s'"=:(])\.netrc([\s'"\/):;,]|$)`,
    String.raw`(^|[\/\s'"=:(])\.pgpass([\s'"\/):;,]|$)`,
    String.raw`(^|[\/\s'"=:(])\.git-credentials([\s'"\/):;,]|$)`,
    String.raw`(^|[\/\s'"=:(])\.vault-token([\s'"\/):;,]|$)`,
    String.raw`(^|[\/\s'"=:(])\.mcp-auth([\/\s'"=:;,]|$)`,
    String.raw`(^|[\/\s'"=:(])\.gitconfig([\s'"\/):;,]|$)`,
    String.raw`(^|[\/\s'"=:(])\.composio([\/\s'"=:;,]|$)`,
    String.raw`(^|[\/\s'"=:(])\.config\/gh\/hosts\.yml([\s'"):;,]|$)`,
    String.raw`(^|[\/\s'"=:(])\.docker\/config\.json([\s'"):;,]|$)`,
    String.raw`(^|[\/\s'"=:(])\.kube\/config([\s'"):;,]|$)`,
    // Claude Code state: login, prompt history and conversation transcripts.
    String.raw`(^|[\/\s'"=:(])\.claude\/(projects|sessions|session-env|file-history)([\/\s'"=:;,]|$)`,
    String.raw`(^|[\/\s'"=:(])\.claude\/history\.jsonl([\s'"):;,]|$)`,
    // Keystores, password databases and Terraform state.
    String.raw`(^|[\/\s'"=:(])[\w.-]*\.(?:p12|pfx|jks|kdbx|keystore)([\s'"):;,]|$)`,
    String.raw`(^|[\/\s'"=:(])[\w.-]*\.tfstate(?:\.backup)?([\s'"):;,]|$)`,
    String.raw`(^|[\/\s'"=:(])id_(rsa|dsa|ecdsa|ed25519|ed25519_sk|ecdsa_sk|eddsa)([\s'"\/):;,]|$)`,
  ].join("|"),
  "i",
);

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
const leakOf = (token) => inSegment([`\\b(?:${LEAK_VERB})\\b`, token], { flags: "i" });

// File-reading/transmitting verbs, excluding search/print-of-pattern tools
// (grep, sed, awk, …). Used for the bare `*key` heuristic so that grepping for
// the word "key" is not denied while `cat mykey` still is.
const READ_VERB =
  "cat|tac|less|more|head|tail|cp|mv|install|scp|rsync|tar|zip|gzip|bzip2|xz|" +
  "base64|base32|xxd|od|hexdump|strings|dd|python[0-9.]*|node|deno|bun|perl|ruby|php";

const leakReadOf = (token, verbs = READ_VERB) =>
  inSegment([`\\b(?:${verbs})\\b`, token], { flags: "i" });

// Readers for key-like file names: the plain readers plus the line tools that
// take file operands only (no pattern argument), so `sort deploy_key` is a
// leak while `grep -rn api_key src/` and `sed -i 's/old_key/new_key/' f` are
// searches and edits of ordinary files.
const KEY_READ_VERB =
  READ_VERB + "|sort|nl|rev|split|comm|join|paste|pr|fmt|expand|unexpand|fold|csplit|diff|cmp";

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
// The name must start a word (lookbehind) and not be an option (`--key=2`):
// the leading boundary also keeps the match linear on long words.
const KEY_FILE =
  "(?<![\\w.-])(?!-)(?:[\\w.-]*(?:_key|-key|_priv)|id_(?:rsa|dsa|ecdsa|ed25519|eddsa))(?![A-Za-z0-9])(?!\\.pub\\b)";

// A bare file name ending in `key` (e.g. `mykey`, `deploykey`) is treated as a
// private key for file-reading verbs. The trailing boundary keeps public
// artifacts such as `public-keys.d`, `authorized_keys` and `*.pub` readable.
const BARE_KEY = "(?<![\\w.-])(?!-)(?:[\\w.-]*key)(?![A-Za-z0-9])(?!\\.pub\\b)";

// Key-like tokens shared by the git-plumbing and renamed-extractor rules below:
// private extensions, extensionless key names and bare `*key`.
const KEY_TOKEN = `(?:\\.pem\\b(?!\\.pub\\b)|\\.key\\b(?!\\.pub\\b)|${KEY_FILE}|${BARE_KEY})`;

// Cloud metadata endpoints: AWS/GCP/Azure/OpenStack link-local address, the
// Alibaba address, the AWS IPv6 endpoint, the `instance-data` alias and their
// IPv4-mapped / NAT64 IPv6 spellings (`::ffff:a9fe:a9fe`).
const METADATA_HOST_RE =
  /169\.254\.169\.254|100\.100\.100\.200|\bfd00:0{0,2}ec2(?::0{1,4}){0,5}::?0{0,2}254\b|ffff:(?:0{1,4}:)?(?:a9fe:a9fe|6464:64c8)\b|64:ff9b::(?:a9fe:a9fe|6464:64c8)\b|(?:\/\/|@|\s|^)instance-data(?:\.ec2\.internal)?\.?(?=[:\/\s]|$)|\bmetadata\.google\.internal\b|\b1684301000\b|\b0x646464c8\b/i;

const DENY_BASH = [
  /\bsudo\b/,
  /\brm\s+(-[a-zA-Z]+\s+)*-[a-zA-Z]*[rf][a-zA-Z]*\s+\/(\s|$)/, // rm -rf /
  // rm ... / (the last line ends with a bare slash after an `rm`).
  {
    test: (value) => {
      const last = value.slice(value.lastIndexOf("\n") + 1);
      const m = /\brm\s/.exec(last);
      return m !== null && /\s\/\s*$/.test(last.slice(m.index + 3));
    },
  },
  // `rm -rf /*` and `/..` traversals (`/tmp/../`, `/tmp/opencode/../../`)
  // resolve to `/` but miss the bare-slash rules. `rm -rf dist/*` (no leading
  // slash) stays allowed. Equivalent spellings (`//`, `~`, `$HOME`, `/usr`) are
  // handled by destructiveTarget() below.
  inSegment([/\brm(?=\s)/, /\s\/\*(?=[\s;|&]|$)/]),
  inSegment([/\brm(?=\s)/, /\/\.\.(?:\/|$)/]),
  /\bmkfs(\.\w+)?\b/,
  inSegment([/\bdd\b/, /\bof=\/(?:dev\/)?[a-z]/], { split: /[|;&]/ }), // dd of=/dev/...
  /\bchmod\s+(-[a-zA-Z]+\s+)*0?777\s+\/(\s|$)/,
  // chmod traversals/globs and any chown of `/`.
  inSegment([/\bchmod(?=\s)/, /\s\/\*(?=[\s;|&]|$)/]),
  inSegment([/\bchmod(?=\s)/, /\/\.\.(?:\/|$)/]),
  inSegment([/\bchown(?=\s)/, /\s\/(?=[\s;|&*]|$)/]),
  inSegment([/\bchown(?=\s)/, /\/\.\.(?:\/|$)/]),
  />\s*\/dev\/(sd|nvme|hd)/,
  // Mode-independent backstops. The vendored patterns cover these in
  // balanced/strict, but `off` disables them entirely. Any depth below a pid
  // (`/proc/<pid>/task/<tid>/environ`); globs are handled by procEnviron().
  /\/proc\/(?:[^\s\/]*\/){1,8}environ\b/,
  METADATA_HOST_RE,
  // Encoded metadata-IP forms. Decimal, dotted/packed hex and octal all reach
  // the same host; the trailing-dot form is already caught by the literal above.
  /\b2852039166\b|\b0x[aA]9[fF][eE][aA]9[fF][eE]\b|0x[aA]9\s*\.\s*0x[fF][eE]\s*\.\s*0x[aA]9\s*\.\s*0x[fF][eE]\b|\b0251\.0376\.0251\.0376\b|::ffff:(a9fe:a9fe|169\.254\.169\.254)/i,
  inSegment([/\bdocker\b/, /-v\s+\/:/]),
  inSegment([/\bdocker\b/, /--privileged\b/]),
  // Long-form root mounts. `--volume /:/host` and `--mount …,source=/,…` escape
  // like `-v /:/…`; named volumes (`data:/data`) and host subdirectories stay
  // allowed.
  inSegment([/\bdocker\b/, /--volume\s+\/:\//]),
  inSegment([/\bdocker\b/, /--mount\b/, /\bsource\s*=\s*\/(?:[\s,]|$)/]),
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
  leakReadOf(KEY_FILE, KEY_READ_VERB),
  leakReadOf(BARE_KEY),
  /(^|[;&|]\s*)(?:source|\.)\s+[^\s'"|;&<>]*\.(?:pem|key)\b(?!\.pub\b)/i,
  /<\s*[^\s'"|;&]*\.(?:pem|key)\b(?!\.pub\b)/i,
  // `openssl` reading a private key (-in/-inkey/-text, or asn1parse). Generation
  // commands (genrsa/genpkey/req/keygen) stay allowed.
  inSegment([/\bopenssl\s+(?:rsa|pkey|ec|dsa|pkcs8|pkcs12|asn1parse)\b/, /(?:-inkey\b|-in\b|-text\b)/], {
    flags: "i",
  }),
  // Extract a public key from a private key file. Case-sensitive: `-Y sign`
  // (used by git SSH signing) must stay allowed.
  inSegment([/\bssh-keygen\b/, /-y\b/, /-f\b/]),
  // git subcommands that print committed content over key material.
  // `show`/`cat-file` use `rev:path` form (so key-named branches stay usable);
  // `log` only dumps with `-p`/`--patch` (`--oneline` is metadata); `diff` dumps
  // unless `--stat`. `git show HEAD:README.md` and `git log --oneline` stay
  // allowed.
  inSegment([/\bgit\s+(?:show|cat-file)\b/, `:[^\\s;|&:]*${KEY_TOKEN}`]),
  inSegment([/\bgit\s+grep\b/, KEY_TOKEN]),
  inSegment([/\bgit\s+archive\b/, KEY_TOKEN]),
  inSegment([/\bgit\s+log\b/, /(?:-p\b|--patch\b)/, KEY_TOKEN]),
  inSegment([/\bgit\s+diff\b/, KEY_TOKEN], { unless: /--stat\b/ }),
  // Renamed extractor binaries (`./k -y -f deploy_key`). Token-gated (a key-like
  // `-f`/`-in` target) so local tools with `-y`/`-f` flags over ordinary files
  // stay allowed. Plain renamed readers without extraction flags remain a
  // documented heuristic residual.
  inSegment([/(?:^|[;|&\s])(?:\bssh-keygen\b|[^\s;|&]+\/[\w.-]+)/, /-y\b/, /-f\b/, KEY_TOKEN]),
  inSegment(
    [
      /(?:^|[;|&\s])(?:\bopenssl\b|[^\s;|&]+\/[\w.-]+)\s+(?:rsa|pkey|ec|dsa|pkcs8|pkcs12|asn1parse)\b/,
      /(?:-inkey\b|-in\b|-text\b)/,
      KEY_TOKEN,
    ],
    { flags: "i" },
  ),
  // GnuPG private material and secret-key export (defense in depth; the private
  // keys are never copied into the container anyway).
  /\bprivate-keys-v1\.d\b/,
  inSegment([/\bgpg\b/, /--export-secret(?:-keys|-subkeys)?\b/], { flags: "i" }),
  // Bare environment dumps (no arguments or assignments): `env`, `printenv`,
  // `set`, `export`, `declare` and `typeset` alone print the whole
  // environment, including provider keys from the env file. With arguments or
  // assignments (`printenv PATH`, `env FOO=1 cmd`, `set -e`, `export FOO=1`,
  // `declare -A map`) they stay allowed. The verb may sit behind wrapper words
  // (`command`, `exec`, `time`, `busybox`, a leading backslash or an absolute
  // path), inside a subshell or a command substitution. envDump() below covers
  // the remaining wrappers (`bash -c`, `nice`, `timeout`, `xargs`, …) and flag
  // spellings (`declare -xp`, `printenv -0`, `ps eww`, `compgen -A variable`).
  /(^|[;|&(`\n]|\$\()\s*(?:(?:command|exec|builtin|nohup|time)\s+)*\\?(?:\/(?:[\w.-]+\/)*)?(?:busybox\s+)?\b(env|printenv|set|export|declare|typeset)\b\s*([;|&)`\n]|$)/i,
  // `env` with only NUL/unset switches still prints the environment.
  /(^|[;|&(`\n]|\$\()\s*(?:\/(?:[\w.-]+\/)*)?env\s+(?:-0|--null|-u\s*\w+|--unset=\w+)(?:\s+(?:-0|--null|-u\s*\w+|--unset=\w+))*\s*([;|&)`\n]|$)/i,
  // Dump switches that ignore arguments and always print the environment:
  // `declare -p`/`typeset -p` dump every variable with values, bypassing the
  // bare-dump rule above. Declaration flags (`-A/-a/-r/...`) stay allowed.
  /\bexport\s+-p\b/i,
  /\bdeclare\s+-p\b/i,
  /\btypeset\s+-p\b/i,
  /\bcompgen\s+-e\b/i,
  /\bcompgen\s+-v\b/i,
  /\bdeclare\s+-x\b/i,
  /\btypeset\s+-x\b/i,
  // Targeted reads of secret-like variable names. `printenv PATH` stays
  // allowed; `printenv SECRET`, `printenv OPENCODE_API_KEY`, `printenv *_TOKEN`,
  // etc. are denied in every mode. `echo $VAR` expansion stays allowed by
  // design (blocking it would break ordinary scripting; see BALANCED_EXCLUDED_IDS).
  inSegment([/\bprintenv\b/, /(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH|API[_-]?KEY)\b/], {
    flags: "i",
  }),
  // Full environment dumps via interpreters. Bulk reads
  // (`console.log(process.env)`, `print(os.environ)`, `puts ENV`,
  // `print_r($_ENV)`), including copies wrapped in a serializer or container
  // (`JSON.stringify(process.env)`, `print(dict(os.environ))`,
  // `json.dumps({**os.environ})`), are denied in every mode; scoped member
  // access (`process.env.PATH`, `os.environ.get("X")`, `ENV["X"]`, `$ENV{X}`)
  // stays allowed for normal config reads. Staged copies (`x =
  // {...process.env}` printed later) remain a documented residual.
  /\bconsole\s*\.\s*(?:log|dir|debug|info)\s*\(\s*process\s*\.\s*env\s*\)/,
  inSegment([/\bnode\b/, /-(?:p\b|print\b)/, /\bprocess\s*\.\s*env\b(?!\s*(?:\.\s*[A-Za-z_$][\w$]*|\[|\?\.))/]),
  /\b(?:console\s*\.\s*\w+|JSON\s*\.\s*stringify|(?:util\s*\.\s*)?inspect|process\s*\.\s*std(?:out|err)\s*\.\s*write)\s*\(\s*(?:[^(),\n]{0,120},\s*)?(?:[\w.]+\s*\(\s*){0,3}(?:\{\s*)?(?:\.\.\.\s*)?process\s*\.\s*env\b(?!\s*(?:\.\s*[A-Za-z_$]|\?\.|\[))/,
  /\bprint\s*\(\s*os\s*\.\s*environ(?:\s*\.\s*(?:copy|items|keys|values)\s*\(\s*\))?\s*\)/,
  /\bpprint\s*\(\s*os\s*\.\s*environ\s*\)/,
  /\b(?:p?print|json\s*\.\s*dumps?|repr|str|(?:sys\s*\.\s*)?std(?:out|err)\s*\.\s*write|yaml\s*\.\s*(?:safe_)?dump)\s*\(\s*(?:[^(),\n]{0,120},\s*)?(?:[\w.]+\s*\(\s*){0,3}(?:\{\s*)?(?:\*{1,2}\s*)?os\s*\.\s*environ\b(?!\s*(?:\[|\.\s*(?:get|setdefault|pop|__getitem__)\s*\())/,
  /\bputs\s+ENV\b(?!\s*(\[|\.\s*(?:fetch|key\?|slice|dig|values_at)\s*\())|\bp\s+ENV\b(?!\s*(\[|\.\s*(?:fetch|key\?|slice|dig|values_at)\s*\())|\bENV\s*\.\s*(?:inspect|to_h|to_hash)\b/,
  inSegment([/(?:\bprint\b|\bsay\b|\bwarn\b|\bprintf\b)/, /%ENV\b/], { split: /[\n;&]/ }),
  /(?:\bprint_r\b|\bvar_dump\b|\bvar_export\b)\s*\(\s*(?:getenv\s*\(\s*\)|\$_ENV\b(?!\s*\[)|\$_SERVER\b(?!\s*\[))/,
  /\bconsole\s*\.\s*(?:log|dir)\s*\(\s*Deno\s*\.\s*env\s*\.\s*toObject\s*\(\s*\)\s*\)/,
  // Forwarded SSH agent is a signing oracle: forbid manipulating the host agent
  // (delete/lock identities, or remove a specific one with -e). Signing and
  // listing stay allowed.
  inSegment([/\bssh-add\b/, /-[DdxXe]\b/]),
  // Do not let the container stop or reconfigure the host gpg-agent.
  inSegment([/\bgpgconf\b/, /--(?:kill|reload)\b/], { flags: "i" }),
];

// `git push` / `git reset --hard` behind option words or wrappers
// (`git -C . push`, `command git push`, `env git push`) miss the literal-prefix
// permission rule, so they are escalated to the user here. At most eight
// option words (each with an optional value) keep the match linear.
const GIT_OPTION = String.raw`(?:\s+-\S+(?:\s+(?!-)\S+)?){0,8}`;
const GIT_ASK = [
  new RegExp(String.raw`\bgit\b${GIT_OPTION}\s+push\b`),
  inSegment([new RegExp(String.raw`\bgit\b${GIT_OPTION}\s+reset\b`), /--hard\b/]),
];

// --- Simple-command analysis ------------------------------------------------
// The checks below look at what actually runs: the normalized command is cut
// into simple commands (separators, subshells, substitutions) and transparent
// wrappers are peeled off, so `bash -c 'env'`, `nice env`, `timeout 5 env`,
// `xargs env` and `if env; then` all reach the same verdict as `env`.

const PREFIX_WORDS = new Set(["!", "{", "}", "then", "do", "else", "elif", "if", "while", "until"]);
// Wrappers that run their operands as a command, with the options that take
// a separate argument.
const WRAPPER_OPTIONS = {
  command: /^-$/,
  builtin: /^-$/,
  exec: /^-a$/,
  nohup: /^-$/,
  time: /^-[fo]$/,
  eval: /^-$/,
  busybox: /^-$/,
  setsid: /^-$/,
  unbuffer: /^-$/,
  nice: /^-n$/,
  ionice: /^-[cnt]$/,
  timeout: /^-[sk]$/,
  stdbuf: /^-[ioe]$/,
  watch: /^-[nq]$|^--interval$/,
  xargs: /^-[nIadLPsE]$/,
  strace: /^-[oepsEuabPI]$/,
  env: /^-[uCS]$/,
};
const SHELL_NAMES = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash"]);
const REDIRECT_WORD = /^(?:\d*(?:>>?|<<?<?|>&|<&)|&>>?)(.*)$/;

const baseName = (word) => word.replace(/^\\/, "").replace(/^.*\//, "");

// Peel wrappers off one simple command. Returns the words of the command that
// actually runs, `["env"]` for an `env` that runs nothing (it prints the
// environment), or [] for a lookup such as `command -v env`.
const unwrapCommand = (input) => {
  let words = input;
  for (let rounds = 0; rounds < 32 && words.length > 0; rounds++) {
    const head = words[0].replace(/^\\/, "");
    const verb = baseName(head);
    if (PREFIX_WORDS.has(head) || /^[A-Za-z_]\w*=/.test(head)) {
      words = words.slice(1);
      continue;
    }
    if (verb === "command" && words.length > 1 && /^-[a-zA-Z]*[vV]/.test(words[1])) return [];
    if (Object.hasOwn(WRAPPER_OPTIONS, verb)) {
      let i = 1;
      while (i < words.length && /^-./.test(words[i])) {
        const opt = words[i++];
        if (opt === "--") break;
        if (WRAPPER_OPTIONS[verb].test(opt)) i++;
      }
      if (verb === "timeout" && i < words.length) i++; // the duration
      if (verb === "env") {
        while (i < words.length && /^[A-Za-z_]\w*=/.test(words[i])) i++;
        if (i >= words.length) return ["env"];
      }
      words = words.slice(i);
      continue;
    }
    if (SHELL_NAMES.has(verb)) {
      // `sh -c 'cmd'`: quotes are gone after normalization, so the command
      // string is simply the words after the options.
      let i = 1;
      let inline = false;
      while (i < words.length && /^[-+]./.test(words[i])) {
        const opt = words[i++];
        if (opt === "--") break;
        if (/^-[a-zA-Z]*c/.test(opt)) inline = true;
        if (/^[-+]O$|^[-+]o$/.test(opt)) i++;
      }
      if (!inline) return words;
      words = words.slice(i);
      continue;
    }
    return words;
  }
  return words;
};

// Cut a normalized command into simple commands. Each entry keeps the segment
// text (for redirections) and the unwrapped words without redirections.
const simpleCommands = (normalized) => {
  const out = [];
  for (const text of normalized.split(/[;&|\n()`]|\$\(/)) {
    const raw = text.trim().split(/\s+/).filter(Boolean);
    const words = [];
    for (let i = 0; i < raw.length; i++) {
      const r = REDIRECT_WORD.exec(raw[i]);
      if (r) {
        if (r[1] === "") i++; // the target is the next word
        continue;
      }
      words.push(raw[i]);
    }
    out.push({ text, words: unwrapCommand(words) });
  }
  return out;
};

// `ps` options whose next word is an argument (process names such as `sleep`
// must not be read as BSD flags).
const PS_ARG_OPTIONS = new Set([
  "-C", "-G", "-g", "-o", "-O", "-p", "-q", "-s", "-t", "-u", "-U",
  "--sort", "--format", "--pid", "--ppid", "--user", "--User", "--group", "--Group",
  "--sid", "--tty", "--cols", "--columns", "--rows", "--lines", "--width",
]);

// `ps` with the BSD `e` flag (`ps eww`, `ps auxe`) prints every process's
// environment. Dash options (`-e`, `-ef`) select processes and stay allowed.
const psShowsEnvironment = (args) => {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (PS_ARG_OPTIONS.has(a)) {
      i++;
      continue;
    }
    if (a.startsWith("-")) {
      if (/^-[A-Za-z]*[CGgoOpqstuU]$/.test(a) && a.length > 2) i++;
      continue;
    }
    if (!/^[A-Za-z]+$/.test(a)) continue;
    if (a.includes("e")) return true;
    if (/[oOpUtk]$/.test(a)) i++;
  }
  return false;
};

const isOption = (word) => /^[-+]./.test(word);

// Commands that print the whole environment (or every variable).
const envDump = (words) => {
  if (words.length === 0) return false;
  const verb = baseName(words[0]);
  const args = words.slice(1);
  const names = args.filter((a) => !isOption(a));
  const flags = args.filter(isOption).join(" ");
  switch (verb) {
    case "env":
      return true; // unwrapCommand only returns `env` when it runs nothing
    case "printenv":
      return names.length === 0;
    case "set":
      return args.length === 0;
    case "export":
    case "declare":
    case "typeset":
      return names.length === 0 || /(?:^|\s)-[a-zA-Z]*p/.test(flags);
    case "compgen":
      return (
        /(?:^|\s)-[a-zA-Z]*[ev]/.test(flags) ||
        args.some((a, i) => a === "-A" && /^(?:variable|export)$/.test(args[i + 1] ?? ""))
      );
    case "ps":
      return psShowsEnvironment(args);
    default:
      return false;
  }
};

// Power management at command position only, so prose such as
// `git commit -m 'fix graceful shutdown handler'` or `rg shutdown src/` is not
// mistaken for a reboot.
const POWER_VERBS = new Set(["shutdown", "reboot", "halt", "poweroff"]);
const powerCommand = (words) => {
  if (words.length === 0) return false;
  const verb = baseName(words[0]);
  if (POWER_VERBS.has(verb)) return true;
  if (verb === "systemctl" || verb === "loginctl") {
    return words.slice(1).some((w) => /^(?:reboot|poweroff|halt|kexec)$/.test(w));
  }
  if (verb === "init" || verb === "telinit") return words.slice(1).some((w) => /^[06]$/.test(w));
  return false;
};

// --- git configuration that runs commands -----------------------------------
// Repository config and hooks run on the host the next time the user runs git
// there, outside the sandbox. Setting any key that names a program is refused
// in every mode, whether persisted (`git config`, `git clone -c`) or inline
// (`git -c`); reading (`--get`, `-l`) stays allowed.
const GIT_EXEC_KEYS = [
  /^core\.(?:hookspath|fsmonitor|sshcommand|askpass|gitproxy|alternaterefscommand|editor|pager)$/,
  /^(?:.+\.)?editor$/,
  /^pager\..+$/,
  /^filter\..+\.(?:clean|smudge|process)$/,
  /^diff\.(?:.+\.(?:textconv|command)|external)$/,
  /^(?:merge|difftool|mergetool)\..+\.(?:driver|cmd)$/,
  /^credential\.(?:.+\.)?helper$/,
  /^gpg\.(?:.+\.)?(?:program|defaultkeycommand)$/,
  /^include\.path$|^includeif\..+\.path$/,
  /^init\.templatedir$/,
  /^remote\..+\.(?:uploadpack|receivepack|vcs)$/,
  /^protocol\.ext\.allow$/,
  /^uploadpack\.packobjectshook$/,
  /^sendemail\.(?:.+\.)?(?:smtpserver|tocmd|cccmd|headercmd)$/,
  /^(?:web\.browser|browser\..+\.(?:cmd|path)|man\..+\.(?:cmd|path))$/,
];
// Editors and pagers that cannot smuggle a command (`git -c core.pager=cat log`
// and `git -c core.editor=true rebase --continue` are everyday idioms).
const SAFE_EDITOR_PAGER = /^(?:|cat|true|false|:|less|more|vi|vim|nvim|nano|emacs)$/;

// Verdict for setting `key` to `value`: "deny", "ask" or undefined.
const gitConfigVerdict = (key, value) => {
  const k = key.toLowerCase();
  if (/^alias\./.test(k) || /^submodule\..+\.update$/.test(k)) {
    if (/^\s*!/.test(value)) return "deny";
    // An alias for push/reset would skip the approval below.
    if (/^alias\./.test(k) && /^\s*(?:push\b|reset\b.*--hard\b)/.test(value)) return "ask";
    return undefined;
  }
  if (!GIT_EXEC_KEYS.some((re) => re.test(k))) return undefined;
  if (/(?:^|\.)(?:editor|pager)$|^pager\./.test(k) && SAFE_EDITOR_PAGER.test(value.trim())) {
    return undefined;
  }
  return "deny";
};

const gitConfigPair = (spec) => {
  const eq = spec.indexOf("=");
  return eq < 0 ? gitConfigVerdict(spec, "true") : gitConfigVerdict(spec.slice(0, eq), spec.slice(eq + 1));
};

const GIT_CONFIG_READ =
  /^(?:--get(?:-all|-regexp|-urlmatch|-color|-colorbool)?|-l|--list|--unset(?:-all)?|--remove-section|--rename-section|-h|--help)$/;
const GIT_CONFIG_OPTION_ARG = new Set(["-f", "--file", "--blob", "--type", "--default", "--comment", "--value", "--url"]);

// `git config [options] key value` (and `git config set key value`).
const gitConfigCommand = (args) => {
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-e" || a === "--edit") return "deny";
    if (GIT_CONFIG_READ.test(a)) return undefined;
    if (GIT_CONFIG_OPTION_ARG.has(a)) {
      i++;
      continue;
    }
    if (a.startsWith("-")) continue;
    positional.push(a);
  }
  if (/^(?:get|list|unset|rename-section|remove-section)$/.test(positional[0] ?? "")) return undefined;
  if (positional[0] === "edit") return "deny";
  if (positional[0] === "set") positional.shift();
  if (positional.length < 2) return undefined; // a bare key only reads it
  return gitConfigVerdict(positional[0], positional.slice(1).join(" "));
};

const GIT_GLOBAL_OPTION_ARG = new Set([
  "-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--list-cmds", "--attr-source",
]);

const strongest = (verdicts) =>
  verdicts.includes("deny") ? "deny" : verdicts.includes("ask") ? "ask" : undefined;

// Verdict for one unwrapped git invocation: "deny", "ask" or undefined.
const gitVerdict = (words) => {
  if (words.length === 0 || baseName(words[0]) !== "git") return undefined;
  const verdicts = [];
  let i = 1;
  for (; i < words.length && words[i].startsWith("-"); i++) {
    const opt = words[i];
    if (opt === "-c") verdicts.push(gitConfigPair(words[++i] ?? ""));
    else if (opt.startsWith("--config-env")) {
      // The value comes from an environment variable: assume the worst.
      const spec = opt.includes("=") ? opt.slice(opt.indexOf("=") + 1) : words[++i] ?? "";
      verdicts.push(gitConfigVerdict(spec.replace(/=.*$/, ""), "!"));
    } else if (GIT_GLOBAL_OPTION_ARG.has(opt)) i++;
  }
  const sub = words[i];
  const args = words.slice(i + 1);
  if (sub === "config") verdicts.push(gitConfigCommand(args));
  if (/^(?:clone|init|submodule)$/.test(sub ?? "")) {
    // A template directory copies its hooks into the new repository, and
    // `clone -c` writes the new repository's config.
    if (args.some((a) => /^--template(?:=|$)/.test(a))) verdicts.push("deny");
    for (let j = 0; j < args.length; j++) {
      if (args[j] === "-c" || args[j] === "--config") verdicts.push(gitConfigPair(args[j + 1] ?? ""));
      else if (args[j].startsWith("--config=")) verdicts.push(gitConfigPair(args[j].slice(9)));
    }
  }
  if (sub === "push" || (sub === "reset" && args.includes("--hard"))) verdicts.push("ask");
  return strongest(verdicts);
};

// A path into git's control files: hooks (any depth, so submodule hooks under
// `.git/modules/<sub>/hooks/` count), `config`/`config.worktree`, or the `.git`
// entry itself (a `.git` file redirects the git directory).
const GIT_CONTROL = String.raw`\.git(?:\/(?:[^\s;|&<>\/]*\/){0,16}(?:hooks|config(?:\.worktree)?)(?![\w.-])|\/?(?![^\s;|&<>)]))`;
const GIT_CONTROL_RE = new RegExp(GIT_CONTROL, "i");
// Copy/move destinations anywhere inside `.git` except `.git/info/`.
const GIT_DIR_TARGET_RE = /(?:^|\/)[^\/]*\.git(?:\/(?!info\/)|$)/i;
const COPY_VERBS = new Set(["cp", "mv", "install", "ln", "rsync"]);
const SHELL_GIT_WRITES = [
  // Redirections into a hook or the config (`>`, `>>`, `>|`, `&>`).
  new RegExp(String.raw`>\|?\s*[^\s;|&<>]*${GIT_CONTROL}`, "i"),
  inSegment([/\b(?:tee|truncate|touch)\b/, GIT_CONTROL], { flags: "i" }),
  inSegment([/\bsed\b/, /\s(?:-[a-zA-Z]*i|--in-place)/, GIT_CONTROL], { flags: "i" }),
  inSegment([/\bdd\b/, new RegExp(String.raw`\bof=[^\s;|&<>]*${GIT_CONTROL}`)], { flags: "i" }),
  // Interpreters writing the files (`python -c "open('.git/hooks/x','w')"`):
  // `;` inside the quoted program does not end the command here.
  inSegment([/\b(?:python[0-9.]*|node|deno|bun|perl|ruby|php)\b/, GIT_CONTROL], {
    flags: "i",
    split: /\n|&&|\|\|/,
  }),
];

// Copy/move/link destinations inside `.git` (the last operand or `-t DIR`).
const copyTarget = (words) => {
  if (words.length === 0 || !COPY_VERBS.has(baseName(words[0]))) return undefined;
  const operands = [];
  for (let i = 1; i < words.length; i++) {
    const w = words[i];
    if (w === "-t" || w === "--target-directory") return words[i + 1];
    if (w.startsWith("--target-directory=")) return w.slice(19);
    if (/^-t./.test(w)) return w.slice(2);
    if (!w.startsWith("-")) operands.push(w);
  }
  return operands.length >= 2 ? operands[operands.length - 1] : undefined;
};

const WRITE_VERBS = new Set(["cp", "mv", "install", "ln", "rsync", "tee", "touch", "truncate", "sed", "dd", "chmod"]);

// Shell writes that would plant something git runs later on the host.
const gitControlWrite = (normalized, commands) => {
  if (SHELL_GIT_WRITES.some((rule) => rule.test(normalized))) return true;
  let insideGitDir = false;
  for (const { text, words } of commands) {
    const target = copyTarget(words);
    if (target !== undefined && (GIT_CONTROL_RE.test(target) || GIT_DIR_TARGET_RE.test(target))) return true;
    if (words.length === 0) continue;
    const verb = baseName(words[0]);
    if (verb === "cd" || verb === "pushd") {
      insideGitDir = words.slice(1).some((w) => /(?:^|\/)[^\/]*\.git(?:\/|$)/i.test(w));
      continue;
    }
    // `cd .git/hooks && cat > pre-commit`: relative writes from inside `.git`.
    if (insideGitDir && (/>/.test(text) || WRITE_VERBS.has(verb))) return true;
  }
  return false;
};

// `/proc/<pid>/environ` spelled with globs (`/proc/self/env*`,
// `/proc/*/environ`, `/proc/1/*`), or read relative to a `cd /proc/<pid>`.
const globMatches = (pattern, name) => {
  if (!/[*?[]/.test(pattern)) return pattern === name;
  try {
    return globToRegExp(pattern).test(name);
  } catch (e) {
    return false;
  }
};
const PROC_RECURSIVE = inSegment([
  /\b(?:rg|grep|egrep|fgrep|ag|ack|tar|zip|rsync|cp)\b/,
  /(?:^|\s)\/proc\/[^\s\/]+(?:\/task\/[^\s\/]+)?\/?(?=\s|$)/,
]);
const procEnviron = (normalized) => {
  for (const m of normalized.matchAll(/\/proc\/[^\s;|&<>()`'"]*/g)) {
    const parts = m[0].split("/").filter(Boolean);
    if (parts.length > 2 && globMatches(parts[parts.length - 1], "environ")) return true;
  }
  if (PROC_RECURSIVE.test(normalized)) return true;
  if (/\b(?:cd|pushd)\s+\/proc\//.test(normalized)) {
    return normalized.split(/[\s;&|<>()`]+/).some((w) => globMatches(w, "environ"));
  }
  return false;
};

// Dotfile secrets a glob such as `.e*` or `.[e]nv` can expand to. A wildcard
// first never matches a dotfile in the shell, so only globs that start with a
// literal dot count (non-dot names need two literal leading characters).
const GLOB_SECRET_NAMES = [
  ".env",
  ".env.local",
  ".env.production",
  ".env.development",
  ".npmrc",
  ".netrc",
  ".pgpass",
  ".gitconfig",
  ".git-credentials",
  ".credentials.json",
  ".vault-token",
  "auth.json",
  "mcp-auth.json",
  "opencode.db",
  "id_rsa",
  "id_ed25519",
  "id_ecdsa",
  "id_dsa",
];

const globToRegExp = (glob) => {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") re += ".*";
    else if (c === "?") re += ".";
    else if (c === "[") {
      const end = glob.indexOf("]", i + 2);
      if (end === -1) {
        re += "\\[";
        continue;
      }
      let cls = glob.slice(i + 1, end);
      if (cls[0] === "!") cls = "^" + cls.slice(1);
      re += "[" + cls.replace(/\\/g, "\\\\") + "]";
      i = end;
    } else re += c.replace(/[.+^${}()|\\/]/g, "\\$&");
  }
  return new RegExp("^" + re + "$");
};

const LEAK_VERB_RE = new RegExp(`\\b(?:${LEAK_VERB})\\b`, "i");

// Directories that only hold credentials: any glob inside them is a leak
// (`cat ~/.local/share/opencode/*` reads auth.json and the session database).
const SECRET_DIR_RE =
  /(?:^|\/)(?:\.local\/share\/opencode|\.ssh|\.mcp-auth|\.composio|\.gnupg\/private-keys-v1\.d)$/;

// A leak verb applied to a glob that can expand to a secret dotfile.
const globLeaks = (normalized) => {
  for (const segment of normalized.split(/[;&|\n]+/)) {
    if (!LEAK_VERB_RE.test(segment)) continue;
    for (const word of segment.split(/\s+/)) {
      if (word.startsWith("-") || !/[*?[]/.test(word)) continue;
      const slash = word.lastIndexOf("/");
      const base = word.slice(slash + 1);
      if (slash > 0 && SECRET_DIR_RE.test(word.slice(0, slash))) return true;
      let re;
      try {
        re = globToRegExp(base);
      } catch (e) {
        continue;
      }
      const dotted = base.startsWith(".");
      const literalLead = /^[A-Za-z0-9_.-]{2}/.test(base);
      if (
        GLOB_SECRET_NAMES.some(
          (name) => re.test(name) && (name.startsWith(".") ? dotted : literalLead),
        )
      ) {
        return true;
      }
    }
  }
  return false;
};

// Directories whose removal, permission change or move is never legitimate
// from a coding session. Equivalent spellings (`//`, `/.`, `~`, `$HOME`,
// `${HOME}`, trailing `/*`) are canonicalised first.
const PROTECTED_DIRS = new Set([
  "/",
  "/bin",
  "/boot",
  "/dev",
  "/etc",
  "/home",
  "/lib",
  "/lib32",
  "/lib64",
  "/opt",
  "/proc",
  "/root",
  "/run",
  "/sbin",
  "/srv",
  "/sys",
  "/tmp",
  "/usr",
  "/var",
  HOME_DIR,
]);

const canonicalTarget = (arg) => {
  const expanded = arg.replace(/^(?:~|\$HOME|\$\{HOME\})(?=\/|$)/, HOME_DIR);
  if (!expanded.startsWith("/")) return undefined;
  return normalizeLexical(expanded) || "/";
};

const isProtectedTarget = (arg) => {
  const direct = canonicalTarget(arg);
  if (direct !== undefined && PROTECTED_DIRS.has(direct)) return true;
  // `/usr/*` and `~/.*` wipe the contents of the directory they sit in.
  const glob = /^(.*)\/\.?\*$/.exec(arg);
  if (glob) {
    const parent = canonicalTarget(glob[1] === "" ? "/" : glob[1]);
    return parent !== undefined && PROTECTED_DIRS.has(parent);
  }
  return false;
};

const WRAPPER_WORDS = new Set(["command", "exec", "builtin", "nohup", "time", "env"]);
const DESTRUCTIVE_VERBS = new Set(["rm", "chmod", "chown", "chgrp", "mv", "shred", "truncate", "find"]);

// rm/chmod/chown/mv/find aimed at a protected directory, including `cd /` or
// `cd ~` followed by a wipe of the current directory (`rm -rf *`).
const destructiveTarget = (normalized) => {
  let dangerousCwd = false;
  for (const segment of normalized.split(/[;&|\n]+/)) {
    const words = segment.trim().split(/\s+/).filter(Boolean);
    while (words.length > 0 && WRAPPER_WORDS.has(words[0].replace(/^\\/, ""))) words.shift();
    if (words.length === 0) continue;
    const verb = words[0].replace(/^\\/, "").replace(/^.*\//, "");
    const args = words.slice(1);
    if (verb === "cd") {
      const dest = args.find((a) => !a.startsWith("-"));
      dangerousCwd = dest === undefined ? true : isProtectedTarget(dest);
      continue;
    }
    if (!DESTRUCTIVE_VERBS.has(verb)) continue;
    const operands = args.filter((a) => !a.startsWith("-"));
    if (verb === "find") {
      const acts = /\s-delete\b|\s-exec(?:dir)?\s+(?:rm|chmod|chown|mv|shred)\b/.test(segment);
      const roots = [];
      for (const a of args) {
        if (a.startsWith("-") || a === "(" || a === "!") break;
        roots.push(a);
      }
      if (acts && roots.some(isProtectedTarget)) return true;
      continue;
    }
    let targets = operands;
    if (verb === "chmod" || verb === "chown" || verb === "chgrp") targets = operands.slice(1);
    if (verb === "mv") targets = operands.slice(0, -1);
    for (const t of targets) {
      if (isProtectedTarget(t)) return true;
      if (dangerousCwd && /^(?:\.|\.\.|\.\/|\*|\.\*|\.\/\*)$/.test(t)) return true;
    }
  }
  return false;
};

// Network clients that can carry local data off the machine.
const URL_EGRESS_VERBS = new Set(["curl", "wget"]);
const SOCKET_EGRESS_VERBS = new Set(["nc", "ncat", "netcat", "socat", "telnet"]);
const LOCAL_HOST = /^(?:localhost|127(?:\.\d+){3}|\[?::1\]?|0\.0\.0\.0|host\.docker\.internal)$/i;
const SECRET_VAR = /\$\{?([A-Za-z_]\w*)/g;
const SECRET_VAR_NAME = /KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH|COOKIE|SESSION/i;
const UPLOAD_FLAG_FILE =
  /(?:^|\s)(?:-T|--upload-file|--post-file|--body-file)(?:=|\s+)(\S+)|(?:^|\s)(?:-d|--data|--data-binary|--data-raw|--data-urlencode|-F|--form)(?:=|\s*)(?:[\w.-]+=)?@(\S+)/g;

const hostOf = (word) => {
  const m = /^(?:[a-z][a-z0-9+.-]*:\/\/)?(?:[^/@\s]*@)?(\[[0-9a-f:]+\]|[^/:\s]+)/i.exec(word);
  return m ? m[1] : undefined;
};

// Secret-looking variables or local files sent to a non-local host. Local
// hosts (dev servers) and uploads from the approved scratch directory stay
// allowed; provider keys live in the environment, so secret-named variables
// never leave through curl/wget/nc.
const egressLeak = (normalized) => {
  for (const segment of normalized.split(/[;&|\n]+/)) {
    const words = segment.trim().split(/\s+/).filter(Boolean);
    while (words.length > 0 && WRAPPER_WORDS.has(words[0])) words.shift();
    if (words.length === 0) continue;
    const verb = words[0].replace(/^.*\//, "");
    const isUrl = URL_EGRESS_VERBS.has(verb);
    const isSocket = SOCKET_EGRESS_VERBS.has(verb);
    if (!isUrl && !isSocket) continue;

    const operands = words.slice(1).filter((w) => !w.startsWith("-"));
    const hosts = isSocket
      ? [hostOf(operands[0] ?? "")].filter(Boolean)
      : operands.filter((w) => w.includes("://")).map(hostOf).filter(Boolean);
    if (hosts.length > 0 && hosts.every((h) => LOCAL_HOST.test(h))) continue;

    for (const m of segment.matchAll(SECRET_VAR)) {
      if (SECRET_VAR_NAME.test(m[1])) return true;
    }
    for (const m of segment.matchAll(UPLOAD_FLAG_FILE)) {
      const file = m[1] ?? m[2];
      if (file && !file.startsWith("/tmp/opencode/")) return true;
    }
    if (isSocket && /<\s*(?!\/tmp\/opencode\/)\S/.test(segment)) return true;
  }
  return false;
};

// Verdict for a URL handed to the web-fetch tool: only http(s) is fetched,
// cloud metadata is refused, and loopback/private targets (reachable because
// the container shares the host network) are escalated to the user.
const urlVerdict = (value) => {
  if (!/^\s*[a-z][a-z0-9+.-]*:/i.test(value)) return undefined;
  let url;
  try {
    url = new URL(value.trim());
  } catch (e) {
    return "deny";
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return "deny";
  let host = url.hostname.toLowerCase().replace(/\.$/, "");
  // IPv4-mapped, IPv4-compatible and NAT64 IPv6 literals reach the embedded
  // IPv4 address (the URL parser serializes them as hex: `[::ffff:a9fe:a9fe]`).
  const mapped = /^\[(?:::ffff:(?:0:)?|::|64:ff9b::)([0-9a-f]{1,4}):([0-9a-f]{1,4})\]$/.exec(host);
  if (mapped) {
    const hi = parseInt(mapped[1], 16);
    const lo = parseInt(mapped[2], 16);
    host = [hi >> 8, hi & 255, lo >> 8, lo & 255].join(".");
  }
  if (
    /^169\.254\./.test(host) ||
    host === "100.100.100.200" ||
    host === "metadata" ||
    host === "metadata.google.internal" ||
    host === "instance-data" ||
    host === "instance-data.ec2.internal" ||
    /^\[fd00:0{0,2}ec2(?::0{1,4}){0,5}::?0{0,2}254\]$/.test(host)
  ) {
    return "deny";
  }
  if (mapped) return "ask";
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    /^127\./.test(host) ||
    host === "0.0.0.0" ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(host) ||
    host.startsWith("[") // IPv6 literals: loopback, ULA, mapped IPv4
  ) {
    return "ask";
  }
  return undefined;
};

// `*.env.example` templates stay readable (the generated config also allows
// them); `.env`, `.env.local`, `.env_local`, `.env-prod` and `prod.env` are
// denied, like the shell rules. Also denies provider/MCP and OpenCode
// credentials (auth.json, mcp-auth.json, the opencode.db session store),
// credentials, SSH private keys, GnuPG private keys, host git/Composio config
// that can carry tokens, other credential stores, and key-like file names (no
// extension). Case-insensitive: bind mounts from macOS/Windows hosts are not.
const DENY_READ = new RegExp(
  [
    String.raw`(^|\/)[^\/]*\.env(?:[._-](?!example$)[^\/]*)?$`,
    String.raw`\.pem$`,
    String.raw`\.key$`,
    String.raw`(^|\/)auth\.json$`,
    String.raw`(^|\/)mcp-auth\.json$`,
    String.raw`(^|\/)opencode\.db(?:-wal|-shm|-journal)?$`,
    String.raw`(^|\/)id_(rsa|dsa|ecdsa|ed25519|ed25519_sk|ecdsa_sk|eddsa)$`,
    String.raw`(^|\/)\.ssh(\/|$)`,
    String.raw`(^|\/)\.npmrc$`,
    String.raw`(^|\/)\.netrc$`,
    String.raw`(^|\/)\.pgpass$`,
    String.raw`(^|\/)\.git-credentials$`,
    String.raw`(^|\/)\.vault-token$`,
    String.raw`(^|\/)\.mcp-auth(\/|$)`,
    String.raw`(^|\/)\.?credentials(\.|$)`,
    String.raw`(^|\/)\.config\/gh\/hosts\.yml$`,
    String.raw`(^|\/)\.docker\/config\.json$`,
    String.raw`(^|\/)\.kube\/config$`,
    String.raw`(^|\/)\.claude\/(projects|sessions|session-env|file-history)(\/|$)`,
    String.raw`(^|\/)\.claude\/history\.jsonl$`,
    String.raw`(^|\/)private-keys-v1\.d(\/|$)`,
    String.raw`(^|\/)\.gitconfig$`,
    String.raw`(^|\/)\.composio(\/|$)`,
    String.raw`\.(?:p12|pfx|jks|kdbx|keystore)$`,
    String.raw`\.tfstate(?:\.backup)?$`,
    String.raw`^\/proc\/(?:[^\/]+\/)+(?:environ|mem|maps)$`,
    String.raw`(^|\/)[\w.-]*(?:_key|-key|_priv)$`,
    String.raw`(^|\/)[\w.-]*key$`,
  ].join("|"),
  "i",
);

// Files that run later, outside the sandbox: git hooks and repository config at
// any depth (submodules keep theirs under `.git/modules/<sub>/`), the
// per-worktree config, and a `.git` file (which redirects the git directory).
const DENY_WRITE = /(^|\/)[^\/]*\.git\/(?:[^\/]*\/){0,16}(?:hooks\/|config(?:\.worktree)?$)|(^|\/)\.git$/i;
// Files that configure the agent, CI or the editor deserve a human decision.
const ASK_WRITE =
  /(^|\/)\.github\/workflows\/|(^|\/)opencode\.jsonc?$|(^|\/)\.mcp\.json$|(^|\/)\.opencode\/|(^|\/)\.envrc$|(^|\/)\.vscode\/|(^|\/)\.husky\//;

// Actions whose values are scanned against the vendored pattern sets.
const TOOL_ACTIONS = new Set([
  "bash",
  "shell",
  "read",
  "edit",
  "write",
  "multiedit",
  "webfetch",
  "websearch",
]);
// Prompt-injection patterns only make sense for free-text inputs, not paths.
const INJECTION_ACTIONS = new Set(["bash", "shell", "webfetch", "websearch"]);
const SHELL_ACTIONS = new Set(["bash", "shell"]);
const READ_ACTIONS = new Set(["read", "grep", "glob", "list"]);
const WRITE_ACTIONS = new Set(["edit", "write", "multiedit"]);
// Actions the guard has an opinion on; anything else is logged once so the
// runtime's real action names can be reviewed (see policies/README.md).
const KNOWN_ACTIONS = new Set([
  ...TOOL_ACTIONS,
  ...READ_ACTIONS,
  "external_directory",
]);
// Action names are matched case-insensitively (`Write`, `EDIT`), and the
// file-changing tools other runtimes or plugins report get the write checks.
const ACTION_ALIASES = new Map([
  ["apply_patch", "edit"],
  ["applypatch", "edit"],
  ["patch", "edit"],
  ["multi_edit", "multiedit"],
  ["notebookedit", "edit"],
  ["notebook_edit", "edit"],
  ["str_replace", "edit"],
  ["str_replace_editor", "edit"],
  ["create", "write"],
  ["view", "read"],
  ["ls", "list"],
]);
const PATCH_ACTIONS = new Set(["apply_patch", "applypatch", "patch"]);

const canonicalAction = (raw) => {
  if (typeof raw !== "string") return raw;
  const lower = raw.trim().toLowerCase();
  return ACTION_ALIASES.get(lower) ?? lower;
};

// A patch action may carry the patch text instead of paths: check the files
// it touches (apply_patch `*** Add/Update/Delete File:`/`*** Move to:` and
// unified-diff `---`/`+++`/`rename to` headers).
const PATCH_TARGET_RE =
  /^(?:\*\*\* (?:Add|Update|Delete) File:|\*\*\* Move to:|\+\+\+|---|rename to|copy to)[ \t]+(.+?)[ \t]*$/gm;
const patchTargets = (value) => {
  if (!value.includes("\n")) return [value];
  const out = [];
  for (const m of value.matchAll(PATCH_TARGET_RE)) {
    const target = m[1].replace(/\t.*$/, "");
    if (target === "/dev/null") continue;
    out.push(/^[ab]\//.test(target) && !target.startsWith("/") ? target.slice(2) : target);
  }
  return out;
};

// Extra writable locations beyond the project root(s). The runtime advertises
// `/tmp/opencode` as an approved scratch directory, so writes there are allowed
// in every mode (the project directory itself is the other writable location).
const EXTRA_WRITE_ROOTS = ["/tmp/opencode"];

// Event resources are normally an array of strings. A bare string is accepted,
// nested arrays are flattened and scalars stringified, so no item escapes the
// checks; anything else (objects, null items) is malformed and handled
// fail-closed by the caller.
const toResources = (raw) => {
  if (raw === undefined || raw === null) return [];
  if (typeof raw === "string") return [raw];
  if (!Array.isArray(raw)) return undefined;
  const out = [];
  const visit = (item, depth) => {
    if (typeof item === "string") out.push(item);
    else if (typeof item === "number" || typeof item === "boolean" || typeof item === "bigint") {
      out.push(String(item));
    } else if (Array.isArray(item) && depth < 8) return item.every((x) => visit(x, depth + 1));
    else return false;
    return true;
  };
  return raw.every((item) => visit(item, 0)) ? out : undefined;
};

// A resource that names a file (absolute, home-relative or explicitly
// relative), as opposed to a pattern or free text.
const PATH_LIKE = /^(?:\/|~\/|\.\.?\/)[^\n]*$/;

const noted = new Set();

// OpenCode V2 plugin module: default export with id + setup. Blocking uses the
// permission "evaluate" hook: configured deny rules are final and skip the hook
// (first enforcement layer), while this hook upgrades allow/ask decisions to
// deny for anything the config patterns do not spell out (second layer).
export default {
  id: "opencode-dockerized.security-guard",
  async setup(ctx) {
    // Never treat "/" (or a non-absolute/empty value) as a writable root: a
    // session whose directory is "/" must not become a global write allow. The
    // scratch root is always present, so confinement can never be skipped for
    // lack of a project directory.
    const roots = [
      ctx.location && ctx.location.directory,
      ctx.location && ctx.location.project && ctx.location.project.directory,
      ctx.location && ctx.location.project && ctx.location.project.canonical,
      ...EXTRA_WRITE_ROOTS,
    ].filter((r) => typeof r === "string" && r.startsWith("/") && r !== "/");
    // A root reached through a symlink is compared by its real location too.
    const realRoots = roots.map((r) => tryRealpath(r)).filter((r) => r !== undefined && r !== "/");
    const isInsideRoots = (p) =>
      [...roots, ...realRoots].some((r) => p === r || p.startsWith(r + "/"));

    // Relative tool paths resolve against the project directory (the
    // runtime's session directory), never against this process's cwd.
    const toAbsolute = (path) => {
      if (path.startsWith("/")) return path;
      if (path === "~" || path.startsWith("~/")) return HOME_DIR + path.slice(1);
      return (roots[0] ?? "") + "/" + path;
    };

    audit({
      event: "start",
      rules: {
        unsafe: UNSAFE_PATTERNS.length,
        injection: INJECTION_PATTERNS.length,
        allow: ALLOW_PATTERNS.length,
      },
      degraded: POLICIES_DEGRADED,
    });

    // Record and apply a decision. The audit entry carries the rule label, the
    // size and a short hash of the resources, never the command text.
    const decide = (event, resources, effect, rule, message) => {
      event.effect = effect;
      event.message = message;
      audit({
        event: "decision",
        action: event.action,
        effect,
        rule,
        len: resources.reduce((n, r) => n + r.length, 0),
        sha: createHash("sha256").update(resources.join("\n")).digest("hex").slice(0, 16),
      });
    };

    const denyPolicy = (event, resources, rule) =>
      decide(
        event,
        resources,
        "deny",
        `opencode-policy/${rule.id}`,
        `Blocked by workspace policy (opencode-policy/${rule.id}): ${rule.reason}`,
      );

    // Scan values against the ported patterns (first match wins). Returns true
    // when it denied.
    const scanValues = (event, resources, rules) => {
      if (rules.length === 0) return false;
      for (const value of resources) {
        if (value === "") continue;
        const rule = matchRule(rules, stripAllowed(value));
        if (rule) {
          denyPolicy(event, resources, rule);
          return true;
        }
      }
      return false;
    };

    // A read target is refused when its literal, resolved or real path is a
    // secret.
    const deniedRead = (path) => {
      const absolute = toAbsolute(path);
      const real = tryRealpath(absolute);
      return (
        DENY_READ.test(path) ||
        DENY_READ.test(normalizeLexical(absolute)) ||
        (real !== undefined && DENY_READ.test(real))
      );
    };

    const evaluateEvent = (event) => {
      if (event.effect === "deny") return;
      const rawAction = typeof event.action === "string" ? event.action.trim().toLowerCase() : event.action;
      const action = canonicalAction(event.action);
      let resources = toResources(event.resources);
      const deny = (rule, message) => decide(event, resources ?? [], "deny", rule, message);
      const guarded = TOOL_ACTIONS.has(action) || READ_ACTIONS.has(action);

      if (resources === undefined) {
        if (guarded) {
          deny("builtin:malformed-event", "Blocked by opencode-dockerized security policy: malformed event");
        }
        return;
      }
      if (PATCH_ACTIONS.has(rawAction)) resources = resources.flatMap(patchTargets);
      if (!KNOWN_ACTIONS.has(action) && typeof action === "string" && !noted.has(action)) {
        noted.add(action);
        audit({ event: "unmapped-action", action });
      }

      const shell = SHELL_ACTIONS.has(action);
      if (shell && POLICIES_DEGRADED) {
        deny(
          "builtin:policies-not-loaded",
          `Blocked by opencode-dockerized security policy: the ${POLICY_MODE} policy files failed to load, so shell commands are refused. Run 'opencode-dockerized config sync' on the host, or set setting.security_policy=off.`,
        );
        return;
      }

      const total = resources.reduce((n, r) => n + r.length, 0);
      if (guarded && total > MAX_SCAN_LENGTH) {
        deny(
          "builtin:too-large",
          `Blocked by opencode-dockerized security policy: value too large to evaluate safely (${total} > ${MAX_SCAN_LENGTH} characters); write large payloads to a file with the write tool.`,
        );
        return;
      }

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
      if (shell) {
        const command = resources.join(" ");
        const normalized = normalizeShell(command);
        const message =
          "Blocked by opencode-dockerized security policy: " + command.slice(0, 200);
        for (const [i, pattern] of DENY_BASH.entries()) {
          if (pattern.test(command) || pattern.test(normalized)) {
            deny(`builtin:deny-bash-${i}`, message);
            return;
          }
        }
        // Path-reference secret checks are independent of the program used and
        // of the vendored policy mode (defense in depth, even in "off").
        for (const pattern of DENY_SECRET_PATH) {
          if (pattern.test(command) || pattern.test(normalized)) {
            deny("builtin:secret-path", message);
            return;
          }
        }
        if (globLeaks(normalized)) {
          deny("builtin:secret-glob", message);
          return;
        }
        if (procEnviron(normalized)) {
          deny("builtin:proc-environ", message);
          return;
        }
        if (destructiveTarget(normalized)) {
          deny("builtin:destructive-target", message);
          return;
        }
        if (egressLeak(normalized)) {
          deny("builtin:egress", message);
          return;
        }
        const commands = simpleCommands(normalized);
        if (commands.some(({ words }) => envDump(words))) {
          deny("builtin:env-dump", message);
          return;
        }
        if (commands.some(({ words }) => powerCommand(words))) {
          deny("builtin:power", message);
          return;
        }
        if (gitControlWrite(normalized, commands)) {
          deny("builtin:git-control-write", message);
          return;
        }
        const git = strongest(commands.map(({ words }) => gitVerdict(words)));
        if (git === "deny") {
          deny(
            "builtin:git-config-exec",
            "Blocked by opencode-dockerized security policy: git configuration that runs a program executes outside the sandbox: " +
              command.slice(0, 200),
          );
          return;
        }
        if (event.effect === "allow" && (git === "ask" || GIT_ASK.some((p) => p.test(normalized)))) {
          decide(
            event,
            resources,
            "ask",
            "builtin:git-push-or-reset",
            "opencode-dockerized: git push / reset --hard needs approval: " + command.slice(0, 200),
          );
        }
      }

      // Read checks for the read tools, and for any other action that names a
      // file (unknown or future tools, `external_directory`), so a secret is
      // never reachable through an action the guard does not know yet.
      const readTargets = READ_ACTIONS.has(action)
        ? resources
        : !shell && !WRITE_ACTIONS.has(action) && action !== "webfetch" && action !== "websearch"
          ? resources.filter((r) => PATH_LIKE.test(r))
          : [];
      for (const path of readTargets) {
        if (path !== "" && deniedRead(path)) {
          deny(
            "builtin:deny-read",
            "Blocked by opencode-dockerized security policy: refusing to read " + path.slice(0, 200),
          );
          return;
        }
      }

      if (action === "webfetch") {
        for (const url of resources) {
          const verdict = urlVerdict(url);
          if (verdict === "deny") {
            deny(
              "builtin:url",
              "Blocked by opencode-dockerized security policy: refusing to fetch " + url.slice(0, 200),
            );
            return;
          }
          if (verdict === "ask" && event.effect === "allow") {
            decide(
              event,
              resources,
              "ask",
              "builtin:url-local",
              "opencode-dockerized: local or private network target needs approval: " + url.slice(0, 200),
            );
          }
        }
      }

      if (WRITE_ACTIONS.has(action) && roots.length > 0) {
        let needsApproval = false;
        for (const path of resources) {
          if (path === "") continue;
          // Resolve relative targets against the project directory instead of
          // skipping them. The runtime resolves relative tool paths against the
          // session directory, so `../outside.txt` must not become a
          // confinement bypass that relies solely on the first-layer
          // `permissions`. `/tmp/opencode` stays writable.
          const absolute = toAbsolute(path);
          // Follow symlinks the way the kernel will on write: every existing
          // component, a dangling link at the target, and `..` after a link.
          // Both the lexical path and the physical one must stay inside.
          const physical = physicalPath(absolute);
          const candidates = [normalizeLexical(absolute) || "/"];
          if (physical !== undefined) candidates.push(physical);
          if (physical === undefined || candidates.some((c) => !isInsideRoots(c))) {
            deny(
              "builtin:write-outside",
              "Blocked by opencode-dockerized security policy: write outside project directory: " +
                path.slice(0, 200),
            );
            return;
          }
          if (candidates.some((c) => DENY_WRITE.test(c))) {
            deny(
              "builtin:write-deferred-exec",
              "Blocked by opencode-dockerized security policy: git hooks and .git/config run outside the sandbox: " +
                path.slice(0, 200),
            );
            return;
          }
          if (candidates.some((c) => ASK_WRITE.test(c))) needsApproval = true;
        }
        if (needsApproval && event.effect === "allow") {
          decide(
            event,
            resources,
            "ask",
            "builtin:write-config",
            "opencode-dockerized: editing agent, CI or editor configuration needs approval",
          );
        }
      }
    };

    await ctx.permission.hook("evaluate", (event) => {
      try {
        evaluateEvent(event);
      } catch (e) {
        // A broken hook must not fail open: refuse and leave a trace.
        event.effect = "deny";
        event.message =
          "Blocked by opencode-dockerized security policy: the guard failed while evaluating this action";
        audit({ event: "hook-error", action: event.action, error: String(e && e.message).slice(0, 200) });
      }
    });
  },
};
