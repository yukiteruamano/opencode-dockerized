// Lint for the vendored policy sets and the guard's rule bookkeeping:
//   - every JSON file is a well-formed array of { id, pattern, reason, flags? }
//   - ids are unique and every pattern compiles
//   - every id listed in BALANCED_EXCLUDED_IDS exists (stale ids hide dead code)
//   - no rule is slow on adversarial input at the guard's scan cap (ReDoS)
//   - policies/SHA256SUMS matches the files and SOURCE.json matches VERSION
//
// Usage: node tests/policy-lint.test.mjs

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const policies = join(repo, "policies");
const FILES = ["unsafe-tool-patterns.json", "prompt-injection-patterns.json", "allow-patterns.json"];

// Mirrors MAX_SCAN_LENGTH in plugins/security-guard.js; read from the source so
// the two cannot drift apart.
const guardSource = readFileSync(join(repo, "plugins/security-guard.js"), "utf8");
const capMatch = /const MAX_SCAN_LENGTH = (\d+) \* 1024;/.exec(guardSource);
const CAP = capMatch ? Number(capMatch[1]) * 1024 : 32 * 1024;
const BUDGET_MS = 250;

let failures = 0;
const check = (label, ok) => {
  if (!ok) {
    failures++;
    console.log(`FAIL ${label}`);
  }
};

const allIds = new Set();
const rulesByFile = {};
for (const file of FILES) {
  let rules;
  try {
    rules = JSON.parse(readFileSync(join(policies, file), "utf8"));
  } catch (e) {
    check(`${file}: valid JSON (${e.message})`, false);
    continue;
  }
  check(`${file}: is an array`, Array.isArray(rules));
  rulesByFile[file] = rules;
  const seen = new Set();
  for (const rule of rules) {
    const where = `${file}/${rule && rule.id}`;
    check(`${where}: has id, pattern and reason`, rule && rule.id && typeof rule.pattern === "string" && typeof rule.reason === "string");
    check(`${where}: id is unique`, !seen.has(rule.id));
    seen.add(rule.id);
    allIds.add(rule.id);
    try {
      new RegExp(rule.pattern, rule.flags ?? "i");
    } catch (e) {
      check(`${where}: pattern compiles (${e.message})`, false);
    }
  }
}

// BALANCED_EXCLUDED_IDS entries must name real rules.
const block = /const BALANCED_EXCLUDED_IDS = new Set\(\[([\s\S]*?)\]\);/.exec(guardSource);
check("BALANCED_EXCLUDED_IDS found in the guard", Boolean(block));
// Ids are the quoted entries that start a line; quoted words inside the
// explanatory comments are not ids.
for (const m of block ? block[1].matchAll(/^\s*"([^"]+)",/gm) : []) {
  check(`BALANCED_EXCLUDED_IDS: "${m[1]}" exists in the vendored sets`, allIds.has(m[1]));
}

// ReDoS budget: adversarial strings at the scan cap, per rule.
const unit = (s) => s.repeat(Math.ceil(CAP / s.length)).slice(0, CAP);
const ADVERSARIAL = [
  unit("A"),
  unit(" "),
  unit("a "),
  unit("for "),
  unit("while "),
  unit("&"),
  unit("; "),
  unit("$ "),
  unit("/"),
  unit("-"),
  unit("0x"),
  unit("A".repeat(41) + " "),
  unit("cat "),
  unit("curl http://x "),
];
for (const file of FILES.slice(0, 2)) {
  for (const rule of rulesByFile[file] ?? []) {
    let re;
    try {
      re = new RegExp(rule.pattern, (rule.flags ?? "i").replace(/[gy]/g, ""));
    } catch (e) {
      continue;
    }
    for (const input of ADVERSARIAL) {
      const t0 = process.hrtime.bigint();
      re.test(input);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      check(`${file}/${rule.id}: ${ms.toFixed(0)} ms on "${input.slice(0, 12)}…" x${input.length} (budget ${BUDGET_MS})`, ms < BUDGET_MS);
    }
  }
}

// Integrity: SHA256SUMS and SOURCE.json.
const sums = new Map(
  readFileSync(join(policies, "SHA256SUMS"), "utf8")
    .trim()
    .split("\n")
    .map((line) => {
      const [hash, name] = line.trim().split(/\s+/);
      return [name, hash];
    }),
);
for (const file of FILES) {
  const actual = createHash("sha256").update(readFileSync(join(policies, file))).digest("hex");
  check(`SHA256SUMS: ${file} matches (update the sums and bump VERSION after editing)`, sums.get(file) === actual);
}
const source = JSON.parse(readFileSync(join(policies, "SOURCE.json"), "utf8"));
const version = Number(readFileSync(join(policies, "VERSION"), "utf8").trim());
check("SOURCE.json: policy_version equals VERSION", source.policy_version === version);
check("SOURCE.json: names the upstream package and version", Boolean(source.upstream && source.upstream.package && source.upstream.version));
for (const file of ["unsafe-tool-patterns.json", "prompt-injection-patterns.json"]) {
  check(`SOURCE.json: records the upstream hash of ${file}`, /^[0-9a-f]{64}$/.test(source.upstream_sha256 && source.upstream_sha256[file]));
}

if (failures > 0) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("Policy lint passed.");
