// Shared harness for the security-guard tests: stages the guard next to its
// ./policies data exactly like the wrapper does, builds a real project tree
// (so symlink escapes hit the real filesystem) and loads the guard per mode.

import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  symlinkSync,
  copyFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..");

const POLICY_FILES = [
  "unsafe-tool-patterns.json",
  "prompt-injection-patterns.json",
  "allow-patterns.json",
];

// Copy the guard (and, unless disabled, the policy JSON files) into a temp dir.
export function stageGuard({ withPolicies = true } = {}) {
  const stage = mkdtempSync(join(tmpdir(), "guard-"));
  mkdirSync(join(stage, "policies"), { recursive: true });
  copyFileSync(join(repo, "plugins/security-guard.js"), join(stage, "security-guard.js"));
  if (withPolicies) {
    for (const f of POLICY_FILES) {
      copyFileSync(join(repo, "policies", f), join(stage, "policies", f));
    }
  }
  return stage;
}

export function makeProject() {
  const root = mkdtempSync(join(tmpdir(), "proj-"));
  const PROJECT = join(root, "project");
  const OUTSIDE = join(root, "outside");
  mkdirSync(join(PROJECT, "src"), { recursive: true });
  mkdirSync(OUTSIDE, { recursive: true });
  writeFileSync(join(PROJECT, "src/a.ts"), "export const a = 1;\n");
  writeFileSync(join(OUTSIDE, ".env"), "API_KEY=leak\n");
  symlinkSync(join(OUTSIDE, ".env"), join(PROJECT, "link-to-env"));
  symlinkSync(OUTSIDE, join(PROJECT, "link-out"));
  return { root, PROJECT, OUTSIDE };
}

let loadCounter = 0;

// Load the guard in `mode`. The returned function maps (action, value) to
// "deny" | "allow" (an "ask" counts as allow); `.raw(action, resources)` returns
// the final event so tests can assert on "ask" and on the message.
export async function loadGuard(stage, PROJECT, mode, { directory = PROJECT } = {}) {
  process.env.OPENCODE_DOCKERIZED_POLICY = mode;
  // Keep test runs out of the real audit log unless a test asks for one.
  process.env.OPENCODE_DOCKERIZED_GUARD_LOG ??= "/dev/null";
  const url = pathToFileURL(join(stage, "security-guard.js")).href + `?mode=${mode}&n=${loadCounter++}`;
  const mod = await import(url);
  let evaluate;
  await mod.default.setup({
    location: { directory },
    permission: {
      hook: (name, fn) => {
        if (name === "evaluate") evaluate = fn;
      },
    },
  });
  const raw = (action, resources) => {
    const event = { effect: "allow", action, resources };
    evaluate(event);
    return event;
  };
  const fn = (action, value) => (raw(action, [value]).effect === "deny" ? "deny" : "allow");
  fn.raw = raw;
  return fn;
}

export function cleanup(...dirs) {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
}

export { join };
