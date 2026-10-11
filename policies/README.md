# Security pattern data (ported)

The `*.json` files in this directory are the rule sets from
**[opencode-policy](https://github.com/tjvjk/opencode-policy)** (`opencode-policy@0.1.4`
on npm), vendored verbatim:

- `unsafe-tool-patterns.json` — unsafe shell/tool patterns (denies secret exposure,
  exfiltration, reverse shells, destructive commands, cross-workspace access, …)
- `prompt-injection-patterns.json` — instruction-override / prompt-injection patterns

Upstream ships them for the OpenCode **V1** plugin API, which does not load on the
V2-only setup used here — so instead of depending on that package, the generator in
`lib/config-lib.sh` copies these files to `~/.config/opencode-dockerized/plugins/policies/`
and our V2 `security-guard.js` hook evaluates them with the same first-match semantics
(`new RegExp(pattern, flags ?? "i")`).

## Local patches

The files are verbatim copies except for these deliberate, documented changes
(re-apply them when refreshing from upstream):

- `prompt-injection-patterns.json` / `base64-payload-2` — upstream
  `[A-Za-z0-9+/]{40,}={0,2}.*(…)` backtracks cubically (4000 characters take ~17 s
  and freeze the synchronous hook). The replacement anchors on the start of a base64
  run, captures it atomically (lookahead + backreference) and bounds the gap to the
  exec word to 2000 characters, so matching is linear. Same detections otherwise.

To refresh the rules, replace the JSON files here (keeping the
`[{ "id", "pattern", "reason", "flags"? }]` shape) and bump `VERSION` (a plain
integer). `lib/config-lib.sh` compares it with the installed copy under
`~/.config/opencode-dockerized/plugins/policies/` and refreshes the rule files
(backing up the previous ones) whenever the version changes or a file is missing.
Deleting the installed copies still re-seeds them on the next run.

## License / attribution

See `LICENSE.opencode-policy` (MIT License, Copyright (c) 2026, tjvjk). Pattern
research adapted in part from `vakovalskii/topsha` (per upstream README).
