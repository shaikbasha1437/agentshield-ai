# Verification

What was checked before release, and how. Times are America/Chicago, 2026-11-19.

## Automated tests (`npm test`, Node 24)

51 tests in 9 files, all passing locally and in CI.

| File | What it covers |
| --- | --- |
| `test/lib-core.test.js` | SHA-256 against `node:crypto`; YAML subset round-trip and line numbers; normalisation (look-alikes, leetspeak, spacing, tag characters, base64, ROT13); injection rules, discussion dampening and multilingual rules; hidden-text detection; redaction (Luhn, SSN shape, keys, allowlists); canary and prompt leaks; URL and exfiltration checks; schema enforcement; diff. |
| `test/firewall.test.js` | Dangerous commands; read-only SQL; paths, traversal and null bytes; domains, private IPs and userinfo tricks; amounts, hard limits and budgets; recipients; command allowlists; rate limits; kill switch; taint tracking; monitor mode. |
| `test/policy.test.js` | All 8 presets validate and pass their own tests; validation errors carry paths and line numbers; YAML and JSON exports round-trip; the test runner reports failures. |
| `test/guard.test.js` | Input, conversation, ingest, output and execute; the approval queue (diff, approve, deny, restore) and dry-run; the audit chain (redaction, tamper and removal detection); OpenAI, Anthropic, MCP and LangChain-style wrappers with mocked clients; the classifier with mocked replies and errors; spotlight boundary neutralising. |
| `test/proxy.test.js` | The proxy against a **mocked local upstream**: forwarding, injection blocked before upstream, redaction, risky tool calls held, single-use approvals, admin auth (401/403), kill switch, upstream errors passed through, server key overriding the caller's key, and keys absent from the audit log. |
| `test/bench.test.js` | Suite shape (257 cases, unique ids, only `.example` hosts); Wilson, percentile and exact McNemar values; balanced thresholds; preset ordering; the gate catches the regressed policy and the committed baseline is current; CLI exit codes; the Action entry point (outputs, summary, HTML report). |
| `test/app.test.js` | All 16 playground scenarios with sql.js: attacks do harm with the guard off and none with it on; benign tasks are harmless and unblocked either way. Also: approval and diff for the large refund, monitor mode, the kill switch, the live loop with a mocked model, provider request builders (including the Anthropic browser header), the service-worker file list, the manifest, and the lib package shape. |
| `test/hygiene.test.js` | No numbering labels, no visa wording, no real-looking keys and no non-`.example` addresses in any public file. |

## Benchmark statistics cross-checked in Python

The per-case outcomes for the balanced, strict and permissive policies were dumped to JSON and recomputed independently with NumPy 2.5.5 and SciPy 1.18.1. The recomputation covered:

- Wilson 95% intervals for the stop, blocked, false-positive and friction rates;
- every category interval;
- latency mean, p50 and p95 (`numpy.percentile`, linear);
- exact McNemar tests (`scipy.stats.binomtest`).

Result: **110 checks, 0 mismatches** (tolerance 1e-9).

| Comparison | Only stopped by the first | Only stopped by the second | p |
| --- | --- | --- | --- |
| balanced vs strict | 0 | 5 | 0.0625 |
| balanced vs permissive | 107 | 0 | 1.23e-32 |

## Browser verification on the live site

The Playwright scripts are kept outside the repo. They ran against https://shaikbasha1437.github.io/agentshield-ai/ with fresh storage:

| Browser | Checks passed |
| --- | --- |
| Chrome | **66 / 66** |
| Firefox | **64 / 64** (the two service-worker and offline checks run in Chrome only) |

What the checks covered:

- **Playground:** all 16 scenarios with the guard on, the guard-off harms shown, and the step detail modal.
- **Approvals:** the approval queue with a diff, deny and then undo, and approve-and-run.
- **Inspect:** inspector samples, the redacted output, and the tool-call tester, including a JSON error.
- **Benchmark:** run (balanced at 87.4%), the comparison, latency and case tables, the case filter, and the Markdown report export.
- **Modals:** close via X, Cancel, Esc, a backdrop click and browser Back.
- **Policy editor:** live validation with line numbers and a gutter marker; the discard prompt when switching with unsaved edits (cancel keeps them); revert; the policy test runner; activate, then undo.
- **Kill switch:** on, tools blocked, off.
- **Audit:** chain intact, and the tamper demo detects the edit without touching the real log.
- **Settings:** a dirty Settings modal prompts before discarding.
- **Keys:** with a fake key in live mode, the key is absent from the backup, the audit export, app state and localStorage. "Forget keys now" works.
- **Data:** reset, then undo; the share link import (also into an already open tab); IndexedDB persistence across reloads; dark theme.
- **Small screens:** no horizontal overflow at 375 px on every tab or in the help modal.
- **PWA:** the service-worker cache is `agentshield-v3` and the app loads offline (Chrome).
- **Console:** no errors.

## CI and Pages

- **CI workflow:** runs `npm test`. Then the Action (node24) runs the balanced policy against the committed baseline, which passes. It also runs a deliberately weakened policy with `fail-on-gate: false`, which is reported as a regression. The CLI exit code is checked to be 1 for the weakened policy.
- **Report:** uploaded with `actions/upload-artifact@v6`.
- **Status:** all CI and Pages runs succeeded.

## Not verified

- Live mode against real providers. No real keys were used: request builders are unit-tested, and the live loop is tested with a mocked model.
- WebLLM. It was not run, because there is no WebGPU here.
- The proxy against a real upstream. Only mocked upstreams were used.
- The library inside real OpenAI, Anthropic, MCP or LangChain SDK objects. The tests use mocked clients with the same shapes.
- Safari.
