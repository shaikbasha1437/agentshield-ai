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
| `test/hygiene.test.js` | No numbering labels, no restricted wording, no real-looking keys and no non-`.example` addresses in any public file. |

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

The Playwright scripts are kept outside the repo. They ran against the live site (then at the project's earlier URL, before the rename to Quadward) with fresh storage:

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
- **PWA:** the service-worker cache is versioned (now `quadward-v5`) and the app loads offline (Chrome).
- **Console:** no errors.

## CI and Pages

- **CI workflow:** runs `npm test`. Then the Action (node24) runs the balanced policy against the committed baseline, which passes. It also runs a deliberately weakened policy with `fail-on-gate: false`, which is reported as a regression. The CLI exit code is checked to be 1 for the weakened policy.
- **Report:** uploaded with `actions/upload-artifact@v6`.
- **Status:** all CI and Pages runs succeeded.

## Packages, parity and paper

- **npm package (`lib/`):**
  - `npm pack` builds `quadward-0.2.0.tgz` with 23 files.
  - Installed from that tarball, it loads with `import` (including the `/injection` subpath) and with `require()` on Node 24.
  - A TypeScript consumer type-checks against `index.d.ts` with `--strict --module nodenext`.
  - `test/package.test.js` checks that the declared exports match the runtime exports.
- **Python package (`python/`):**
  - `python -m build` and `twine check` pass.
  - The wheel, installed in a clean virtual environment, runs the quickstart and the benchmark.
  - pytest passes 60 tests on Python 3.9 and 3.13.
- **Parity:** the Python package reproduces the JavaScript package's results exactly. This covers outcome, score and rule explanations for:
  - 257 cases × 8 presets = 2,056 verdicts;
  - 309 component texts;
  - about 2,100 mutated variants.
- **Evaluation:** `python dataset/eval.py` runs both packages and fails if any outcome or table differs. It also computes the keyword-filter baseline and the detector-only ablation.
- **Paper:**
  - Compiled with tectonic to 8 pages.
  - Its tables are generated by `eval.py`.
  - Each reference was checked against arXiv or Crossref metadata.
- **Released:** `quadward` 0.2.0 is on PyPI (uploaded 2026-11-24). A clean `pip install quadward` imports, gives the expected verdicts, and its CLI reproduces the benchmark numbers.
- **Not done:** nothing has been published to npm, Hugging Face or arXiv, and no release tags exist. The release workflows run only on `js-v*` and `py-v*` tags.

## Not verified

- Live mode against real providers. No real keys were used: request builders are unit-tested, and the live loop is tested with a mocked model.
- WebLLM. It was not run, because there is no WebGPU here.
- The proxy against a real upstream. Only mocked upstreams were used.
- The library inside real OpenAI, Anthropic, MCP or LangChain SDK objects. The tests use mocked clients with the same shapes.
- Safari.
