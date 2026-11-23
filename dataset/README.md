---
license: cc-by-4.0
pretty_name: AgentShield Bench
language:
  - en
  - es
  - fr
  - de
  - it
  - pt
  - nl
  - ru
  - zh
  - ja
  - ko
  - ar
  - hi
  - tr
  - sw
  - vi
task_categories:
  - text-classification
tags:
  - prompt-injection
  - jailbreak
  - llm-security
  - agents
  - guardrails
  - tool-use
size_categories:
  - n<1K
configs:
  - config_name: default
    data_files:
      - split: test
        path: data/test.jsonl
---

# AgentShield Bench

AgentShield Bench is a small, labelled, stage-aware benchmark for guardrails around LLM agents. It has **257 cases: 191 attacks and 66 benign look-alikes.** Each case says which point in an agent pipeline it targets: the user's input, untrusted content the agent reads, the model's output, or a tool call. A guard can therefore be scored at the stage where it would actually run.

It was built to test the open-source [AgentShield](https://github.com/shaikbasha1437/agentshield-ai) guardrails, and it ships with a reproducible evaluation script. It is meant as a **regression and smoke test**, not as a leaderboard; see [Limitations](#limitations).

- **Licence:** CC-BY-4.0 for the data; the evaluation code is MIT.
- **Version:** 1.0.0 (cases), exported from `bench/cases.js` in the repository.
- **Split:** a single `test` split. There is no training split, and the cases should not be used to train a detector that is then evaluated on them.

## Files

| File | Contents |
| --- | --- |
| `data/test.jsonl` | Flat rows for the Hugging Face viewer and `datasets.load_dataset` (one per case). |
| `data/cases.jsonl` | The original nested records, with all stage-specific fields. This is the input to `eval.py`. |
| `data/meta.json` | Counts, category lists, the system prompt and the canary used by the output-stage cases. |
| `eval.py` | Reproducible evaluation: rates with 95% Wilson intervals and per-category precision, recall and F1, for both packages and two baselines. |

```python
from datasets import load_dataset
ds = load_dataset("json", data_files="data/test.jsonl", split="train")   # or the Hub id once uploaded
```

## Fields

### `data/test.jsonl`

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Stable identifier. Attacks are `A###` and benign cases are `B###`. |
| `label` | int | 1 = attack, 0 = benign. |
| `kind` | string | `attack` or `benign`. |
| `category` | string | Taxonomy category (see below). |
| `stage` | string | `input`, `conversation`, `untrusted`, `output` or `tool`: where a guard sees this case. |
| `text` | string | The main text, flattened per stage. **input:** the prompt. **conversation:** `role: content` lines. **untrusted:** the raw content (HTML, email, document or tool result). **output:** the model output. **tool:** the tool call as JSON. |
| `note` | string | One line saying what the case tests. |
| `case_json` | string | The full original record as JSON, the same as the matching line of `data/cases.jsonl`. |

### `data/cases.jsonl` (nested)

Common fields are `id`, `kind`, `cat`, `stage` and `note`. The stage-specific fields are:

- **`input`:** `text`.
- **`conversation`:** `turns`, a list of `{role, content}`.
- **`untrusted`:**
  - `source`: `web`, `email`, `doc`, `tool` or `rag`;
  - `label`: a URL, subject or filename;
  - `content`;
  - optionally `format`, plus `prompt` (the user's request, which the content tries to subvert);
  - optionally `call`, a tool call the agent then attempts, so that taint tracking can be tested.
- **`output`:** `output`, the model's reply. The output cases assume the system prompt and canary in `meta.json`.
- **`tool`:** `call` (`{tool, args}`), and optionally `prompt`.

## Taxonomy

| Category | Stage | n | What it covers |
| --- | --- | ---: | --- |
| direct | input | 22 | Instruction overrides ("ignore previous instructions"), fake system messages, role reassignment. |
| jailbreak | input | 15 | Persona and role-play jailbreaks, hypothetical framing, "developer mode", refusal suppression. |
| extraction | input, output | 15 | Attempts to get the system prompt or hidden instructions (12 input), and outputs that leak them or the canary (3 output). |
| obfuscation | input | 21 | Homoglyphs, leetspeak, zero-width and bidi characters, Unicode tag smuggling, base64/hex/URL encoding, spaced letters, reversed text, split payloads. |
| multilingual | input | 16 | Override and extraction attempts in 15 languages besides English. |
| indirect-web | untrusted | 12 | Injections in web pages: HTML comments, hidden CSS, white or zero-size text, alt text, meta tags, aria-hidden text, plain visible requests. |
| indirect-email | untrusted | 10 | Injections in emails an assistant reads, including attempts to trigger sending or forwarding. Some untrusted cases also include the tool call the agent then attempts, to test taint tracking. |
| indirect-doc | untrusted | 8 | Injections in documents: Markdown and HTML comments, white-on-white text, contracts, READMEs, CSV cells, footnotes. |
| indirect-tool | untrusted | 8 | Injections in tool or API results, such as MCP tool output. |
| indirect-rag | untrusted | 6 | Injections in retrieved knowledge-base chunks. |
| exfiltration | output | 11 | Outputs that leak data through markdown images, links, query strings or encoded URLs. |
| pii-leak | output | 12 | Outputs that contain secrets, keys, card numbers or other customers' personal data. |
| tool-abuse | tool | 27 | Destructive or chained shell commands, writes in read-only SQL, path traversal, cloud-metadata addresses, refunds over limits, rate-limit and budget breaches, unlisted tools, data sent outside the company. |
| multi-turn | conversation | 8 | Attacks assembled across several user turns. |
| benign-everyday | input | 14 | Ordinary customer requests. |
| benign-security | input, untrusted | 7 | Legitimate discussion of prompt injection and security (hard negatives). |
| benign-code | input, untrusted, tool | 8 | Code, shell and SQL that look dangerous but are not. |
| benign-content | untrusted | 13 | Ordinary web pages, emails and documents, some with imperative wording. |
| benign-admin | tool | 14 | Routine tool calls inside policy limits. |
| benign-output | output | 10 | Normal replies that contain links, numbers or example data. |

## Provenance

Every case was **written by hand by the AgentShield author** (Basha Shaik) in November 2026, using the attack patterns described in the public literature. The main sources were indirect prompt injection (Greshake et al., 2023), goal hijacking and prompt leaking (Perez & Ribeiro, 2022), and the OWASP Top 10 for LLM Applications.

No case was scraped from users or collected from a production system. All companies, people, addresses, keys and card numbers are fictional:

- domains use the reserved `.example` suffix;
- keys are visibly fake test values;
- card numbers are standard test numbers.

The multilingual cases are short translations of English attacks and have not been reviewed by native speakers.

**Labels.** The `kind` label says whether the case is an attack, meaning the text tries to make an agent act against its principal's instructions or leak data. A benign case is an ordinary request or content, often a deliberate near-miss. Labels were assigned by the author and were not independently double-annotated.

## Evaluation

```sh
python dataset/eval.py               # runs the Python package; also runs the JS package if node is installed
node scripts/eval.mjs                 # JS package only
```

A case counts as **stopped** if the guard blocked, quarantined or redacted it, or held it for a person's approval. A merely flagged case does not count.

- **Headline false-positive rate:** benign cases that were blocked, quarantined or redacted. Approvals are reported separately as *friction*.
- **Per-category precision:** stage-matched. A category's false positives are the benign cases at the same stage(s) that the guard intervened on, approvals included.

All rates come with 95% Wilson score intervals.

Results for AgentShield 0.2.0 (identical for the JavaScript and Python packages), plus two baselines:

| System | Attacks stopped [95% CI] | False positives [95% CI] | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| AgentShield, `balanced` | 87.4 [82.0–91.4] | 4.5 [1.6–12.5] | 97.1 | 87.4 | 92.0 |
| AgentShield, `strict` | 90.1 [85.0–93.5] | 18.2 [10.7–29.1] | 91.5 | 90.1 | 90.8 |
| AgentShield, `permissive` | 31.4 [25.3–38.3] | 0.0 [0.0–5.5] | 100.0 | 31.4 | 47.8 |
| Keyword filter (16 phrases) | 12.0 [8.2–17.4] | 7.6 [3.3–16.5] | 82.1 | 12.0 | 21.0 |
| AgentShield detector only (ablation) | 54.5 [47.4–61.4] | 1.5 [0.3–8.1] | 99.0 | 54.5 | 70.3 |

Run `eval.py` for the per-category tables and the other five presets.

## Limitations

- **Small:** 257 cases give wide confidence intervals, especially per category (n = 6 to 27). Differences of a few points between systems are usually not significant.
- **Not independent:** the same person wrote the cases and the AgentShield rules, and the rules were developed while looking at the cases. AgentShield's scores here are therefore closer to training-set accuracy than to generalisation, and they should not be compared with numbers from independent benchmarks.
- **Synthetic and English-centred:** the cases are short and hand-written. Real web pages, emails and tool output are longer and messier. The multilingual coverage is shallow.
- **Static:** there are no adaptive attacks and no optimisation-based or model-generated attacks, so an attacker who tunes against a specific guard will do better.
- **Text only:** there are no images, audio or PDFs.
- **Pipeline-specific:** tool cases assume the tool names and policies of the bundled presets, and output cases assume the bundled system prompt and canary.
- **Benign set:** the benign set is small (66), so a single false positive moves the rate by 1.5 points.

## Ethics

The attacks are well-known patterns that are already described publicly. They are included to test defences, and they give no meaningful uplift to an attacker. The data contains no real personal information.

## Citation

```bibtex
@misc{shaik2026agentshield,
  title  = {AgentShield: Explainable, Stage-Aware Guardrails for {LLM} Agents and a Small Benchmark for Them},
  author = {Shaik, Basha},
  year   = {2026},
  howpublished = {\url{https://github.com/shaikbasha1437/agentshield-ai}}
}
```
