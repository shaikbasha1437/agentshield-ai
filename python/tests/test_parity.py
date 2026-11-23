"""Parity with the JavaScript package.

``tests/golden/*.jsonl`` are produced by ``node scripts/export-data.mjs`` from the JavaScript library (CI checks
they are up to date). These tests require the Python port to reproduce them exactly: the outcome, score and
explanation of every benchmark case under every preset, and component-level results on every benchmark text."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentshield_guardrails import check_urls, detect, find_sensitive, preset, run_case, scan_hidden
from agentshield_guardrails.bench import cases
from agentshield_guardrails.policy import PRESET_IDS

GOLDEN = Path(__file__).parent / "golden"


def _lines(name):
    with open(GOLDEN / name, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


VERDICTS = _lines("verdicts.jsonl")
COMPONENTS = _lines("components.jsonl")
CASES = {c["id"]: c for c in cases()}


def _texts():
    out = []
    for c in cases():
        if c.get("text"):
            out.append(c["text"])
        if c.get("output"):
            out.append(c["output"])
        if c.get("content"):
            out.append(c["content"])
        for t in c.get("turns") or []:
            v = t.get("content") if t.get("content") is not None else t.get("text")
            out.append("" if v is None else v)
        for x in c.get("context") or []:
            out.append(x["content"])
        if c.get("prompt"):
            out.append(c["prompt"])
    return out


def test_golden_covers_every_case_and_preset():
    assert len(CASES) == 257
    assert sum(1 for c in CASES.values() if c["kind"] == "attack") == 191
    assert {v["policy"] for v in VERDICTS} == set(PRESET_IDS)
    assert len(VERDICTS) == 257 * len(PRESET_IDS)


@pytest.mark.parametrize("policy_id", PRESET_IDS)
def test_identical_verdicts_on_every_case(policy_id):
    policy = preset(policy_id)
    mismatches = []
    for g in (v for v in VERDICTS if v["policy"] == policy_id):
        r = run_case(policy, CASES[g["id"]])
        got = {"outcome": r["outcome"], "score": r["score"], "why": r["why"]}
        want = {"outcome": g["outcome"], "score": g["score"], "why": g["why"]}
        if got != want:
            mismatches.append((g["id"], want, got))
    assert not mismatches, "%d mismatches, first: %r" % (len(mismatches), mismatches[:3])


def test_component_outputs_match_on_every_benchmark_text():
    texts = _texts()
    assert len(texts) == len(COMPONENTS)
    bad = []
    for g in COMPONENTS:
        t = texts[g["i"]]
        d = detect(t)
        du = detect(t, source="web")
        h = scan_hidden(t)
        got = {
            "detect": {"score": d["score"], "verdict": d["verdict"], "hits": [[x["rule"], x["effective"], x["layer"]] for x in d["hits"]]},
            "detectUntrusted": {"score": du["score"], "verdict": du["verdict"]},
            "hidden": {"format": h["format"], "kinds": [f["kind"] for f in h["findings"]], "visible": h["visible"], "hidden": h["hidden"]},
            "urls": [[u["kind"], u["url"], u.get("host"), [x["code"] for x in u["issues"]]] for u in check_urls(t, allow_domains=["northwind.example", "*.northwind.example"])],
            "sensitive": [[f["kind"], f["start"], f["end"]] for f in find_sensitive(t)],
        }
        want = {k: g[k] for k in got}
        # character offsets are UTF-16 in JavaScript; compare them only for texts without astral characters
        if any(ord(ch) > 0xFFFF for ch in t):
            got["sensitive"] = [x[0] for x in got["sensitive"]]
            want["sensitive"] = [x[0] for x in want["sensitive"]]
        if got != want:
            bad.append((g["i"], {k: (want[k], got[k]) for k in got if got[k] != want[k]}))
    assert not bad, "%d mismatches, first: %r" % (len(bad), bad[:2])


VARIANTS = _lines("variants.jsonl")


def test_component_outputs_match_on_mutated_variants():
    """~2,000 mutated texts (upper case, zero-width splits, look-alike letters, base64, hidden HTML, emoji and tag
    characters, percent and HTML-entity encoding) must give the same detector, hidden-text, URL and PII results."""
    assert len(VARIANTS) >= 7 * 300
    bad = []
    for g in VARIANTS:
        t = g["text"]
        d = detect(t)
        du = detect(t, source="web")
        h = scan_hidden(t)
        got = {
            "detect": {"score": d["score"], "verdict": d["verdict"], "hits": [[x["rule"], x["effective"], x["layer"]] for x in d["hits"]]},
            "detectUntrusted": {"score": du["score"], "verdict": du["verdict"]},
            "hidden": {"format": h["format"], "kinds": [f["kind"] for f in h["findings"]], "visible": h["visible"], "hidden": h["hidden"]},
            "urls": [[u["kind"], u["url"], u.get("host"), [x["code"] for x in u["issues"]]] for u in check_urls(t, allow_domains=["northwind.example", "*.northwind.example"])],
            "sensitive": [[f["kind"], f["start"], f["end"]] for f in find_sensitive(t)],
        }
        want = {k: g[k] for k in got}
        if any(ord(ch) > 0xFFFF for ch in t):
            got["sensitive"] = [x[0] for x in got["sensitive"]]
            want["sensitive"] = [x[0] for x in want["sensitive"]]
        if got != want:
            bad.append((t[:80], {k: (want[k], got[k]) for k in got if got[k] != want[k]}))
    assert not bad, "%d mismatches, first: %r" % (len(bad), bad[:2])
