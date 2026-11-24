"""Benchmark runner (port of ``bench/run.js`` and ``bench/stats.js``) plus classification metrics.

Runs every case through a fresh guard for the given policy, records what each guard did, and aggregates stop
rates, false positives and friction with 95% Wilson intervals. "Stopped" means the attack did not get through as
intended: blocked, held for a person's approval, quarantined (removed before the model saw it) or redacted.
Flag-only results are reported but do not count as stopped."""
from __future__ import annotations

import math
import time

from ._data import load_cases, load_json
from .firewall import record_call
from .guard import Guard

STOP = {"blocked", "approval", "quarantined", "redacted"}
FP = {"blocked", "quarantined", "redacted"}
Z95 = 1.959963984540054
_META = load_json("bench_meta.json")
SYSTEM_PROMPT: str = _META["systemPrompt"]
CANARY: str = _META["canary"]


def cases() -> list:
    """The 257 benchmark cases (the same records as ``dataset/data/cases.jsonl``)."""
    return [dict(c) for c in load_cases()]


def wilson(k: int, n: int, z: float = Z95) -> dict:
    if not n:
        return {"p": math.nan, "lo": math.nan, "hi": math.nan}
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return {"p": p, "lo": max(0, c - h), "hi": min(1, c + h)}


def _dedupe(xs):
    return list(dict.fromkeys(xs))


def run_case(policy, c: dict) -> dict:
    g = Guard(policy=policy, system_prompt=SYSTEM_PROMPT, canary=CANARY, rand=lambda: 0.42)
    # JS passes systemPrompt into createGuard, which registers it as trusted text; mirror that exactly.
    t: dict = {}

    def timed(k, fn):
        t0 = time.perf_counter()
        r = fn()
        t[k] = t.get(k, 0) + (time.perf_counter() - t0) * 1000
        return r

    outcome = "passed"
    why: list = []
    score = None
    try:
        if c.get("prompt"):
            g.trust(c["prompt"])
        st = c["stage"]
        if st == "input":
            d = timed("input", lambda: g.check_input(c["text"], trust=False))
            score = d["score"]
            outcome = "blocked" if d["action"] == "block" else "flagged" if d["action"] == "flag" else "passed"
            why += [h["rule"] + ("@" + h["layer"] if h["layer"] != "text" else "") for h in d["hits"][:4]]
        elif st == "conversation":
            d = timed("input", lambda: g.check_conversation(c["turns"]))
            score = d["score"]
            outcome = "blocked" if d["action"] == "block" else "flagged" if d["action"] == "flag" else "passed"
            why += [h["rule"] for h in d["hits"][:4]]
            if d["splitAcrossTurns"]:
                why.append("split across turns")
        elif st == "untrusted":
            r = timed("untrusted", lambda: g.ingest(c["content"], source=c.get("source"), label=c.get("label"), format=c.get("format")))
            score = r["score"]
            if r["verdict"] == "quarantined":
                outcome = "quarantined"
                why.append(str(r["removed"]) + " passage(s) removed" if r["removed"] else "hidden text removed")
            elif r["verdict"] == "flagged":
                outcome = "flagged"
            why += [h["rule"] for h in r["hits"][:3]]
            if r["hiddenInstructions"]:
                why.append("hidden: " + ", ".join(h["kind"] for h in r["hiddenInstructions"]))
            if c.get("call"):
                d = timed("tool", lambda: g.check_tool_call(c["call"], log=False))
                o = "blocked" if d["action"] == "deny" else "approval" if d["action"] == "require-approval" else None
                if o:
                    if o == "blocked":
                        outcome = "blocked"
                    elif outcome != "blocked":
                        outcome = "quarantined" if outcome == "quarantined" else "approval"
                    why.append(c["call"]["tool"] + ": " + ", ".join(x["code"] for x in d["reasons"] if x["severity"] != "info"))
        elif st == "output":
            r = timed("output", lambda: g.check_output(c["output"], system_prompt=SYSTEM_PROMPT))
            outcome = "blocked" if r["action"] == "block" else "redacted" if r["action"] == "redact" else "flagged" if r["urls"] else "passed"
            why += r["reasons"]
            for u in r["urls"]:
                why.append((u.get("host") or u["url"])[:40] + ": " + ", ".join(i["code"] for i in u["issues"]))
        elif st == "tool":
            for ctx in c.get("context") or []:
                g.ingest(ctx["content"], source=ctx.get("source"), label=ctx.get("label"))
            for b in c.get("before") or []:
                d = g.check_tool_call(b, log=False)
                if d["action"] == "allow":
                    record_call(g.state, d)
            d = timed("tool", lambda: g.check_tool_call(c["call"], log=False))
            outcome = "blocked" if d["action"] == "deny" else "approval" if d["action"] == "require-approval" else "passed"
            why += [x["code"] for x in d["reasons"] if x["severity"] != "info"]
    except Exception as e:  # noqa: BLE001
        outcome = "error"
        why.append(str(e))
    stopped = outcome in STOP
    benign = c["kind"] == "benign"
    return {"id": c["id"], "kind": c["kind"], "cat": c["cat"], "stage": c["stage"], "outcome": outcome, "stopped": stopped,
            "fp": benign and outcome in FP, "friction": benign and outcome == "approval", "flagged": outcome == "flagged", "score": score,
            "why": _dedupe(why)[:8], "ms": sum(t.values()), "timings": t, "note": c.get("note")}


def run_benchmark(policy="balanced", case_list=None) -> dict:
    cs = case_list if case_list is not None else load_cases()
    t0 = time.perf_counter()
    results = [run_case(policy, c) for c in cs]
    name = policy if isinstance(policy, str) else (policy or {}).get("name", "policy")
    return summarize(results, policy=name, ms=(time.perf_counter() - t0) * 1000)


def summarize(results: list, policy: str = "policy", ms: float | None = None) -> dict:
    atk = [r for r in results if r["kind"] == "attack"]
    ben = [r for r in results if r["kind"] == "benign"]

    def rate(k, n):
        return dict({"k": k, "n": n}, **wilson(k, n))

    cats: dict = {}
    for r in results:
        c = cats.setdefault(r["cat"], {"cat": r["cat"], "kind": r["kind"], "n": 0, "stopped": 0, "blocked": 0, "approval": 0, "quarantined": 0, "redacted": 0,
                                       "flagged": 0, "passed": 0, "fp": 0, "friction": 0, "error": 0})
        c["n"] += 1
        c[r["outcome"]] = c.get(r["outcome"], 0) + 1
        c["stopped"] += 1 if r["stopped"] else 0
        c["fp"] += 1 if r["fp"] else 0
        c["friction"] += 1 if r["friction"] else 0
    categories = []
    for c in cats.values():
        if c["kind"] == "attack":
            c["rate"] = rate(c["stopped"], c["n"])
        else:
            c["fpRate"] = rate(c["fp"], c["n"])
            c["frictionRate"] = rate(c["friction"], c["n"])
        categories.append(c)
    return {
        "format": "quadward-benchmark/1", "policy": policy, "totalMs": ms,
        "counts": {"cases": len(results), "attacks": len(atk), "benign": len(ben)},
        "attack": {"stopped": rate(sum(r["stopped"] for r in atk), len(atk)), "blocked": rate(sum(r["outcome"] == "blocked" for r in atk), len(atk)),
                   "approval": rate(sum(r["outcome"] == "approval" for r in atk), len(atk)), "flaggedOnly": sum(r["outcome"] == "flagged" for r in atk),
                   "passed": sum(r["outcome"] == "passed" for r in atk)},
        "benign": {"falsePositive": rate(sum(r["fp"] for r in ben), len(ben)), "friction": rate(sum(r["friction"] for r in ben), len(ben)),
                   "flagged": sum(r["outcome"] == "flagged" for r in ben), "clean": sum(r["outcome"] == "passed" for r in ben)},
        "categories": categories,
        "gaps": [{"id": r["id"], "cat": r["cat"], "outcome": r["outcome"], "note": r["note"], "why": r["why"]} for r in atk if not r["stopped"]],
        "falsePositives": [{"id": r["id"], "cat": r["cat"], "outcome": r["outcome"], "note": r["note"], "why": r["why"], "friction": r["friction"]} for r in ben if r["fp"] or r["friction"]],
        "results": results,
    }


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else math.nan
    r = tp / (tp + fn) if tp + fn else math.nan
    if tp == 0:
        f1 = 0.0 if tp + fn else math.nan
    else:
        f1 = 2 * p * r / (p + r)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1}


def classification_metrics(results: list) -> dict:
    """Precision, recall and F1, overall and per attack category.

    A case counts as *flagged positive* when the guard intervened: blocked, quarantined, redacted or held for a
    person's approval (the benchmark's "stopped"). Recall for a category is its stop rate. Benign cases carry no
    attack category, so a category's false positives are the benign cases *run at the same guard stage(s)* that
    the guard intervened on; precision is therefore stage-matched. Approvals on benign cases count as false
    positives here (stricter than the headline false-positive rate, which reports them separately as friction)."""
    pos = [r for r in results if r["kind"] == "attack"]
    neg = [r for r in results if r["kind"] == "benign"]
    overall = _prf(sum(r["stopped"] for r in pos), sum(r["stopped"] for r in neg), sum(not r["stopped"] for r in pos))
    per = []
    for cat in dict.fromkeys(r["cat"] for r in pos):
        rs = [r for r in pos if r["cat"] == cat]
        stages = sorted({r["stage"] for r in rs})
        fp = sum(1 for r in neg if r["stage"] in stages and r["stopped"])
        m = _prf(sum(r["stopped"] for r in rs), fp, sum(not r["stopped"] for r in rs))
        m.update({"category": cat, "n": len(rs), "stages": stages, "benignAtStages": sum(1 for r in neg if r["stage"] in stages)})
        per.append(m)
    return {"overall": overall, "perCategory": per}


def _pct(x) -> str:
    return "n/a" if x is None or (isinstance(x, float) and math.isnan(x)) else "%.1f" % (x * 100)


def metrics_table(report: dict) -> str:
    """Markdown table: headline rates, then precision/recall/F1 per attack category."""
    cm = classification_metrics(report["results"])
    a, b = report["attack"], report["benign"]
    lines = [
        "Policy: %s (%d attacks, %d benign)" % (report["policy"], report["counts"]["attacks"], report["counts"]["benign"]),
        "Attacks stopped: %s%% [%s-%s]  False positives: %s%% [%s-%s]  Friction: %s%%" % (
            _pct(a["stopped"]["p"]), _pct(a["stopped"]["lo"]), _pct(a["stopped"]["hi"]), _pct(b["falsePositive"]["p"]), _pct(b["falsePositive"]["lo"]),
            _pct(b["falsePositive"]["hi"]), _pct(b["friction"]["p"])),
        "",
        "| Category | Stage(s) | n | TP | FN | FP (benign, same stage) | Precision | Recall | F1 |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for m in cm["perCategory"]:
        lines.append("| %s | %s | %d | %d | %d | %d / %d | %s | %s | %s |" % (m["category"], ", ".join(m["stages"]), m["n"], m["tp"], m["fn"], m["fp"], m["benignAtStages"],
                                                                         _pct(m["precision"]), _pct(m["recall"]), _pct(m["f1"])))
    o = cm["overall"]
    lines.append("| **all** | all | %d | %d | %d | %d / %d | %s | %s | %s |" % (report["counts"]["attacks"], o["tp"], o["fn"], o["fp"], report["counts"]["benign"],
                                                                          _pct(o["precision"]), _pct(o["recall"]), _pct(o["f1"])))
    return "\n".join(lines)
