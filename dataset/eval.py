#!/usr/bin/env python3
"""Reproducible evaluation for the Quadward benchmark.

    python dataset/eval.py                  # tables for every preset, both packages, plus the baselines
    python dataset/eval.py --preset strict  # one preset
    python dataset/eval.py --latex paper/generated   # also write the LaTeX tables used by the paper

It runs the Python package (quadward) on dataset/data/cases.jsonl. When Node.js is available it also
runs the JavaScript package (scripts/eval.mjs), and it exits non-zero if the two produce different outcomes or tables.
It then scores two baselines on the same cases with the same metric code:

* keyword  - a naive keyword filter: stop the case if any of 16 common jailbreak phrases appears anywhere in its text.
* detector - Quadward's injection detector alone, run over all of the case's text with the balanced thresholds
             (no spotlighting, hidden-text scan, output checks, tool firewall or taint tracking). This is an ablation.

No network access and no API keys are needed. Results are deterministic.
"""
from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
try:
    import quadward as ag
except ImportError:  # running from a checkout without installing the package
    sys.path.insert(0, str(ROOT / "python" / "src"))
    import quadward as ag
from quadward import bench
from quadward.injection import detect

KEYWORDS = [
    "ignore previous instructions", "ignore all previous", "ignore the above", "disregard", "forget your instructions",
    "system prompt", "jailbreak", "do anything now", "developer mode", "no restrictions", "without restrictions",
    "reveal your instructions", "bypass", "pretend you are", "you are now", "override",
]


def load_cases() -> list[dict]:
    with open(HERE / "data" / "cases.jsonl", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def case_text(c: dict) -> str:
    """Every string an outside filter could see for this case: prompt, content, turns, model output, tool call."""
    parts = []
    for k in ("text", "prompt", "content", "output"):
        if isinstance(c.get(k), str):
            parts.append(c[k])
    for t in c.get("turns") or []:
        parts.append(t.get("content") or t.get("text") or "")
    if c.get("call"):
        parts.append(json.dumps(c["call"], ensure_ascii=False))
    return "\n".join(parts)


def baseline_results(cases: list[dict], name: str) -> list[dict]:
    out = []
    for c in cases:
        text = case_text(c)
        if name == "keyword":
            low = text.lower()
            stopped = any(k in low for k in KEYWORDS)
        elif name == "detector":
            stopped = detect(text, block=0.7, flag=0.4)["verdict"] == "block"
        else:
            raise ValueError(name)
        out.append({"id": c["id"], "kind": c["kind"], "cat": c["cat"], "stage": c["stage"], "stopped": stopped})
    return out


def headline(results: list[dict], fp_key: str = "stopped") -> dict:
    atk = [r for r in results if r["kind"] == "attack"]
    ben = [r for r in results if r["kind"] == "benign"]
    cm = bench.classification_metrics(results)
    return {
        "stopped": bench.wilson(sum(r["stopped"] for r in atk), len(atk)),
        "fp": bench.wilson(sum(r.get(fp_key, r["stopped"]) for r in ben), len(ben)),
        "precision": cm["overall"]["precision"], "recall": cm["overall"]["recall"], "f1": cm["overall"]["f1"],
        "perCategory": {m["category"]: m for m in cm["perCategory"]},
    }


def pct(x) -> str:
    return "n/a" if x is None or (isinstance(x, float) and math.isnan(x)) else "%.1f" % (x * 100)


def run_js(presets: list[str]) -> dict | None:
    node = shutil.which("node")
    if not node or not (ROOT / "scripts" / "eval.mjs").exists():  # e.g. a standalone copy of the dataset
        return None
    args = [node, str(ROOT / "scripts" / "eval.mjs"), "--json"]
    if len(presets) == 1:
        args += ["--preset", presets[0]]
    return json.loads(subprocess.run(args, check=True, capture_output=True, text=True, cwd=ROOT).stdout)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--preset", help="evaluate one preset (default: all)")
    ap.add_argument("--no-js", action="store_true", help="skip the JavaScript cross-check")
    ap.add_argument("--latex", metavar="DIR", help="write LaTeX tables for the paper into DIR")
    a = ap.parse_args(argv)
    cases = load_cases()
    assert len(cases) == 257, "expected 257 cases, found %d" % len(cases)
    presets = [a.preset] if a.preset else list(ag.PRESET_IDS)

    reports = {p: bench.run_benchmark(p, cases) for p in presets}
    tables = {p: bench.metrics_table(r) for p, r in reports.items()}
    js = None if a.no_js else run_js(presets)
    mismatch = []
    if js is not None:
        for p, r in reports.items():
            py_out = {x["id"]: x["outcome"] for x in r["results"]}
            if py_out != js[p]["outcomes"]:
                mismatch.append(p + ": outcomes differ on " + ", ".join(k for k in py_out if py_out[k] != js[p]["outcomes"].get(k))[:400])
            if tables[p] != js[p]["table"]:
                mismatch.append(p + ": metric tables differ")

    for p in presets:
        print("## %s\n\n%s\n" % (p, tables[p]))

    rows = []
    for p in presets:
        r = reports[p]
        h = headline(r["results"], fp_key="fp")
        h["fpAny"] = bench.wilson(sum(x["stopped"] for x in r["results"] if x["kind"] == "benign"), r["counts"]["benign"])
        rows.append(("Quadward " + p, h))
    for b, label in (("keyword", "Keyword filter (baseline)"), ("detector", "Detector only (ablation)")):
        h = headline(baseline_results(cases, b))
        h["fpAny"] = h["fp"]
        rows.append((label, h))

    print("## Summary (all 257 cases)\n")
    print("| System | Attacks stopped [95% CI] | False positives [95% CI] | Benign interventions incl. approvals | Precision | Recall | F1 |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for name, h in rows:
        s, f, fa = h["stopped"], h["fp"], h["fpAny"]
        print("| %s | %s [%s-%s] | %s [%s-%s] | %s | %s | %s | %s |" % (name, pct(s["p"]), pct(s["lo"]), pct(s["hi"]), pct(f["p"]), pct(f["lo"]), pct(f["hi"]),
                                                                pct(fa["p"]), pct(h["precision"]), pct(h["recall"]), pct(h["f1"])))
    cats = list(rows[0][1]["perCategory"])
    compare = [r for r in rows if r[0] in ("Quadward balanced", "Keyword filter (baseline)", "Detector only (ablation)")]
    if len(compare) == 3:
        print("\n## Recall by category: balanced vs baselines\n")
        print("| Category | n | Keyword filter | Detector only | Quadward balanced |")
        print("| --- | ---: | ---: | ---: | ---: |")
        kw, det, bal = (dict(compare)[k] for k in ("Keyword filter (baseline)", "Detector only (ablation)", "Quadward balanced"))
        for c in cats:
            print("| %s | %d | %s | %s | %s |" % (c, bal["perCategory"][c]["n"], pct(kw["perCategory"][c]["recall"]), pct(det["perCategory"][c]["recall"]), pct(bal["perCategory"][c]["recall"])))

    if js is None:
        print("\nJavaScript cross-check: skipped (needs Node.js and a checkout of the repository; or --no-js was given).")
    elif mismatch:
        print("\nJavaScript cross-check: MISMATCH\n" + "\n".join(mismatch))
        return 1
    else:
        print("\nJavaScript cross-check: identical outcomes on all %d cases and identical tables for %d preset(s)." % (len(cases), len(presets)))

    if a.latex:
        write_latex(Path(a.latex), rows, reports, compare)
    return 0


def _tex(s: str) -> str:
    return s.replace("&", "\\&").replace("%", "\\%").replace("_", "\\_")


def write_latex(out: Path, rows, reports, compare) -> None:
    out.mkdir(parents=True, exist_ok=True)
    lines = ["% Generated by dataset/eval.py --latex. Do not edit by hand.", "\\begin{tabular}{lrrrrrr}", "\\toprule",
             "System & Stopped (\\%) & 95\\% CI & FP (\\%) & 95\\% CI & Prec. & F1 \\\\", "\\midrule"]
    for name, h in rows:
        s, f = h["stopped"], h["fp"]
        lines.append("%s & %s & %s--%s & %s & %s--%s & %s & %s \\\\" % (_tex(name), pct(s["p"]), pct(s["lo"]), pct(s["hi"]), pct(f["p"]), pct(f["lo"]), pct(f["hi"]),
                                                                    pct(h["precision"]), pct(h["f1"])))
    lines += ["\\bottomrule", "\\end{tabular}"]
    (out / "summary.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")

    if "balanced" in reports:
        cm = bench.classification_metrics(reports["balanced"]["results"])
        lines = ["% Generated by dataset/eval.py --latex. Do not edit by hand.", "\\begin{tabular}{llrrrrrr}", "\\toprule",
                 "Category & Stage & $n$ & TP & FP / benign & Prec. & Rec. & F1 \\\\", "\\midrule"]
        for m in cm["perCategory"]:
            lines.append("%s & %s & %d & %d & %d / %d & %s & %s & %s \\\\" % (_tex(m["category"]), _tex(", ".join(m["stages"])), m["n"], m["tp"], m["fp"], m["benignAtStages"],
                                                                          pct(m["precision"]), pct(m["recall"]), pct(m["f1"])))
        o = cm["overall"]
        lines += ["\\midrule", "All & all & %d & %d & %d / %d & %s & %s & %s \\\\" % (o["tp"] + o["fn"], o["tp"], o["fp"], reports["balanced"]["counts"]["benign"],
                                                                                 pct(o["precision"]), pct(o["recall"]), pct(o["f1"])), "\\bottomrule", "\\end{tabular}"]
        (out / "per_category.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if len(compare) == 3:
        d = dict(compare)
        kw, det, bal = d["Keyword filter (baseline)"], d["Detector only (ablation)"], d["Quadward balanced"]
        lines = ["% Generated by dataset/eval.py --latex. Do not edit by hand.", "\\begin{tabular}{lrrrr}", "\\toprule",
                 "Category & $n$ & Keyword & Detector only & Balanced \\\\", "\\midrule"]
        for c, m in bal["perCategory"].items():
            lines.append("%s & %d & %s & %s & %s \\\\" % (_tex(c), m["n"], pct(kw["perCategory"][c]["recall"]), pct(det["perCategory"][c]["recall"]), pct(m["recall"])))
        lines += ["\\bottomrule", "\\end{tabular}"]
        (out / "recall_compare.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("LaTeX tables written to " + str(out))


if __name__ == "__main__":
    sys.exit(main())
