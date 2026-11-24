"""Command line: ``quadward bench|check|test|presets``. Runs fully offline."""
from __future__ import annotations

import argparse
import json
import sys

from .bench import metrics_table, run_benchmark
from .extras import run_policy_tests
from .guard import Guard
from .policy import PRESET_IDS, parse_policy, preset, preset_info


def _load(spec: str) -> dict:
    if spec in PRESET_IDS:
        return preset(spec)
    with open(spec, encoding="utf-8") as f:
        r = parse_policy(f.read())
    if not r["policy"]:
        raise SystemExit("Policy has errors: " + "; ".join((e["path"] + ": " if e["path"] else "") + e["message"] for e in r["errors"]))
    return r["policy"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="quadward", description="Explainable guardrails for LLM agents.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bench", help="run the 257-case benchmark and print the metrics table")
    b.add_argument("--policy", default="balanced")
    b.add_argument("--json", help="write the full report to this file")
    c = sub.add_parser("check", help="score one input and explain the rule hits")
    c.add_argument("--policy", default="balanced")
    c.add_argument("text", nargs="+")
    t = sub.add_parser("test", help="run the tests stored in a policy")
    t.add_argument("--policy", default="balanced")
    sub.add_parser("presets", help="list the built-in presets")
    a = ap.parse_args(argv)
    if a.cmd == "presets":
        for pid in PRESET_IDS:
            print(pid.ljust(16) + preset_info(pid)["description"])
        return 0
    policy = _load(a.policy)
    if a.cmd == "bench":
        rep = run_benchmark(policy)
        print(metrics_table(rep))
        if a.json:
            with open(a.json, "w", encoding="utf-8") as f:
                json.dump(rep, f, indent=1, default=str)
        return 0
    if a.cmd == "check":
        d = Guard(policy=policy).check_input(" ".join(a.text))
        print(d["verdict"].upper() + " score " + str(d["score"]))
        for h in d["hits"]:
            print("  " + h["rule"] + " [" + h["category"] + "] +" + str(h["effective"]) + " via " + h["layer"] + ": " + h["why"])
        return 0
    if a.cmd == "test":
        res = run_policy_tests(policy)
        bad = 0
        for r in res:
            bad += 0 if r["pass"] else 1
            print(("pass " if r["pass"] else "FAIL ") + r["name"] + ("" if r["pass"] else " (expected " + str(r["expect"]) + ", got " + r["got"] + ")"))
        print(str(len(res) - bad) + "/" + str(len(res)) + " policy tests passed")
        return 1 if bad else 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
