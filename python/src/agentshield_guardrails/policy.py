"""Policy model (port of ``lib/policy.js``): validate and fill in defaults.

A policy says how strict each guard is and, per tool, what is allowed, denied or needs a person. Policies are
plain dicts with the same keys as the JavaScript package (camelCase), so one JSON or YAML file serves both.
YAML input needs the optional ``pyyaml`` extra; JSON and dicts work with no dependencies."""
from __future__ import annotations

import copy
import json

from ._data import load_json, rules
from ._jsre import compile_js, js_trim

_P = rules()["policy"]
DEFAULTS: dict = _P["defaults"]
KINDS: list = _P["kinds"]
ACTIONS: list = _P["actions"]
SENSITIVE_KINDS: list = _P["sensitiveKinds"]
REDACT_KINDS = [d["kind"] for d in rules()["detectors"]]
RULE_KEYS = {"action": "action", "kind": "kind", "description": "string", "paths": "list", "denyPaths": "list", "domains": "list", "sql": ["read-only", "any"],
             "maxAmount": "number", "hardLimit": "number", "overLimit": "action", "budget": "object", "recipients": "list", "unknownRecipient": "action",
             "commands": "list", "otherCommands": "action", "dangerous": "action", "denyArgs": "list", "rateLimit": "object", "trustOutput": "boolean",
             "commandArgs": "list", "pathArgs": "list"}


def _is_obj(x) -> bool:
    return isinstance(x, dict)


def _is_num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _is_int(x) -> bool:
    return _is_num(x) and float(x).is_integer()


def _merge(base, over):
    if not _is_obj(over):
        return copy.deepcopy(base) if over is None else copy.deepcopy(over)
    out = copy.deepcopy(base) if _is_obj(base) else {}
    for k, v in over.items():
        out[k] = _merge(out[k], v) if _is_obj(v) and _is_obj(out.get(k)) else copy.deepcopy(v)
    return out


def normalize_policy(raw: dict | None) -> dict:
    p = _merge(DEFAULTS, raw or {})
    rules_ = {}
    for name, r in (p["tools"].get("rules") or {}).items():
        rules_[name] = {"action": r} if isinstance(r, str) else dict({"action": "allow"}, **r)
    p["tools"]["rules"] = rules_
    if raw and _is_obj(raw.get("output")) and isinstance(raw["output"].get("redact"), list):
        p["output"]["redact"] = list(raw["output"]["redact"])
    if raw and _is_obj(raw.get("taint")) and isinstance(raw["taint"].get("sensitiveKinds"), list):
        p["taint"]["sensitiveKinds"] = list(raw["taint"]["sensitiveKinds"])
    return p


_TOOL_NAME = compile_js(r"^[\w.:\-/]+$", "")


def validate_policy(raw) -> dict:
    """Returns ``{errors, warnings, policy}``; errors and warnings are ``{path, line, message}``."""
    errors: list = []
    warnings: list = []

    def err(path, message):
        errors.append({"path": path, "line": None, "message": message})

    def warn(path, message):
        warnings.append({"path": path, "line": None, "message": message})

    if not _is_obj(raw):
        err("", "A policy must be a map of settings (key: value).")
        return {"errors": errors, "warnings": warnings, "policy": None}
    for k in raw:
        if k not in DEFAULTS:
            warn(k, 'Unknown setting "' + k + '" is ignored.')
    if raw.get("version") is not None and raw.get("version") != 1:
        err("version", "Only version 1 is supported.")
    if raw.get("mode") is not None and raw.get("mode") not in ("enforce", "monitor", "dry-run"):
        err("mode", "mode must be enforce, monitor or dry-run.")
    if raw.get("killSwitch") is not None and not isinstance(raw.get("killSwitch"), bool):
        err("killSwitch", "killSwitch must be true or false.")

    def num01(path, v):
        if v is not None and (not _is_num(v) or v < 0 or v > 1):
            err(path, "Must be a number from 0 to 1.")

    def lst(path, v):
        if v is not None and (not isinstance(v, list) or any(not isinstance(x, str) for x in v)):
            err(path, "Must be a list of strings.")

    def enumv(path, v, opts):
        if v is not None and v not in opts:
            err(path, "Must be one of: " + ", ".join(opts) + ".")

    inp = raw.get("input") or {}
    if raw.get("input") is not None and not _is_obj(raw.get("input")):
        err("input", "input must be a map.")
        inp = {}
    inj = inp.get("injection")
    if inj is not None:
        if not _is_obj(inj):
            err("input.injection", "Use { block: 0.7, flag: 0.4 }.")
        else:
            num01("input.injection.block", inj.get("block"))
            num01("input.injection.flag", inj.get("flag"))
            if _is_num(inj.get("block")) and _is_num(inj.get("flag")) and inj["flag"] > inj["block"]:
                err("input.injection.flag", "flag must not be higher than block.")
    if inp.get("classifier") is not None and not _is_obj(inp.get("classifier")):
        err("input.classifier", "Use { enabled: true, threshold: 0.8 }.")
    elif inp.get("classifier"):
        num01("input.classifier.threshold", inp["classifier"].get("threshold"))
    if inp.get("maxLength") is not None and not (_is_int(inp["maxLength"]) and inp["maxLength"] > 0):
        err("input.maxLength", "Must be a positive whole number.")
    un = raw.get("untrusted") or {}
    if not _is_obj(un):
        un = {}
    enumv("untrusted.spotlight", un.get("spotlight"), ["delimit", "datamark", "off"])
    enumv("untrusted.hiddenText", un.get("hiddenText"), ["strip", "flag", "keep"])
    num01("untrusted.flag", un.get("flag"))
    if un.get("quarantine") is not None and not isinstance(un.get("quarantine"), bool):
        err("untrusted.quarantine", "Must be true or false.")
    out = raw.get("output") or {}
    if not _is_obj(out):
        out = {}
    lst("output.redact", out.get("redact"))
    for i, k in enumerate(out.get("redact") if isinstance(out.get("redact"), list) else []):
        if k not in REDACT_KINDS:
            err("output.redact[" + str(i) + "]", 'Unknown kind "' + str(k) + '". Known: ' + ", ".join(REDACT_KINDS) + ".")
    lst("output.allowEmails", out.get("allowEmails"))
    if out.get("links") is not None:
        if not _is_obj(out["links"]):
            err("output.links", "Use { allow: [...], action: flag }.")
        else:
            lst("output.links.allow", out["links"].get("allow"))
            enumv("output.links.action", out["links"].get("action"), ["flag", "strip", "block"])
    enumv("output.exfiltration", out.get("exfiltration"), ["block", "flag"])
    enumv("output.leaks", out.get("leaks"), ["block", "flag"])
    if out.get("schema") is not None and not _is_obj(out.get("schema")):
        err("output.schema", "schema must be a JSON-schema map or null.")
    tools = raw.get("tools") or {}
    if raw.get("tools") is not None and not _is_obj(raw.get("tools")):
        err("tools", "tools must be a map.")
        tools = {}
    enumv("tools.default", tools.get("default"), ACTIONS)

    def rl(path, v):
        if v is None:
            return
        if not _is_obj(v) or not (_is_int(v.get("max")) and v["max"] > 0) or not (_is_num(v.get("per")) and v["per"] > 0):
            err(path, "Use { max: 10, per: 60 } (calls per seconds).")

    rl("tools.rateLimit", tools.get("rateLimit"))
    if tools.get("rules") is not None and not _is_obj(tools.get("rules")):
        err("tools.rules", "rules must be a map of tool name to rule.")
    for name, r in (tools.get("rules") if _is_obj(tools.get("rules")) else {}).items():
        p = "tools.rules." + name
        if not _TOOL_NAME.search(name):
            err(p, "Tool names may use letters, digits, _ . : - and /.")
        if isinstance(r, str):
            enumv(p, r, ACTIONS)
            continue
        if not _is_obj(r):
            err(p, "A rule is a map, or just allow / deny / require-approval.")
            continue
        for k, v in r.items():
            t = RULE_KEYS.get(k)
            pk = p + "." + k
            if not t:
                warn(pk, 'Unknown rule setting "' + k + '" is ignored.')
                continue
            if t == "action":
                enumv(pk, v, ACTIONS)
            elif t == "kind":
                enumv(pk, v, KINDS)
            elif t == "list":
                lst(pk, v)
            elif t == "number":
                if not _is_num(v) or v < 0:
                    err(pk, "Must be a number of at least 0.")
            elif t == "boolean":
                if not isinstance(v, bool):
                    err(pk, "Must be true or false.")
            elif t == "string":
                if not isinstance(v, str):
                    err(pk, "Must be text.")
            elif isinstance(t, list):
                enumv(pk, v, t)
        if r.get("budget") is not None:
            b = r["budget"]
            if not _is_obj(b) or not _is_num(b.get("amount")) or b["amount"] < 0:
                err(p + ".budget", "Use { amount: 500, per: session } (per: session, hour or day).")
            else:
                enumv(p + ".budget.per", b.get("per"), ["session", "hour", "day"])
        rl(p + ".rateLimit", r.get("rateLimit"))
        if _is_num(r.get("maxAmount")) and _is_num(r.get("hardLimit")) and r["hardLimit"] < r["maxAmount"]:
            err(p + ".hardLimit", "hardLimit must be at least maxAmount.")
        for i, rx in enumerate(r.get("denyArgs") if isinstance(r.get("denyArgs"), list) else []):
            try:
                compile_js(str(rx), "i")
            except Exception as e:  # noqa: BLE001
                err(p + ".denyArgs[" + str(i) + "]", "Not a valid regular expression: " + str(e))
        if r.get("action") == "deny" and len(r) > 1:
            warn(p, "This tool is denied, so its other settings never apply.")
    ta = raw.get("taint") or {}
    if not _is_obj(ta):
        ta = {}
    enumv("taint.untrustedArgs", ta.get("untrustedArgs"), ACTIONS)
    enumv("taint.flaggedContext", ta.get("flaggedContext"), ACTIONS)
    lst("taint.sensitiveKinds", ta.get("sensitiveKinds"))
    for i, k in enumerate(ta.get("sensitiveKinds") if isinstance(ta.get("sensitiveKinds"), list) else []):
        if k not in KINDS:
            err("taint.sensitiveKinds[" + str(i) + "]", 'Unknown kind "' + str(k) + '".')
    if raw.get("audit") is not None and not _is_obj(raw.get("audit")):
        err("audit", "audit must be a map.")
    if raw.get("tests") is not None:
        if not isinstance(raw["tests"], list):
            err("tests", "tests must be a list.")
        else:
            for i, t in enumerate(raw["tests"]):
                p = "tests[" + str(i) + "]"
                if not _is_obj(t):
                    err(p, "Each test is a map.")
                    continue
                n = sum(1 for k in ("input", "call", "output", "untrusted") if t.get(k) is not None)
                if n != 1:
                    err(p, "A test needs exactly one of input, untrusted, output or call.")
                if t.get("call") is not None and (not _is_obj(t["call"]) or not isinstance(t["call"].get("tool"), str)):
                    err(p + ".call", "Use { tool: name, args: { ... } }.")
                if t.get("expect") not in ("allow", "deny", "require-approval", "block", "flag", "redact", "quarantine"):
                    err(p + ".expect", "expect must be allow, deny, require-approval, block, flag, redact or quarantine.")
    if not errors:
        tr = (tools.get("rules") if _is_obj(tools.get("rules")) else None) or {}
        if tools.get("default") == "allow" and not any((v.get("action") if _is_obj(v) else v) == "deny" for v in tr.values()):
            warn("tools.default", "Unknown tools are allowed and nothing is denied. Consider require-approval as the default.")
        if raw.get("mode") == "monitor":
            warn("mode", "Monitor mode logs what would be blocked but blocks nothing.")
        if raw.get("killSwitch") is True:
            warn("killSwitch", "The kill switch is on: every tool call is denied.")
    return {"errors": errors, "warnings": warnings, "policy": None if errors else normalize_policy(raw)}


def parse_policy(text: str) -> dict:
    """Parse policy text (JSON, or YAML when ``pyyaml`` is installed). Returns ``{policy, errors, warnings, raw}``."""
    src = "" if text is None else str(text)
    t = js_trim(src)
    if not t:
        return {"policy": None, "errors": [{"path": "", "line": None, "message": "The policy is empty."}], "warnings": [], "raw": None}
    if t[0] == "{":
        try:
            raw = json.loads(t)
        except ValueError as e:
            return {"policy": None, "errors": [{"path": "", "line": None, "message": "Invalid JSON: " + str(e)}], "warnings": [], "raw": None}
    else:
        try:
            import yaml  # type: ignore
        except ImportError:
            return {"policy": None, "errors": [{"path": "", "line": None, "message": "YAML policies need the optional dependency: pip install 'agentshield-guardrails[yaml]'"}], "warnings": [], "raw": None}
        try:
            raw = yaml.safe_load(src)
        except yaml.YAMLError as e:
            line = getattr(getattr(e, "problem_mark", None), "line", None)
            return {"policy": None, "errors": [{"path": "", "line": None if line is None else line + 1, "message": str(e)}], "warnings": [], "raw": None}
    v = validate_policy(raw)
    return {"policy": v["policy"], "errors": v["errors"], "warnings": v["warnings"], "raw": raw}


_PRESETS = load_json("presets.json")
PRESET_IDS: list = list(_PRESETS.keys())


def preset(name: str) -> dict:
    """A ready-made policy (balanced, strict, permissive, support-bot, sql-analyst, browser-agent, mcp-tools, email-assistant)."""
    if name not in _PRESETS:
        raise KeyError("No preset called " + name + ". Known: " + ", ".join(PRESET_IDS))
    return copy.deepcopy(_PRESETS[name]["policy"])


def preset_info(name: str) -> dict:
    p = _PRESETS[name]
    return {"label": p["label"], "description": p["description"], "yaml": p["yaml"]}
