"""Tool/action firewall (port of ``lib/firewall.js``).

Every tool call is checked against the policy before it runs: allow, deny or require a person's approval, with
every reason listed. Checks: kill switch, per-tool action, path and domain allowlists, read-only SQL, amount limits
and budgets, recipient allowlists, command allowlists, dangerous commands, argument deny-patterns, rate limits,
taint from untrusted content, and sensitive actions taken while flagged content is in context."""
from __future__ import annotations

import math
import time

from ._data import rules
from ._jsre import compile_js
from ._url import parse_url
from ._util import js_num_str
from .dangerous import COMMAND_ARG_KEYS, dangerous_command, shell_segments, sql_read_only
from .output import host_allowed, match_any
from .taint import walk_strings

SENSITIVE_KINDS: list = list(rules()["policy"]["sensitiveKinds"])
RANK = {"allow": 0, "require-approval": 1, "deny": 2}
PATH_KEYS = ["path", "file", "filename", "filepath", "file_path", "dir", "directory", "folder", "target", "src", "source", "dest", "destination", "from", "output"]
URL_KEYS = ["url", "uri", "href", "link", "endpoint", "webhook", "callback", "site", "page"]
RCPT_KEYS = ["to", "cc", "bcc", "recipient", "recipients", "email", "emails", "address", "reply_to", "replyto", "forward_to"]
AMOUNT_KEYS = ["amount", "value", "total", "sum", "price", "usd", "amount_usd", "quantity_usd"]


def _worst(a, b):
    return b if b in RANK and RANK[b] > RANK.get(a, -1) else a


_KIND_RULES = [
    ("email-draft", [compile_js("draft", ""), compile_js("mail|email|message", "")]),
    ("email", [compile_js(r"send.*(mail|email)|(mail|email).*send|^email$|forward", "")]),
    ("payment", [compile_js("refund|charge|pay|transfer|wire|invoice_pay|payout|purchase", "")]),
    ("shell", [compile_js("shell|exec|terminal|bash|command|run_cmd|^sh$", "")]),
    ("sql", [compile_js("sql|query|database|db_", "")]),
    ("file-delete", [compile_js("delete_file|remove_file|unlink|rm_", "")]),
    ("file-write", [compile_js("write|save|create_file|edit_file|append", "")]),
    ("file-read", [compile_js("read|open_file|list_files|cat|get_file|ls", "")]),
    ("web", [compile_js("fetch|http|browse|web|url|navigate|scrape", "")]),
    ("deploy", [compile_js("deploy|kubectl|scale|rollout|terraform", "")]),
    ("git", [compile_js("git|merge|push|commit", "")]),
    ("message", [compile_js("slack|post_message|send_message|sms|tweet", "")]),
    ("search", [compile_js("search|lookup|kb_", "")]),
]


def guess_kind(name) -> str:
    """Guess a tool's kind from its name when the policy does not say."""
    n = str(name).lower()
    for kind, res in _KIND_RULES:
        if all(r.search(n) for r in res):
            return kind
    return "other"


def normalize_path(p, cwd: str = "/workspace") -> str:
    s = ("" if p is None else str(p)).replace("\\", "/")
    if s.startswith("~"):
        s = "/home/user" + s[1:]
    if not s.startswith("/"):
        s = (cwd[:-1] if cwd.endswith("/") else cwd) + "/" + s
    out: list = []
    for part in s.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            if out:
                out.pop()
        else:
            out.append(part)
    return "/" + "/".join(out)


def _glob_path_source(g) -> str:
    s = "".join("\\" + c if c in ".+^${}()|[]\\" else c for c in str(g))
    s = compile_js(r"\*\*\/?", "g").sub("\x00", s)
    s = s.replace("*", "\x01").replace("?", "\x02").replace("\x00", "(?:.*/)?.*").replace("\x01", "[^/]*").replace("\x02", "[^/]")
    return "^" + s + "$"


def path_match(p: str, globs) -> bool:
    for g in globs or []:
        r = compile_js(_glob_path_source(g), "")
        if r.search(p) or r.search(p + "/"):
            return True
    return False


_INDEX = compile_js(r"\[\d+\]", "g")


def _key_of(path: str) -> str:
    return _INDEX.sub("", path).split(".")[-1].lower()


_AMOUNT_RE = compile_js(r"-?\d[\d,]*(?:\.\d+)?", "")


def parse_amount(v) -> float:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    m = _AMOUNT_RE.search("" if v is None else str(v))
    return float(m.group(0).replace(",", "")) if m else math.nan


_EMAILS = compile_js(r"[\w.%+-]+@[\w-]+(?:\.[\w-]+)+", "g")


def emails_in(v) -> list:
    return [x.lower() for x in _EMAILS.findall("" if v is None else str(v))]


def create_firewall_state() -> dict:
    return {"calls": {}, "spend": {}, "all": []}


_HTTP_PREFIX = compile_js(r"^https?:", "i")
_NUL = compile_js(r"\0", "")
_TRAVERSAL = compile_js(r"(^|\/)\.\.(\/|$)", "")
_HTTP_URL_START = compile_js(r"^https?:\/\/", "i")
_HTTP_URLS = compile_js(r"https?:\/\/[^\s\"'<>]+", "gi")
_HTTP_PROTO = compile_js(r"^https?:$", "")
_DOTTED_QUAD = compile_js(r"^\d+\.\d+\.\d+\.\d+$", "")
_PRIVATE = compile_js(r"^(10|127|169\.254|192\.168|172\.(1[6-9]|2\d|3[01]))\.", "")
_WS = compile_js(r"\s+", "")
_RISK = compile_js(r"critical|dangerous:(rm-rf-root|pipe-to-shell|disk-wipe|reverse-shell|secret-exfil|sql-drop|sql-truncate|sql-delete-all|infra-destroy)", "")


def _fmt_num(x) -> str:
    return js_num_str(x)


def check_tool_call(policy: dict, call: dict, taint=None, state: dict | None = None, now: float | None = None, cwd: str | None = None) -> dict:
    """Decide on one tool call. ``call = {tool, args}``. Returns
    ``{tool, kind, action, reasons: [{code, severity, detail, arg?}], risk, mode, amount, wouldBe?}``."""
    now = time.time() * 1000 if now is None else now
    st = state if state is not None else create_firewall_state()
    tool = str((call or {}).get("tool") or "")
    args = (call or {}).get("args") or {}
    rules_ = (policy.get("tools") or {}).get("rules") or {}
    rule = rules_.get(tool) if isinstance(rules_.get(tool), dict) else None
    kind = (rule or {}).get("kind") or guess_kind(tool)
    reasons: list = []
    st_ = {"action": "allow", "amount": math.nan}

    def add(severity, code, detail, arg=None):
        r = {"code": code, "severity": severity, "detail": detail}
        if arg is not None:
            r["arg"] = arg
        reasons.append(r)
        st_["action"] = _worst(st_["action"], severity)

    def finish():
        action = st_["action"]
        amount = st_["amount"]
        if action == "deny":
            risk = "critical" if any(_RISK.search(x["code"]) for x in reasons) else "high"
        elif action == "require-approval":
            risk = "medium"
        else:
            risk = "medium" if any(x["code"] == "sensitive-action" for x in reasons) else "low"
        mode = policy.get("mode") or "enforce"
        d = {"tool": tool, "kind": kind, "action": action, "reasons": reasons, "risk": risk, "mode": mode, "amount": amount if math.isfinite(amount) else None}
        if mode == "monitor" and action != "allow" and not any(x["code"] == "kill-switch" for x in reasons):
            d["wouldBe"] = action
            d["action"] = "allow"
        return d

    if policy.get("killSwitch"):
        add("deny", "kill-switch", "The kill switch is on, so no tool may run.")
        return finish()
    if not tool:
        add("deny", "no-tool", "The call names no tool.")
        return finish()
    if not rule:
        d = (policy.get("tools") or {}).get("default") or "require-approval"
        if d != "allow":
            add(d, "unlisted-tool", '"' + tool + '" is not in the policy; the default for unlisted tools is ' + d + ".")
    elif rule.get("action") != "allow":
        add(rule.get("action"), "tool-rule", 'The policy sets "' + tool + '" to ' + str(rule.get("action")) + ".")
    if rule and rule.get("action") == "deny":
        return finish()
    r = rule or {}
    work_cwd = cwd or "/workspace"

    # ---- paths
    path_keys = [k.lower() for k in (r.get("pathArgs") or PATH_KEYS)]

    def on_path(v, p):
        if _key_of(p) not in path_keys:
            return
        if _HTTP_PREFIX.search(v):
            return
        if _NUL.search(v):
            add("deny", "null-byte", "Path contains a null byte.", p)
            return
        np = normalize_path(v, work_cwd)
        if _TRAVERSAL.search(v.replace("\\", "/")):
            add("deny" if r.get("paths") and not path_match(np, r["paths"]) else "require-approval", "path-traversal",
                '"' + v + '" climbs out with ".." (resolves to ' + np + ").", p)
        if r.get("denyPaths") and path_match(np, r["denyPaths"]):
            add("deny", "path-denied", np + " matches a denied path.", p)
        elif r.get("paths") and not path_match(np, r["paths"]):
            add("deny", "path-not-allowed", np + " is outside the allowed paths (" + ", ".join(r["paths"]) + ").", p)

    walk_strings(args, on_path)

    # ---- domains
    def on_url(v, p):
        is_url_key = _key_of(p) in URL_KEYS
        if not is_url_key and not _HTTP_URL_START.search(v):
            return
        urls = [v] if is_url_key else _HTTP_URLS.findall(v)
        for u in urls:
            pu = parse_url(u)
            if not pu:
                if is_url_key:
                    add("deny", "bad-url", '"' + u + '" is not a valid URL.', p)
                continue
            if not _HTTP_PROTO.search(pu.protocol):
                add("deny", "unsafe-scheme", pu.protocol + " URLs are not allowed.", p)
                continue
            if pu.username or pu.password:
                add("deny", "userinfo-trick", "The URL hides its real host (" + pu.hostname + ') behind an "@".', p)
            if r.get("domains") and is_url_key and not host_allowed(pu.hostname, r["domains"]):
                add("deny", "domain-not-allowed", pu.hostname + " is not on the allowed domains (" + ", ".join(r["domains"]) + ").", p)
            if _DOTTED_QUAD.search(pu.hostname) and _PRIVATE.search(pu.hostname):
                add("deny", "private-network", pu.hostname + " is a private or metadata address.", p)

    walk_strings(args, on_url)

    # ---- recipients
    if r.get("recipients") or kind in ("email", "email-draft", "message"):
        def on_rcpt(v, p):
            if _key_of(p) not in RCPT_KEYS:
                return
            for e in emails_in(v):
                if r.get("recipients") and not match_any(e, r["recipients"]):
                    add(r.get("unknownRecipient") or "require-approval", "recipient-not-allowed", e + " is not on the recipient allowlist.", p)

        walk_strings(args, on_rcpt)

    # ---- amounts, limits and budgets
    def on_amount(v, p):
        if _key_of(p) in AMOUNT_KEYS:
            a = parse_amount(v)
            if math.isfinite(a):
                st_["amount"] = st_["amount"] + a if math.isfinite(st_["amount"]) else a

    walk_strings(args, on_amount)
    amount = st_["amount"]
    if math.isfinite(amount):
        if amount < 0:
            add("deny", "negative-amount", "Negative amounts are not allowed.")
        if r.get("hardLimit") is not None and amount > r["hardLimit"]:
            add("deny", "over-hard-limit", "$" + _fmt_num(amount) + " is over the hard limit of $" + _fmt_num(r["hardLimit"]) + ".")
        elif r.get("maxAmount") is not None and amount > r["maxAmount"]:
            add(r.get("overLimit") or "require-approval", "over-limit", "$" + _fmt_num(amount) + " is over the $" + _fmt_num(r["maxAmount"]) + " limit.")
        if r.get("budget"):
            spent = _spent_in(st, tool, r["budget"].get("per"), now)
            if spent + amount > r["budget"]["amount"]:
                add("require-approval", "over-budget", "$" + _fmt_num(spent) + " already spent this " + (r["budget"].get("per") or "session") + "; $" + _fmt_num(amount)
                    + " more would pass the $" + _fmt_num(r["budget"]["amount"]) + " budget.")
    elif kind == "payment" and (r.get("maxAmount") is not None or r.get("budget")):
        add("require-approval", "amount-unknown", "Could not read the amount, so the limit cannot be checked.")

    # ---- commands
    cmd_keys = [k.lower() for k in (r.get("commandArgs") or COMMAND_ARG_KEYS)]
    command_like = kind in ("shell", "sql", "deploy", "git") or bool(r.get("commands")) or bool(r.get("sql"))
    n_keys = len(args) if isinstance(args, (dict, list)) else (len(args) if isinstance(args, str) else 0)

    def on_cmd(v, p):
        if _key_of(p) not in cmd_keys and not (command_like and n_keys == 1):
            return
        if kind == "sql" or r.get("sql"):
            if r.get("sql") == "read-only":
                ro = sql_read_only(v)
                if not ro["ok"]:
                    add("deny", "sql-not-read-only", "Only read queries are allowed (" + ro["reason"] + ").", p)
        for h in dangerous_command(v):
            add("deny" if h["severity"] == "critical" else (r.get("dangerous") or "require-approval"), "dangerous:" + h["id"], h["why"], p)
        if r.get("dangerous") == "deny":
            for x in reasons:
                if x["code"].startswith("dangerous:") and x["severity"] != "deny":
                    x["severity"] = "deny"
                    st_["action"] = "deny"
        if r.get("commands") and kind != "sql":
            for seg in shell_segments(v):
                ok = any(seg == c or seg.startswith(c + " ") for c in r["commands"])
                if not ok:
                    add(r.get("otherCommands") or "require-approval", "command-not-allowed", '"' + " ".join(_WS.split(seg)[:3]) + '" is not an allowed command.', p)

    walk_strings(args, on_cmd)
    if r.get("denyArgs"):
        def on_deny(v, p):
            for rx in r["denyArgs"]:
                if compile_js(rx, "i").search(v):
                    add("deny", "denied-argument", "Argument matches the denied pattern /" + rx + "/.", p)

        walk_strings(args, on_deny)

    # ---- rate limits
    lim = r.get("rateLimit") or (policy.get("tools") or {}).get("rateLimit")
    if lim:
        pool = (st["calls"].get(tool) or []) if r.get("rateLimit") else st["all"]
        recent = sum(1 for t in pool if now - t < lim["per"] * 1000)
        if recent >= lim["max"]:
            add("deny", "rate-limit", str(recent) + " calls in the last " + _fmt_num(lim["per"]) + "s (limit " + _fmt_num(lim["max"]) + ").")

    # ---- sensitive action kinds
    if kind in ("payment", "email"):
        reasons.append({"code": "sensitive-action", "severity": "info", "detail": "Moves money (sandboxed here)." if kind == "payment" else "Sends a message outside the system."})

    # ---- taint and flagged context
    sensitive = (policy.get("taint") or {}).get("sensitiveKinds") or SENSITIVE_KINDS
    if taint is not None:
        tainted = taint.check_args(args)
        seen = set()
        for t in tainted:
            k = t["arg"] + "|" + t["entity"]
            if k in seen:
                continue
            seen.add(k)
            sev = (policy.get("taint") or {}).get("untrustedArgs") or "require-approval"
            if sev != "allow" and (kind in sensitive or kind in ("web", "other", "email-draft")):
                add(sev, "tainted-argument", '"' + t["arg"] + '" carries ' + (t["entity"] if t["kind"] == "phrase" else t["kind"] + " " + t["entity"]) + " taken from untrusted " + t["label"] + ".", t["arg"])
        flagged = taint.flagged_sources()
        if flagged and kind in sensitive:
            sev = (policy.get("taint") or {}).get("flaggedContext") or "require-approval"
            if sev != "allow":
                add(sev, "flagged-context", "Instruction-like text was found in " + ", ".join(f["label"] for f in flagged) + " this turn, so a " + kind + " action needs a person.")
    return finish()


def _spent_in(st: dict, tool: str, per, now: float) -> float:
    win = 3600e3 if per == "hour" else 86400e3 if per == "day" else math.inf
    total = 0
    for x in st["spend"].get(tool) or []:
        if now - x["t"] < win:
            total += x["amount"]
    return total


def record_call(st: dict, decision: dict, now: float | None = None) -> None:
    """Record that a call actually ran (for rate limits and budgets)."""
    now = time.time() * 1000 if now is None else now
    st["calls"].setdefault(decision["tool"], []).append(now)
    st["all"].append(now)
    if decision.get("amount") is not None and decision["amount"] > 0:
        st["spend"].setdefault(decision["tool"], []).append({"t": now, "amount": decision["amount"]})
