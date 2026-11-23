"""Output guards (port of ``lib/output.js``): secret and PII redaction, system-prompt and canary leak detection,
data-exfiltration checks on URLs and Markdown images, link allowlisting and JSON-schema enforcement."""
from __future__ import annotations

import json
import math
import random

from ._data import rules
from ._jsre import compile_js, js_trim, utf16_len
from ._url import parse_url
from .normalize import decode_uri_component, nfkc, strip_invisible

DETECTORS = [
    {"kind": d["kind"], "label": d["label"], "re": compile_js(d["source"], d["flags"]), "value": d["value"], "check": d["check"]}
    for d in rules()["detectors"]
]
DEFAULT_REDACT: list = list(rules()["defaultRedact"])
_NON_DIGIT = compile_js(r"\D", "g")
_PLACEHOLDER = compile_js(r"^(?:\*+|x+|\[redacted[^\]]*\]|<[^>]+>|\$\{?\w+\}?|null|none|true|false|changeme|example|your[_-]?\w*)$", "i")
_SIX_DIGITS = compile_js(r"\d{6}", "")


def luhn(digits) -> bool:
    d = _NON_DIGIT.sub("", str(digits))
    if len(d) < 13 or len(d) > 19:
        return False
    total = 0
    alt = False
    for ch in reversed(d):
        n = ord(ch) - 48
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def _glob_source(g) -> str:
    s = str(g).lower()
    s = "".join("\\" + c if c in ".+^${}()|[]\\" else c for c in s)
    s = s.replace("**", "\x00").replace("*", "[^@/]*").replace("\x00", ".*").replace("?", ".")
    return "^" + s + "$"


def match_any(value, patterns) -> bool:
    v = str(value or "").lower()
    return any(compile_js(_glob_source(p), "").search(v) for p in (patterns or []))


def find_sensitive(text, kinds=None, allow_emails=None, allow_domains=None) -> list:
    """Find secrets and personal data. Returns ``[{kind, label, start, end, value}]``."""
    s = "" if text is None else str(text)
    ks = set(kinds if kinds is not None else DEFAULT_REDACT)
    out: list = []

    def taken(a, b):
        return any(a < x["end"] and b > x["start"] for x in out)

    for d in DETECTORS:
        if d["kind"] not in ks:
            continue
        for m in d["re"].finditer(s):
            start = m.start()
            val = m.group(0)
            if d["value"]:
                pre = m.group(1) + (m.group(2) or "")
                start = m.start() + len(pre)
                val = m.group(d["value"])
                if _PLACEHOLDER.search(val):
                    continue
            if d["check"] == "luhn" and not luhn(val):
                continue
            if d["kind"] == "email" and (match_any(val, allow_emails) or match_any(val.split("@")[1], allow_domains)):
                continue
            if d["kind"] == "phone" and len(_NON_DIGIT.sub("", val)) < 10:
                continue
            if d["kind"] == "iban" and not _SIX_DIGITS.search(val.replace(" ", "")):
                continue
            end = start + len(val)
            if taken(start, end):
                continue
            out.append({"kind": d["kind"], "label": d["label"], "start": start, "end": end, "value": val})
    return sorted(out, key=lambda x: x["start"])


def mask(kind: str, value) -> str:
    v = str(value)
    if kind == "card":
        return "[card \u2022\u2022\u2022\u2022" + _NON_DIGIT.sub("", v)[-4:] + "]"
    if kind == "email":
        u, d = v.split("@")[0], v.split("@")[1]
        return "[email " + u[:1] + "\u2026@" + d + "]"
    if kind == "phone":
        return "[phone \u2022\u2022\u2022" + _NON_DIGIT.sub("", v)[-2:] + "]"
    return "[" + kind.replace("_", " ") + " redacted]"


def redact(text, kinds=None, allow_emails=None, allow_domains=None, secrets=None, style: str | None = None) -> dict:
    """Redact in place. Returns ``{text, redactions: [{kind, label, preview}]}`` (previews never hold the value)."""
    s = "" if text is None else str(text)
    found = find_sensitive(s, kinds=kinds, allow_emails=allow_emails, allow_domains=allow_domains)
    parts = []
    pos = 0
    for f in found:
        parts.append(s[pos:f["start"]] + ("[" + f["kind"] + "]" if style == "kind" else mask(f["kind"], f["value"])))
        pos = f["end"]
    parts.append(s[pos:])
    out = "".join(parts)
    for sec in secrets or []:
        if sec and len(sec) >= 6:
            out = out.replace(sec, "[your key redacted]")
    return {"text": out, "redactions": [{"kind": f["kind"], "label": f["label"], "preview": mask(f["kind"], f["value"])} for f in found]}


def make_canary(rand=None) -> str:
    r = rand or random.random
    a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "CANARY-" + "".join(a[math.floor(r() * len(a))] for _ in range(10))


_NON_WORD = compile_js(r"[^\p{L}\p{N}\s]", "gu")
_WS_SPLIT = compile_js(r"\s+", "")
_SQUASH = compile_js(r"[\s\-_.\u200B-\u200D]", "g")
_DASH_US = compile_js(r"[-_]", "g")


def _words(s) -> list:
    t = _NON_WORD.sub(" ", nfkc(strip_invisible(str(s or "")).lower()))
    return [w for w in _WS_SPLIT.split(t) if w]


def leak_check(output, canaries=None, system_prompt: str | None = None) -> list:
    """Did the output reveal the system prompt? Checks canary tokens (also with separators stripped) and 8-word overlaps."""
    out = "" if output is None else str(output)
    findings = []
    squashed = _SQUASH.sub("", out).upper()
    for c in canaries or []:
        if not c:
            continue
        if c in out:
            findings.append({"kind": "canary", "detail": "output contains the canary token " + c[:9] + "\u2026"})
        elif _DASH_US.sub("", c).upper() in squashed:
            findings.append({"kind": "canary", "detail": "output contains the canary token with separators inserted"})
        elif c[::-1] in out:
            findings.append({"kind": "canary", "detail": "output contains the canary token reversed"})
    if system_prompt:
        sp = _words(system_prompt)
        ow = _words(out)
        n = 8
        if len(sp) >= n and len(ow) >= n:
            grams = {" ".join(sp[i:i + n]) for i in range(len(sp) - n + 1)}
            hit = 0
            seen: set = set()
            for i in range(len(ow) - n + 1):
                g = " ".join(ow[i:i + n])
                if g in grams and g not in seen:
                    hit += 1
                    seen.add(g)
            coverage = hit / max(1, len(grams))
            if hit >= 2 or coverage >= 0.25:
                findings.append({"kind": "system-prompt", "detail": str(hit) + " eight-word passage(s) of the system prompt appear in the output (" + str(math.floor(coverage * 100 + 0.5)) + "% of it)"})
    return findings


def _entropy(s: str) -> float:
    f: dict = {}
    for c in s:
        f[c] = f.get(c, 0) + 1
    n = utf16_len(s)
    h = 0.0
    for k in f:
        p = f[k] / n
        h -= p * math.log2(p)
    return h


_MD_IMAGE = compile_js(r"!\[([^\]]*)\]\(\s*<?([^)\s>]+)>?[^)]*\)", "g")
_MD_LINK = compile_js(r"(?<!!)\[([^\]]*)\]\(\s*<?([^)\s>]+)>?[^)]*\)", "g")
_HTML_IMG = compile_js(r"<img\b[^>]*\bsrc\s*=\s*[\"']?([^\"'\s>]+)", "gi")
_HTML_A = compile_js(r"<a\b[^>]*\bhref\s*=\s*[\"']?([^\"'\s>]+)", "gi")
_BARE = compile_js(r"\b(?:https?|ftp|javascript|data|file):[^\s<>\"'`)\]]+", "gi")
_TRAIL_PUNCT = compile_js(r"[.,;:!?]+$", "")


def extract_urls(text) -> list:
    s = "" if text is None else str(text)
    out = []
    for m in _MD_IMAGE.finditer(s):
        out.append({"url": m.group(2), "kind": "markdown-image", "index": m.start(), "raw": m.group(0)})
    for m in _MD_LINK.finditer(s):
        out.append({"url": m.group(2), "kind": "markdown-link", "index": m.start(), "raw": m.group(0), "text": m.group(1)})
    for m in _HTML_IMG.finditer(s):
        out.append({"url": m.group(1), "kind": "html-image", "index": m.start(), "raw": m.group(0)})
    for m in _HTML_A.finditer(s):
        out.append({"url": m.group(1), "kind": "html-link", "index": m.start(), "raw": m.group(0)})
    covered = [(u["index"], u["index"] + len(u["raw"])) for u in out]
    for m in _BARE.finditer(s):
        if any(a <= m.start() < b for a, b in covered):
            continue
        out.append({"url": _TRAIL_PUNCT.sub("", m.group(0)), "kind": "bare", "index": m.start(), "raw": m.group(0)})
    return out


_WWW = compile_js(r"^www\.", "")


def host_allowed(host, allow) -> bool:
    return match_any(_WWW.sub("", str(host or ""), count=1), allow) or match_any(host, allow)


_SCHEME_START = compile_js(r"^\w+:", "")
_RELATIVE = compile_js(r"^(\/|\.|#)", "")
_AT = compile_js(r"@", "")
_IP_HOST = compile_js(r"^\d+\.\d+\.\d+\.\d+$|^\[", "")
_PUNY = compile_js(r"(^|\.)xn--", "")
_ALPHA_DASH_I = compile_js(r"^[a-z-]+$", "i")
_TEMPLATED = compile_js(r"\{[^}]*\}|%7b", "i")
_URL_SENSITIVE_KINDS = ["api_key", "jwt", "card", "ssn", "email", "phone", "secret_assignment", "private_key"]


def _decode_safe(s) -> str:
    try:
        return decode_uri_component(str(s).replace("+", " "))
    except ValueError:
        return str(s)


def check_urls(text, allow_domains=None, allow_emails=None, link_action: str | None = None, sensitive=None) -> list:
    """Check each URL: scheme, allowlist, look-alike hosts, and data smuggled into the query or path.
    Returns ``[{url, kind, host, issues: [{code, severity: 'block'|'flag', detail}]}]``."""
    allow = allow_domains or []
    sens_ctx = sensitive or []
    results = []
    for u in extract_urls(text):
        issues: list = []
        r = dict(u)

        def add(code, severity, detail):
            issues.append({"code": code, "severity": severity, "detail": detail})

        p = parse_url(u["url"])
        if not p:
            if not _SCHEME_START.search(u["url"]) and _RELATIVE.search(u["url"]):
                r["issues"] = issues
                results.append(r)
                continue
            add("bad-url", "flag", "not a valid absolute URL")
            r["issues"] = issues
            results.append(r)
            continue
        scheme = p.protocol.replace(":", "", 1)
        if scheme in ("javascript", "data", "file", "vbscript"):
            add("unsafe-scheme", "block", scheme + ": links can run code or read local files")
        host = p.hostname.lower()
        parts = u["url"].split("/")
        if p.username or p.password or _AT.search(parts[2] if len(parts) > 2 else ""):
            add("userinfo-trick", "block", 'the part before "@" hides the real host (' + host + ")")
        if _IP_HOST.search(host):
            add("ip-host", "flag", "raw IP address instead of a domain")
        if _PUNY.search(host):
            add("punycode", "flag", "internationalised (punycode) host, can imitate another domain")
        allowed = not allow or not host or host_allowed(host, allow)
        image = u["kind"].endswith("image")
        if not allowed:
            add("image-unknown-domain" if image else "domain-not-allowed", "block" if image else ("block" if link_action == "block" else "flag"),
                host + " is not on the allowlist" + ("; images load automatically, so their URL can carry data out with no click" if image else ""))
        q = (p.search or "") + (p.hash or "")
        path = p.pathname or ""
        vals = [v for _, v in p.search_params]
        segs = [x for x in path.split("/") if x]
        data_like = [v for v in vals + segs if utf16_len(v) >= 24 and _entropy(v) >= 3.6 and not _ALPHA_DASH_I.search(v)]
        sens = find_sensitive(_decode_safe(q + " " + path), kinds=_URL_SENSITIVE_KINDS, allow_emails=allow_emails, allow_domains=allow)
        decoded_url = _decode_safe(u["url"]).lower()
        contains_known = [x for x in sens_ctx if x and utf16_len(x) >= 4 and str(x).lower() in decoded_url]
        if sens:
            labels = list(dict.fromkeys(x["label"] for x in sens))
            add("url-carries-sensitive", "block", "URL contains " + ", ".join(labels))
        if contains_known:
            add("url-carries-context", "block", "URL contains text from the conversation or tools (" + str(len(contains_known)) + " match" + ("es" if len(contains_known) > 1 else "") + ")")
        if _TEMPLATED.search(u["url"]):
            add("templated-url", "block", "URL has a {placeholder} for data")
        if not allowed and (data_like or utf16_len(q) > 120):
            add("url-with-data", "block", "query or path carries a long encoded value to an unknown domain")
        r["host"] = host
        r["issues"] = issues
        results.append(r)
    return results


def _js_type(value) -> str:
    if isinstance(value, list):
        return "array"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) or (isinstance(value, float) and value.is_integer()):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, dict):
        return "object"
    return "undefined"


def _jstr(v) -> str:
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def validate_schema(value, schema, path: str = "$") -> list:
    errs: list = []
    if not isinstance(schema, dict):
        return errs
    t = _js_type(value)
    if schema.get("type"):
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(x == t or (x == "number" and t == "integer") for x in types):
            errs.append(path + ": expected " + "|".join(types) + ", got " + t)
            return errs
    if schema.get("enum") and not any(_jstr(e) == _jstr(value) for e in schema["enum"]):
        errs.append(path + ": must be one of " + ", ".join(_jstr(e) for e in schema["enum"]))
    if "const" in schema and _jstr(schema["const"]) != _jstr(value):
        errs.append(path + ": must equal " + _jstr(schema["const"]))
    if isinstance(value, str):
        if schema.get("maxLength") is not None and utf16_len(value) > schema["maxLength"]:
            errs.append(path + ": longer than " + str(schema["maxLength"]))
        if schema.get("minLength") is not None and utf16_len(value) < schema["minLength"]:
            errs.append(path + ": shorter than " + str(schema["minLength"]))
        if schema.get("pattern") and not compile_js(schema["pattern"], "").search(value):
            errs.append(path + ": does not match " + schema["pattern"])
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if schema.get("maximum") is not None and value > schema["maximum"]:
            errs.append(path + ": above " + str(schema["maximum"]))
        if schema.get("minimum") is not None and value < schema["minimum"]:
            errs.append(path + ": below " + str(schema["minimum"]))
    if t == "object":
        for k in schema.get("required") or []:
            if k not in value:
                errs.append(path + ': missing required "' + k + '"')
        props = schema.get("properties") or {}
        for k, v in value.items():
            if props.get(k):
                errs.extend(validate_schema(v, props[k], path + "." + k))
            elif schema.get("additionalProperties") is False:
                errs.append(path + ': unexpected property "' + k + '"')
    if t == "array":
        if schema.get("maxItems") is not None and len(value) > schema["maxItems"]:
            errs.append(path + ": more than " + str(schema["maxItems"]) + " items")
        if schema.get("minItems") is not None and len(value) < schema["minItems"]:
            errs.append(path + ": fewer than " + str(schema["minItems"]) + " items")
        if schema.get("items"):
            for i, v in enumerate(value):
                errs.extend(validate_schema(v, schema["items"], path + "[" + str(i) + "]"))
    return errs


_FENCE = compile_js(r"^```(?:json)?\s*([\s\S]*?)\s*```$", "i")


def _reject_constant(name):
    raise ValueError("Unexpected token " + name)


def enforce_schema(text, schema) -> dict:
    """Parse model output as JSON (tolerating a ```json fence) and validate it. Returns ``{ok, value, errors}``."""
    s = js_trim("" if text is None else str(text))
    m = _FENCE.search(s)
    body = m.group(1) if m else s
    try:
        value = json.loads(body, parse_constant=_reject_constant)
    except ValueError as e:
        return {"ok": False, "value": None, "errors": ["output is not valid JSON: " + str(e).split(":")[0]]}
    errors = validate_schema(value, schema)
    return {"ok": not errors, "value": value, "errors": errors}
