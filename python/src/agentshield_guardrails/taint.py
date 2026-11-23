"""Taint tracking (port of ``lib/taint.js``).

Text from untrusted sources (web pages, emails, documents, tool results, RAG chunks) is registered with its
provenance; text from the user and the system prompt is registered as trusted. When a tool call's arguments carry
an address, link, domain, account number, path or a long phrase that appeared only in untrusted content, that
argument is tainted: the call came, at least in part, from data the agent read rather than from its user."""
from __future__ import annotations

from ._jsre import compile_js, js_trim, utf16_len
from ._url import parse_url
from ._util import js_num_str

STOP = {"the", "a", "an", "and", "or", "to", "of", "in", "on", "for", "is", "it", "this", "that", "with", "be", "are", "as", "at", "by", "from"}
_TRAIL = compile_js(r"[.,;:!?)\]}'\"]+$", "")
_EMAIL = compile_js(r"\b[\w.%+-]+@[\w-]+(?:\.[\w-]+)+\b", "g")
_URL = compile_js(r"\bhttps?:\/\/[^\s<>\"'`)\]]+", "gi")
_URL_TRAIL = compile_js(r"[.,;:!?]+$", "")
_WWW = compile_js(r"^www\.", "")
_DOMAIN = compile_js(r"\b(?:[a-z0-9-]+\.)+(?:example|com|net|org|io|dev|app|ai|co|xyz|info|biz|ru|cn|tk|top|site|online|link)\b", "gi")
_IBAN = compile_js(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}\b", "g")
_ACCOUNT = compile_js(r"\b(?:acct|account|iban|wallet|routing)[\s#:_-]*([A-Za-z0-9-]{6,})\b", "gi")
_PATH = compile_js(r"(?:^|[\s\"'(=])((?:~|\.{1,2})?\/[\w.@-]+(?:\/[\w.@-]+)+)", "g")
_AMOUNT = compile_js(r"(?:\$|usd\s?|eur\s?|€)\s?(\d[\d,]*(?:\.\d{1,2})?)", "gi")
_CODE = compile_js(r"`([^`\n]{6,200})`", "g")
_SHINGLE_CLEAN = compile_js(r"[^\p{L}\p{N}@.\s-]", "gu")
_WS_SPLIT = compile_js(r"\s+", "")


def extract_entities(text) -> dict:
    s = "" if text is None else str(text)
    out: dict = {}

    def add(kind, v):
        k = _TRAIL.sub("", str(v).lower(), count=1)
        if utf16_len(k) >= 3 and k not in out:
            out[k] = kind

    for m in _EMAIL.finditer(s):
        add("email", m.group(0))
        add("domain", m.group(0).split("@")[1])
    for m in _URL.finditer(s):
        add("url", m.group(0))
        p = parse_url(_URL_TRAIL.sub("", m.group(0), count=1))
        if p is not None:
            add("domain", _WWW.sub("", p.hostname, count=1))
    for m in _DOMAIN.finditer(s):
        add("domain", m.group(0))
    for m in _IBAN.finditer(s):
        add("account", m.group(0).replace(" ", ""))
    for m in _ACCOUNT.finditer(s):
        add("account", m.group(1))
    for m in _PATH.finditer(s):
        add("path", m.group(1))
    for m in _AMOUNT.finditer(s):
        v = m.group(1).replace(",", "")
        if float(v) >= 100:
            add("amount", v)
    for m in _CODE.finditer(s):
        add("code", js_trim(m.group(1)))
    return out


def shingles(text, n: int = 7) -> dict:
    """Ordered set (dict keys) of n-word phrases, stop words removed."""
    t = _SHINGLE_CLEAN.sub(" ", ("" if text is None else str(text)).lower())
    w = [x for x in _WS_SPLIT.split(t) if x and x not in STOP]
    return dict.fromkeys(" ".join(w[i:i + n]) for i in range(len(w) - n + 1))


def _scalar_str(v):
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float)):
        return js_num_str(v)
    return None


def walk_strings(args, fn, path: str = "") -> None:
    """Calls fn(value, path) for every string or number inside args (as JavaScript's walkStrings does)."""
    if args is None:
        return
    s = _scalar_str(args)
    if s is not None:
        fn(s, path)
    elif isinstance(args, list):
        for i, x in enumerate(args):
            walk_strings(x, fn, path + "[" + str(i) + "]")
    elif isinstance(args, dict):
        for k, x in args.items():
            walk_strings(x, fn, path + "." + k if path else k)


class TaintTracker:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.trusted_text: list = []
        self.trusted: dict = {}
        self.trusted_grams: dict = {}
        self.sources: list = []

    def add_trusted(self, text) -> None:
        s = "" if text is None else str(text)
        self.trusted_text.append(s)
        for k, v in extract_entities(s).items():
            self.trusted[k] = v
        for g in shingles(s):
            self.trusted_grams[g] = None

    def add_untrusted(self, text, id: str | None = None, label: str | None = None, kind: str | None = None, flagged: bool = False) -> dict:
        s = "" if text is None else str(text)
        sid = id or "src-" + str(len(self.sources) + 1)
        src = {"id": sid, "label": label or sid, "kind": kind or "untrusted", "entities": extract_entities(s), "grams": shingles(s), "flagged": bool(flagged)}
        self.sources.append(src)
        return src

    def mark_flagged(self, sid: str) -> None:
        for s in self.sources:
            if s["id"] == sid:
                s["flagged"] = True
                return

    def flagged_sources(self) -> list:
        return [s for s in self.sources if s["flagged"]]

    def is_trusted_value(self, v) -> bool:
        k = str(v).lower()
        if k in self.trusted:
            return True
        return any(k in t.lower() for t in self.trusted_text)

    def check_value(self, value) -> list:
        v = "" if value is None else str(value)
        if not v or not self.sources:
            return []
        ents = extract_entities(v)
        out = []
        for k, kind in ents.items():
            if self.is_trusted_value(k):
                continue
            for s in self.sources:
                if k in s["entities"]:
                    out.append({"entity": k, "kind": kind, "source": s["id"], "label": s["label"]})
                    break
        if utf16_len(v) >= 40:
            n = 0
            src = None
            for x in shingles(v):
                if x in self.trusted_grams:
                    continue
                s = next((y for y in self.sources if x in y["grams"]), None)
                if s:
                    n += 1
                    src = src or s
            if n >= 2:
                out.append({"entity": str(n) + " phrase(s) copied from untrusted text", "kind": "phrase", "source": src["id"], "label": src["label"]})
        if utf16_len(v) < 200 and utf16_len(js_trim(v)) >= 4 and not ents:
            k = js_trim(v).lower()
            if not self.is_trusted_value(k):
                for s in self.sources:
                    if k in s["entities"]:
                        out.append({"entity": k, "kind": s["entities"][k], "source": s["id"], "label": s["label"]})
                        break
        return out

    def check_args(self, args) -> list:
        out: list = []

        def visit(v, path):
            for t in self.check_value(v):
                out.append(dict({"arg": path}, **t))

        walk_strings(args, visit)
        return out

    def to_json(self) -> dict:
        return {"trusted": len(self.trusted), "sources": [{"id": s["id"], "label": s["label"], "kind": s["kind"], "flagged": s["flagged"], "entities": len(s["entities"])} for s in self.sources]}
