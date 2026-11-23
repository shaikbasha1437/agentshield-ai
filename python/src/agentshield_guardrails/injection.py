"""Prompt-injection and jailbreak detector (port of ``lib/injection.js``).

Rules are explainable regular expressions, each with a category, a weight and a reason, loaded from the same
rule table the JavaScript package uses. They run on several views of the text (look-alike letters folded,
invisible characters removed, leetspeak undone, letter spacing collapsed, base64/hex/rot13/reversed/URL-encoded
runs decoded, Unicode tag characters decoded, split payloads re-joined), and the weights combine into a 0-1 score.

This is a heuristic filter. It catches common, known phrasings; a determined attacker can paraphrase around it.
That is why the tool firewall and taint tracking exist: they stop the action even when detection misses."""
from __future__ import annotations

from ._data import rules
from ._jsre import compile_js, js_trim
from ._util import js_round3
from .normalize import TAG_RE, count_invisible, mixed_script_words, views

RULES = [
    {"id": r["id"], "cat": r["category"], "w": r["weight"], "re": compile_js(r["source"], r["flags"]), "why": r["why"]}
    for r in rules()["injection"]
]
_RULE_BY_ID = {r["id"]: r for r in RULES}
COMPACT = compile_js(rules()["compact"]["source"], rules()["compact"]["flags"])
DISCUSSION = compile_js(rules()["discussion"]["source"], rules()["discussion"]["flags"])
_DISC_STRIP = compile_js(r"https?:\/\/\S+|[\w.+-]+@[\w-]+(?:\.[\w-]+)+|\b[\w-]+(?:\.[\w-]+)*\.(?:example|test|invalid|localhost)\b", "gi")
_QUOTED = compile_js("\"[^\"\\n]{3,300}\"|'[^'\\n]{6,300}'|`[^`\\n]{3,300}`|```[\\s\\S]*?```|\\u201c[^\\u201d\\n]{3,300}\\u201d|\\u00ab[^\\u00bb\\n]{3,300}\\u00bb", "g")
FLAG_EMOJI_TAGS = compile_js(r"\u{1F3F4}[\u{E0061}-\u{E007A}]{2,7}\u{E007F}", "gu")
_PLAIN_SQ = compile_js(r"[‘’‚‛′`´]", "g")
_PLAIN_DQ = compile_js(r"[“”„‟″]", "g")
_PLAIN_DASH = compile_js(r"[‐‑‒–—―]", "g")
_PLAIN_WS = compile_js(r"[ \t\u00A0]+", "g")
_BIDI_OVERRIDE = compile_js(r"[\u202A-\u202E\u2066-\u2069]", "g")
_ZW_IN_WORD = compile_js(r"\p{L}[\u200B-\u200D\u2060\uFEFF\u00AD]+\p{L}", "u")
_EVASIVE_NOTE = compile_js(r"decoding|look-alike", "")
_SENT_SPLIT = compile_js(r"(?<=[.!?\u3002\uff01\uff1f])\s+|\n+", "")
_STRONG = ("override", "extraction", "jailbreak", "multilingual")


def _quoted_spans(t: str) -> list:
    return [(m.start(), m.end()) for m in _QUOTED.finditer(t)]


def _noisy_or(ws) -> float:
    p = 1
    for w in ws:
        p = p * (1 - max(0, min(1, w)))
    return 1 - p


def _canon_discussion_count(t: str) -> int:
    return sum(1 for _ in DISCUSSION.finditer(_DISC_STRIP.sub(" ", str(t))))


def detect(text, block: float = 0.7, flag: float = 0.4, source: str | None = None, decode: bool = True) -> dict:
    """Detect instruction-like text.

    ``block`` / ``flag`` are the score thresholds (default 0.7 / 0.4). ``source`` is ``'user'`` (default) or an
    untrusted source; untrusted content is held to a stricter standard because data should never address the
    model. Returns ``{score, verdict: 'allow'|'flag'|'block', hits: [...], signals: {...}}``."""
    raw = "" if text is None else str(text)
    block = 0.7 if block is None else block
    flag = 0.4 if flag is None else flag
    untrusted = bool(source) and source not in ("user", "system")
    if not js_trim(raw):
        return {"score": 0, "verdict": "allow", "hits": [], "signals": {}}
    vs = views(raw[:200000] if len(raw) > 200000 else raw, decode=decode)
    plain = _PLAIN_WS.sub(" ", _PLAIN_DASH.sub("-", _PLAIN_DQ.sub('"', _PLAIN_SQ.sub("'", raw.lower()))))
    best: dict = {}
    for v in vs:
        if v.get("compact"):
            continue
        for r in RULES:
            m = r["re"].search(v["text"])
            if not m:
                continue
            prev = best.get(r["id"])
            if not prev or (prev["obfuscated"] and not v["obfuscated"]):
                best[r["id"]] = {"rule": r["id"], "category": r["cat"], "weight": r["w"], "layer": v["layer"], "obfuscated": v["obfuscated"],
                                 "match": m.group(0)[:160], "index": m.start() if v["layer"] == "text" else -1, "why": r["why"]}
    cv = next((v for v in vs if v.get("compact")), None)
    if cv and not any(h["category"] in _STRONG for h in best.values()):
        m = COMPACT.search(cv["text"])
        if m:
            best["compact-signature"] = {"rule": "compact-signature", "category": "obfuscation", "weight": 0.7, "layer": "compact", "obfuscated": True,
                                         "match": m.group(0), "index": -1,
                                         "why": "A known attack phrase spelled out with spaces, dots or symbols between the letters."}
    hits: list = []
    disc = _canon_discussion_count(vs[0]["text"])
    qs = _quoted_spans(vs[0]["text"])
    signals: dict = {"discussion": disc}
    for h in best.values():
        eff = h["weight"]
        note = ""
        dampened = False
        if h["obfuscated"]:
            note = "found only after decoding (" + h["layer"] + ")"
        else:
            if not _RULE_BY_ID[h["rule"]]["re"].search(plain):
                note = "hidden with look-alike or invisible characters"
        if not h["obfuscated"] and disc >= 2:
            in_quote = h["index"] >= 0 and any(a <= h["index"] < b for a, b in qs)
            eff *= 0.2 if in_quote else 0.45
            dampened = True
            note = (note + "; " if note else "") + ("quoted inside text that discusses attacks (down-weighted)" if in_quote else "appears in text that discusses attacks (down-weighted)")
        if untrusted and h["category"] != "jailbreak" and not dampened:
            eff = min(0.95, eff * 1.2)
        hits.append({"rule": h["rule"], "category": h["category"], "weight": h["weight"], "effective": js_round3(eff), "layer": h["layer"],
                     "match": h["match"], "why": h["why"], "note": note, "dampened": dampened})
    no_flags = FLAG_EMOJI_TAGS.sub("", raw)
    inv = count_invisible(no_flags)
    tag_text = TAG_RE.findall(no_flags)
    if len(tag_text) >= 4:
        hits.append(_signal("unicode-tag-smuggling", 0.6, str(len(tag_text)) + " invisible tag characters", "Invisible Unicode tag characters can carry a hidden ASCII message."))
    bidi = len(_BIDI_OVERRIDE.findall(raw))
    if bidi:
        hits.append(_signal("bidi-control", 0.35, str(bidi) + " bidirectional override character(s)", "Bidirectional overrides make text display differently from how it is read."))
    if inv["zeroWidth"] >= 2 and _ZW_IN_WORD.search(raw):
        hits.append(_signal("zero-width-chars", 0.25, str(inv["zeroWidth"]) + " zero-width character(s) inside words", "Zero-width characters inside words are used to split keywords."))
    mixed = mixed_script_words(raw)
    if mixed:
        hits.append(_signal("mixed-script", 0.3, ", ".join(mixed[:3]), "Words that mix Latin with Cyrillic or Greek letters, a filter-evasion trick."))
    instr = [h for h in hits if h["category"] != "obfuscation"]
    evasive = [h for h in instr if _EVASIVE_NOTE.search(h["note"])]
    if evasive:
        hits.append({"rule": "evasion", "category": "obfuscation", "weight": 0.4, "effective": 0.4, "layer": evasive[0]["layer"],
                     "match": ", ".join(h["rule"] for h in evasive), "why": "An instruction was disguised; disguising instructions is itself a strong signal.", "note": "", "dampened": False})
    damp = [h for h in hits if h["dampened"]]
    full = [h for h in hits if not h["dampened"]]
    damp_score = min(1, max(h["effective"] for h in damp) + 0.05 * (len(damp) - 1)) if damp else 0
    score = js_round3(_noisy_or([h["effective"] for h in full] + ([damp_score] if damp_score else [])))
    hits.sort(key=lambda h: -h["effective"])
    verdict = "block" if score >= block else "flag" if score >= flag else "allow"
    signals.update({"invisible": inv, "views": len(vs)})
    return {"score": score, "verdict": verdict, "hits": hits, "signals": signals}


def _signal(rule, w, match, why):
    return {"rule": rule, "category": "obfuscation", "weight": w, "effective": w, "layer": "text", "match": match, "why": why, "note": "", "dampened": False}


def scan_sentences(text, block: float = 0.7, flag: float = 0.4, source: str | None = None) -> list:
    """Split text into sentences/lines and report the instruction-like ones (used to quarantine untrusted content)."""
    s = "" if text is None else str(text)
    out = []
    pos = 0
    for p in _SENT_SPLIT.split(s):
        idx = s.find(p, pos)
        if idx >= 0:
            pos = idx + len(p)
        if not js_trim(p):
            continue
        d = detect(p, block=block, flag=flag, source=source, decode=True)
        if d["verdict"] != "allow":
            out.append({"text": p, "index": idx, "score": d["score"], "verdict": d["verdict"], "hits": d["hits"]})
    return out


def explain(result: dict) -> str:
    if not result or not result.get("hits"):
        return "No instruction-like patterns found."
    return "\n".join(h["rule"] + " (" + _fmt(h["effective"]) + (", " + h["note"] if h.get("note") else "") + "): " + h["why"] for h in result["hits"][:6])


def _fmt(x) -> str:
    return str(int(x)) if float(x).is_integer() else repr(x)
