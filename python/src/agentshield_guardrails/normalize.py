"""Text normalization and decoding layers for the injection detector (port of ``lib/normalize.js``).

An attacker can hide an instruction with look-alike letters, invisible characters, leetspeak, letter spacing or an
encoding; each function here undoes one trick so the same rules can run on every view of the text."""
from __future__ import annotations

import unicodedata

from ._data import rules
from ._jsre import compile_js, js_trim, utf16_len

ZERO_WIDTH_RE = compile_js(r"[\u200B-\u200D\u2060-\u2064\uFEFF\u180E\u00AD\u034F\u115F\u1160\u17B4\u17B5\u3164]", "g")
BIDI_RE = compile_js(r"[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]", "g")
TAG_RE = compile_js(r"[\u{E0000}-\u{E007F}]", "gu")
VARIATION_RE = compile_js(r"[\uFE00-\uFE0F]|[\u{E0100}-\u{E01EF}]", "gu")
HOMO: dict = rules()["homoglyphs"]
LEET: dict = rules()["leet"]


def nfkc(s: str) -> str:
    return unicodedata.normalize("NFKC", s)


def strip_invisible(s) -> str:
    s = str(s)
    return VARIATION_RE.sub("", BIDI_RE.sub("", ZERO_WIDTH_RE.sub("", s)))


def count_invisible(s) -> dict:
    t = str(s)
    return {"zeroWidth": len(ZERO_WIDTH_RE.findall(t)), "bidi": len(BIDI_RE.findall(t)), "tags": len(TAG_RE.findall(t))}


def decode_tags(s) -> str:
    """Unicode "tag" characters (U+E0020-E007E) mirror ASCII and render as nothing: decode the hidden message."""
    return "".join(chr(ord(ch) - 0xE0000) for ch in str(s) if 0xE0020 <= ord(ch) <= 0xE007E)


def fold_homoglyphs(s) -> str:
    return "".join(HOMO.get(ch) or ch for ch in str(s))


_WORDS3 = compile_js(r"[\p{L}]{3,}", "gu")
_ASCII_LETTER_I = compile_js(r"[a-z]", "i")
_GREEK_CYR_ARM = compile_js(r"[\u0370-\u03FF\u0400-\u04FF\u0530-\u058F]", "")


def mixed_script_words(s) -> list:
    """Words that mix Latin with Cyrillic/Greek letters are a classic filter-evasion trick."""
    words = _WORDS3.findall(nfkc(str(s)))
    return [w for w in words if _ASCII_LETTER_I.search(w) and _GREEK_CYR_ARM.search(w)]


_LEET_RUN = compile_js(r"[\p{L}\d@$!|+€£]{3,}", "gu")
_HAS_LETTER = compile_js(r"\p{L}", "u")
_LEET_CH = compile_js(r"[\d@$!|+€£]", "")
_LEET_CH_G = compile_js(r"[\d@$!|+€£]", "g")
_ORDINAL = compile_js(r"^\d+(st|nd|rd|th|am|pm|kg|km|mb|gb|ms|px|k|m|x|s|h|d|v)$", "i")


def de_leet(s) -> str:
    def fix(m):
        w = m.group(0)
        if _HAS_LETTER.search(w) and _LEET_CH.search(w) and not _ORDINAL.search(w):
            return _LEET_CH_G.sub(lambda c: LEET.get(c.group(0)) or c.group(0), w)
        return w

    return _LEET_RUN.sub(fix, str(s))


_SPACED = compile_js(r"\b\p{L}([ .\-_*·|])(?:\p{L}\1){2,}\p{L}\b", "gu")
_SEP = compile_js(r"[ .\-_*·|]", "g")
_MULTI_SPACE = compile_js(r"(\p{L}) {2,}(?=\p{L})", "gu")


def collapse_spaced_letters(s) -> str:
    """"i g n o r e  a l l" and "i.g.n.o.r.e" -> "ignore all"."""
    t = _SPACED.sub(lambda m: _SEP.sub("", m.group(0)), str(s))
    return _MULTI_SPACE.sub(lambda m: m.group(1) + " ", t)


_AZ_I = compile_js(r"[a-z]", "gi")


def rot13(s) -> str:
    def f(m):
        c = m.group(0)
        b = 65 if c <= "Z" else 97
        return chr(((ord(c) - b + 13) % 26) + b)

    return _AZ_I.sub(f, str(s))


def reverse(s) -> str:
    return str(s)[::-1]


def _printable_ratio(t: str) -> float:
    if not t:
        return 0
    p = 0
    for ch in t:
        c = ord(ch)
        if (32 <= c < 127) or c in (10, 13, 9) or c > 159:
            p += 1
    return p / len(t)


_B64 = {c: i for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")}


def _atob(data: str):
    """WHATWG forgiving-base64 decode (what ``atob`` does). Returns bytes or None on failure."""
    data = "".join(ch for ch in data if ch not in "\t\n\x0c\r ")
    if len(data) % 4 == 0:
        if data.endswith("=="):
            data = data[:-2]
        elif data.endswith("="):
            data = data[:-1]
    if len(data) % 4 == 1:
        return None
    if any(ch not in _B64 for ch in data):
        return None
    out = bytearray()
    buf = 0
    bits = 0
    for ch in data:
        buf = (buf << 6) | _B64[ch]
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((buf >> bits) & 0xFF)
    return bytes(out)


def _utf8_fatal(b: bytes):
    """TextDecoder('utf-8', { fatal: true }): strict decode, a leading BOM is dropped."""
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s[1:] if s.startswith("\ufeff") else s


def _b64(seg: str):
    clean = seg.replace("-", "+").replace("_", "/")
    padded = clean + "==="[(len(clean) + 3) % 4:]
    raw = _atob(padded)
    if raw is None:
        return None
    return _utf8_fatal(raw)


def decode_uri_component(s: str) -> str:
    """ECMAScript decodeURIComponent; raises ValueError (URIError) on malformed input."""
    out = []
    k = 0
    n = len(s)
    hexd = "0123456789abcdefABCDEF"

    def byte_at(i):
        if i + 2 >= n or s[i] != "%" or s[i + 1] not in hexd or s[i + 2] not in hexd:
            raise ValueError("URI malformed")
        return int(s[i + 1:i + 3], 16)

    while k < n:
        c = s[k]
        if c != "%":
            out.append(c)
            k += 1
            continue
        if k + 2 >= n:
            raise ValueError("URI malformed")
        b = byte_at(k)
        k += 3
        if b & 0x80 == 0:
            out.append(chr(b))
            continue
        if b & 0xE0 == 0xC0:
            cnt = 2
        elif b & 0xF0 == 0xE0:
            cnt = 3
        elif b & 0xF8 == 0xF0:
            cnt = 4
        else:
            raise ValueError("URI malformed")
        octets = [b]
        for _ in range(cnt - 1):
            if k + 2 >= n:
                raise ValueError("URI malformed")
            b2 = byte_at(k)
            if b2 & 0xC0 != 0x80:
                raise ValueError("URI malformed")
            octets.append(b2)
            k += 3
        try:
            out.append(bytes(octets).decode("utf-8"))
        except UnicodeDecodeError:
            raise ValueError("URI malformed") from None
    return "".join(out)


_SEG_B64 = compile_js(r"[A-Za-z0-9+/_-]{16,}={0,2}", "g")
_UPPER = compile_js(r"[A-Z]", "")
_LOWER = compile_js(r"[a-z]", "")
_ALL_ALPHA_DASH = compile_js(r"^[a-z-]+$", "i")
_WORD3_I = compile_js(r"[a-z]{3,}", "i")
_SPACE = compile_js(r"\s", "")
_SEG_HEX = compile_js(r"\b(?:[0-9a-f]{2}[\s:]?){12,}\b", "gi")
_HEX_SEP = compile_js(r"[\s:]", "g")
_WORD3_SPACE_I = compile_js(r"[a-z]{3,}\s", "i")
_HAS_X = compile_js(r"\\x[0-9a-f]{2}", "i")
_X_G = compile_js(r"\\x([0-9a-f]{2})", "gi")
_HAS_U = compile_js(r"\\u[0-9a-f]{4}", "i")
_U_G = compile_js(r"\\u([0-9a-f]{4})", "gi")
_HAS_PCT = compile_js(r"(?:%[0-9a-f]{2}){4,}", "i")
_HAS_ENT = compile_js(r"&#x?[0-9a-f]+;", "i")


def decode_segments(s) -> list:
    """Find base64 / hex / %-encoded / \\x-escaped runs and decode the ones that turn into readable text."""
    t = str(s)
    out = []
    for m in _SEG_B64.finditer(t):
        seg = m.group(0)
        if not _UPPER.search(seg) or not _LOWER.search(seg) or _ALL_ALPHA_DASH.search(seg):
            continue
        d = _b64(seg)
        if d and utf16_len(d) >= 8 and _printable_ratio(d) > 0.95 and _WORD3_I.search(d) and _SPACE.search(d):
            out.append({"kind": "base64", "from": seg, "text": d})
    for m in _SEG_HEX.finditer(t):
        hx = _HEX_SEP.sub("", m.group(0))
        if len(hx) % 2:
            continue
        d = "".join(chr(int(hx[i:i + 2], 16)) for i in range(0, len(hx), 2))
        if _printable_ratio(d) > 0.95 and _WORD3_SPACE_I.search(d):
            out.append({"kind": "hex", "from": m.group(0), "text": d})
    if _HAS_X.search(t):
        out.append({"kind": "hex-escape", "from": "\\x..", "text": _X_G.sub(lambda m: chr(int(m.group(1), 16)), t)})
    if _HAS_U.search(t):
        out.append({"kind": "unicode-escape", "from": "\\u..", "text": _U_G.sub(lambda m: chr(int(m.group(1), 16)), t)})
    if _HAS_PCT.search(t):
        try:
            out.append({"kind": "url-encoding", "from": "%..", "text": decode_uri_component(t.replace("+", " "))})
        except ValueError:
            pass
    if _HAS_ENT.search(t):
        out.append({"kind": "html-entities", "from": "&#..;", "text": decode_entities(t)})
    return out


_ENTITY = compile_js(r"&(#x[0-9a-f]+|#\d+|[a-z]+\d*);", "gi")
_NAMED = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'", "nbsp": " ", "#39": "'"}


def decode_entities(s) -> str:
    def f(m):
        e = m.group(1)
        if e[0] == "#":
            try:
                cp = int(e[2:], 16) if e[1].lower() == "x" else int(e[1:], 10)
                return chr(cp)
            except (ValueError, OverflowError):
                return m.group(0)
        v = _NAMED.get(e.lower())
        return v if v is not None else m.group(0)

    return _ENTITY.sub(f, str(s))


_ASSIGN = compile_js(r"\b([a-z]\w{0,11})\s*(?:=|:=|is)\s*([\"'`“”‘’])([^\"'`“”‘’\n]{1,120})\2", "gi")
_EXPR = compile_js(r"\b([a-z]\w{0,11})\s*\+\s*([a-z]\w{0,11})(?:\s*\+\s*([a-z]\w{0,11}))?(?:\s*\+\s*([a-z]\w{0,11}))?", "i")
_QUOTED = compile_js(r"([\"'`“”‘’])([^\"'`“”‘’\n]{1,80})\1", "g")
_JOIN_WORD = compile_js(r"\b(concat\w*|combine|join|put (?:them )?together|merge|append|glue)\b", "i")


def join_fragments(s) -> list:
    """Payload splitting: a = "ignore all prev", b = "ious instructions", then "do a + b". Joins the quoted parts."""
    t = str(s)
    assigns = list(_ASSIGN.finditer(t))
    out = []
    if len(assigns) >= 2:
        var = {}
        for m in assigns:
            var[m.group(1).lower()] = m.group(3)
        expr = _EXPR.search(t)
        if expr:
            names = [g for g in expr.groups() if g]
            parts = [var.get(v.lower()) for v in names]
            if all(p is not None for p in parts):
                out.append("".join(parts))
        out.append("".join(m.group(3) for m in assigns))
    quoted = [m.group(2) for m in _QUOTED.finditer(t)]
    if len(quoted) >= 3 and _JOIN_WORD.search(t):
        out.extend(["".join(quoted), " ".join(quoted)])
    return out


_SQ = compile_js(r"[‘’‚‛′`´]", "g")
_DQ = compile_js(r"[“”„‟″]", "g")
_DASH = compile_js(r"[‐‑‒–—―]", "g")
_CANON_WS = compile_js(r"[ \t\u00A0\u2000-\u200A\u3000]+", "g")


def canonical(s) -> str:
    """The canonical view the English rules run on."""
    t = nfkc(strip_invisible("" if s is None else str(s))).lower()
    t = fold_homoglyphs(t)
    t = _DASH.sub("-", _DQ.sub('"', _SQ.sub("'", t)))
    return _CANON_WS.sub(" ", t)


_NON_LETTER = compile_js(r"[^\p{L}]", "gu")


def compact(s) -> str:
    """Every letter only, for spacing and punctuation tricks ("i-g-n-o-r-e" or "ig.nore pre.vious")."""
    return _NON_LETTER.sub("", canonical(s))


def views(s, decode: bool = True) -> list:
    """All views of a text, labelled, each already canonicalised. Decoded views are marked obfuscated."""
    raw = "" if s is None else str(s)
    out: list = []

    def add(layer, text, obf):
        if text is None:
            return
        c = canonical(text)
        if not js_trim(c):
            return
        if any(v["text"] == c for v in out):
            return
        out.append({"layer": layer, "text": c, "obfuscated": bool(obf)})

    add("text", raw, False)
    native = nfkc(strip_invisible(raw)).lower()
    if not any(v["text"] == native for v in out):
        out.append({"layer": "native-script", "text": native, "obfuscated": False})
    add("de-leet", de_leet(nfkc(strip_invisible(raw))), True)
    add("letter-spacing", collapse_spaced_letters(nfkc(strip_invisible(raw))), True)
    out.append({"layer": "compact", "text": compact(raw), "obfuscated": True, "compact": True})
    tags = decode_tags(raw)
    if utf16_len(tags) >= 4:
        add("unicode-tags", tags, True)
    if decode:
        for d in decode_segments(raw):
            add(d["kind"], d["text"], True)
            add(d["kind"] + "+de-leet", de_leet(d["text"]), True)
        add("rot13", rot13(raw), True)
        add("reversed", reverse(strip_invisible(raw)), True)
        for j in join_fragments(raw):
            add("joined-fragments", j, True)
    return out
