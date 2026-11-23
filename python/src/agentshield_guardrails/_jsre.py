"""Translate JavaScript regular expressions into Python ``re`` patterns with the same meaning.

The detection rules are written once, as JavaScript regular expressions, and exported to ``data/rules.json``.
This module compiles those sources for Python so both packages run the same rules. It handles the places where
the two dialects differ for the constructs the rules use:

* ``\\w``, ``\\d`` and ``\\b`` are ASCII-only in JavaScript, so patterns compile with ``re.ASCII``;
* ``\\s`` in JavaScript also matches Unicode spaces (and ``re.ASCII`` would drop them), so it is spelled out;
* ``.`` excludes ``\\n``, ``\\r``, U+2028 and U+2029 unless the ``s`` flag is set;
* ``$`` only matches at the very end unless the ``m`` flag is set (Python's also matches before a final newline);
* ``\\p{L}`` / ``\\p{N}`` (with the ``u`` flag) become explicit character classes built from ``unicodedata``;
* ``\\u{...}``, ``(?<name>...)`` and ``\\k<name>`` use Python's spelling.

Known, accepted differences: under the ``i`` flag only ASCII letters fold case (JavaScript also folds some
non-ASCII letters), lengths are counted in code points rather than UTF-16 units, and the Unicode tables follow
the running Python version.
"""
from __future__ import annotations

import functools
import re
import sys
import unicodedata

JS_WS = "\\t\\n\\x0b\\x0c\\r \\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
LINE_TERM = "\\n\\r\\u2028\\u2029"
_WS_CHARS = frozenset("\t\n\x0b\x0c\r \xa0\u1680\u2028\u2029\u202f\u205f\u3000\ufeff" + "".join(chr(c) for c in range(0x2000, 0x200B)))


def is_js_space(ch: str) -> bool:
    return ch in _WS_CHARS


def js_trim(s: str) -> str:
    """String.prototype.trim(): strips JavaScript whitespace and line terminators."""
    a, b = 0, len(s)
    while a < b and s[a] in _WS_CHARS:
        a += 1
    while b > a and s[b - 1] in _WS_CHARS:
        b -= 1
    return s[a:b]


def utf16_len(s: str) -> int:
    """JavaScript's String length (UTF-16 code units)."""
    return len(s) + sum(1 for ch in s if ord(ch) > 0xFFFF)


@functools.lru_cache(maxsize=None)
def _category_class(prefix: str) -> str:
    ranges = []
    start = None
    prev = None
    for cp in range(sys.maxunicode + 1):
        if unicodedata.category(chr(cp)).startswith(prefix):
            if start is None:
                start = cp
            prev = cp
        elif start is not None:
            ranges.append((start, prev))
            start = None
    if start is not None:
        ranges.append((start, prev))

    def esc(cp: int) -> str:
        return "\\U%08x" % cp

    return "".join(esc(a) if a == b else esc(a) + "-" + esc(b) for a, b in ranges)


def _prop_class(name: str) -> str:
    name = name.split("=")[-1]
    aliases = {"L": "L", "Letter": "L", "N": "N", "Number": "N", "Lu": "Lu", "Ll": "Ll", "Nd": "Nd"}
    if name not in aliases:
        raise ValueError("unsupported Unicode property \\p{%s}" % name)
    return _category_class(aliases[name])


class _Class:
    """A parsed [...] class: positive items (Python class syntax) and negated sub-classes."""

    def __init__(self) -> None:
        self.items: list[str] = []
        self.negated_parts: list[str] = []


def _translate(src: str, flags: str) -> str:
    out: list[str] = []
    i = 0
    n = len(src)
    unicode_mode = "u" in flags or "v" in flags
    dotall = "s" in flags
    multiline = "m" in flags

    def read_escape(j: int, in_class: bool):
        """Returns (kind, value, new_index). kind: 'item' (class/atom text), 'neg' (negated class body),
        'assert' (outside-class assertion text)."""
        c = src[j]
        if c in "dDwW":
            return "item", "\\" + c, j + 1
        if c == "s":
            return "body", JS_WS, j + 1
        if c == "S":
            return "neg", JS_WS, j + 1
        if c in "bB":
            if in_class:
                return "item", "\\x08" if c == "b" else "B", j + 1
            return "assert", "\\" + c, j + 1
        if c in "pP" and unicode_mode and j + 1 < n and src[j + 1] == "{":
            k = src.index("}", j)
            body = _prop_class(src[j + 2:k])
            return ("body" if c == "p" else "neg"), body, k + 1
        if c == "u":
            if unicode_mode and j + 1 < n and src[j + 1] == "{":
                k = src.index("}", j)
                return "item", "\\U%08x" % int(src[j + 2:k], 16), k + 1
            if j + 4 < n + 0 and re.fullmatch(r"[0-9a-fA-F]{4}", src[j + 1:j + 5] or ""):
                cp = int(src[j + 1:j + 5], 16)
                # a surrogate pair written as two \\u escapes (only meaningful in unicode mode)
                if 0xD800 <= cp <= 0xDBFF and src[j + 5:j + 7] == "\\u" and re.fullmatch(r"[0-9a-fA-F]{4}", src[j + 7:j + 11] or ""):
                    lo = int(src[j + 7:j + 11], 16)
                    if 0xDC00 <= lo <= 0xDFFF:
                        return "item", "\\U%08x" % (0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)), j + 11
                return "item", "\\u%04x" % cp, j + 5
            return "item", "u", j + 1
        if c == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", src[j + 1:j + 3] or ""):
            return "item", "\\x" + src[j + 1:j + 3].lower(), j + 3
        if c == "k" and not in_class and j + 1 < n and src[j + 1] == "<":
            k = src.index(">", j)
            return "assert", "(?P=%s)" % src[j + 2:k], k + 1
        if c.isdigit():
            if c == "0" and not (j + 1 < n and src[j + 1].isdigit()):
                return "item", "\\x00", j + 1
            k = j
            while k < n and src[k].isdigit():
                k += 1
            if in_class:
                return "item", "\\" + src[j:k], k
            return "assert", "\\" + src[j:k], k
        if c in "fnrtv":
            return "item", {"f": "\\x0c", "n": "\\n", "r": "\\r", "t": "\\t", "v": "\\x0b"}[c], j + 1
        if c == "c" and j + 1 < n and src[j + 1].isalpha():
            return "item", "\\x%02x" % (ord(src[j + 1]) % 32), j + 2
        # identity escape (punctuation, or a letter with no special meaning outside unicode mode)
        return "item", re.escape(c), j + 1

    while i < n:
        ch = src[i]
        if ch == "\\":
            kind, val, i = read_escape(i + 1, False)
            if kind == "item":
                out.append(val)
            elif kind == "body":
                out.append("[" + val + "]")
            elif kind == "neg":
                out.append("[^" + val + "]")
            else:
                out.append(val)
            continue
        if ch == "[":
            j = i + 1
            negate = False
            if j < n and src[j] == "^":
                negate = True
                j += 1
            cls = _Class()
            if j < n and src[j] == "]":
                # [] never matches, [^] matches anything
                out.append("(?s:.)" if negate else "(?!)")
                i = j + 1
                continue
            while j < n and src[j] != "]":
                c = src[j]
                if c == "\\":
                    kind, val, j = read_escape(j + 1, True)
                    if kind == "neg":
                        cls.negated_parts.append(val)
                    else:
                        cls.items.append(val)
                    continue
                if c in "[&~|" or (c == "-" and False):
                    cls.items.append("\\" + c)
                elif c == "^":
                    cls.items.append("\\^")
                else:
                    cls.items.append(c)
                j += 1
            i = j + 1
            body = "".join(cls.items)
            if not cls.negated_parts:
                out.append("[" + ("^" if negate else "") + body + "]")
            else:
                alts = ([("[" + body + "]")] if body else []) + ["[^" + p + "]" for p in cls.negated_parts]
                if not negate:
                    out.append("(?:" + "|".join(alts) + ")")
                else:
                    out.append("(?:" + "".join("(?!" + a + ")" for a in alts) + "(?s:.))")
            continue
        if ch == ".":
            out.append("(?s:.)" if dotall else "[^" + LINE_TERM + "]")
            i += 1
            continue
        if ch == "$":
            out.append("(?=[" + LINE_TERM + "]|\\Z)" if multiline else "\\Z")
            i += 1
            continue
        if ch == "^":
            out.append("(?:(?<=[" + LINE_TERM + "])|\\A)" if multiline else "\\A")
            i += 1
            continue
        if ch == "(" and src.startswith("(?<", i) and i + 3 < n and src[i + 3] not in "=!":
            out.append("(?P<")
            i += 3
            continue
        if ch == "{":
            m = re.match(r"\{\d+(,\d*)?\}", src[i:])
            if m:
                out.append(m.group(0))
                i += len(m.group(0))
            else:
                out.append("\\{")
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


@functools.lru_cache(maxsize=4096)
def compile_js(source: str, flags: str = "") -> re.Pattern:
    """Compile a JavaScript regex source and flag string (g, i, m, s, u, y are accepted)."""
    py_flags = re.ASCII
    if "i" in flags:
        py_flags |= re.IGNORECASE
    return re.compile(_translate(source, flags), py_flags)


def js_lower(s: str) -> str:
    """String.prototype.toLowerCase(). Python's str.lower() follows the same Unicode default mapping."""
    return s.lower()
