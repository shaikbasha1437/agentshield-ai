"""Hidden-text detection for untrusted HTML, Markdown and plain text (port of ``lib/hidden.js``).

People see the rendered page; a model reads the source. Anything a person would not see (comments, CSS-hidden or
white text, off-screen boxes, alt/title/aria text, invisible characters, Unicode tag smuggling, link-reference
comments) is pulled out and reported, so the guard can strip or inspect it. A regex scanner, not a browser."""
from __future__ import annotations

from ._data import rules
from ._jsre import compile_js, js_trim
from .normalize import count_invisible, decode_entities, decode_tags, strip_invisible

HIDE_STYLE = [(compile_js(r["source"], r["flags"]), r["label"]) for r in rules()["hideStyle"]]
WHITE = compile_js(rules()["white"]["source"], rules()["white"]["flags"])
TRANSPARENT = compile_js(rules()["transparent"]["source"], rules()["transparent"]["flags"])

_BG = compile_js(r"background(?:-color)?\s*:\s*([^;\"']+)", "i")
_COLOR = compile_js(r"(?:^|[;\s\"'])color\s*:\s*([^;\"']+)", "i")
_H2T_BLOCKS = compile_js(r"<(script|style|noscript|template)\b[\s\S]*?<\/\1>", "gi")
_COMMENT = compile_js(r"<!--[\s\S]*?-->", "g")
_COMMENT_CAP = compile_js(r"<!--([\s\S]*?)-->", "g")
_BR = compile_js(r"<br\s*\/?>", "gi")
_BLOCK_END = compile_js(r"<\/(p|div|li|h\d|tr|section|article)>", "gi")
_TAG = compile_js(r"<[^>]+>", "g")
_SP_TAB = compile_js(r"[ \t]+", "g")
_BLANK_LINES = compile_js(r"\n\s*\n+", "g")
_LOOKS_HTML = compile_js(r"<\/?(html|body|div|span|p|a|img|section|article|table|li|ul|h\d|meta|br|font|style|script)\b[^>]*>", "i")
_LOOKS_MD = compile_js(r"!\[[^\]]*\]\(|\[[^\]]+\]\(|^#{1,6}\s", "m")
_FLAG_TAGS = compile_js(r"\u{1F3F4}[\u{E0061}-\u{E007A}]{2,7}\u{E007F}", "gu")
_WS_RUN = compile_js(r"\s+", "g")
_SCRIPTS = compile_js(r"<(script|noscript|template)\b[^>]*>([\s\S]*?)<\/\1>", "gi")
_THREE_WORDS = compile_js(r"[a-z]{3,}\s+[a-z]{3,}\s+[a-z]{3,}", "i")
_STARTS_CODE = compile_js(r"^\s*[{[(]", "")
_CODE_HINT = compile_js(r"function|=>|var |const |let |\(\)", "")
_META = compile_js(r"<meta\b[^>]*\bcontent\s*=\s*(\"([^\"]*)\"|'([^']*)')[^>]*>", "gi")
_SPLIT_WS = compile_js(r"\s+", "")
_FONT_WHITE = compile_js(r"<font\b[^>]*color\s*=\s*[\"']?(#?f{3}\b|#?f{6}\b|white)[^>]*>([\s\S]*?)<\/font>", "gi")
_FONT_WHITE_STRIP = compile_js(r"<font\b[^>]*color\s*=\s*[\"']?(#?f{3}\b|#?f{6}\b|white)[^>]*>[\s\S]*?<\/font>", "gi")
_ATTRS = compile_js(r"\b(alt|title|aria-label|data-[\w-]+|placeholder)\s*=\s*(\"([^\"]{20,})\"|'([^']{20,})')", "gi")
_IMG_SRC = compile_js(r"<img\b[^>]*\bsrc\s*=\s*[\"']?([^\"'\s>]+)", "gi")
_QUERY_DATA = compile_js(r"[?&][^=]+=[^&]{12,}", "")
_MD_COMMENT = compile_js(r"^\s*\[(?:\/\/|comment|_)\]:\s*(?:#|<>)?\s*[(\"']([^)\"']+)[)\"']", "gim")
_MD_IMG = compile_js(r"!\[([^\]]*)\]\(\s*<?([^)\s>]+)>?(?:\s+[\"']([^\"']*)[\"'])?\s*\)", "g")
_MD_QUERY_DATA = compile_js(r"[?&][^=]+=[^&)]{12,}", "")
_BRACES = compile_js(r"\{[^}]*\}", "")
_INLINE_HIDDEN = compile_js(r"<(span|div|p|font)\b([^>]*)>([\s\S]*?)<\/\1>", "gi")
_MD_COMMENT_LINE = compile_js(r"^\s*\[(?:\/\/|comment|_)\]:.*$", "gim")
_ELEMENT = compile_js(r"<(\/?)([a-zA-Z][\w-]*)\b([^>]*?)(\/?)>", "g")
_STYLE_ATTR = compile_js(r"\bstyle\s*=\s*(?:\"([^\"]*)\"|'([^']*)')", "i")
_ATTR_PAIRS = compile_js(r"\b[\w-]+\s*=\s*(\"[^\"]*\"|'[^']*')", "g")
_HIDDEN_WORD = compile_js(r"(?:^|\s)hidden(?:\s|$|=)", "i")
_HIDDEN_FALSE = compile_js(r"hidden\s*=\s*[\"']?false", "i")
_ARIA_HIDDEN = compile_js(r"aria-hidden\s*=\s*[\"']?true", "i")
_HIDDEN_CLASS = compile_js(r"\bclass\s*=\s*[\"'][^\"']*\b(sr-only|visually-hidden|screen-reader-only|d-none|invisible|offscreen)\b", "i")
_ANY_WS = compile_js(r"\s", "g")
_WHITE_BG = compile_js(r"^(#f{3}|#f{6}|white)\b", "")
VOID = {"br", "img", "hr", "input", "meta", "link", "source", "area", "base", "col", "embed", "param", "track", "wbr"}


def _bg_of(style):
    m = _BG.search(style or "")
    return js_trim(m.group(1)).lower() if m else None


def _color_of(style):
    m = _COLOR.search(style or "")
    return js_trim(m.group(1)).lower() if m else None


def html_to_text(html) -> str:
    s = str(html)
    s = _H2T_BLOCKS.sub(" ", s)
    s = _COMMENT.sub(" ", s)
    s = _BR.sub("\n", s)
    s = _BLOCK_END.sub("\n", s)
    s = _TAG.sub(" ", s)
    s = decode_entities(s)
    return js_trim(_BLANK_LINES.sub("\n", _SP_TAB.sub(" ", s)))


def looks_like_html(s) -> bool:
    return bool(_LOOKS_HTML.search(str(s)))


def _wcount(v: str) -> int:
    return len(_SPLIT_WS.split(v))


def scan_hidden(content, format: str | None = None) -> dict:
    """Returns ``{format, findings: [{kind, text, detail}], visible, hidden}``."""
    s = "" if content is None else str(content)
    findings: list = []

    def add(kind, text, detail=""):
        t = js_trim(_WS_RUN.sub(" ", str(text or "")))
        if t:
            findings.append({"kind": kind, "text": t[:2000], "detail": detail or ""})

    fmt = format or ("html" if looks_like_html(s) else "markdown" if _LOOKS_MD.search(s) else "text")
    tags = decode_tags(_FLAG_TAGS.sub("", s))
    if len(js_trim(tags)) >= 4:
        add("unicode-tags", tags, "Unicode tag characters (invisible) spell out text")
    inv = count_invisible(s)
    if inv["zeroWidth"] >= 3:
        add("zero-width", str(inv["zeroWidth"]) + " zero-width characters", "invisible characters that can split or hide words")
    if inv["bidi"]:
        add("bidi", str(inv["bidi"]) + " bidirectional control characters", "can make text display in a different order than it is read")
    if fmt == "html":
        for m in _COMMENT_CAP.finditer(s):
            add("html-comment", m.group(1), "HTML comment")
        for m in _SCRIPTS.finditer(s):
            txt = _TAG.sub(" ", m.group(2))
            if _THREE_WORDS.search(txt) and not _STARTS_CODE.search(txt) and not _CODE_HINT.search(txt):
                tag = m.group(1).lower()
                add(tag, txt, "<" + tag + "> text that is not displayed")
        for m in _META.finditer(s):
            v = m.group(2) if m.group(2) is not None else m.group(3)
            if v and _wcount(v) >= 6:
                add("meta", decode_entities(v), "<meta> content")
        for el in elements(s):
            why = hidden_why(el["attrs"])
            if why:
                inner = html_to_text(el["inner"])
                if inner:
                    add("css-hidden", inner, why)
        for m in _FONT_WHITE.finditer(s):
            add("css-hidden", html_to_text(m.group(2)), "white <font> text")
        for m in _ATTRS.finditer(s):
            v = decode_entities(m.group(3) if m.group(3) is not None else m.group(4))
            if _wcount(v) >= 5:
                add("attribute", v, m.group(1).lower() + " attribute text")
        for m in _IMG_SRC.finditer(s):
            u = m.group(1)
            if _QUERY_DATA.search(u):
                add("image-url-data", u, "image URL carrying query data")
        visible = html_to_text(_strip_hidden_html(s))
    else:
        for m in _COMMENT_CAP.finditer(s):
            add("html-comment", m.group(1), "HTML comment in " + fmt)
        for m in _MD_COMMENT.finditer(s):
            add("markdown-comment", m.group(1), "Markdown link-reference comment (not rendered)")
        for m in _MD_IMG.finditer(s):
            if m.group(1) and _wcount(m.group(1)) >= 5:
                add("alt-text", m.group(1), "image alt text")
            if m.group(3) and _wcount(m.group(3)) >= 5:
                add("attribute", m.group(3), "image title text")
            if _MD_QUERY_DATA.search(m.group(2)) or _BRACES.search(m.group(2)):
                add("image-url-data", m.group(2), "image URL carrying query data")
        for m in _INLINE_HIDDEN.finditer(s):
            st = m.group(2)
            if any(r.search(st) for r, _ in HIDE_STYLE) or WHITE.search(st):
                add("css-hidden", html_to_text(m.group(3)), "inline HTML hidden by style")
        visible = _MD_COMMENT_LINE.sub("", _COMMENT.sub("", s))
    visible = strip_invisible(visible)
    hidden = "\n".join(f["text"] for f in findings if f["kind"] not in ("zero-width", "bidi"))
    return {"format": fmt, "findings": findings, "visible": visible, "hidden": hidden}


def elements(s: str) -> list:
    """Every element with its inner HTML, matching nested tags of the same name by depth."""
    out: list = []
    stack: list = []
    for m in _ELEMENT.finditer(s):
        close = m.group(1) == "/"
        tag = m.group(2).lower()
        if tag in VOID or m.group(4) == "/":
            continue
        if not close:
            stack.append({"tag": tag, "attrs": m.group(3), "start": m.start(), "innerStart": m.end()})
        else:
            for i in range(len(stack) - 1, -1, -1):
                if stack[i]["tag"] == tag:
                    o = stack[i]
                    del stack[i:]
                    out.append({"tag": tag, "attrs": o["attrs"], "inner": s[o["innerStart"]:m.start()], "start": o["start"], "end": m.end()})
                    break
        if len(out) > 20000:
            break
    return out


def _style_of(attrs: str) -> str:
    m = _STYLE_ATTR.search(attrs or "")
    if not m:
        return ""
    return m.group(1) if m.group(1) is not None else m.group(2)


def hidden_why(attrs: str):
    style = _style_of(attrs)
    for r, label in HIDE_STYLE:
        if r.search(style):
            return label
    if _HIDDEN_WORD.search(_ATTR_PAIRS.sub(" ", attrs)) and not _HIDDEN_FALSE.search(attrs):
        return "hidden attribute"
    if _ARIA_HIDDEN.search(attrs):
        return "aria-hidden"
    if _HIDDEN_CLASS.search(attrs):
        return "hidden by class"
    c = _color_of(style)
    bg = _bg_of(style)
    if c and bg and _ANY_WS.sub("", c) == _ANY_WS.sub("", bg):
        return "text colour matches background"
    if WHITE.search(style) and (not bg or _WHITE_BG.search(bg)):
        return "white text"
    if TRANSPARENT.search(style):
        return "transparent text"
    return None


def _strip_hidden_html(s: str) -> str:
    out = _COMMENT.sub("", s)
    ranges = sorted(((el["start"], el["end"]) for el in elements(out) if hidden_why(el["attrs"])), key=lambda r: r[0])
    res = []
    pos = 0
    for a, b in ranges:
        if a < pos:
            continue
        res.append(out[pos:a] + " ")
        pos = b
    res.append(out[pos:])
    return _FONT_WHITE_STRIP.sub(" ", "".join(res))
