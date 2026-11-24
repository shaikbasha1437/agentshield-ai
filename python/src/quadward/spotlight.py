"""Spotlighting untrusted content (port of ``lib/spotlight.js``): wrap it in labelled, randomised boundaries (or
datamark it) so the model can tell data from instructions, and neutralise anything inside that tries to close the
boundary or forge a role."""
from __future__ import annotations

import math
import random

from ._data import rules
from ._jsre import compile_js

SPOTLIGHT_NOTE: str = rules()["spotlightNote"]
_A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_CLOSE = compile_js(r"<<\/?\s*untrusted\b[^>]*>>", "gi")
_CHAT = compile_js(r"<\|?(im_start|im_end|system|endoftext|eot_id|start_header_id|end_header_id|begin_of_text)\|?>", "gi")
_ROLE = compile_js(r"<\/?\s*(system|assistant|developer|user|instructions?|tool|function_results?|untrusted_[a-z_]*)\b[^>]*>", "gi")
_ATTR = compile_js(r"[\"\n\r<>]", "g")
_SP_TAB = compile_js(r"[ \t]+", "g")


def boundary_id(rand=None) -> str:
    r = rand or random.random
    return "".join(_A[math.floor(r() * len(_A))] for _ in range(8))


def _angles(m) -> str:
    return m.group(0).replace("<", "\u2039").replace(">", "\u203a")


def neutralize(text) -> str:
    s = "" if text is None else str(text)
    s = _CLOSE.sub(_angles, s)
    s = _CHAT.sub(lambda m: "\u2039" + m.group(1) + "\u203a", s)
    return _ROLE.sub(_angles, s)


def _attr(s) -> str:
    return _ATTR.sub(" ", "" if s is None else str(s))[:160]


def spotlight(text, mode: str = "delimit", source: str | None = None, label: str | None = None, note: str | None = None, id: str | None = None, rand=None) -> str:
    """mode: 'delimit' (default), 'datamark' or 'off'."""
    mode = mode or "delimit"
    body = neutralize(text)
    if mode == "off":
        return body
    bid = id or boundary_id(rand)
    inner = _SP_TAB.sub("^", body) if mode == "datamark" else body
    return ("<<untrusted id=" + bid + ' source="' + _attr(source or "unknown") + '"' + (' label="' + _attr(label) + '"' if label else "")
            + (' guard="' + _attr(note) + '"' if note else "") + ">>\n" + inner + "\n<</untrusted id=" + bid + ">>")
