"""Small helpers that reproduce JavaScript number and string behaviour exactly."""
from __future__ import annotations

import math


def js_round3(x: float) -> float:
    """Math.round(x * 1000) / 1000"""
    return math.floor(x * 1000 + 0.5) / 1000


def js_num_str(v) -> str:
    """String(number) for the values that appear in tool arguments."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if math.isnan(v):
            return "NaN"
        if math.isinf(v):
            return "Infinity" if v > 0 else "-Infinity"
        if v == int(v) and abs(v) < 1e21:
            return str(int(v))
        r = repr(v)
        if "e" in r:
            mant, exp = r.split("e")
            exp_i = int(exp)
            if -7 < exp_i < 21:
                return format(v, "f").rstrip("0").rstrip(".")
            return mant + "e" + ("+" if exp_i > 0 else "-") + str(abs(exp_i))
        return r
    return str(v)


def is_obj(x) -> bool:
    return isinstance(x, dict)
