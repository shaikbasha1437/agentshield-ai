"""Dangerous-command detection for shell, SQL, git, Kubernetes and cloud CLIs (port of ``lib/dangerous.js``).

Only command-like arguments are checked (command, cmd, script, query, sql ...), so a README that merely mentions
"rm -rf build/" can be written to a file without tripping this. Each pattern carries a severity: critical (denied)
or high (needs a person)."""
from __future__ import annotations

from ._data import rules
from ._jsre import compile_js, js_trim

COMMAND_PATTERNS = [
    {"id": p["id"], "severity": p["severity"], "re": compile_js(p["source"], p["flags"]), "why": p["why"]} for p in rules()["commandPatterns"]
]
COMMAND_ARG_KEYS: list = list(rules()["commandArgKeys"])
_BLOCK_COMMENT = compile_js(r"\/\*[\s\S]*?\*\/", "g")
_LINE_COMMENT = compile_js(r"(^|\s)--[^\n]*", "g")
_SQ_LIT = compile_js(r"'(?:[^']|'')*'", "g")
_DQ_LIT = compile_js(r"\"(?:[^\"]|\"\")*\"", "g")
WRITE_KW = compile_js(r"\b(insert|update|delete|drop|alter|create|replace|truncate|attach|detach|grant|revoke|vacuum|reindex|merge|upsert|copy|call|exec|execute|lock|rename|comment\s+on|set\s+role)\b", "i")
_FIRST = compile_js(r"^\(*\s*(\w+)", "")
_AUDIT_COLS = compile_js(r"\b(created_at|updated_at|deleted_at|is_deleted|replaced_by|create_date|update_time)\b", "gi")
_INTO = compile_js(r"\binto\s+\w", "i")
_EQ = compile_js(r"=", "")
_SHELL_SPLIT = compile_js(r"\s*(?:;|&&|\|\||\||\n|`|\$\()\s*", "")
_PARENS = compile_js(r"^\(+|\)+$", "g")
_READ_FIRST = ("select", "with", "explain", "show", "describe", "desc", "pragma", "values")


def dangerous_command(cmd) -> list:
    """Matching dangerous patterns for a command string, most severe first, with the specific pattern removed when
    a broader one of the same family also matched."""
    raw = "" if cmd is None else str(cmd)
    sql = " ; ".join(sql_statements(raw))
    hits = [{"id": p["id"], "severity": p["severity"], "why": p["why"]} for p in COMMAND_PATTERNS if p["re"].search(sql if p["id"].startswith("sql-") else raw)]
    ids = {h["id"] for h in hits}
    drop = set()
    if "rm-rf-root" in ids:
        drop.add("rm-recursive")
    if "git-force-push-main" in ids:
        drop.add("git-force-push")
    if "kubectl-delete-all" in ids:
        drop.add("kubectl-delete")
    if "sql-delete-all" in ids:
        drop.add("sql-delete")
    return sorted((h for h in hits if h["id"] not in drop), key=lambda h: 0 if h["severity"] == "critical" else 1)


def strip_sql_comments(s) -> str:
    return _LINE_COMMENT.sub(lambda m: m.group(1), _BLOCK_COMMENT.sub(" ", str(s)))


def sql_statements(q) -> list:
    """String literals are blanked first so a value like 'drop table' inside a WHERE clause does not count."""
    blanked = _DQ_LIT.sub('""', _SQ_LIT.sub("''", strip_sql_comments("" if q is None else str(q))))
    return [x for x in (js_trim(p) for p in blanked.split(";")) if x]


def sql_read_only(q) -> dict:
    st = sql_statements(q)
    if not st:
        return {"ok": False, "reason": "empty query", "statements": 0}
    for s in st:
        m = _FIRST.search(s)
        first = m.group(1).lower() if m else None
        if first not in _READ_FIRST:
            return {"ok": False, "reason": "statement starts with " + (first or "?").upper(), "statements": len(st)}
        if first == "pragma" and _EQ.search(s):
            return {"ok": False, "reason": "PRAGMA that sets a value", "statements": len(st)}
        if WRITE_KW.search(_AUDIT_COLS.sub("", s)):
            m2 = WRITE_KW.search(s)
            return {"ok": False, "reason": "contains " + (m2.group(1).upper() if m2 else "?"), "statements": len(st)}
        if _INTO.search(s) and first == "select":
            return {"ok": False, "reason": "SELECT ... INTO writes a table", "statements": len(st)}
    return {"ok": True, "reason": (str(len(st)) + " read statements") if len(st) > 1 else "read-only", "statements": len(st)}


def shell_segments(cmd) -> list:
    """Split a shell line into simple commands (on ; && || | and newlines) for allowlisting by prefix."""
    parts = _SHELL_SPLIT.split("" if cmd is None else str(cmd))
    return [x for x in (_PARENS.sub("", js_trim(p)) for p in parts) if x]
