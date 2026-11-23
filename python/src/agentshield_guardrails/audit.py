"""Append-only audit log with a SHA-256 hash chain (port of ``lib/audit.js``).

Each entry stores the hash of the one before it, so editing, removing or reordering any entry breaks verification
from that point on. Values are redacted before they are written. Tamper-evident, not tamper-proof."""
from __future__ import annotations

import datetime as _dt
import hashlib
import json

from ._jsre import compile_js
from .output import redact

GENESIS = "0" * 64
_SECRET_KEY = compile_js(r"^(api[_-]?key|key|authorization|password|secret|token)$", "i")


def canonical_json(v) -> str:
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical_json(v[k]) for k in sorted(v)) + "}"
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(canonical_json(x) for x in v) + "]"
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def redact_deep(v, secrets=None, allow_emails=None, kinds=None, max_string: int = 4000):
    if isinstance(v, str):
        r = redact(v, secrets=secrets, allow_emails=allow_emails, kinds=kinds)["text"]
        return r[:max_string] + "\u2026 [" + str(len(r) - max_string) + " more characters]" if len(r) > max_string else r
    if isinstance(v, (list, tuple)):
        return [redact_deep(x, secrets, allow_emails, kinds, max_string) for x in v]
    if isinstance(v, dict):
        return {k: ("[redacted]" if _SECRET_KEY.search(k) and isinstance(x, str) else redact_deep(x, secrets, allow_emails, kinds, max_string)) for k, x in v.items()}
    return v


def entry_hash(e: dict) -> str:
    return hashlib.sha256("|".join([e["prev"], str(e["seq"]), e["ts"], e["type"], canonical_json(e["data"])]).encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AuditLog:
    def __init__(self, redact: bool = True, secrets=None, allow_emails=None, now=None, on_append=None) -> None:
        self.entries: list = []
        self.redact = redact
        self.secrets = list(secrets or [])
        self.allow_emails = list(allow_emails or [])
        self.now = now or _now_iso
        self.on_append = on_append

    def append(self, type: str, data) -> dict:
        prev = self.entries[-1]["hash"] if self.entries else GENESIS
        clean = redact_deep(data, self.secrets, self.allow_emails) if self.redact else json.loads(json.dumps(data))
        e = {"seq": len(self.entries) + 1, "ts": self.now(), "type": str(type), "data": clean, "prev": prev}
        e["hash"] = entry_hash(e)
        self.entries.append(e)
        if self.on_append:
            self.on_append(e)
        return e

    def verify(self) -> dict:
        return verify_chain(self.entries)

    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else GENESIS

    def to_json(self) -> dict:
        return {"format": "agentshield-audit/1", "head": self.head(), "count": len(self.entries), "entries": self.entries}


def verify_chain(entries: list) -> dict:
    prev = GENESIS
    for i, e in enumerate(entries):
        if e.get("seq") != i + 1:
            return {"ok": False, "count": len(entries), "brokenAt": i + 1, "reason": "entry " + str(i + 1) + " has sequence number " + str(e.get("seq")) + " (an entry was removed or reordered)"}
        if e.get("prev") != prev:
            return {"ok": False, "count": len(entries), "brokenAt": e["seq"], "reason": "entry " + str(e["seq"]) + " does not point at the hash of entry " + str(e["seq"] - 1)}
        if entry_hash(e) != e.get("hash"):
            return {"ok": False, "count": len(entries), "brokenAt": e["seq"], "reason": "entry " + str(e["seq"]) + " was changed after it was written (hash mismatch)"}
        prev = e["hash"]
    return {"ok": True, "count": len(entries), "brokenAt": None, "reason": ("all " + str(len(entries)) + " entries chain correctly") if entries else "the log is empty"}
