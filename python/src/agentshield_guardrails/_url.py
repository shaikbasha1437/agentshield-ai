"""A compact WHATWG URL parser covering what the guards read from a URL: scheme, user info, host, path, query,
fragment and query parameters. It mirrors ``new URL(u)`` in browsers and Node closely enough for the security
checks (look-alike hosts, user-info tricks, data in the query or path); it is not a full implementation of the
URL Standard (notably, internationalised hosts use Python's IDNA 2003 codec rather than UTS #46)."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

SPECIAL = {"http": "80", "https": "443", "ws": "80", "wss": "443", "ftp": "21", "file": None}
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+\-.]*:")
_FORBIDDEN_HOST = set("\x00\t\n\r #/:<>?@[\\]^|")
_FORBIDDEN_DOMAIN = _FORBIDDEN_HOST | {chr(c) for c in range(0x20)} | {"%", "\x7f"}


@dataclass
class URL:
    protocol: str
    username: str = ""
    password: str = ""
    hostname: str = ""
    port: str = ""
    pathname: str = ""
    search: str = ""
    hash: str = ""
    query: str | None = None
    search_params: list = field(default_factory=list)


def _pct_encode(s: str, encode_set) -> str:
    out = []
    for ch in s:
        if ch in encode_set or ord(ch) < 0x20 or ord(ch) > 0x7E:
            out.append("".join("%%%02X" % b for b in ch.encode("utf-8", "surrogatepass")))
        else:
            out.append(ch)
    return "".join(out)


_FRAGMENT_SET = set(' "<>`')
_QUERY_SET = set(' "#<>')
_SPECIAL_QUERY_SET = _QUERY_SET | {"'"}
_PATH_SET = _QUERY_SET | set("?`{}^")
_USERINFO_SET = _PATH_SET | set("/:;=@[\\]|")


def _pct_decode_bytes(s: str) -> bytes:
    b = s.encode("utf-8", "surrogatepass")
    out = bytearray()
    i = 0
    while i < len(b):
        c = b[i]
        if c == 0x25 and i + 2 < len(b) and all(chr(x) in "0123456789abcdefABCDEF" for x in b[i + 1:i + 3]):
            out.append(int(b[i + 1:i + 3].decode(), 16))
            i += 3
        else:
            out.append(c)
            i += 1
    return bytes(out)


def _parse_ipv4_number(part: str):
    if part == "":
        return None
    r = 10
    if len(part) >= 2 and part[:2].lower() == "0x":
        part = part[2:]
        r = 16
    elif len(part) >= 2 and part[0] == "0":
        part = part[1:]
        r = 8
    if part == "":
        return 0
    try:
        return int(part, r)
    except ValueError:
        return None


def _ends_in_number(host: str) -> bool:
    parts = host.split(".")
    if parts[-1] == "":
        if len(parts) == 1:
            return False
        parts.pop()
    last = parts[-1]
    if last and all(c in "0123456789" for c in last):
        return True
    return _parse_ipv4_number(last) is not None


def _parse_ipv4(host: str):
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    if len(parts) > 4:
        return None
    nums = []
    for p in parts:
        n = _parse_ipv4_number(p)
        if n is None:
            return None
        nums.append(n)
    if any(n > 255 for n in nums[:-1]):
        return None
    if nums[-1] >= 256 ** (5 - len(nums)):
        return None
    ipv4 = nums[-1]
    for i, n in enumerate(nums[:-1]):
        ipv4 += n * 256 ** (3 - i)
    return ".".join(str((ipv4 >> s) & 255) for s in (24, 16, 8, 0))


def _parse_host(inp: str, special: bool):
    if inp.startswith("["):
        if not inp.endswith("]"):
            return None
        try:
            return "[" + ipaddress.IPv6Address(inp[1:-1]).compressed + "]"
        except ValueError:
            return None
    if not special:
        if any(c in _FORBIDDEN_HOST for c in inp):
            return None
        return _pct_encode(inp, set())
    try:
        domain = _pct_decode_bytes(inp).decode("utf-8", "replace")
    except Exception:
        return None
    if all(ord(c) < 0x80 for c in domain):
        ascii_domain = domain.lower()
    else:
        try:
            ascii_domain = domain.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
    if ascii_domain == "" or any(c in _FORBIDDEN_DOMAIN for c in ascii_domain):
        return None
    if _ends_in_number(ascii_domain):
        return _parse_ipv4(ascii_domain)
    return ascii_domain


def _form_decode(q: str) -> list:
    out = []
    for seq in q.split("&"):
        if not seq:
            continue
        name, _, value = seq.partition("=")
        dec = lambda x: _pct_decode_bytes(x.replace("+", " ")).decode("utf-8", "replace")  # noqa: E731
        out.append((dec(name), dec(value)))
    return out


def _normalize_path(path: str, special: bool) -> str:
    segs = re.split(r"[/\\]" if special else r"/", path)
    out: list = []
    n = len(segs)
    for i, seg in enumerate(segs):
        low = seg.lower()
        last = i == n - 1
        if low in ("..", ".%2e", "%2e.", "%2e%2e"):
            if out:
                out.pop()
            if last:
                out.append("")
        elif low in (".", "%2e"):
            if last:
                out.append("")
        else:
            out.append(_pct_encode(seg, _PATH_SET))
    return "/" + "/".join(out)


def parse_url(u) -> URL | None:
    """``new URL(u)``; returns None when the URL would throw."""
    s = str(u)
    s = s.strip("".join(chr(c) for c in range(0x21)))
    s = s.replace("\t", "").replace("\n", "").replace("\r", "")
    m = _SCHEME.match(s)
    if not m:
        return None
    scheme = m.group(0)[:-1].lower()
    rest = s[m.end():]
    special = scheme in SPECIAL
    frag = None
    if "#" in rest:
        rest, frag = rest.split("#", 1)
    query = None
    url = URL(protocol=scheme + ":")
    if special and scheme != "file":
        rest = rest.lstrip("/\\")
        end = len(rest)
        for i, ch in enumerate(rest):
            if ch in "/\\?":
                end = i
                break
        authority, rest = rest[:end], rest[end:]
        if "@" in authority:
            userinfo, authority = authority.rsplit("@", 1)
            user, _, pw = userinfo.partition(":")
            url.username = _pct_encode(user, _USERINFO_SET)
            url.password = _pct_encode(pw, _USERINFO_SET)
            if authority == "":
                return None
        host, port = authority, ""
        if not host.startswith("["):
            if ":" in host:
                host, port = host.split(":", 1)
        elif "]:" in host:
            host, port = host.split("]:", 1)
            host += "]"
        if port:
            if not port.isdigit() or not port.isascii() or int(port) > 65535:
                return None
            port = str(int(port))
            if SPECIAL.get(scheme) == port:
                port = ""
        if host == "":
            return None
        h = _parse_host(host, True)
        if h is None:
            return None
        url.hostname, url.port = h, port
        if "?" in rest:
            rest, query = rest.split("?", 1)
        url.pathname = _normalize_path(rest[1:] if rest[:1] in ("/", "\\") else rest, True) if rest else "/"
    elif scheme == "file":
        if "?" in rest:
            rest, query = rest.split("?", 1)
        rest = rest.replace("\\", "/")
        if rest.startswith("//"):
            rest = rest[2:]
            slash = rest.find("/")
            host, rest = (rest, "") if slash < 0 else (rest[:slash], rest[slash:])
            if host and host.lower() != "localhost":
                h = _parse_host(host, True)
                if h is None:
                    return None
                url.hostname = h
        url.pathname = _normalize_path(rest.lstrip("/"), True)
    else:
        if "?" in rest:
            rest, query = rest.split("?", 1)
        if rest.startswith("//"):
            rest = rest[2:]
            slash = rest.find("/")
            authority, rest = (rest, "") if slash < 0 else (rest[:slash], rest[slash:])
            if "@" in authority:
                userinfo, authority = authority.rsplit("@", 1)
                user, _, pw = userinfo.partition(":")
                url.username = _pct_encode(user, _USERINFO_SET)
                url.password = _pct_encode(pw, _USERINFO_SET)
            host, _, port = authority.partition(":")
            if port and not port.isdigit():
                return None
            h = _parse_host(host, False) if host else ""
            if h is None:
                return None
            url.hostname, url.port = h, port
            url.pathname = _normalize_path(rest[1:], False) if rest else ""
        else:
            url.pathname = _pct_encode(rest, set())
    if query is not None:
        url.query = _pct_encode(query, _SPECIAL_QUERY_SET if special else _QUERY_SET)
        url.search = "?" + url.query if url.query else ""
        url.search_params = _form_decode(url.query)
    if frag is not None:
        f = _pct_encode(frag, _FRAGMENT_SET)
        url.hash = "#" + f if f else ""
    return url
