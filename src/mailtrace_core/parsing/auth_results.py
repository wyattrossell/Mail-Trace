"""Parse ``Authentication-Results`` (RFC 8601) and ``ARC-Authentication-Results``.

These headers are assertions made by whichever server wrote them. They are
useful, but they are *reported* results. Independent re-verification lives
in :mod:`mailtrace_core.parsing.auth`.
"""

from __future__ import annotations

import re

from mailtrace_core.models import AuthResult

_METHOD_RE = re.compile(r"^([a-z0-9_-]+)(?:/\d+)?\s*=\s*([a-z0-9_-]+)$", re.IGNORECASE)
_KV_RE = re.compile(r'([a-z0-9_.-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s;]+)', re.IGNORECASE)


def _strip_comments(text: str) -> str:
    out: list[str] = []
    depth = 0
    quoted = False
    for ch in text:
        if ch == '"' and depth == 0:
            quoted = not quoted
        if not quoted:
            if ch == "(":
                depth += 1
                continue
            if ch == ")":
                depth = max(0, depth - 1)
                continue
        if depth == 0:
            out.append(ch)
    return "".join(out)


def _split_semicolons(text: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    quoted = False
    for ch in text:
        if ch == '"':
            quoted = not quoted
        if ch == ";" and not quoted:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def parse_authentication_results(value: str) -> list[AuthResult]:
    """Parse one header value into one :class:`AuthResult` per method."""
    cleaned = " ".join(_strip_comments(value).split())
    segments = _split_semicolons(cleaned)
    if not segments:
        return []
    authserv = segments[0].split()[0] if segments[0].split() else ""
    results: list[AuthResult] = []
    for seg in segments[1:]:
        if seg.lower() == "none":
            continue
        tokens = seg.split(None, 1)
        head = tokens[0]
        rest = tokens[1] if len(tokens) > 1 else ""
        m = _METHOD_RE.match(head)
        if not m:
            # Tolerate "method = result" with spaces.
            m2 = re.match(r"^([a-z0-9_-]+)\s*=\s*([a-z0-9_-]+)\s*(.*)$", seg, re.IGNORECASE)
            if not m2:
                continue
            method, result, rest = m2.group(1), m2.group(2), m2.group(3)
        else:
            method, result = m.group(1), m.group(2)
        props: dict[str, str] = {}
        reason = ""
        for km in _KV_RE.finditer(rest):
            key = km.group(1).lower()
            val = km.group(2)
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            if key == "reason":
                reason = val
            else:
                props[key] = val
        results.append(
            AuthResult(
                authserv_id=authserv,
                method=method.lower(),
                result=result.lower(),
                properties=props,
                reason=reason,
                raw=seg,
            )
        )
    return results


def parse_all(headers: list[tuple[str, str]]) -> list[AuthResult]:
    """Collect results from every A-R and ARC-A-R header in the message."""
    out: list[AuthResult] = []
    for name, value in headers:
        lname = name.lower()
        if lname in {"authentication-results", "arc-authentication-results", "x-authentication-results"}:
            for r in parse_authentication_results(value):
                if lname.startswith("arc-"):
                    r.method = "arc:" + r.method
                out.append(r)
    return out


def best_reported(results: list[AuthResult], method: str) -> AuthResult | None:
    """The first non-ARC reported result for a method (top-most header wins)."""
    for r in results:
        if r.method == method:
            return r
    return None
