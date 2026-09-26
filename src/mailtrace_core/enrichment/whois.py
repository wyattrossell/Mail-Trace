"""Port-43 WHOIS fallback for TLDs whose registry has no RDAP service.

Two queries at most: ``whois.iana.org`` for the referral, then the registry
or registrar server it names. The text is parsed with tolerant regexes; the
raw response is kept so the examiner can read it.
"""

from __future__ import annotations

import re
import socket
from collections.abc import Callable
from typing import Any

from mailtrace_core.enrichment.context import Context, ProviderAnswer
from mailtrace_core.enrichment.models import Lookup, LookupStatus
from mailtrace_core.util import netguard

QueryFn = Callable[[str, str], str]

_FIELDS: dict[str, list[str]] = {
    "registrar": [
        r"^\s*registrar:\s*(.+)$",
        r"^\s*sponsoring registrar:\s*(.+)$",
        r"^\s*registrar name:\s*(.+)$",
    ],
    "created": [
        r"^\s*creation date:\s*(.+)$",
        r"^\s*created(?: on)?:\s*(.+)$",
        r"^\s*registered(?: on)?:\s*(.+)$",
        r"^\s*registration time:\s*(.+)$",
        r"^\s*domain registration date:\s*(.+)$",
    ],
    "updated": [
        r"^\s*updated date:\s*(.+)$",
        r"^\s*last updated(?: on)?:\s*(.+)$",
        r"^\s*modified:\s*(.+)$",
        r"^\s*last modified:\s*(.+)$",
        r"^\s*changed:\s*(.+)$",
    ],
    "expires": [
        r"^\s*registry expiry date:\s*(.+)$",
        r"^\s*expir(?:y|ation) date:\s*(.+)$",
        r"^\s*expires(?: on)?:\s*(.+)$",
        r"^\s*paid-till:\s*(.+)$",
    ],
    "registrar_abuse_email": [
        r"^\s*registrar abuse contact email:\s*(.+)$",
        r"^\s*abuse contact email:\s*(.+)$",
        r"^\s*abuse-mailbox:\s*(.+)$",
    ],
    "registrar_abuse_phone": [
        r"^\s*registrar abuse contact phone:\s*(.+)$",
        r"^\s*abuse contact phone:\s*(.+)$",
    ],
    "registrar_iana_id": [r"^\s*registrar iana id:\s*(.+)$"],
    "registrant_org": [
        r"^\s*registrant organi[sz]ation:\s*(.+)$",
        r"^\s*registrant:\s*(.+)$",
        r"^\s*org(?:anisation)?:\s*(.+)$",
    ],
    "registrant_country": [r"^\s*registrant country:\s*(.+)$"],
}
_NS_RE = re.compile(r"^\s*(?:name server|nserver|nameserver|ns):\s*([^\s]+)", re.IGNORECASE | re.MULTILINE)
_STATUS_RE = re.compile(r"^\s*(?:domain )?status:\s*([^\s]+)", re.IGNORECASE | re.MULTILINE)
_REFER_RE = re.compile(r"^\s*(?:refer|whois(?: server)?):\s*([^\s]+)", re.IGNORECASE | re.MULTILINE)


def socket_query(server: str, query: str, timeout: float = 10.0) -> str:
    netguard.require(netguard.NetCategory.WHOIS)
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall(query.encode("idna", errors="replace") + b"\r\n")
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def parse_whois(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"source": "whois", "raw": text[:6000]}
    for key, patterns in _FIELDS.items():
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
            if m and m.group(1).strip():
                out[key] = m.group(1).strip()
                break
        out.setdefault(key, None)
    out["nameservers"] = sorted({m.group(1).lower().rstrip(".") for m in _NS_RE.finditer(text)})
    out["statuses"] = sorted({m.group(1) for m in _STATUS_RE.finditer(text)})
    return out


def whois_domain(
    domain: str, ctx: Context, query: QueryFn = socket_query
) -> tuple[dict[str, Any] | None, Lookup]:
    if not ctx.settings.whois_fallback:
        return None, ctx.skip("whois", domain, "WHOIS fallback disabled in settings")
    if ctx.http is None and ctx.resolver is None:
        return None, ctx.skip("whois", domain, "offline")

    def call() -> ProviderAnswer:
        tld = domain.rsplit(".", 1)[-1]
        referral = query("whois.iana.org", tld)
        m = _REFER_RE.search(referral)
        if not m:
            return ProviderAnswer(LookupStatus.NOT_FOUND, detail=f"IANA lists no WHOIS server for .{tld}")
        server = m.group(1)
        text = query(server, domain)
        low = text.lower()
        if "no match" in low or "not found" in low or "no data found" in low or "no entries found" in low:
            return ProviderAnswer(LookupStatus.NOT_FOUND, detail=f"{server}: no match")
        parsed = parse_whois(text)
        # Thin registries (.com/.net) refer to the registrar for details.
        m2 = re.search(r"^\s*registrar whois server:\s*([^\s]+)", text, re.IGNORECASE | re.MULTILINE)
        if m2 and m2.group(1).lower() != server.lower() and not parsed.get("registrar_abuse_email"):
            try:
                deeper = parse_whois(query(m2.group(1), domain))
                for k, v in deeper.items():
                    if v and not parsed.get(k):
                        parsed[k] = v
            except OSError:
                pass
        parsed["server"] = server
        return ProviderAnswer(LookupStatus.OK, value=parsed)

    try:
        return ctx.cached_call("whois", domain, call, ttl_hours=24 * 7)
    except OSError as exc:  # socket errors surface here when not wrapped as HttpError
        from mailtrace_core.enrichment.base import lookup

        return None, lookup("whois", domain, LookupStatus.ERROR, str(exc))
