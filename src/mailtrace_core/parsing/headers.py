"""Received-chain reconstruction, hop trust, and originating-IP candidates.

``Received:`` headers are prepended by each server, so the header order in
the message is newest-first. This module reverses them so ``hops[0]`` is the
earliest (closest to the sender) and ``hops[-1]`` is the final delivery.

Only hops added by servers we can attribute to the recipient's side are
marked ``trusted``. Everything older than the trust boundary was written by
someone else and may be fabricated. The originating-IP candidates say which
of those they rely on.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime

from mailtrace_core.models import Confidence, Hop, OriginCandidate
from mailtrace_core.parsing.urls import registrable_domain
from mailtrace_core.util.timeutil import parse_rfc2822

_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
_IPV6 = r"(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:%\w+)?"
_IP_RE = re.compile(rf"(?:IPv6:)?({_IPV6}|{_IPV4})")
_BRACKET_IP_RE = re.compile(rf"\[(?:IPv6:)?({_IPV6}|{_IPV4})\]")
_CLAUSE_RE = re.compile(r"(?<![\w.-])(from|by|via|with|id|for)\s+", re.IGNORECASE)
_HELO_KV_RE = re.compile(r"helo=\[?([^\s\])]+)\]?", re.IGNORECASE)

# Hosts operated by major mailbox providers / security gateways. Used only to
# extend a trust run that already starts at the recipient's mailbox.
_PROVIDER_SUFFIXES = (
    "google.com",
    "googlemail.com",
    "gmail.com",
    "outlook.com",
    "office365.com",
    "microsoft.com",
    "hotmail.com",
    "yahoo.com",
    "yahoodns.net",
    "aol.com",
    "icloud.com",
    "apple.com",
    "pphosted.com",
    "proofpoint.com",
    "mimecast.com",
    "barracudanetworks.com",
    "messagelabs.com",
    "mailgun.net",
    "mail.protection.outlook.com",
)

OUT_OF_ORDER_TOLERANCE_S = 300.0
"""Negative delays smaller than this are recorded as clock skew, not reorder."""
IMPLAUSIBLE_DELAY_S = 24 * 3600.0

ORIGIN_IP_HEADERS = (
    "X-Originating-IP",
    "X-Sender-IP",
    "X-Source-IP",
    "X-Real-IP",
    "X-Original-IP",
    "X-Client-IP",
    "X-Forwarded-For",
    "X-Sender-Ip",
    "X-PHP-Originating-Script",
)


def _mask_comments(text: str) -> str:
    """Replace the inside of (...) with spaces so keywords there are ignored."""
    out: list[str] = []
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
            out.append(" ")
        elif ch == ")":
            depth = max(0, depth - 1)
            out.append(" ")
        elif depth > 0:
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


def _strip_comments(text: str) -> str:
    out: list[str] = []
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return " ".join("".join(out).split())


def _comments(text: str) -> list[str]:
    found: list[str] = []
    depth = 0
    buf: list[str] = []
    for ch in text:
        if ch == "(":
            depth += 1
            if depth == 1:
                buf = []
                continue
        if ch == ")":
            depth = max(0, depth - 1)
            if depth == 0:
                found.append("".join(buf))
                continue
        if depth > 0:
            buf.append(ch)
    return found


def _first_ip(text: str) -> str | None:
    m = _BRACKET_IP_RE.search(text)
    if m:
        return _clean_ip(m.group(1))
    m = _IP_RE.search(text)
    if m:
        return _clean_ip(m.group(1))
    return None


def _clean_ip(ip: str) -> str | None:
    ip = ip.split("%")[0]
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


def _is_ip(token: str) -> bool:
    return _clean_ip(token.strip("[]")) is not None


def split_clauses(received: str) -> tuple[dict[str, str], str | None]:
    """Split a Received value into ``{clause: text}`` and the date string."""
    value = " ".join(received.split())
    date_str: str | None = None
    masked = _mask_comments(value)
    semi = masked.rfind(";")
    if semi != -1:
        date_str = value[semi + 1 :].strip() or None
        value = value[:semi]
        masked = masked[:semi]
    clauses: dict[str, str] = {}
    matches = list(_CLAUSE_RE.finditer(masked))
    for i, m in enumerate(matches):
        key = m.group(1).lower()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(value)
        if key not in clauses:  # keep the first occurrence only
            clauses[key] = value[start:end].strip()
    return clauses, date_str


def parse_received(raw: str, index: int) -> Hop:
    """Parse one Received header value into a :class:`Hop`."""
    clauses, date_str = split_clauses(raw)
    hop = Hop(index=index, raw=" ".join(raw.split()))

    frm = clauses.get("from")
    if frm:
        plain = _strip_comments(frm)
        tokens = plain.split()
        first = tokens[0] if tokens else None
        comments = _comments(frm)
        hop.from_ip = _first_ip(frm)
        if first and _is_ip(first):
            # Exim style: "from [1.2.3.4] (helo=foo)"
            hop.from_host = None
            for c in comments:
                hm = _HELO_KV_RE.search(c)
                if hm:
                    hop.from_helo = hm.group(1)
        else:
            hop.from_helo = first
            hop.from_host = first
            # Sendmail/Postfix style: "from helo (rdns [ip])"
            for c in comments:
                ctokens = c.split()
                if ctokens and not _is_ip(ctokens[0].strip("[]")) and "=" not in ctokens[0]:
                    cand = ctokens[0].rstrip(".")
                    if "." in cand and not cand.lower().startswith("unknown"):
                        hop.from_host = cand
                hm = _HELO_KV_RE.search(c)
                if hm:
                    hop.from_helo = hm.group(1)
        if hop.from_host and hop.from_host.lower() in {"unknown", "localhost"}:
            hop.anomalies.append(f"sending host identified only as '{hop.from_host}'")

    by = clauses.get("by")
    if by:
        plain = _strip_comments(by)
        tokens = plain.split()
        if tokens:
            hop.by_host = tokens[0].strip("[]").rstrip(".")
        hop.by_ip = _first_ip(by)

    with_ = clauses.get("with")
    if with_:
        hop.protocol = _strip_comments(with_).split()[0] if _strip_comments(with_) else None
        if hop.protocol and hop.protocol.lower() in {"microsoft", "local"}:
            hop.protocol = _strip_comments(with_)[:40]

    hid = clauses.get("id")
    if hid:
        toks = _strip_comments(hid).split()
        hop.hop_id = toks[0] if toks else None

    for_ = clauses.get("for")
    if for_:
        toks = _strip_comments(for_).split()
        hop.for_addr = toks[0].strip("<>;") if toks else None

    if date_str:
        hop.timestamp = parse_rfc2822(date_str)
        if hop.timestamp is None:
            hop.anomalies.append(f"unparseable timestamp: {date_str!r}")
    else:
        hop.anomalies.append("no timestamp")

    if not frm and not by:
        hop.anomalies.append("Received header has neither 'from' nor 'by' clause")
    return hop


def build_hops(received_headers: list[str]) -> list[Hop]:
    """Parse headers in message order (newest first) and return origin-first."""
    reversed_headers = list(reversed(received_headers))
    hops = [parse_received(raw, i) for i, raw in enumerate(reversed_headers)]
    _compute_delays(hops)
    return hops


def _compute_delays(hops: list[Hop]) -> None:
    prev_ts: datetime | None = None
    for hop in hops:
        if hop.timestamp is None:
            continue
        if prev_ts is not None:
            delta = (hop.timestamp - prev_ts).total_seconds()
            hop.delay_seconds = delta
            if delta < -OUT_OF_ORDER_TOLERANCE_S:
                hop.anomalies.append(
                    f"timestamp is {abs(delta):.0f}s EARLIER than previous hop (out of order)"
                )
            elif delta < 0:
                hop.anomalies.append(f"minor clock skew: {abs(delta):.0f}s earlier than previous hop")
            elif delta > IMPLAUSIBLE_DELAY_S:
                hop.anomalies.append(f"implausibly long delay: {delta / 3600:.1f} hours")
        prev_ts = hop.timestamp


def check_against_date_header(hops: list[Hop], date_header: datetime | None) -> list[str]:
    """Message-level warnings comparing hop times to the Date: header."""
    warnings: list[str] = []
    if date_header is None:
        return warnings
    stamped = [h for h in hops if h.timestamp is not None]
    if not stamped:
        return warnings
    first = stamped[0]
    last = stamped[-1]
    delta_first = (first.timestamp - date_header).total_seconds()  # type: ignore[operator]
    if delta_first < -OUT_OF_ORDER_TOLERANCE_S:
        warnings.append(
            f"Date header is {abs(delta_first):.0f}s AFTER the earliest Received timestamp "
            "(Date may be forged or the sender's clock is wrong)"
        )
    elif delta_first > IMPLAUSIBLE_DELAY_S:
        warnings.append(
            f"Date header is {delta_first / 3600:.1f} hours before the earliest Received "
            "timestamp (composed long before sending, or Date is backdated)"
        )
    if last.timestamp is not None and (last.timestamp - date_header).total_seconds() < -3600:
        warnings.append("Date header is more than an hour after final delivery")
    return warnings


def _host_domain(host: str | None) -> str | None:
    if not host:
        return None
    host = host.lower().strip("[]").rstrip(".")
    if _is_ip(host):
        return None
    return registrable_domain(host)


def _matches_any(domain: str | None, suffixes: tuple[str, ...] | list[str] | set[str]) -> bool:
    if not domain:
        return False
    for s in suffixes:
        s = s.lower().lstrip(".")
        if domain == s or domain.endswith("." + s):
            return True
    return False


def mark_trust(hops: list[Hop], recipient_domains: set[str]) -> int | None:
    """Mark recipient-side hops as trusted. Returns the boundary hop index.

    The boundary is the oldest trusted hop, i.e. the first server that we
    believe belongs to the recipient's infrastructure. Its ``from_ip`` is the
    connecting IP that infrastructure actually observed.
    """
    if not hops:
        return None
    recipient_domains = {d.lower().lstrip("@") for d in recipient_domains if d}
    boundary: int | None = None
    anchor_domain: str | None = None

    for hop in reversed(hops):
        by_host = (hop.by_host or "").lower().strip("[]").rstrip(".")
        by_dom = _host_domain(hop.by_host)
        reason = ""
        if by_host and _matches_any(by_host, recipient_domains):
            reason = f"'by' host belongs to recipient domain ({by_host})"
        elif boundary is None and hop.index == len(hops) - 1:
            # The newest header was written by the system the message was
            # exported from. It is the one hop we can always attribute.
            reason = "final delivery hop (written by the mailbox system the message came from)"
        elif by_host and _matches_any(by_host, _PROVIDER_SUFFIXES):
            reason = f"'by' host is a known mailbox provider/gateway ({by_dom})"
        elif anchor_domain and by_dom == anchor_domain:
            reason = f"'by' host shares domain with final delivery server ({by_dom})"
        elif not hop.from_host and not hop.from_ip and not hop.from_helo:
            # Pure internal transfer ("Received: by X with SMTP id ...") with no
            # 'from' clause: only ever written by the system holding the mail.
            reason = "internal transfer with no 'from' clause, following a trusted hop"
        elif by_dom is None and hop.by_host and _ip_is_private(hop.from_ip or ""):
            reason = "internal relay (private source address) following a trusted hop"
        if reason:
            hop.trusted = True
            hop.trust_reason = reason
            boundary = hop.index
            if anchor_domain is None and by_dom:
                anchor_domain = by_dom
        else:
            break  # trust is contiguous from the top; stop at the first foreign hop
    for hop in hops:
        if not hop.trusted:
            hop.trust_reason = "below trust boundary: written by an unverified party"
    return boundary


_NON_PUBLIC_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
        "::ffff:0:0/96",
    )
]
"""Explicit list rather than ``is_private`` so the RFC 5737 documentation
ranges used in test material are treated as ordinary public addresses."""


def _ip_is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _NON_PUBLIC_NETS if addr.version == net.version)


def origin_candidates(
    hops: list[Hop],
    boundary: int | None,
    headers: list[tuple[str, str]],
) -> list[OriginCandidate]:
    """Rank possible originating IPs with explicit provenance."""
    out: list[OriginCandidate] = []
    seen: set[str] = set()

    def add(ip: str | None, source: str, conf: Confidence, note: str) -> None:
        if not ip or ip in seen:
            return
        seen.add(ip)
        out.append(
            OriginCandidate(ip=ip, source=source, confidence=conf, note=note, is_private=_ip_is_private(ip))
        )

    # 1. First external hop: the IP that connected to the recipient-side boundary.
    if boundary is not None:
        # Walk forward from the boundary skipping private/internal IPs.
        for hop in hops[boundary:]:
            if hop.from_ip and not _ip_is_private(hop.from_ip):
                add(
                    hop.from_ip,
                    f"hop:{hop.index} first external hop",
                    Confidence.LIKELY,
                    "This IP connected directly to recipient-side infrastructure; the "
                    "connection is real but the host may be a relay or a compromised server.",
                )
                break
            if hop.from_ip:
                add(
                    hop.from_ip,
                    f"hop:{hop.index} internal address at boundary",
                    Confidence.UNVERIFIED,
                    "Private/internal address recorded at the trust boundary; the real "
                    "external hop is probably older but unverified.",
                )

    # 2. Earliest Received header in the chain (may be forged).
    if hops:
        first = hops[0]
        if first.from_ip:
            conf = Confidence.LIKELY if first.trusted else Confidence.UNVERIFIED
            add(
                first.from_ip,
                "hop:0 earliest Received header",
                conf,
                "Earliest hop in the chain."
                + ("" if first.trusted else " Below the trust boundary; could be fabricated."),
            )

    # 3. Vendor X-headers that claim an origin.
    for name, value in headers:
        if name.lower() in {h.lower() for h in ORIGIN_IP_HEADERS}:
            ip = _first_ip(value)
            add(
                ip,
                f"header:{name}",
                Confidence.UNVERIFIED,
                "Set by whichever server chose to add this header; it is not "
                "authenticated and is trivially forgeable.",
            )
    return out
