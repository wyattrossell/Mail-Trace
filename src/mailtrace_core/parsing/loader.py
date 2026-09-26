"""Load .eml, Outlook .msg, and pasted raw headers into :class:`ParsedEmail`.

Loaders only populate the message-level fields (headers, addresses, bodies,
attachments). Hop analysis, authentication and URL inventory are layered on
by :mod:`mailtrace_core.parsing.pipeline`.
"""

from __future__ import annotations

import email
import email.header
import email.policy
import email.utils
import re
from email.message import Message
from pathlib import Path

from mailtrace_core.models import Address, ParsedEmail, SourceFormat
from mailtrace_core.parsing.attachments import inventory_attachments, record_from_bytes
from mailtrace_core.parsing.body import extract_bodies
from mailtrace_core.util.timeutil import parse_rfc2822

_POLICY = email.policy.compat32.clone(raise_on_defect=False)
_FOLD_RE = re.compile(r"\r?\n[ \t]+")


def unfold(value: str) -> str:
    return _FOLD_RE.sub(" ", value).strip()


def decode_header_value(value: str) -> str:
    """Decode RFC 2047 encoded words; fall back to the raw text on failure."""
    value = unfold(value)
    if "=?" not in value:
        return value
    try:
        return str(email.header.make_header(email.header.decode_header(value)))
    except Exception:  # noqa: BLE001
        return value


def _raw_headers(msg: Message) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for name, value in msg.raw_items():
        out.append((name, decode_header_value(str(value))))
    return out


def parse_addresses(value: str | None) -> list[Address]:
    if not value:
        return []
    out: list[Address] = []
    for name, addr in email.utils.getaddresses([value]):
        name = name.strip().strip('"')
        addr = addr.strip()
        if not addr and not name:
            continue
        # getaddresses can leave a display name with the address inside it.
        if not addr and "@" in name:
            addr, name = name, ""
        out.append(Address(display_name=name, address=addr))
    return out


def _first_address(value: str | None) -> Address | None:
    addrs = parse_addresses(value)
    return addrs[0] if addrs else None


def _return_path(value: str | None) -> Address | None:
    if value is None:
        return None
    v = unfold(value).strip()
    if v in {"<>", ""}:
        return Address(display_name="", address="")
    return _first_address(v)


def _populate_from_message(pe: ParsedEmail, msg: Message) -> None:
    pe.headers = _raw_headers(msg)
    pe.message_id = pe.header("Message-ID")
    pe.subject = pe.header("Subject")
    pe.date = parse_rfc2822(pe.header("Date"))
    if pe.header("Date") and pe.date is None:
        pe.warnings.append("Date header could not be parsed")
    pe.from_ = _first_address(pe.header("From"))
    pe.sender = _first_address(pe.header("Sender"))
    pe.reply_to = parse_addresses(pe.header("Reply-To"))
    pe.return_path = _return_path(pe.header("Return-Path"))
    pe.to = parse_addresses(pe.header("To"))
    pe.cc = parse_addresses(pe.header("Cc"))
    if len(pe.header_all("From")) > 1:
        pe.warnings.append("multiple From headers present")
    if pe.from_ is None:
        pe.warnings.append("no parseable From address")


def load_eml_bytes(data: bytes, name: str = "message.eml") -> ParsedEmail:
    msg = email.message_from_bytes(data, policy=_POLICY)
    pe = ParsedEmail(source_format=SourceFormat.EML, source_name=name, raw_bytes=data)
    _populate_from_message(pe, msg)
    pe.body_text, pe.body_html = extract_bodies(msg)
    pe.attachments = inventory_attachments(msg)
    if msg.defects:
        for d in msg.defects:
            pe.warnings.append(f"MIME defect: {type(d).__name__}")
    return pe


def load_raw_headers(text: str, name: str = "pasted-headers") -> ParsedEmail:
    """Parse a pasted block of headers (with or without a body after them)."""
    # Normalise line endings and strip leading blank lines/BOM.
    cleaned = text.replace("\r\n", "\n").replace("\r", "\n").lstrip("﻿\n")
    # Some webmail "show original" views indent continuation lines with tabs
    # already; nothing to do. If the first line does not look like a header,
    # try to find the first header line.
    lines = cleaned.split("\n")
    start = 0
    for i, line in enumerate(lines):
        if re.match(r"^[A-Za-z0-9-]+:\s", line) or re.match(r"^[A-Za-z0-9-]+:$", line):
            start = i
            break
    cleaned = "\n".join(lines[start:])
    data = cleaned.encode("utf-8", errors="replace")
    msg = email.message_from_bytes(data, policy=_POLICY)
    pe = ParsedEmail(source_format=SourceFormat.RAW_HEADERS, source_name=name, raw_bytes=data)
    _populate_from_message(pe, msg)
    pe.body_text, pe.body_html = extract_bodies(msg)
    pe.attachments = inventory_attachments(msg)
    if not pe.headers:
        pe.warnings.append("no headers recognised in pasted text")
    if not pe.body_text and not pe.body_html:
        pe.warnings.append("headers only: body-dependent checks (DKIM body hash, links) skipped")
    return pe


def load_msg_path(path: Path) -> ParsedEmail:
    """Load an Outlook .msg via extract-msg. Attachments are read, never opened."""
    import extract_msg

    pe = ParsedEmail(source_format=SourceFormat.MSG, source_name=path.name)
    msg = extract_msg.openMsg(str(path))
    try:
        header_text: str = getattr(msg, "headerText", "") or ""
        if header_text.strip():
            hdr_msg = email.message_from_string(header_text, policy=_POLICY)
            _populate_from_message(pe, hdr_msg)
            pe.raw_bytes = b""  # .msg loses the signed wire form; DKIM cannot be re-verified
        else:
            pe.warnings.append(
                "no transport headers stored in .msg (likely a sent item or draft); "
                "hop and authentication analysis unavailable"
            )
        # Fill in from MAPI properties where headers were absent.
        if pe.subject is None:
            pe.subject = getattr(msg, "subject", None)
        if pe.from_ is None:
            sender = getattr(msg, "sender", None)
            if sender:
                pe.from_ = _first_address(str(sender))
        if not pe.to:
            pe.to = parse_addresses(getattr(msg, "to", None) or "")
        if not pe.cc:
            pe.cc = parse_addresses(getattr(msg, "cc", None) or "")
        if pe.date is None:
            d = getattr(msg, "date", None)
            if d is not None:
                pe.date = d if hasattr(d, "tzinfo") else parse_rfc2822(str(d))
        if pe.message_id is None:
            pe.message_id = getattr(msg, "messageId", None)

        body = getattr(msg, "body", None)
        pe.body_text = body if isinstance(body, str) else ""
        html = getattr(msg, "htmlBody", None)
        if isinstance(html, bytes):
            html = html.decode("utf-8", errors="replace")
        pe.body_html = html if isinstance(html, str) else ""

        for i, att in enumerate(getattr(msg, "attachments", []) or []):
            data = getattr(att, "data", None)
            if not isinstance(data, bytes):
                # Embedded .msg or unknown attachment type; record what we can.
                pe.warnings.append(
                    f"attachment {i} is an embedded message/object; not expanded (passive mode)"
                )
                continue
            fname = (
                getattr(att, "longFilename", None)
                or getattr(att, "shortFilename", None)
                or getattr(att, "name", None)
                or f"attachment-{i}"
            )
            pe.attachments.append(
                record_from_bytes(str(fname), data, getattr(att, "mimetype", None), index=i)
            )
    finally:
        try:
            msg.close()
        except Exception:  # noqa: BLE001
            pass
    pe.warnings.append("source is .msg: DKIM re-verification not possible (no wire-format bytes)")
    return pe


def load_path(path: Path, fmt: SourceFormat | None = None) -> ParsedEmail:
    from mailtrace_core.case.manager import sniff_format

    path = Path(path)
    fmt = fmt or sniff_format(path)
    if fmt is SourceFormat.MSG:
        return load_msg_path(path)
    data = path.read_bytes()
    if fmt is SourceFormat.RAW_HEADERS:
        return load_raw_headers(data.decode("utf-8", errors="replace"), path.name)
    return load_eml_bytes(data, path.name)
