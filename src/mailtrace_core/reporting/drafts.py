"""Ready-to-send report drafts. Nothing here transmits anything.

Drafts are produced as structured fields (for web forms such as IC3 and
FTC ReportFraud) or as :class:`EmailDraft` objects (APWG, registrar and
hosting abuse desks). The GUI and CLI hand them to the examiner as text, a
``mailto:`` link, or an ``.eml`` draft file that the default mail client
opens as an unsent message with attachments.
"""

from __future__ import annotations

import mimetypes
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import quote

from mailtrace_core.case.settings import Settings
from mailtrace_core.models import Confidence
from mailtrace_core.reporting.models import Report
from mailtrace_core.util.defang import defang_email, defang_ip

APWG_ADDRESS = "reportphishing@apwg.org"
IC3_URL = "https://www.ic3.gov"
FTC_URL = "https://reportfraud.ftc.gov"


@dataclass(slots=True)
class EmailDraft:
    kind: str
    """``apwg``, ``abuse-registrar``, ``abuse-hosting``, ``ic3``, ``ftc``."""
    title: str
    to: list[str]
    subject: str
    body: str
    cc: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    notes: str = ""
    """Guidance shown to the examiner (e.g. where to paste, what to add)."""
    fields: list[tuple[str, str, str]] = field(default_factory=list)
    """(section, field, value) triples for web forms."""


def _signature(settings: Settings, report: Report) -> str:
    lines = [
        settings.reporter_name or report.meta.examiner or "",
        report.meta.case_agency or report.meta.agency_name or "",
        settings.reporter_email,
        settings.reporter_phone,
    ]
    return "\n".join(x for x in lines if x)


def _first_origin(report: Report) -> str | None:
    for c in report.result.email.origin_candidates:
        if c.confidence is Confidence.LIKELY:
            return c.ip
    return report.result.email.origin_candidates[0].ip if report.result.email.origin_candidates else None


def _narrative(report: Report) -> str:
    pe = report.result.email
    v = report.verdict
    who = ""
    if pe.from_:
        who = (
            f'"{pe.from_.display_name}" <{defang_email(pe.from_.address)}>'
            if pe.from_.display_name
            else defang_email(pe.from_.address)
        )
    date = pe.date.strftime("%Y-%m-%d %H:%M %Z") if pe.date else (pe.header("Date") or "unknown date")
    lines = [
        f"On {date} an email was received by {', '.join(defang_email(a.address) for a in pe.to) or 'the victim'} "
        f"purporting to be from {who or 'an unknown sender'}"
        + (f' with the subject "{pe.subject}".' if pe.subject else "."),
        f"Assessment: {v.label} (confidence: {v.confidence.value}). {v.sender_assessment} (confidence: {v.sender_confidence.value}).",
    ]
    origin = _first_origin(report)
    if origin:
        lines.append(
            f"The message was delivered to the recipient's mail system from IP address {origin} "
            "(from the Received headers; see technical details)."
        )
    keys = [k for k in report.key_observations][:6]
    if keys:
        lines.append("Key indicators: " + "; ".join(keys) + ".")
    return "\n".join(lines)


def _indicator_block(report: Report, defang: bool = True) -> str:
    pe = report.result.email
    out = [
        "Indicators (defanged; replace [.] with . and hxxp with http when entering into forms):"
        if defang
        else "Indicators:"
    ]
    if pe.from_:
        out.append(f"  From address: {defang_email(pe.from_.address) if defang else pe.from_.address}")
    for a in pe.reply_to:
        out.append(f"  Reply-To: {defang_email(a.address) if defang else a.address}")
    if pe.return_path and pe.return_path.address:
        out.append(
            f"  Return-Path: {defang_email(pe.return_path.address) if defang else pe.return_path.address}"
        )
    origin = _first_origin(report)
    if origin:
        out.append(f"  Originating IP: {defang_ip(origin) if defang else origin}")
    seen = set()
    for u in pe.urls:
        if u.scheme in {"http", "https"} and u.normalized not in seen:
            seen.add(u.normalized)
            out.append(f"  URL: {u.defanged if defang else u.normalized}")
    for att in pe.attachments:
        out.append(f"  Attachment: {att.filename} ({att.size} bytes) SHA-256 {att.sha256}")
    if pe.message_id:
        out.append(f"  Message-ID: {pe.message_id}")
    return "\n".join(out)


# ---------------------------------------------------------------------- IC3
def ic3_draft(report: Report, settings: Settings) -> EmailDraft:
    pe = report.result.email
    origin = _first_origin(report)
    urls = [u.normalized for u in pe.urls if u.scheme in {"http", "https"}]
    fields: list[tuple[str, str, str]] = [
        (
            "Victim information",
            "Name / address / phone / email",
            "[complainant or victim details - enter manually]",
        ),
        ("Victim information", "Business name (if applicable)", ""),
        (
            "Incident description",
            "Date of incident",
            pe.date.strftime("%m/%d/%Y") if pe.date else (pe.header("Date") or ""),
        ),
        ("Incident description", "How were you contacted?", "Email"),
        (
            "Incident description",
            "Description of incident",
            _narrative(report) + "\n\n" + _indicator_block(report, defang=False),
        ),
        ("Incident description", "Did you lose money? / amount", "[enter if known]"),
        ("Subject information", "Email address used by the subject", pe.from_.address if pe.from_ else ""),
        (
            "Subject information",
            "Other email addresses (Reply-To / Return-Path)",
            ", ".join(
                dict.fromkeys(
                    [a.address for a in pe.reply_to]
                    + ([pe.return_path.address] if pe.return_path and pe.return_path.address else [])
                )
            ),
        ),
        ("Subject information", "Website / URL(s)", "\n".join(urls)),
        ("Subject information", "IP address", origin or ""),
        ("Subject information", "Name / alias used", pe.from_.display_name if pe.from_ else ""),
        ("Other information", "Email header / Message-ID", pe.message_id or ""),
        (
            "Other information",
            "Attachments (name / SHA-256)",
            "\n".join(f"{a.filename} / {a.sha256}" for a in pe.attachments),
        ),
        (
            "Other information",
            "Reporting agency / case number",
            f"{report.meta.case_agency or report.meta.agency_name} / {report.meta.case_number}".strip(" /"),
        ),
        ("Other information", "MailTrace report ID", report.meta.report_id),
    ]
    body = "\n".join(f"[{s}] {f}:\n{v}\n" for s, f, v in fields)
    return EmailDraft(
        kind="ic3",
        title="IC3 complaint (ic3.gov) - field-by-field",
        to=[],
        subject="IC3 complaint data",
        body=body,
        fields=fields,
        notes=f"IC3 accepts complaints only through its web form at {IC3_URL}. Paste each value into the matching field. "
        "The description field carries the plain-language narrative and the raw (non-defanged) indicators. "
        "Do not paste the full .eml into the form; keep it as evidence in the case folder.",
    )


# ---------------------------------------------------------------------- FTC
def ftc_draft(report: Report, settings: Settings) -> EmailDraft:
    pe = report.result.email
    urls = [u.normalized for u in pe.urls if u.scheme in {"http", "https"}]
    fields: list[tuple[str, str, str]] = [
        ("What happened", "Category", "Phishing / imposter scam (email)"),
        ("What happened", "How did they contact you?", "Email"),
        ("What happened", "Date", pe.date.strftime("%m/%d/%Y") if pe.date else ""),
        ("What happened", "Did you pay or lose money?", "[enter if known]"),
        ("What happened", "Details", _narrative(report) + "\n\n" + _indicator_block(report, defang=False)),
        (
            "Who scammed you",
            "Company or person they claimed to be",
            pe.from_.display_name if pe.from_ else "",
        ),
        ("Who scammed you", "Email address", pe.from_.address if pe.from_ else ""),
        ("Who scammed you", "Website", urls[0] if urls else ""),
        ("Who scammed you", "Other contact details (Reply-To)", ", ".join(a.address for a in pe.reply_to)),
        ("About you", "Reporter", "[complainant details - enter manually]"),
    ]
    body = "\n".join(f"[{s}] {f}:\n{v}\n" for s, f, v in fields)
    return EmailDraft(
        kind="ftc",
        title="FTC ReportFraud (reportfraud.ftc.gov) - field-by-field",
        to=[],
        subject="FTC report data",
        body=body,
        fields=fields,
        notes=f"ReportFraud accepts reports only through its web form at {FTC_URL}. Paste each value into the matching step.",
    )


# --------------------------------------------------------------------- APWG
def apwg_draft(report: Report, settings: Settings, eml_path: str | None) -> EmailDraft:
    pe = report.result.email
    body = (
        "Phishing report submitted to the Anti-Phishing Working Group.\n\n"
        + _narrative(report)
        + "\n\n"
        + _indicator_block(report)
        + "\n\n"
        "The original message is attached as a .eml file (unaltered, forwarded as attachment).\n\n"
        f"Reference: {report.meta.report_id}\n\n" + _signature(settings, report)
    )
    return EmailDraft(
        kind="apwg",
        title="APWG forwarding (reportphishing@apwg.org)",
        to=[APWG_ADDRESS],
        subject=f"Phishing report: {pe.subject or '(no subject)'}"[:200],
        body=body,
        attachments=[eml_path] if eml_path else [],
        notes="APWG asks that the original message be forwarded as an attachment, not inline. Use 'Save .eml draft' "
        "so the attachment is included; a mailto: link cannot carry attachments.",
    )


# -------------------------------------------------------------------- Abuse
def abuse_drafts(report: Report, settings: Settings, eml_path: str | None) -> list[EmailDraft]:
    en = report.result.enrichment
    pe = report.result.email
    drafts: list[EmailDraft] = []
    if en is None:
        return drafts
    sender_domains = {a.domain for a in [pe.from_, pe.return_path, *pe.reply_to] if a and a.domain}
    seen: set[str] = set()

    def make(kind: str, to: str, what: str, matched: str, title: str) -> None:
        if not to or to.lower() in seen:
            return
        seen.add(to.lower())
        body = (
            f"To the abuse desk,\n\nI am reporting abuse of infrastructure under your responsibility: {what}.\n\n"
            + _narrative(report)
            + "\n\n"
            + _indicator_block(report)
            + "\n\n"
            f"Identified via: {matched}.\n\n"
            "Requested action:\n"
            "  1. Preserve all account, registration, login and payment records associated with this resource "
            "pending legal process (a formal preservation request under 18 U.S.C. 2703(f) will follow where applicable).\n"
            "  2. Take appropriate action against the abusive resource in accordance with your terms of service.\n"
            "  3. Provide the correct contact for legal process if it differs from this address.\n\n"
            "The original message headers are attached. Please reference the case number below in any reply.\n\n"
            f"Case reference: {report.meta.case_number or report.meta.report_id}\n\n"
            + _signature(settings, report)
        )
        drafts.append(
            EmailDraft(
                kind=kind,
                title=title,
                to=[to],
                subject=f"Abuse report and preservation request: {what}"[:200],
                body=body,
                attachments=[eml_path] if eml_path else [],
                notes="Contact taken from the RDAP/WHOIS record. Confirm it is current before sending.",
            )
        )

    for d in en.domains:
        if d.registrar_abuse_email:
            is_sender = d.domain in sender_domains
            what = f"the domain {d.domain} ({'used as the sender identity' if is_sender else 'linked in a phishing message'})"
            make(
                "abuse-registrar",
                d.registrar_abuse_email,
                what,
                f"registrar {d.registrar or ''} abuse contact for {d.domain}",
                f"Registrar abuse: {d.registrar or d.registrar_abuse_email} ({d.domain})",
            )
    for ip in en.ips:
        if ip.abuse_contacts and not ip.is_private:
            role = (
                "origin of the message"
                if any(r.startswith("origin") for r in ip.roles)
                else (
                    "host of a linked phishing site"
                    if any(r.startswith("url host") for r in ip.roles)
                    else "a relay in the message path"
                )
            )
            what = f"the IP address {ip.ip} ({role})"
            make(
                "abuse-hosting",
                ip.abuse_contacts[0],
                what,
                f"RDAP abuse contact for {ip.network_name or ip.ip}",
                f"Network abuse: {ip.network_name or ip.asn_org or ip.ip} ({ip.ip})",
            )
    return drafts


def all_drafts(report: Report, settings: Settings, eml_path: str | None) -> list[EmailDraft]:
    return [
        ic3_draft(report, settings),
        ftc_draft(report, settings),
        apwg_draft(report, settings, eml_path),
        *abuse_drafts(report, settings, eml_path),
    ]


# ------------------------------------------------------------------ delivery
def mailto_url(draft: EmailDraft) -> str:
    params = [f"subject={quote(draft.subject)}", f"body={quote(draft.body)}"]
    if draft.cc:
        params.append("cc=" + quote(",".join(draft.cc)))
    return f"mailto:{','.join(draft.to)}?" + "&".join(params)


def write_eml_draft(draft: EmailDraft, path: Path, from_addr: str = "") -> Path:
    """Write an unsent RFC 5322 draft (``X-Unsent: 1``) that mail clients open for editing."""
    msg = EmailMessage()
    msg["X-Unsent"] = "1"
    if from_addr:
        msg["From"] = from_addr
    if draft.to:
        msg["To"] = ", ".join(draft.to)
    if draft.cc:
        msg["Cc"] = ", ".join(draft.cc)
    msg["Subject"] = draft.subject
    msg.set_content(draft.body)
    for att in draft.attachments:
        p = Path(att)
        if not p.is_file():
            continue
        mime = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
        if p.suffix.lower() == ".eml":
            mime = "message/rfc822"
        maintype, subtype = mime.split("/", 1)
        msg.add_attachment(p.read_bytes(), maintype=maintype, subtype=subtype, filename=p.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(msg.as_bytes())
    return path


def draft_as_text(draft: EmailDraft) -> str:
    head = [
        f"To: {', '.join(draft.to)}" if draft.to else "",
        f"Subject: {draft.subject}",
        f"Attachments: {', '.join(Path(a).name for a in draft.attachments)}" if draft.attachments else "",
    ]
    return "\n".join(x for x in head if x) + "\n\n" + draft.body
