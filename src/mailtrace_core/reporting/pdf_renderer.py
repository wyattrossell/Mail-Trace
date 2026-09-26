"""PDF report with ReportLab.

Every page carries the agency header (with optional logo), classification,
report ID, generation timestamp, tool version and "Page n of N".
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from mailtrace_core.models import Confidence, Severity
from mailtrace_core.reporting.models import Report
from mailtrace_core.reporting.route_diagram import route_drawing
from mailtrace_core.util.defang import defang_email, defang_ip, defang_url

PAGE = letter
MARGIN = 0.65 * inch
HEADER_H = 0.75 * inch
FOOTER_H = 0.45 * inch
USABLE_W = PAGE[0] - 2 * MARGIN

_SEV_COLOUR = {
    Severity.HIGH: "#c62828",
    Severity.MEDIUM: "#b26a00",
    Severity.LOW: "#1565c0",
    Severity.INFO: "#5f6877",
}
_CONF_COLOUR = {
    Confidence.CONFIRMED: "#1b8a4c",
    Confidence.LIKELY: "#b26a00",
    Confidence.UNVERIFIED: "#5f6877",
}


def _styles() -> dict[str, ParagraphStyle]:
    ss = getSampleStyleSheet()
    base = ParagraphStyle("base", parent=ss["Normal"], fontName="Helvetica", fontSize=9.5, leading=12.5)
    return {
        "body": base,
        "small": ParagraphStyle(
            "small", parent=base, fontSize=8, leading=10, textColor=colors.HexColor("#5f6877")
        ),
        "cell": ParagraphStyle("cell", parent=base, fontSize=8, leading=10),
        "mono": ParagraphStyle("mono", parent=base, fontName="Courier", fontSize=7.6, leading=9.5),
        "h1": ParagraphStyle(
            "h1", parent=base, fontName="Helvetica-Bold", fontSize=15, leading=19, spaceAfter=6
        ),
        "h2": ParagraphStyle(
            "h2",
            parent=base,
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            spaceBefore=12,
            spaceAfter=5,
            textColor=colors.HexColor("#1c2128"),
        ),
        "h3": ParagraphStyle(
            "h3", parent=base, fontName="Helvetica-Bold", fontSize=10, leading=13, spaceBefore=8, spaceAfter=3
        ),
        "verdict": ParagraphStyle(
            "verdict", parent=base, fontName="Helvetica-Bold", fontSize=11.5, leading=15
        ),
        "bullet": ParagraphStyle("bullet", parent=base, leftIndent=12, bulletIndent=2, alignment=TA_LEFT),
    }


def _p(text: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "")).replace("\n", "<br/>"), style)


def _badge(text: str, colour: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(f'<font color="{colour}"><b>{escape(text)}</b></font>', style)


def _table(rows: list[list[Any]], widths: list[float], header: bool = True, zebra: bool = True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9cfd8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f5")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]
    if zebra:
        for i in range(1 if header else 0, len(rows)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fafbfc")))
    t.setStyle(TableStyle(style))
    return t


class _NumberedCanvas(rl_canvas.Canvas):
    """Two-pass canvas so the footer can print "Page n of N"."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._report: Report = kwargs.pop("report")
        super().__init__(*args, **kwargs)
        self._saved: list[dict[str, Any]] = []

    def showPage(self) -> None:  # noqa: N802
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            self._draw_chrome(total)
            super().showPage()
        super().save()

    def _draw_chrome(self, total: int) -> None:
        m = self._report.meta
        w, h = PAGE
        self.saveState()
        # header
        x = MARGIN
        top = h - MARGIN + 0.15 * inch
        if m.logo_path:
            try:
                from reportlab.lib.utils import ImageReader

                img = ImageReader(m.logo_path)
                iw, ih = img.getSize()
                lh = 0.5 * inch
                lw = lh * iw / ih
                self.drawImage(img, x, top - lh, lw, lh, mask="auto")
                x += lw + 8
            except Exception:  # noqa: BLE001 - a bad logo must not block the report
                pass
        self.setFont("Helvetica-Bold", 11)
        self.drawString(x, top - 12, m.agency_name or "MailTrace")
        self.setFont("Helvetica", 8)
        if m.agency_line2:
            self.drawString(x, top - 23, m.agency_line2)
        self.setFont("Helvetica-Bold", 10)
        self.drawRightString(w - MARGIN, top - 12, "Email Forensic Analysis Report")
        self.setFont("Helvetica", 7.5)
        self.drawRightString(w - MARGIN, top - 23, f"Report ID {m.report_id}")
        if m.classification:
            self.setFillColor(colors.HexColor("#c62828"))
            self.setFont("Helvetica-Bold", 7.5)
            self.drawCentredString(w / 2, h - 0.3 * inch, m.classification)
            self.setFillColor(colors.black)
        self.setStrokeColor(colors.HexColor("#1c2128"))
        self.setLineWidth(0.8)
        self.line(MARGIN, top - 30, w - MARGIN, top - 30)
        # footer
        self.setStrokeColor(colors.HexColor("#c9cfd8"))
        self.setLineWidth(0.5)
        self.line(MARGIN, MARGIN - 6, w - MARGIN, MARGIN - 6)
        self.setFont("Helvetica", 7)
        self.setFillColor(colors.HexColor("#5f6877"))
        left = m.report_id + (f"  ·  {m.footer_note}" if m.footer_note else "")
        self.drawString(MARGIN, MARGIN - 17, left)
        self.drawCentredString(
            w / 2, MARGIN - 17, f"Generated {m.generated_at}  ·  MailTrace v{m.tool_version}"
        )
        self.drawRightString(w - MARGIN, MARGIN - 17, f"Page {self._pageNumber} of {total}")
        if m.classification:
            self.drawCentredString(w / 2, MARGIN - 27, m.classification)
        self.restoreState()


def _findings_table(report: Report, st: dict[str, ParagraphStyle]) -> Table:
    rows: list[list[Any]] = [
        [
            _p("Sev.", st["cell"]),
            _p("Conf.", st["cell"]),
            _p("Rule", st["cell"]),
            _p("Finding", st["cell"]),
            _p("Explanation and evidence", st["cell"]),
        ]
    ]
    for f in report.result.findings:
        ev = "".join(
            f"<br/>• <font name='Courier' size='7'>{escape(e.source)}</font>: {escape(e.value[:160])}"
            + (f" ({escape(e.note)})" if e.note else "")
            for e in f.evidence[:4]
        )
        rows.append(
            [
                _badge(f.severity.value, _SEV_COLOUR[f.severity], st["cell"]),
                _badge(f.confidence.value, _CONF_COLOUR[f.confidence], st["cell"]),
                _p(f.rule_id, st["cell"]),
                _p(f.title, st["cell"]),
                Paragraph(escape(f.explanation) + ev, st["cell"]),
            ]
        )
    if len(rows) == 1:
        rows.append([_p("No findings.", st["cell"]), "", "", "", ""])
    return _table(rows, [0.5 * inch, 0.65 * inch, 0.55 * inch, 1.7 * inch, USABLE_W - 3.4 * inch])


def build_story(report: Report) -> list[Any]:
    st = _styles()
    r, m, v, pe, au, en = (
        report,
        report.meta,
        report.verdict,
        report.result.email,
        report.result.email.auth,
        report.result.enrichment,
    )
    s: list[Any] = []

    s.append(_p("1. Case information", st["h2"]))
    meta_rows = [
        [
            _p("Case number", st["cell"]),
            _p(m.case_number or "n/a", st["cell"]),
            _p("Examiner", st["cell"]),
            _p(m.examiner or "n/a", st["cell"]),
        ],
        [
            _p("Agency", st["cell"]),
            _p(m.case_agency or m.agency_name or "n/a", st["cell"]),
            _p("Generated (UTC)", st["cell"]),
            _p(m.generated_at, st["cell"]),
        ],
        [
            _p("Tool", st["cell"]),
            _p(f"MailTrace v{m.tool_version}", st["cell"]),
            _p("Case folder", st["cell"]),
            _p(m.case_root or "none", st["mono"]),
        ],
    ]
    s.append(
        _table(
            meta_rows, [1.1 * inch, 2.4 * inch, 1.1 * inch, USABLE_W - 4.6 * inch], header=False, zebra=False
        )
    )
    s.append(_p("Evidence", st["h3"]))
    ev_rows: list[list[Any]] = [
        [_p(h, st["cell"]) for h in ("ID", "File", "Size", "SHA-256 / MD5", "Ingested (UTC)")]
    ]
    for e in r.evidence:
        ev_rows.append(
            [
                _p(e.item_id, st["cell"]),
                _p(e.filename, st["cell"]),
                _p(str(e.size), st["cell"]),
                _p(f"{e.sha256}\n{e.md5}", st["mono"]),
                _p(e.ingested_at.isoformat(), st["cell"]),
            ]
        )
    if not r.evidence:
        ev_rows.append(
            [
                _p(f"Analysed from {pe.source_name} without case intake; no hashes recorded.", st["cell"]),
                "",
                "",
                "",
                "",
            ]
        )
    s.append(_table(ev_rows, [0.5 * inch, 1.6 * inch, 0.6 * inch, 3.6 * inch, USABLE_W - 6.3 * inch]))

    s.append(_p("2. Executive summary", st["h2"]))
    verdict_tbl = Table(
        [
            [
                Paragraph(
                    f"<b>{escape(v.label)}</b> &nbsp; <font color='{_CONF_COLOUR[v.confidence]}'><b>{v.confidence.value}</b></font><br/>"
                    f"{escape(v.sender_assessment)} &nbsp; <font color='{_CONF_COLOUR[v.sender_confidence]}'><b>{v.sender_confidence.value}</b></font>"
                    + (
                        f"<br/><font size='7.5' color='#5f6877'>Basis: {escape('; '.join(v.basis))}</font>"
                        if v.basis
                        else ""
                    ),
                    st["body"],
                )
            ]
        ],
        colWidths=[USABLE_W],
    )
    verdict_tbl.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 1.2, colors.HexColor("#1c2128")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    s.append(verdict_tbl)
    s.append(Spacer(1, 6))
    for para in r.executive_summary:
        s.append(_p(para, st["body"]))
        s.append(Spacer(1, 3))
    if r.key_observations:
        s.append(_p("Key observations", st["h3"]))
        for k in r.key_observations:
            s.append(Paragraph(escape(k), st["bullet"], bulletText="•"))

    s.append(_p("3. Message identity", st["h2"]))
    ident = [
        ["Subject", pe.subject or ""],
        ["From", f"{pe.from_.display_name} <{defang_email(pe.from_.address)}>" if pe.from_ else ""],
        ["Reply-To", ", ".join(defang_email(a.address) for a in pe.reply_to)],
        ["Return-Path", defang_email(pe.return_path.address) if pe.return_path else ""],
        ["To", ", ".join(defang_email(a.address) for a in pe.to)],
        ["Date header", pe.date.isoformat() if pe.date else (pe.header("Date") or "")],
        ["Message-ID", pe.message_id or ""],
    ]
    s.append(
        _table(
            [[_p(k, st["cell"]), _p(val, st["cell"])] for k, val in ident],
            [1.2 * inch, USABLE_W - 1.2 * inch],
            header=False,
        )
    )

    s.append(_p("4. Delivery route", st["h2"]))
    recipient = pe.to[0].address if pe.to else None
    s.append(route_drawing(pe.hops, recipient, max_width=USABLE_W))
    s.append(
        _p(
            "Solid boxes were written by the recipient's infrastructure; dashed boxes by other parties and may be fabricated.",
            st["small"],
        )
    )
    hop_rows: list[list[Any]] = [
        [
            _p(h, st["cell"])
            for h in ("#", "Trust", "Timestamp", "Delay", "From host / IP", "By host", "Proto", "Anomalies")
        ]
    ]
    for h in pe.hops:
        delay = f"{h.delay_seconds:+.0f}s" if h.delay_seconds is not None else ""
        hop_rows.append(
            [
                _p(str(h.index), st["cell"]),
                _p("trusted" if h.trusted else "unverified", st["cell"]),
                _p(h.timestamp.isoformat() if h.timestamp else "", st["mono"]),
                _p(delay, st["cell"]),
                _p(
                    f"{h.from_host or h.from_helo or ''}\n{defang_ip(h.from_ip) if h.from_ip else ''}",
                    st["cell"],
                ),
                _p(h.by_host or "", st["cell"]),
                _p(h.protocol or "", st["cell"]),
                _p("; ".join(h.anomalies), st["cell"]),
            ]
        )
    if len(hop_rows) == 1:
        hop_rows.append([_p("No Received headers.", st["cell"])] + [""] * 7)
    t = _table(
        hop_rows,
        [
            0.3 * inch,
            0.65 * inch,
            1.35 * inch,
            0.5 * inch,
            1.7 * inch,
            1.3 * inch,
            0.55 * inch,
            USABLE_W - 6.35 * inch,
        ],
    )
    for i, h in enumerate(pe.hops, start=1):
        if h.trusted:
            t.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), colors.HexColor("#e9f6ee"))]))
    s.append(t)
    s.append(_p("Originating IP candidates", st["h3"]))
    oc = [[_p(h, st["cell"]) for h in ("IP", "Confidence", "Source", "Note")]]
    for c in pe.origin_candidates:
        oc.append(
            [
                _p(defang_ip(c.ip) + (" (private)" if c.is_private else ""), st["mono"]),
                _badge(c.confidence.value, _CONF_COLOUR[c.confidence], st["cell"]),
                _p(c.source, st["cell"]),
                _p(c.note, st["cell"]),
            ]
        )
    if len(oc) == 1:
        oc.append([_p("None identified.", st["cell"]), "", "", ""])
    s.append(_table(oc, [1.5 * inch, 0.8 * inch, 1.9 * inch, USABLE_W - 4.2 * inch]))

    s.append(_p("5. Authentication", st["h2"]))
    ar: list[list[Any]] = [[_p(h, st["cell"]) for h in ("Check", "Result", "Domain", "Detail")]]
    if au.spf:
        ar.append(
            [
                _p("SPF (independent)", st["cell"]),
                _p(au.spf.result, st["cell"]),
                _p(au.spf.domain or "", st["cell"]),
                _p(
                    f"client IP {defang_ip(au.spf.client_ip) if au.spf.client_ip else '-'}; matched {au.spf.matched_mechanism or '-'}; {au.spf.detail}\n{au.spf.record or ''}",
                    st["cell"],
                ),
            ]
        )
    if au.dkim:
        ar.append(
            [
                _p("DKIM (independent)", st["cell"]),
                _p(au.dkim.result, st["cell"]),
                _p(f"{au.dkim.domain or ''} (s={au.dkim.selector or ''})", st["cell"]),
                _p(f"{au.dkim.detail}; signed: {', '.join(au.dkim.signed_headers)}", st["cell"]),
            ]
        )
    if au.dmarc:
        ar.append(
            [
                _p("DMARC (independent)", st["cell"]),
                _p(au.dmarc.result, st["cell"]),
                _p(au.dmarc.domain or "", st["cell"]),
                _p(
                    f"policy p={au.dmarc.policy or '-'}; {au.dmarc.detail}\n{au.dmarc.record or ''}",
                    st["cell"],
                ),
            ]
        )
    for x in au.reported:
        ar.append(
            [
                _p(f"Reported: {x.method}", st["cell"]),
                _p(x.result, st["cell"]),
                _p(x.authserv_id, st["cell"]),
                _p(x.raw, st["small"]),
            ]
        )
    s.append(_table(ar, [1.3 * inch, 0.7 * inch, 1.6 * inch, USABLE_W - 3.6 * inch]))
    if au.skipped_checks:
        s.append(_p("Skipped: " + ", ".join(au.skipped_checks), st["small"]))

    s.append(_p("6. Findings and spoofing indicators", st["h2"]))
    s.append(_findings_table(report, st))

    s.append(_p("7. Links and attachments (defanged)", st["h2"]))
    ur: list[list[Any]] = [[_p(h, st["cell"]) for h in ("Source", "URL", "Visible text", "Flags")]]
    for u in pe.urls:
        flags = [
            x
            for x, ok in (
                ("text/href mismatch", u.display_mismatch),
                ("IP host", u.is_ip_host),
                (f"IDN ({u.unicode_host})", u.is_idn),
                ("shortener", u.is_shortener),
            )
            if ok
        ]
        ur.append(
            [
                _p(u.source, st["cell"]),
                _p(u.defanged, st["mono"]),
                _p(u.display_text or "", st["cell"]),
                _p("; ".join(flags), st["cell"]),
            ]
        )
    if len(ur) == 1:
        ur.append([_p("No URLs.", st["cell"]), "", "", ""])
    s.append(_table(ur, [0.9 * inch, 3.3 * inch, 1.6 * inch, USABLE_W - 5.8 * inch]))
    at: list[list[Any]] = [
        [_p(h, st["cell"]) for h in ("Attachment", "Size", "Declared / detected", "SHA-256", "Notes")]
    ]
    for a in pe.attachments:
        at.append(
            [
                _p(a.filename, st["cell"]),
                _p(str(a.size), st["cell"]),
                _p(
                    f"{a.declared_type}\n{a.detected_type or 'unknown'}"
                    + (" MISMATCH" if a.type_mismatch else ""),
                    st["cell"],
                ),
                _p(a.sha256, st["mono"]),
                _p("; ".join(a.notes), st["cell"]),
            ]
        )
    if len(at) == 1:
        at.append([_p("No attachments.", st["cell"]), "", "", "", ""])
    s.append(_table(at, [1.3 * inch, 0.5 * inch, 1.5 * inch, 2.3 * inch, USABLE_W - 5.6 * inch]))

    s.append(_p("8. Enrichment", st["h2"]))
    if en is None:
        s.append(_p("No enrichment was performed for this report.", st["body"]))
    else:
        s.append(
            _p(
                f"{en.lookups_performed} lookups performed, {en.lookups_cached} from the case cache; started {en.started_at}, finished {en.finished_at}.",
                st["small"],
            )
        )
        if en.risk:
            s.append(_p(f"Risk score: {en.risk.score} / 100 ({en.risk.band})", st["h3"]))
            rr: list[list[Any]] = [[_p(h, st["cell"]) for h in ("Points", "Factor", "Evidence", "Source")]]
            for f in en.risk.factors:
                rr.append(
                    [
                        _p(f"{f.points:+d}", st["cell"]),
                        _p(f.name, st["cell"]),
                        _p(f.evidence, st["cell"]),
                        _p(f.source, st["cell"]),
                    ]
                )
            s.append(_table(rr, [0.55 * inch, 2.6 * inch, USABLE_W - 4.0 * inch, 0.85 * inch]))
            for n in en.risk.notes:
                s.append(_p(n, st["small"]))
        s.append(_p("IP addresses", st["h3"]))
        ir: list[list[Any]] = [
            [
                _p(h, st["cell"])
                for h in (
                    "IP / role",
                    "ASN / org / location",
                    "Network / abuse (RDAP)",
                    "Flags",
                    "Reputation",
                )
            ]
        ]
        for ip in en.ips:
            loc = " / ".join(x for x in (ip.country, ip.region, ip.city) if x)
            flags = ", ".join(
                n
                for n, ok in (("hosting", ip.hosting), ("VPN", ip.vpn), ("proxy", ip.proxy), ("Tor", ip.tor))
                if ok
            )
            ir.append(
                [
                    _p(f"{defang_ip(ip.ip)}\n{'; '.join(ip.roles)}\n{', '.join(ip.reverse_dns)}", st["cell"]),
                    _p(
                        f"{'AS' + str(ip.asn) + ' ' if ip.asn else ''}{ip.asn_org or ip.isp or ''}\n{loc}",
                        st["cell"],
                    ),
                    _p(
                        f"{ip.network_name or ''} {ip.network_cidr or ''}\n{', '.join(ip.abuse_contacts)}",
                        st["cell"],
                    ),
                    _p(flags + ("\n" + "; ".join(ip.flag_reasons) if ip.flag_reasons else ""), st["cell"]),
                    _p(
                        "\n".join(f"{rv.provider}: {rv.verdict} ({rv.summary})" for rv in ip.reputation),
                        st["cell"],
                    ),
                ]
            )
        if len(ir) == 1:
            ir.append([_p("None.", st["cell"]), "", "", "", ""])
        s.append(_table(ir, [1.7 * inch, 1.6 * inch, 1.6 * inch, 1.1 * inch, USABLE_W - 6.0 * inch]))
        s.append(_p("Domains", st["h3"]))
        dr: list[list[Any]] = [
            [
                _p(h, st["cell"])
                for h in (
                    "Domain / role",
                    "Registrar / created / age",
                    "Registrar abuse / registrant",
                    "A / MX / NS",
                    "Reputation",
                )
            ]
        ]
        for d in en.domains:
            age = f"{d.age_days} d{' NEW' if d.is_new else ''}" if d.age_days is not None else ""
            dr.append(
                [
                    _p(f"{d.domain}\n{'; '.join(d.roles)}", st["cell"]),
                    _p(f"{d.registrar or ''}\n{d.created or ''}\n{age}", st["cell"]),
                    _p(
                        f"{d.registrar_abuse_email or ''} {d.registrar_abuse_phone or ''}\n{d.registrant_org or ''} {d.registrant_country or ''}",
                        st["cell"],
                    ),
                    _p(f"A: {', '.join(d.a)}\nMX: {', '.join(d.mx)}\nNS: {', '.join(d.ns)}", st["mono"]),
                    _p(
                        "\n".join(f"{rv.provider}: {rv.verdict} ({rv.summary})" for rv in d.reputation),
                        st["cell"],
                    ),
                ]
            )
        if len(dr) == 1:
            dr.append([_p("None.", st["cell"]), "", "", "", ""])
        s.append(_table(dr, [1.6 * inch, 1.5 * inch, 1.5 * inch, 1.6 * inch, USABLE_W - 6.2 * inch]))
        reps = en.url_reputation + en.attachment_reputation
        if reps:
            s.append(_p("URL and attachment reputation (hash lookups only)", st["h3"]))
            pr: list[list[Any]] = [
                [_p(h, st["cell"]) for h in ("Provider", "Type", "Verdict", "Summary", "Target")]
            ]
            for rv in reps:
                pr.append(
                    [
                        _p(rv.provider, st["cell"]),
                        _p(rv.target_type, st["cell"]),
                        _p(rv.verdict, st["cell"]),
                        _p(rv.summary, st["cell"]),
                        _p(defang_url(rv.target) if rv.target_type == "url" else rv.target, st["mono"]),
                    ]
                )
            s.append(_table(pr, [0.9 * inch, 0.6 * inch, 0.8 * inch, 1.7 * inch, USABLE_W - 4.0 * inch]))
        if en.skipped:
            s.append(_p("Providers not consulted: " + "; ".join(en.skipped), st["small"]))

    s.append(_p("9. Legal process targets", st["h2"]))
    if en and en.legal_targets:
        s.append(_p("Preservation first. " + en.preservation_note, st["body"]))
        s.append(Spacer(1, 4))
        lr: list[list[Any]] = [
            [
                _p(h, st["cell"])
                for h in (
                    "Provider / role",
                    "Matched on",
                    "Contact / portal / jurisdiction",
                    "Records typically available",
                    "Notes",
                )
            ]
        ]
        for tg in en.legal_targets:
            verify = (
                "\nverify before use" + (f" (last verified {tg.last_verified})" if tg.last_verified else "")
                if tg.verify_before_use
                else ""
            )
            lr.append(
                [
                    _p(f"{tg.provider_name}\n{tg.role}{verify}", st["cell"]),
                    _p(tg.matched_on, st["cell"]),
                    _p(
                        "\n".join(
                            x
                            for x in (tg.portal, tg.email, tg.phone, tg.guidelines_url, tg.jurisdiction)
                            if x
                        ),
                        st["cell"],
                    ),
                    _p("\n".join("• " + rec for rec in tg.records_available), st["cell"]),
                    _p(tg.notes, st["small"]),
                ]
            )
        s.append(_table(lr, [1.5 * inch, 1.3 * inch, 1.6 * inch, 1.7 * inch, USABLE_W - 6.1 * inch]))
    else:
        s.append(
            _p(
                "No legal-process targets were identified"
                + ("" if en else " (enrichment not performed)")
                + ".",
                st["body"],
            )
        )

    s.append(_p("10. Limitations", st["h2"]))
    for lim in r.limitations:
        s.append(Paragraph(escape(lim), st["bullet"], bulletText="•"))

    s.append(PageBreak())
    s.append(_p("Appendix A. Audit log", st["h2"]))
    if r.audit_entries:
        alr: list[list[Any]] = [
            [_p(h, st["cell"]) for h in ("#", "UTC time", "Action", "Details", "Entry hash")]
        ]
        for e in r.audit_entries:
            details = "; ".join(f"{k}={val}" for k, val in e.get("details", {}).items())
            alr.append(
                [
                    _p(str(e.get("seq")), st["cell"]),
                    _p(e.get("timestamp_utc", ""), st["mono"]),
                    _p(e.get("action", ""), st["cell"]),
                    _p(details[:400], st["small"]),
                    _p(str(e.get("entry_hash", ""))[:16] + "…", st["mono"]),
                ]
            )
        s.append(_table(alr, [0.35 * inch, 1.5 * inch, 1.1 * inch, USABLE_W - 4.1 * inch, 1.15 * inch]))
    else:
        s.append(_p("No case audit log (analysis run outside a case).", st["body"]))
    s.append(_p("Appendix B. Analysis settings", st["h2"]))
    s.append(
        _table(
            [[_p(k, st["cell"]), _p(str(val), st["mono"])] for k, val in r.settings_snapshot.items()],
            [2.2 * inch, USABLE_W - 2.2 * inch],
            header=False,
        )
    )
    if pe.warnings:
        s.append(_p("Parser warnings", st["h3"]))
        for w in pe.warnings:
            s.append(Paragraph(escape(w), st["bullet"], bulletText="•"))
    return [
        KeepTogether(x) if isinstance(x, Table) and len(getattr(x, "_cellvalues", [])) <= 3 else x for x in s
    ]


def render_pdf(report: Report) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=PAGE,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN + HEADER_H * 0.6,
        bottomMargin=MARGIN + FOOTER_H * 0.6,
        title=f"Email Forensic Analysis Report {report.meta.report_id}",
        author=report.meta.examiner or "MailTrace",
        subject=report.meta.case_number,
        creator=f"MailTrace v{report.meta.tool_version}",
    )
    doc.build(build_story(report), canvasmaker=lambda *a, **k: _NumberedCanvas(*a, report=report, **k))
    return buf.getvalue()


def write_pdf(report: Report, path: Path) -> Path:
    path.write_bytes(render_pdf(report))
    return path
