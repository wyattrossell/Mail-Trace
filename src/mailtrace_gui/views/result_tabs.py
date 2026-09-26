"""Result tabs: summary, hops, authentication, findings, links, attachments, headers, audit."""

from __future__ import annotations

from html import escape
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from mailtrace_core.case.audit import read_audit_log, verify_audit_log
from mailtrace_core.models import (
    AnalysisResult,
    Confidence,
    Finding,
    ParsedEmail,
    Severity,
)
from mailtrace_core.reporting.summary import executive_summary
from mailtrace_core.reporting.verdict import assess
from mailtrace_core.util.defang import defang_email, defang_ip
from mailtrace_gui.theme.styles import Palette, badge_html


def _mono() -> QFont:
    f = QFont("Cascadia Mono")
    f.setStyleHint(QFont.StyleHint.Monospace)
    return f


def _item(
    text: str, *, mono: bool = False, color: str | None = None, tip: str | None = None
) -> QTableWidgetItem:
    it = QTableWidgetItem(text)
    it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
    if mono:
        it.setFont(_mono())
    if color:
        it.setForeground(QColor(color))
    if tip:
        it.setToolTip(tip)
    return it


def _table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setAlternatingRowColors(True)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setWordWrap(False)
    t.horizontalHeader().setStretchLastSection(True)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    return t


class _Card(QFrame):
    def __init__(self, title: str) -> None:
        super().__init__()
        self.setObjectName("card")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(14, 12, 14, 12)
        h = QLabel(title)
        h.setObjectName("h2")
        h.setStyleSheet("background: transparent;")
        self.lay.addWidget(h)


# ----------------------------------------------------------------- Summary
class SummaryTab(QWidget):
    def __init__(self, palette: Palette) -> None:
        super().__init__()
        self.p = palette
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(12)
        self.narrative = _Card("What this means")
        self.narrative_body = QLabel("Analyse a message to see a plain-language summary here.")
        self.narrative_body.setTextFormat(Qt.TextFormat.RichText)
        self.narrative_body.setWordWrap(True)
        self.narrative_body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.narrative_body.setStyleSheet("background: transparent;")
        self.narrative.lay.addWidget(self.narrative_body)
        lay.addWidget(self.narrative)
        top = QHBoxLayout()
        self.identity = _Card("Message")
        self.identity_form = QFormLayout()
        self.identity_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.identity.lay.addLayout(self.identity_form)
        self.verdict = _Card("Authentication & origin")
        self.verdict_body = QLabel()
        self.verdict_body.setTextFormat(Qt.TextFormat.RichText)
        self.verdict_body.setWordWrap(True)
        self.verdict_body.setStyleSheet("background: transparent;")
        self.verdict.lay.addWidget(self.verdict_body)
        self.verdict.lay.addStretch(1)
        top.addWidget(self.identity, 3)
        top.addWidget(self.verdict, 2)
        lay.addLayout(top)
        self.warnings = _Card("Warnings & skipped checks")
        self.warnings_body = QLabel()
        self.warnings_body.setWordWrap(True)
        self.warnings_body.setTextFormat(Qt.TextFormat.RichText)
        self.warnings_body.setStyleSheet("background: transparent;")
        self.warnings.lay.addWidget(self.warnings_body)
        lay.addWidget(self.warnings)
        lay.addStretch(1)

    def _show_narrative(self, result: AnalysisResult) -> None:
        """Plain-language account of the message for supervisors and non-technical readers."""
        p = self.p
        v = assess(result)
        conf_colour = {"confirmed": p.confirmed, "likely": p.likely, "unverified": p.unverified}
        paras = executive_summary(result, v)
        html = (
            f"<div style='font-size:11.5pt;font-weight:600;margin-bottom:6px'>{escape(v.label)} "
            f"{badge_html(v.confidence.value, conf_colour[v.confidence.value])}</div>"
            + "".join(f"<p style='margin:4px 0'>{escape(para)}</p>" for para in paras)
            + f"<p style='margin-top:8px;color:{p.text_muted}'><b>What to do next.</b> Keep the original file as "
            "evidence (it is already hashed in the case folder), send preservation requests to the providers listed "
            "on the Legal process tab, and verify each finding before relying on it. The same wording, with the "
            "technical detail behind it, appears in the generated report.</p>"
        )
        self.narrative_body.setText(html)

    def _row(self, label: str, value: str, mono: bool = False) -> None:
        v = QLabel(value or "—")
        v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        v.setWordWrap(True)
        v.setStyleSheet("background: transparent;")
        if mono:
            v.setFont(_mono())
        k = QLabel(label)
        k.setObjectName("muted")
        k.setStyleSheet("background: transparent;")
        self.identity_form.addRow(k, v)

    def show(self, result: AnalysisResult) -> None:  # type: ignore[override]
        pe = result.email
        self._show_narrative(result)
        while self.identity_form.rowCount():
            self.identity_form.removeRow(0)
        self._row("Source", f"{pe.source_name}  ({pe.source_format.value})")
        self._row("Subject", pe.subject or "")
        if pe.from_:
            self._row("From", f"{pe.from_.display_name}  <{defang_email(pe.from_.address)}>".strip())
        self._row("Reply-To", ", ".join(defang_email(a.address) for a in pe.reply_to))
        self._row(
            "Return-Path",
            defang_email(pe.return_path.address)
            if pe.return_path and pe.return_path.address
            else ("<>" if pe.return_path else ""),
        )
        self._row("To", ", ".join(defang_email(a.address) for a in pe.to))
        self._row("Date", pe.date.isoformat() if pe.date else (pe.header("Date") or ""))
        self._row("Message-ID", pe.message_id or "", mono=True)

        a = pe.auth
        p = self.p
        colour = {
            "pass": p.confirmed,
            "fail": p.high,
            "softfail": p.medium,
            "permerror": p.medium,
            "temperror": p.info,
            "none": p.info,
            "neutral": p.info,
            "skipped": p.unverified,
        }

        def badge(label: str, res: str | None) -> str:
            res = res or "n/a"
            return f"{label} {badge_html(res, colour.get(res, p.info))}"

        parts = [
            "<div style='line-height:1.9'>"
            + " &nbsp; ".join(
                [
                    badge("SPF", a.spf.result if a.spf else None),
                    badge("DKIM", a.dkim.result if a.dkim else None),
                    badge("DMARC", a.dmarc.result if a.dmarc else None),
                ]
            )
            + "</div>"
        ]
        if a.dmarc and a.dmarc.policy:
            parts.append(f"<span style='color:{p.text_muted}'>DMARC policy p={a.dmarc.policy}</span>")
        parts.append("<br><b>Origin candidates</b>")
        conf_colour = {
            Confidence.CONFIRMED: p.confirmed,
            Confidence.LIKELY: p.likely,
            Confidence.UNVERIFIED: p.unverified,
        }
        for c in pe.origin_candidates[:5]:
            parts.append(
                f"<div><code>{defang_ip(c.ip)}</code> "
                f"{badge_html(c.confidence.value, conf_colour[c.confidence])} "
                f"<span style='color:{p.text_muted}'>{c.source}"
                f"{' (private)' if c.is_private else ''}</span></div>"
            )
        if not pe.origin_candidates:
            parts.append(f"<div style='color:{p.text_muted}'>none identified</div>")
        rep = result.enrichment
        if rep is not None and rep.risk is not None:
            rc = {"critical": p.high, "high": p.high, "moderate": p.medium, "low": p.confirmed}[rep.risk.band]
            parts.append(
                f"<br><b>Risk score</b> <span style='font-size:14pt;font-weight:700'>{rep.risk.score}</span>"
                f"<span style='color:{p.text_muted}'>/100</span> {badge_html(rep.risk.band, rc)} "
                f"<span style='color:{p.text_muted}'>see Risk &amp; enrichment tab</span>"
            )
        counts = {s: sum(1 for f in result.findings if f.severity is s) for s in Severity}
        parts.append(
            "<br><b>Findings</b> "
            + " ".join(
                badge_html(f"{counts[s]} {s.value}", getattr(p, s.value)) for s in Severity if counts[s]
            )
        )
        self.verdict_body.setText("".join(parts))

        w = [f"<li>{x}</li>" for x in pe.warnings]
        if result.skipped_checks:
            w.append(
                f"<li><b>Skipped checks:</b> {', '.join(result.skipped_checks)} "
                "(offline or DNS disabled). The report will note these as not performed.</li>"
            )
        self.warnings_body.setText("<ul style='margin:0'>" + "".join(w) + "</ul>" if w else "None.")


# -------------------------------------------------------------------- Hops
class HopsTab(QWidget):
    COLS = [
        "#",
        "Trust",
        "Timestamp (as written)",
        "Delay",
        "From host",
        "From IP",
        "By host",
        "Protocol",
        "Anomalies",
    ]

    def __init__(self, palette: Palette) -> None:
        super().__init__()
        self.p = palette
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        hint = QLabel(
            "Origin first. Hops above the trust boundary were written by the recipient's "
            "infrastructure; anything below it was written by other parties and may be forged."
        )
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        self.table = _table(self.COLS)
        self.raw = QPlainTextEdit()
        self.raw.setReadOnly(True)
        self.raw.setFont(_mono())
        self.raw.setMaximumHeight(120)
        self.raw.setPlaceholderText("Select a hop to see the raw Received header")
        self.table.itemSelectionChanged.connect(self._show_raw)
        lay.addWidget(hint)
        lay.addWidget(self.table, 1)
        lay.addWidget(self.raw)
        self._hops: list = []

    def _show_raw(self) -> None:
        rows = {i.row() for i in self.table.selectedItems()}
        if rows:
            hop = self._hops[min(rows)]
            self.raw.setPlainText(hop.raw + ("\n\nTrust: " + hop.trust_reason if hop.trust_reason else ""))

    def show(self, pe: ParsedEmail) -> None:  # type: ignore[override]
        self._hops = pe.hops
        t = self.table
        t.setRowCount(0)
        for hop in pe.hops:
            r = t.rowCount()
            t.insertRow(r)
            delay = "" if hop.delay_seconds is None else f"{hop.delay_seconds:+.0f}s"
            trust = "trusted" if hop.trusted else "unverified"
            vals = [
                str(hop.index),
                trust,
                hop.timestamp.isoformat() if hop.timestamp else "",
                delay,
                hop.from_host or hop.from_helo or "",
                defang_ip(hop.from_ip) if hop.from_ip else "",
                hop.by_host or "",
                hop.protocol or "",
                "; ".join(hop.anomalies),
            ]
            for c, v in enumerate(vals):
                it = _item(v, mono=c in {2, 5}, tip=hop.trust_reason if c == 1 else None)
                if hop.trusted:
                    it.setBackground(QColor(self.p.trusted_bg))
                if c == 1:
                    it.setForeground(QColor(self.p.confirmed if hop.trusted else self.p.unverified))
                if c == 8 and hop.anomalies:
                    it.setForeground(QColor(self.p.medium))
                if c == 3 and hop.delay_seconds is not None and hop.delay_seconds < 0:
                    it.setForeground(QColor(self.p.high))
                t.setItem(r, c, it)
        t.resizeColumnsToContents()
        t.horizontalHeader().setSectionResizeMode(8, QHeaderView.ResizeMode.Stretch)


# ---------------------------------------------------------------- Auth tab
class AuthTab(QWidget):
    def __init__(self, palette: Palette) -> None:
        super().__init__()
        self.p = palette
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        grid = QGridLayout()
        self.cards: dict[str, QLabel] = {}
        for i, name in enumerate(("SPF", "DKIM", "DMARC")):
            card = _Card(name)
            body = QLabel()
            body.setWordWrap(True)
            body.setTextFormat(Qt.TextFormat.RichText)
            body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            body.setStyleSheet("background: transparent;")
            card.lay.addWidget(body)
            card.lay.addStretch(1)
            grid.addWidget(card, 0, i)
            self.cards[name] = body
        lay.addLayout(grid)
        rep = QLabel("Reported by receiving servers (Authentication-Results headers)")
        rep.setObjectName("h2")
        lay.addWidget(rep)
        self.table = _table(["Server", "Method", "Result", "Properties", "Reason"])
        lay.addWidget(self.table, 1)

    def _badge(self, res: str) -> str:
        p = self.p
        colour = {
            "pass": p.confirmed,
            "fail": p.high,
            "softfail": p.medium,
            "permerror": p.medium,
            "neutral": p.info,
            "none": p.info,
            "temperror": p.info,
            "skipped": p.unverified,
        }
        return badge_html(res, colour.get(res, p.info))

    def show(self, pe: ParsedEmail) -> None:  # type: ignore[override]
        a = pe.auth
        muted = self.p.text_muted
        if a.spf:
            self.cards["SPF"].setText(
                f"{self._badge(a.spf.result)}<br><br>Domain: <code>{a.spf.domain or '-'}</code><br>"
                f"Client IP: <code>{defang_ip(a.spf.client_ip) if a.spf.client_ip else '-'}</code><br>"
                f"Matched: <code>{a.spf.matched_mechanism or '-'}</code><br>"
                f"<span style='color:{muted}'>{a.spf.detail}</span><br>"
                f"<span style='color:{muted};font-family:monospace'>{a.spf.record or ''}</span>"
            )
        if a.dkim:
            self.cards["DKIM"].setText(
                f"{self._badge(a.dkim.result)}<br><br>d=<code>{a.dkim.domain or '-'}</code> "
                f"s=<code>{a.dkim.selector or '-'}</code><br>"
                f"Signed: <span style='color:{muted}'>{', '.join(a.dkim.signed_headers) or '-'}</span><br>"
                f"<span style='color:{muted}'>{a.dkim.detail}</span>"
            )
        if a.dmarc:
            al = []
            if a.dmarc.spf_aligned is not None:
                al.append(
                    f"SPF {'aligned' if a.dmarc.spf_aligned else 'not aligned'} ({a.dmarc.alignment_spf})"
                )
            if a.dmarc.dkim_aligned is not None:
                al.append(
                    f"DKIM {'aligned' if a.dmarc.dkim_aligned else 'not aligned'} ({a.dmarc.alignment_dkim})"
                )
            self.cards["DMARC"].setText(
                f"{self._badge(a.dmarc.result)}<br><br>Domain: <code>{a.dmarc.domain or '-'}</code><br>"
                f"Policy: <code>{a.dmarc.policy or '-'}</code><br>{'<br>'.join(al)}<br>"
                f"<span style='color:{muted}'>{a.dmarc.detail}</span><br>"
                f"<span style='color:{muted};font-family:monospace'>{a.dmarc.record or ''}</span>"
            )
        t = self.table
        t.setRowCount(0)
        for r_ in a.reported:
            r = t.rowCount()
            t.insertRow(r)
            props = " ".join(f"{k}={v}" for k, v in r_.properties.items())
            for c, v in enumerate([r_.authserv_id, r_.method, r_.result, props, r_.reason]):
                it = _item(v, mono=c == 3)
                if c == 2:
                    it.setForeground(
                        QColor(
                            self.p.confirmed
                            if v == "pass"
                            else self.p.high
                            if v in {"fail", "softfail"}
                            else self.p.text
                        )
                    )
                t.setItem(r, c, it)
        t.resizeColumnsToContents()


# ---------------------------------------------------------------- Findings
class FindingsTab(QWidget):
    def __init__(self, palette: Palette) -> None:
        super().__init__()
        self.p = palette
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        split = QSplitter(Qt.Orientation.Vertical)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Finding", "Confidence", "Rule", "Category"])
        self.tree.setAlternatingRowColors(True)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.itemSelectionChanged.connect(self._select)
        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(False)
        self.detail.setOpenLinks(False)
        split.addWidget(self.tree)
        split.addWidget(self.detail)
        split.setSizes([420, 220])
        lay.addWidget(split)
        self._findings: dict[int, Finding] = {}

    def _select(self) -> None:
        items = self.tree.selectedItems()
        if not items:
            return
        f = self._findings.get(id(items[0]))
        if not f:
            self.detail.clear()
            return
        p = self.p
        conf_colour = {
            Confidence.CONFIRMED: p.confirmed,
            Confidence.LIKELY: p.likely,
            Confidence.UNVERIFIED: p.unverified,
        }
        ev = "".join(
            f"<li><code>{e.source}</code>: {e.value}"
            + (f" <span style='color:{p.text_muted}'>({e.note})</span>" if e.note else "")
            + "</li>"
            for e in f.evidence
        )
        self.detail.setHtml(
            f"<h3 style='margin:0'>{f.title}</h3>"
            f"<p>{badge_html(f.severity.value, getattr(p, f.severity.value))} "
            f"{badge_html(f.confidence.value, conf_colour[f.confidence])} "
            f"<span style='color:{p.text_muted}'>{f.rule_id} &middot; {f.category}</span></p>"
            f"<p>{f.explanation}</p>"
            + (
                f"<p><b>Evidence</b></p><ul>{ev}</ul>"
                if ev
                else f"<p style='color:{p.text_muted}'>No specific artifact attached.</p>"
            )
        )

    def show(self, result: AnalysisResult) -> None:  # type: ignore[override]
        self.tree.clear()
        self._findings.clear()
        self.detail.clear()
        groups: dict[Severity, QTreeWidgetItem] = {}
        for sev in Severity:
            fs = [f for f in result.findings if f.severity is sev]
            if not fs:
                continue
            g = QTreeWidgetItem([f"{sev.value.upper()}  ({len(fs)})", "", "", ""])
            g.setForeground(0, QColor(getattr(self.p, sev.value)))
            font = g.font(0)
            font.setBold(True)
            g.setFont(0, font)
            g.setFlags(g.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            self.tree.addTopLevelItem(g)
            groups[sev] = g
            for f in fs:
                it = QTreeWidgetItem([f.title, f.confidence.value, f.rule_id, f.category])
                conf_colour = {
                    Confidence.CONFIRMED: self.p.confirmed,
                    Confidence.LIKELY: self.p.likely,
                    Confidence.UNVERIFIED: self.p.unverified,
                }
                it.setForeground(1, QColor(conf_colour[f.confidence]))
                g.addChild(it)
                self._findings[id(it)] = f
        self.tree.expandAll()
        for c in (1, 2, 3):
            self.tree.resizeColumnToContents(c)
        if not result.findings:
            self.detail.setHtml(
                "<p>No findings. This does not prove the message is benign; it means "
                "none of the implemented checks triggered.</p>"
            )


# -------------------------------------------------------------------- Links
class LinksTab(QWidget):
    def __init__(self, palette: Palette) -> None:
        super().__init__()
        self.p = palette
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        hint = QLabel("All URLs are shown defanged and are never fetched. Copy carefully.")
        hint.setObjectName("muted")
        self.table = _table(["Source", "URL (defanged)", "Host", "Visible text", "Flags"])
        lay.addWidget(hint)
        lay.addWidget(self.table, 1)

    def show(self, pe: ParsedEmail) -> None:  # type: ignore[override]
        t = self.table
        t.setRowCount(0)
        for u in pe.urls:
            flags = []
            if u.display_mismatch:
                flags.append("TEXT/HREF MISMATCH")
            if u.is_ip_host:
                flags.append("IP host")
            if u.is_idn:
                flags.append(f"IDN ({u.unicode_host or '?'})")
            if u.is_shortener:
                flags.append("shortener")
            r = t.rowCount()
            t.insertRow(r)
            for c, v in enumerate(
                [u.source, u.defanged, u.host or "", u.display_text or "", ", ".join(flags)]
            ):
                it = _item(v, mono=c in {1, 2})
                if c == 4 and flags:
                    it.setForeground(QColor(self.p.high if u.display_mismatch else self.p.medium))
                t.setItem(r, c, it)
        t.resizeColumnsToContents()
        t.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)


# -------------------------------------------------------------- Attachments
class AttachmentsTab(QWidget):
    def __init__(self, palette: Palette) -> None:
        super().__init__()
        self.p = palette
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        hint = QLabel(
            "Attachments are hashed and type-sniffed from their first bytes only. Nothing is opened."
        )
        hint.setObjectName("muted")
        self.table = _table(["Filename", "Size", "Declared", "Detected", "SHA-256", "MD5", "Notes"])
        lay.addWidget(hint)
        lay.addWidget(self.table, 1)

    def show(self, pe: ParsedEmail) -> None:  # type: ignore[override]
        t = self.table
        t.setRowCount(0)
        for a in pe.attachments:
            r = t.rowCount()
            t.insertRow(r)
            vals = [
                a.filename,
                f"{a.size:,}",
                a.declared_type or "",
                a.detected_type or "unknown",
                a.sha256,
                a.md5,
                "; ".join(a.notes),
            ]
            for c, v in enumerate(vals):
                it = _item(v, mono=c in {4, 5})
                if c == 3 and a.type_mismatch:
                    it.setForeground(QColor(self.p.high))
                if c == 6 and a.notes:
                    it.setForeground(QColor(self.p.medium))
                t.setItem(r, c, it)
        t.resizeColumnsToContents()
        t.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)


# ----------------------------------------------------------------- Headers
class HeadersTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setFont(_mono())
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        lay.addWidget(self.text)

    def show(self, pe: ParsedEmail) -> None:  # type: ignore[override]
        self.text.setPlainText("\n".join(f"{k}: {v}" for k, v in pe.headers))


# ------------------------------------------------------------------- Audit
class AuditTab(QWidget):
    def __init__(self, palette: Palette) -> None:
        super().__init__()
        self.p = palette
        self._path: Path | None = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        row = QHBoxLayout()
        self.status = QLabel("No case open")
        self.status.setObjectName("muted")
        verify = QPushButton("Verify chain")
        verify.clicked.connect(self.refresh)
        row.addWidget(self.status, 1)
        row.addWidget(verify)
        self.table = _table(["#", "UTC time", "Action", "Examiner", "Details", "Entry hash"])
        lay.addLayout(row)
        lay.addWidget(self.table, 1)

    def set_path(self, path: Path | None) -> None:
        self._path = path
        self.refresh()

    def refresh(self) -> None:
        t = self.table
        t.setRowCount(0)
        if not self._path or not self._path.exists():
            self.status.setText("No case open")
            return
        ok, problems = verify_audit_log(self._path)
        self.status.setText("Chain intact" if ok else "CHAIN BROKEN: " + "; ".join(problems[:3]))
        self.status.setStyleSheet(
            f"color: {self.p.confirmed if ok else self.p.high}; background: transparent;"
        )
        for e in read_audit_log(self._path):
            r = t.rowCount()
            t.insertRow(r)
            details = ", ".join(f"{k}={v}" for k, v in e.details.items())
            for c, v in enumerate(
                [str(e.seq), e.timestamp_utc, e.action, e.examiner, details, e.entry_hash[:16] + "…"]
            ):
                t.setItem(r, c, _item(v, mono=c in {1, 5}, tip=e.entry_hash if c == 5 else None))
        t.resizeColumnsToContents()
        t.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
