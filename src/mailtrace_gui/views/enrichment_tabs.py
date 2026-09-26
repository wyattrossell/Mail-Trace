"""Enrichment and legal-process tabs."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from mailtrace_core.enrichment.legal_process import user_table_path
from mailtrace_core.enrichment.models import EnrichmentReport, IpEnrichment, LegalProcessTarget
from mailtrace_core.util.defang import defang_ip, defang_url
from mailtrace_gui.theme.styles import Palette, badge_html
from mailtrace_gui.views.result_tabs import _Card, _item, _table

_VERDICT_COLOUR = {"malicious": "high", "suspicious": "medium", "clean": "confirmed", "unknown": "unverified"}


def _rep_summary(verdicts: list) -> str:  # type: ignore[type-arg]
    return "; ".join(f"{v.provider}: {v.verdict}" for v in verdicts)


def _lookup_tip(lookups: list) -> str:  # type: ignore[type-arg]
    return "\n".join(
        f"{lk.provider}: {lk.status.value}{' (cached)' if lk.cached else ''} {lk.detail}".strip()
        for lk in lookups
    )


class EnrichmentTab(QWidget):
    def __init__(self, palette: Palette) -> None:
        super().__init__()
        self.p = palette
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        top = QHBoxLayout()
        self.risk_card = _Card("Risk score")
        self.risk_body = QLabel()
        self.risk_body.setTextFormat(Qt.TextFormat.RichText)
        self.risk_body.setWordWrap(True)
        self.risk_body.setStyleSheet("background: transparent;")
        self.risk_card.lay.addWidget(self.risk_body)
        self.factors = _table(["Points", "Factor", "Evidence", "Source"])
        self.factors.setMaximumHeight(220)
        self.risk_card.lay.addWidget(self.factors)
        top.addWidget(self.risk_card)
        lay.addLayout(top)

        split = QSplitter(Qt.Orientation.Vertical)
        ip_box = QWidget()
        il = QVBoxLayout(ip_box)
        il.setContentsMargins(0, 0, 0, 0)
        h = QLabel("IP addresses")
        h.setObjectName("h2")
        self.ips = _table(
            [
                "IP",
                "Role",
                "ASN / organisation",
                "Location",
                "Network (RDAP)",
                "Abuse contact",
                "Flags",
                "Reputation",
            ]
        )
        il.addWidget(h)
        il.addWidget(self.ips)

        dom_box = QWidget()
        dl = QVBoxLayout(dom_box)
        dl.setContentsMargins(0, 0, 0, 0)
        h2 = QLabel("Domains")
        h2.setObjectName("h2")
        self.domains = _table(
            ["Domain", "Role", "Registrar", "Created", "Age", "Registrar abuse", "A / MX", "Reputation"]
        )
        dl.addWidget(h2)
        dl.addWidget(self.domains)

        rep_box = QWidget()
        rl = QVBoxLayout(rep_box)
        rl.setContentsMargins(0, 0, 0, 0)
        h3 = QLabel("URL and attachment reputation (hash lookups only; nothing uploaded)")
        h3.setObjectName("h2")
        self.reputation = _table(["Provider", "Type", "Verdict", "Summary", "Target", "Detail"])
        rl.addWidget(h3)
        rl.addWidget(self.reputation)

        for box in (ip_box, dom_box, rep_box):
            split.addWidget(box)
        lay.addWidget(split, 1)

        self.skipped = QLabel()
        self.skipped.setObjectName("muted")
        self.skipped.setWordWrap(True)
        lay.addWidget(self.skipped)

    def clear(self) -> None:
        self.risk_body.setText(
            "Enrichment has not been run for this item. Enable “Enrich” on the toolbar and re-analyse."
        )
        for t in (self.factors, self.ips, self.domains, self.reputation):
            t.setRowCount(0)
        self.skipped.setText("")

    def show(self, rep: EnrichmentReport | None) -> None:  # type: ignore[override]
        if rep is None:
            self.clear()
            return
        p = self.p
        risk = rep.risk
        if risk:
            colour = {"critical": p.high, "high": p.high, "moderate": p.medium, "low": p.confirmed}[risk.band]
            self.risk_body.setText(
                f"<span style='font-size:22pt;font-weight:700'>{risk.score}</span>"
                f"<span style='color:{p.text_muted}'> / 100</span> &nbsp; {badge_html(risk.band, colour)}"
                f"<br><span style='color:{p.text_muted}'>Triage aid only: every point below is "
                f"attributable to a named observation. {rep.lookups_performed} lookups performed, "
                f"{rep.lookups_cached} from the case "
                f"cache. Computed {risk.computed_at}.</span>"
                + ("".join(f"<br><span style='color:{p.medium}'>{n}</span>" for n in risk.notes))
            )
            t = self.factors
            t.setRowCount(0)
            for f in risk.factors:
                r = t.rowCount()
                t.insertRow(r)
                for c, v in enumerate([f"{f.points:+d}", f.name, f.evidence, f.source]):
                    it = _item(v)
                    if c == 0:
                        it.setForeground(
                            QColor(p.confirmed if f.points < 0 else p.high if f.points >= 10 else p.medium)
                        )
                    t.setItem(r, c, it)
            t.resizeColumnsToContents()
            t.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)

        t = self.ips
        t.setRowCount(0)
        for ip in rep.ips:
            self._ip_row(t, ip)
        t.resizeColumnsToContents()

        t = self.domains
        t.setRowCount(0)
        for d in rep.domains:
            r = t.rowCount()
            t.insertRow(r)
            age = "" if d.age_days is None else f"{d.age_days} d" + (" NEW" if d.is_new else "")
            vals = [
                d.domain,
                "; ".join(d.roles),
                d.registrar or "",
                (d.created or "")[:10],
                age,
                " ".join(x for x in (d.registrar_abuse_email, d.registrar_abuse_phone) if x),
                f"{', '.join(d.a[:2])} / {', '.join(d.mx[:2])}",
                _rep_summary(d.reputation),
            ]
            for c, v in enumerate(vals):
                it = _item(v, mono=c in {0, 6}, tip=_lookup_tip(d.lookups))
                if c == 4 and d.is_new:
                    it.setForeground(QColor(p.high))
                if c == 7 and any(x.verdict == "malicious" for x in d.reputation):
                    it.setForeground(QColor(p.high))
                t.setItem(r, c, it)
        t.resizeColumnsToContents()

        t = self.reputation
        t.setRowCount(0)
        for v in [*rep.url_reputation, *rep.attachment_reputation]:
            r = t.rowCount()
            t.insertRow(r)
            target = defang_url(v.target) if v.target_type == "url" else v.target
            for c, val in enumerate([v.provider, v.target_type, v.verdict, v.summary, target, v.detail]):
                it = _item(val, mono=c == 4, tip=v.link or None)
                if c == 2:
                    it.setForeground(QColor(getattr(p, _VERDICT_COLOUR.get(v.verdict, "info"))))
                t.setItem(r, c, it)
        t.resizeColumnsToContents()
        t.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)

        self.skipped.setText(
            "Skipped providers: " + "; ".join(rep.skipped)
            if rep.skipped
            else "All configured providers answered."
        )

    def _ip_row(self, t: QTableWidget, ip: IpEnrichment) -> None:
        p = self.p
        r = t.rowCount()
        t.insertRow(r)
        flags = [
            n
            for n, v in (("hosting", ip.hosting), ("VPN", ip.vpn), ("proxy", ip.proxy), ("Tor", ip.tor))
            if v
        ]
        asn = (f"AS{ip.asn} " if ip.asn else "") + (ip.asn_org or ip.isp or "")
        loc = " / ".join(x for x in (ip.country, ip.region, ip.city) if x)
        net = " ".join(x for x in (ip.network_name, ip.network_cidr) if x)
        vals = [
            defang_ip(ip.ip),
            "; ".join(ip.roles),
            asn,
            loc,
            net,
            ", ".join(ip.abuse_contacts),
            ", ".join(flags),
            _rep_summary(ip.reputation),
        ]
        tip = _lookup_tip(ip.lookups) + ("\n\n" + "\n".join(ip.flag_reasons) if ip.flag_reasons else "")
        for c, v in enumerate(vals):
            it = _item(v, mono=c == 0, tip=tip)
            if c == 6 and flags:
                it.setForeground(QColor(p.high if ip.tor else p.medium))
            if c == 7 and any(x.verdict == "malicious" for x in ip.reputation):
                it.setForeground(QColor(p.high))
            t.setItem(r, c, it)


class LegalTab(QWidget):
    def __init__(self, palette: Palette) -> None:
        super().__init__()
        self.p = palette
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        self.preservation = QLabel()
        self.preservation.setWordWrap(True)
        self.preservation.setTextFormat(Qt.TextFormat.RichText)
        self.preservation.setStyleSheet("background: transparent;")
        lay.addWidget(self.preservation)
        split = QSplitter(Qt.Orientation.Vertical)
        self.table = _table(
            ["Provider", "Role in this case", "Matched on", "Contact / portal", "Jurisdiction"]
        )
        self.table.itemSelectionChanged.connect(self._select)
        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(False)
        self.detail.setOpenLinks(False)
        split.addWidget(self.table)
        split.addWidget(self.detail)
        split.setSizes([300, 300])
        lay.addWidget(split, 1)
        row = QHBoxLayout()
        self.path_label = QLabel(f"Contact table (editable JSON): {user_table_path()}")
        self.path_label.setObjectName("muted")
        self.path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        row.addWidget(self.path_label, 1)
        open_btn = QPushButton("Open folder")
        open_btn.clicked.connect(self._open_folder)
        row.addWidget(open_btn)
        lay.addLayout(row)
        self._targets: list[LegalProcessTarget] = []

    def _open_folder(self) -> None:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices

        QDesktopServices.openUrl(QUrl.fromLocalFile(str(user_table_path().parent)))

    def clear(self) -> None:
        self.table.setRowCount(0)
        self.detail.clear()
        self.preservation.setText("Enrichment has not been run for this item.")

    def show(self, rep: EnrichmentReport | None) -> None:  # type: ignore[override]
        if rep is None:
            self.clear()
            return
        p = self.p
        self.preservation.setText(
            f"<b>Preservation first.</b> <span style='color:{p.text_muted}'>{rep.preservation_note}</span>"
        )
        self._targets = rep.legal_targets
        t = self.table
        t.setRowCount(0)
        for tg in rep.legal_targets:
            r = t.rowCount()
            t.insertRow(r)
            contact = tg.portal or tg.email or tg.guidelines_url
            for c, v in enumerate([tg.provider_name, tg.role, tg.matched_on, contact, tg.jurisdiction]):
                t.setItem(r, c, _item(v))
        t.resizeColumnsToContents()
        t.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        if not rep.legal_targets:
            self.detail.setHtml(
                "<p>No provider could be matched. Check the IP and domain tables for RDAP abuse "
                "contacts, and extend the contact table if a provider recurs in your cases.</p>"
            )

    def _select(self) -> None:
        rows = {i.row() for i in self.table.selectedItems()}
        if not rows:
            return
        tg = self._targets[min(rows)]
        p = self.p
        recs = "".join(f"<li>{r}</li>" for r in tg.records_available)
        when = (
            f" (last verified {tg.last_verified})"
            if tg.last_verified
            else "; this entry has not been verified"
        )
        verify = (
            f"<p style='color:{p.medium}'><b>Verify before use.</b> Confirm the contact against the "
            f"provider's current law-enforcement guidelines{when}.</p>"
        )
        self.detail.setHtml(
            f"<h3 style='margin:0'>{tg.provider_name}</h3>"
            f"<p><b>{tg.role}</b> &middot; matched on <code>{tg.matched_on}</code></p>"
            + (f"<p>Portal: <code>{tg.portal}</code></p>" if tg.portal else "")
            + (f"<p>Email: <code>{tg.email}</code></p>" if tg.email else "")
            + (f"<p>Phone: <code>{tg.phone}</code></p>" if tg.phone else "")
            + (f"<p>Guidelines: <code>{tg.guidelines_url}</code></p>" if tg.guidelines_url else "")
            + (f"<p>Jurisdiction: {tg.jurisdiction}</p>" if tg.jurisdiction else "")
            + (f"<p><b>Records typically available</b></p><ul>{recs}</ul>" if recs else "")
            + (f"<p>{tg.notes}</p>" if tg.notes else "")
            + (verify if tg.verify_before_use else "")
        )
