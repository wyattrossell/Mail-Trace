"""Report tab: generate PDF/HTML/JSON, preview, and the Report Sender panel."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from mailtrace_core.case.manager import Case
from mailtrace_core.case.settings import Settings
from mailtrace_core.models import AnalysisResult, EvidenceItem
from mailtrace_core.reporting import build_report, default_filename, write_report
from mailtrace_core.reporting.drafts import EmailDraft, all_drafts, draft_as_text, mailto_url, write_eml_draft
from mailtrace_core.reporting.html_renderer import render_html
from mailtrace_core.reporting.models import Report
from mailtrace_gui.theme.styles import Palette, badge_html
from mailtrace_gui.views.result_tabs import _Card

try:  # full HTML preview when the WebEngine module is present
    from PySide6.QtWebEngineWidgets import QWebEngineView  # type: ignore[import-not-found]

    _HAS_WEB = True
except Exception:  # noqa: BLE001
    _HAS_WEB = False


class ReportTab(QWidget):
    """Owns report generation and drafts for the current result.

    The tab never sends anything. Every generation, copy, open and save is
    logged to the case audit trail through ``log``.
    """

    def __init__(self, palette: Palette, log: Callable[..., None]) -> None:
        super().__init__()
        self.p = palette
        self._log = log
        self.result: AnalysisResult | None = None
        self.case: Case | None = None
        self.item: EvidenceItem | None = None
        self.settings: Settings | None = None
        self.report: Report | None = None
        self._drafts: list[EmailDraft] = []

        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        top = QHBoxLayout()
        self.status = QLabel("Analyse a message to enable reporting.")
        self.status.setTextFormat(Qt.TextFormat.RichText)
        self.status.setWordWrap(True)
        top.addWidget(self.status, 1)
        self.btn_pdf = QPushButton("Generate PDF")
        self.btn_pdf.setObjectName("primary")
        self.btn_html = QPushButton("Generate HTML")
        self.btn_json = QPushButton("Generate JSON")
        self.btn_all = QPushButton("All three")
        for b, fmt in ((self.btn_pdf, "pdf"), (self.btn_html, "html"), (self.btn_json, "json")):
            b.clicked.connect(lambda _=False, f=fmt: self.generate(f))
        self.btn_all.clicked.connect(lambda: [self.generate(f, ask=False) for f in ("pdf", "html", "json")])
        for b in (self.btn_pdf, self.btn_html, self.btn_json, self.btn_all):
            top.addWidget(b)
        lay.addLayout(top)

        split = QSplitter(Qt.Orientation.Horizontal)
        preview_card = _Card("Report preview")
        if _HAS_WEB:
            self.preview = QWebEngineView()
        else:
            self.preview = QTextBrowser()
            self.preview.setOpenExternalLinks(False)
            self.preview.setOpenLinks(False)
        preview_card.lay.addWidget(self.preview, 1)
        split.addWidget(preview_card)

        sender = _Card("Report Sender - drafts only, nothing is sent automatically")
        self.draft_list = QListWidget()
        self.draft_list.setMaximumHeight(150)
        self.draft_list.currentRowChanged.connect(self._show_draft)
        self.draft_notes = QLabel()
        self.draft_notes.setObjectName("muted")
        self.draft_notes.setWordWrap(True)
        self.draft_text = QPlainTextEdit()
        self.draft_text.setReadOnly(True)
        self.draft_text.setStyleSheet("font-family: Cascadia Mono, Consolas, monospace; font-size: 9pt;")
        row = QHBoxLayout()
        self.btn_copy = QPushButton("Copy to clipboard")
        self.btn_copy.clicked.connect(self.copy_draft)
        self.btn_mail = QPushButton("Open in mail client")
        self.btn_mail.setToolTip(
            "Opens a mailto: link. Attachments cannot be carried this way; use 'Save .eml draft'."
        )
        self.btn_mail.clicked.connect(self.open_mailto)
        self.btn_eml = QPushButton("Save .eml draft (with attachment) and open")
        self.btn_eml.clicked.connect(self.save_eml_draft)
        self.btn_form = QPushButton("Open web form")
        self.btn_form.clicked.connect(self.open_form)
        for b in (self.btn_copy, self.btn_mail, self.btn_eml, self.btn_form):
            row.addWidget(b)
        sender.lay.addWidget(self.draft_list)
        sender.lay.addWidget(self.draft_notes)
        sender.lay.addWidget(self.draft_text, 1)
        sender.lay.addLayout(row)
        split.addWidget(sender)
        split.setSizes([620, 620])
        lay.addWidget(split, 1)
        self._enable(False)

    # ------------------------------------------------------------- state
    def _enable(self, on: bool) -> None:
        for b in (
            self.btn_pdf,
            self.btn_html,
            self.btn_json,
            self.btn_all,
            self.btn_copy,
            self.btn_mail,
            self.btn_eml,
            self.btn_form,
        ):
            b.setEnabled(on)

    def set_context(
        self, result: AnalysisResult | None, case: Case | None, item: EvidenceItem | None, settings: Settings
    ) -> None:
        self.result, self.case, self.item, self.settings = result, case, item, settings
        self.report = None
        self._drafts = []
        self.draft_list.clear()
        self.draft_text.clear()
        if result is None:
            self._enable(False)
            self.status.setText("Analyse a message to enable reporting.")
            return
        self.report = build_report(result, settings, case, item)
        v = self.report.verdict
        conf_colour = {
            "confirmed": self.p.confirmed,
            "likely": self.p.likely,
            "unverified": self.p.unverified,
        }
        self.status.setText(
            f"<b>{v.label}</b> {badge_html(v.confidence.value, conf_colour[v.confidence.value])}<br>"
            f"<span style='color:{self.p.text_muted}'>Report ID {self.report.meta.report_id} · "
            f"{'case ' + case.meta.case_number if case else 'no case open: hashes and audit log will be absent'}</span>"
        )
        html = render_html(self.report)
        if _HAS_WEB:
            self.preview.setHtml(html)
        else:
            self.preview.setHtml(html)
        eml = item.stored_path if item and item.stored_path.lower().endswith(".eml") else None
        self._drafts = all_drafts(self.report, settings, eml)
        for d in self._drafts:
            li = QListWidgetItem(d.title)
            li.setToolTip(", ".join(d.to) or "web form")
            self.draft_list.addItem(li)
        self.draft_list.setCurrentRow(0)
        self._enable(True)
        self._log(
            "report_prepared", report_id=self.report.meta.report_id, drafts=[d.kind for d in self._drafts]
        )

    # --------------------------------------------------------- generation
    def _default_dir(self) -> Path:
        if self.case:
            return self.case.report_dir
        return Path.home() / "Documents"

    def generate(self, fmt: str, ask: bool = True) -> None:
        if self.report is None:
            return
        target = self._default_dir() / default_filename(self.report, fmt)
        if ask:
            chosen, _ = QFileDialog.getSaveFileName(
                self, f"Save {fmt.upper()} report", str(target), f"{fmt.upper()} (*.{fmt})"
            )
            if not chosen:
                return
            target = Path(chosen)
        try:
            path, sha = write_report(self.report, fmt, target, self.case)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Report failed", f"{type(exc).__name__}: {exc}")
            self._log("report_failed", format=fmt, error=str(exc))
            return
        self.status.setText(self.status.text() + f"<br>Wrote {path.name} (SHA-256 {sha[:16]}…)")
        if ask:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    # ------------------------------------------------------------- drafts
    def _current(self) -> EmailDraft | None:
        row = self.draft_list.currentRow()
        return self._drafts[row] if 0 <= row < len(self._drafts) else None

    def _show_draft(self, row: int) -> None:
        d = self._current()
        if d is None:
            return
        self.draft_notes.setText(d.notes)
        self.draft_text.setPlainText(draft_as_text(d))
        self.btn_mail.setEnabled(bool(d.to))
        self.btn_eml.setEnabled(bool(d.to))
        self.btn_form.setEnabled(d.kind in {"ic3", "ftc"})

    def copy_draft(self) -> None:
        d = self._current()
        if d is None:
            return
        QGuiApplication.clipboard().setText(draft_as_text(d))
        self._log("draft_copied", kind=d.kind, to=d.to, subject=d.subject)
        self.draft_notes.setText("Copied to clipboard. " + d.notes)

    def open_mailto(self) -> None:
        d = self._current()
        if d is None or not d.to:
            return
        QDesktopServices.openUrl(QUrl(mailto_url(d)))
        self._log(
            "draft_opened_mailto",
            kind=d.kind,
            to=d.to,
            subject=d.subject,
            attachments_omitted=[Path(a).name for a in d.attachments],
        )

    def save_eml_draft(self) -> None:
        d = self._current()
        if d is None or not d.to or self.settings is None:
            return
        base = self.case.report_dir / "drafts" if self.case else Path.home() / "Documents"
        target = base / f"{d.kind}-{self.report.meta.report_id if self.report else 'draft'}.eml"
        try:
            path = write_eml_draft(d, target, self.settings.reporter_email)
        except OSError as exc:
            QMessageBox.critical(self, "Could not write draft", str(exc))
            return
        self._log(
            "draft_saved_eml",
            kind=d.kind,
            to=d.to,
            path=str(path),
            attachments=[Path(a).name for a in d.attachments],
        )
        try:
            os.startfile(str(path))  # noqa: S606 - opens the user's mail client on the draft
            self._log("draft_opened_eml", kind=d.kind, path=str(path))
        except OSError:
            QMessageBox.information(self, "Draft saved", f"Saved to {path}. Open it with your mail client.")

    def open_form(self) -> None:
        d = self._current()
        if d is None:
            return
        url = "https://www.ic3.gov" if d.kind == "ic3" else "https://reportfraud.ftc.gov"
        QDesktopServices.openUrl(QUrl(url))
        self._log("draft_form_opened", kind=d.kind, url=url)
