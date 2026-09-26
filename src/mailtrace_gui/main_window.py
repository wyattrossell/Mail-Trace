"""Main window: case panel, drop zone, result tabs, and the intake workflow."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QSettings, Qt, QThreadPool, QTimer, Slot
from PySide6.QtGui import QAction, QDragEnterEvent, QDragLeaveEvent, QDropEvent, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QDockWidget,
    QFileDialog,
    QFormLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QSizePolicy,
    QStackedWidget,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from mailtrace_core.case.manager import Case, IntegrityError
from mailtrace_core.case.settings import Settings, load_settings, save_settings
from mailtrace_core.models import AnalysisResult, EvidenceItem, SourceFormat
from mailtrace_core.updates import UpdateCheckResult, check_for_updates
from mailtrace_gui.theme.styles import DARK, LIGHT, Palette, build_qss
from mailtrace_gui.views.dialogs import AboutDialog, CaseDialog, PasteDialog, SettingsDialog
from mailtrace_gui.views.dropzone import ACCEPTED_SUFFIXES, DropZone
from mailtrace_gui.views.enrichment_tabs import EnrichmentTab, LegalTab
from mailtrace_gui.views.report_tab import ReportTab
from mailtrace_gui.views.result_tabs import (
    AttachmentsTab,
    AuditTab,
    AuthTab,
    FindingsTab,
    HeadersTab,
    HopsTab,
    LinksTab,
    SummaryTab,
)
from mailtrace_gui.views.update_banner import UpdateBanner
from mailtrace_gui.workers import AnalysisWorker, file_job, text_job


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("MailTrace")
        self.resize(1360, 860)
        self.setAcceptDrops(True)
        self.settings: Settings = load_settings()
        self.case: Case | None = None
        self.pool = QThreadPool.globalInstance()
        self._qs = QSettings("MailTrace", "MailTrace")
        self.palette_: Palette = DARK if self._qs.value("theme", "dark") == "dark" else LIGHT
        self._busy = False
        self._current_item: EvidenceItem | None = None
        self._last_result: AnalysisResult | None = None

        self._build_toolbar()
        self._build_case_dock()
        self._build_central()
        self.statusBar().showMessage("No case open. Drop a message to begin.")
        self._apply_theme()
        self._build_menu()
        QTimer.singleShot(1500, lambda: self.check_updates(manual=False))

    # ------------------------------------------------------------------ UI
    def _build_menu(self) -> None:
        mb = self.menuBar()
        file_menu = mb.addMenu("&File")
        for text, slot, key in (
            ("New case", self.new_case, "Ctrl+N"),
            ("Open case", self.open_case, "Ctrl+Shift+O"),
            ("Open email…", self.open_email, "Ctrl+O"),
            ("Paste headers…", self.paste_headers, "Ctrl+V"),
        ):
            a = QAction(text, self)
            a.triggered.connect(slot)
            a.setShortcut(QKeySequence(key))
            file_menu.addAction(a)
        file_menu.addSeparator()
        quit_a = QAction("E&xit", self)
        quit_a.triggered.connect(self.close)
        file_menu.addAction(quit_a)
        tools = mb.addMenu("&Tools")
        st = QAction("Settings…", self)
        st.triggered.connect(self.open_settings)
        tools.addAction(st)
        help_menu = mb.addMenu("&Help")
        upd = QAction("Check for updates…", self)
        upd.triggered.connect(lambda: self.check_updates(manual=True))
        help_menu.addAction(upd)
        about = QAction("About MailTrace", self)
        about.triggered.connect(lambda: AboutDialog(self).exec())
        help_menu.addAction(about)

    def check_updates(self, manual: bool) -> None:
        """Run the GitHub release check off the UI thread; never blocks, never installs."""
        if not manual and not self.settings.update_check_enabled:
            return
        self._update_manual = manual
        job = lambda: check_for_updates(  # noqa: E731
            enabled=self.settings.update_check_enabled or manual, force=manual
        )
        worker = AnalysisWorker(job)
        self._update_signals = worker.signals
        worker.signals.finished.connect(self._update_checked, Qt.ConnectionType.QueuedConnection)
        worker.signals.failed.connect(lambda _m: None, Qt.ConnectionType.QueuedConnection)
        self.pool.start(worker)

    @Slot(object)
    def _update_checked(self, res: UpdateCheckResult) -> None:
        self.banner.show_result(res)
        if not getattr(self, "_update_manual", False):
            return
        if res.status == "update_available":
            self.statusBar().showMessage(f"MailTrace {res.latest_version} is available", 6000)
        elif res.status == "up_to_date":
            QMessageBox.information(
                self, "Check for updates", f"MailTrace {res.current_version} is the latest release."
            )
        elif res.status == "skipped" and "disabled" in res.detail:
            QMessageBox.information(
                self, "Check for updates", "Update checks are disabled in Settings > Network."
            )
        else:
            QMessageBox.information(
                self,
                "Check for updates",
                f"Could not check for updates ({res.status}: {res.detail or 'no detail'}).",
            )

    def _build_toolbar(self) -> None:
        tb = QToolBar("Main")
        tb.setMovable(False)
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        self.addToolBar(tb)

        def act(
            text: str, slot: Callable[..., object], shortcut: str | None = None, checkable: bool = False
        ) -> QAction:
            a = QAction(text, self)
            a.triggered.connect(slot)
            if shortcut:
                a.setShortcut(QKeySequence(shortcut))
            a.setCheckable(checkable)
            tb.addAction(a)
            return a

        act("New case", self.new_case, "Ctrl+N")
        act("Open case", self.open_case, "Ctrl+Shift+O")
        tb.addSeparator()
        act("Open email…", self.open_email, "Ctrl+O")
        act("Paste headers…", self.paste_headers, "Ctrl+V")
        tb.addSeparator()
        self.offline_action = act("Offline (no DNS)", self._toggle_offline, checkable=True)
        self.offline_action.setChecked(not self.settings.dns_enabled)
        self.offline_action.setToolTip(
            "When checked, SPF/DKIM/DMARC records are not looked up; the report notes the skipped checks."
        )
        self.enrich_action = act("Enrich", self._toggle_enrich, checkable=True)
        self.enrich_action.setChecked(self.settings.enrichment_enabled)
        self.enrich_action.setToolTip(
            "Run GeoIP, RDAP/WHOIS, reputation and legal-process mapping after analysis. "
            "Passive lookups only; results are cached per case."
        )
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        tb.addWidget(spacer)
        act("Theme", self._toggle_theme)
        act("Settings…", self.open_settings, "Ctrl+,")

    def _build_case_dock(self) -> None:
        dock = QDockWidget("Case", self)
        dock.setFeatures(QDockWidget.DockWidgetFeature.NoDockWidgetFeatures)
        dock.setMinimumWidth(300)
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        form = QFormLayout()
        self.lbl_case = QLabel("—")
        self.lbl_examiner = QLabel("—")
        self.lbl_agency = QLabel("—")
        self.lbl_root = QLabel("—")
        self.lbl_root.setWordWrap(True)
        self.lbl_root.setObjectName("muted")
        for k, v in (
            ("Case", self.lbl_case),
            ("Examiner", self.lbl_examiner),
            ("Agency", self.lbl_agency),
            ("Folder", self.lbl_root),
        ):
            kl = QLabel(k)
            kl.setObjectName("muted")
            form.addRow(kl, v)
        lay.addLayout(form)
        h = QLabel("Evidence")
        h.setObjectName("h2")
        lay.addWidget(h)
        self.evidence_list = QListWidget()
        self.evidence_list.itemActivated.connect(self._reanalyze_item)
        lay.addWidget(self.evidence_list, 1)
        hint = QLabel(
            "Double-click an item to re-run analysis on the stored copy. Its hash is re-verified first."
        )
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        lay.addWidget(hint)
        dock.setWidget(w)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, dock)

    def _build_central(self) -> None:
        self.stack = QStackedWidget()
        self.dropzone = DropZone()
        self.dropzone.open_requested.connect(self.open_email)
        self.dropzone.paste_requested.connect(self.paste_headers)
        self.tabs = QTabWidget()
        self._build_tabs()
        self.stack.addWidget(self.dropzone)
        self.stack.addWidget(self.tabs)
        self.banner = UpdateBanner(self.palette_)
        container = QWidget()
        clay = QVBoxLayout(container)
        clay.setContentsMargins(0, 0, 0, 0)
        clay.setSpacing(0)
        clay.addWidget(self.banner)
        clay.addWidget(self.stack, 1)
        self.setCentralWidget(container)

    def _build_tabs(self) -> None:
        p = self.palette_
        self.tab_summary = SummaryTab(p)
        self.tab_hops = HopsTab(p)
        self.tab_auth = AuthTab(p)
        self.tab_findings = FindingsTab(p)
        self.tab_links = LinksTab(p)
        self.tab_attachments = AttachmentsTab(p)
        self.tab_headers = HeadersTab()
        self.tab_audit = AuditTab(p)
        self.tab_enrichment = EnrichmentTab(p)
        self.tab_legal = LegalTab(p)
        self.tab_report = ReportTab(p, self._log_report)
        for w, name in (
            (self.tab_summary, "Summary"),
            (self.tab_findings, "Findings"),
            (self.tab_enrichment, "Risk && enrichment"),
            (self.tab_legal, "Legal process"),
            (self.tab_report, "Report"),
            (self.tab_hops, "Hops"),
            (self.tab_auth, "Authentication"),
            (self.tab_links, "Links"),
            (self.tab_attachments, "Attachments"),
            (self.tab_headers, "Headers"),
            (self.tab_audit, "Audit log"),
        ):
            self.tabs.addTab(w, name)

    def _apply_theme(self) -> None:
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(build_qss(self.palette_))  # type: ignore[union-attr]

    def _toggle_theme(self) -> None:
        self.palette_ = LIGHT if self.palette_.name == "dark" else DARK
        self._qs.setValue("theme", self.palette_.name)
        self._apply_theme()
        # Rebuild tabs so palette-derived colours refresh; keep the current result.
        current = self.tabs.currentIndex()
        result = getattr(self, "_last_result", None)
        self.tabs.clear()
        self._build_tabs()
        self.tabs.setCurrentIndex(current)
        if self.case:
            self.tab_audit.set_path(self.case.root / "audit.jsonl")
        if result is not None:
            self._show_result(result)

    def _toggle_offline(self, checked: bool) -> None:
        self.settings.dns_enabled = not checked
        save_settings(self.settings)
        self.statusBar().showMessage(
            "Offline: DNS lookups disabled" if checked else "DNS lookups enabled", 4000
        )

    # ---------------------------------------------------------------- Cases
    def _default_base(self) -> str:
        return self.settings.case_base_dir or str(Path.home() / "Documents" / "MailTrace Cases")

    def _ensure_case(self) -> bool:
        if self.case is not None:
            return True
        return self.new_case()

    def new_case(self) -> bool:
        dlg = CaseDialog(
            self._default_base(), self, self.settings.default_examiner, self.settings.default_agency
        )
        if dlg.exec() != CaseDialog.DialogCode.Accepted:
            return False
        base, number, examiner, agency = dlg.values()
        try:
            case = Case.create(base, number, examiner, agency)
        except (FileExistsError, ValueError, OSError) as exc:
            QMessageBox.critical(self, "Cannot create case", str(exc))
            return False
        self.settings.case_base_dir = str(base)
        save_settings(self.settings)
        self._set_case(case)
        return True

    def open_case(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Open case folder", self._default_base())
        if not d:
            return
        try:
            case = Case.open(Path(d))
        except (OSError, KeyError, ValueError) as exc:
            QMessageBox.critical(self, "Cannot open case", f"Not a MailTrace case folder.\n{exc}")
            return
        self._set_case(case)

    def _set_case(self, case: Case) -> None:
        self.case = case
        m = case.meta
        self.lbl_case.setText(m.case_number)
        self.lbl_examiner.setText(m.examiner)
        self.lbl_agency.setText(m.agency)
        self.lbl_root.setText(str(case.root))
        self.setWindowTitle(f"MailTrace — {m.case_number}")
        self._refresh_evidence()
        self.tab_audit.set_path(case.root / "audit.jsonl")
        self.statusBar().showMessage(f"Case {m.case_number} open. Examiner: {m.examiner} ({m.agency})")

    def _refresh_evidence(self) -> None:
        self.evidence_list.clear()
        if not self.case:
            return
        for item in self.case.manifest():
            li = QListWidgetItem(
                f"{item.item_id}  {item.filename}\n      sha256 {item.sha256[:20]}…  {item.size:,} B"
            )
            li.setData(Qt.ItemDataRole.UserRole, item.stored_path)
            li.setToolTip(
                f"SHA-256 {item.sha256}\nMD5 {item.md5}\n"
                f"Ingested {item.ingested_at.isoformat()}\nFrom {item.original_path}"
            )
            self.evidence_list.addItem(li)

    # --------------------------------------------------------------- Intake
    def open_email(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open email", "", "Email files (*.eml *.msg *.txt *.hdr);;All files (*)"
        )
        if path:
            self.ingest_path(Path(path))

    def paste_headers(self) -> None:
        dlg = PasteDialog(self)
        if dlg.exec() != PasteDialog.DialogCode.Accepted:
            return
        text, label = dlg.values()
        if not text.strip():
            return
        if not self._ensure_case():
            return
        assert self.case
        try:
            item = self.case.intake_text(text, label)
        except IntegrityError as exc:
            QMessageBox.critical(self, "Intake failed", str(exc))
            return
        self._refresh_evidence()
        self._run(text_job(text, item.filename, self.settings, self._offline(), **self._enrich_opts()), item)

    def ingest_path(self, path: Path) -> None:
        if self._busy:
            return
        if path.suffix.lower() not in ACCEPTED_SUFFIXES:
            QMessageBox.information(
                self, "Unsupported file", "Drop a .eml, .msg, or .txt file of raw headers."
            )
            return
        if not self._ensure_case():
            return
        assert self.case
        try:
            item = self.case.intake(path)
        except (IntegrityError, OSError) as exc:
            QMessageBox.critical(self, "Intake failed", str(exc))
            return
        self._refresh_evidence()
        self.statusBar().showMessage(f"Ingested {item.item_id}: SHA-256 {item.sha256}")
        self._run(
            file_job(Path(item.stored_path), self.settings, self._offline(), **self._enrich_opts()), item
        )

    def _reanalyze_item(self, li: QListWidgetItem) -> None:
        if not self.case or self._busy:
            return
        stored = Path(li.data(Qt.ItemDataRole.UserRole))
        item = next((i for i in self.case.manifest() if i.stored_path == str(stored)), None)
        if item is None:
            return
        if not self.case.verify_item(item):
            QMessageBox.critical(
                self,
                "Integrity failure",
                f"{item.item_id} no longer matches its recorded hash. Analysis refused.",
            )
            self.tab_audit.refresh()
            return
        if item.source_format is SourceFormat.RAW_HEADERS and item.original_path == "<pasted>":
            text = stored.read_text(encoding="utf-8", errors="replace")
            self._run(
                text_job(text, item.filename, self.settings, self._offline(), **self._enrich_opts()), item
            )
        else:
            self._run(file_job(stored, self.settings, self._offline(), **self._enrich_opts()), item)

    def _log_report(self, action: str, **details: object) -> None:
        if self.case:
            self.case.log(action, **details)
            self.tab_audit.refresh()

    def _offline(self) -> bool:
        return self.offline_action.isChecked()

    def _enrich_opts(self) -> dict[str, object]:
        cache = self.case.working_dir / "enrichment_cache.json" if self.case else None
        return {"enrich": self.enrich_action.isChecked(), "cache_path": cache}

    def _toggle_enrich(self, checked: bool) -> None:
        self.settings.enrichment_enabled = checked
        save_settings(self.settings)
        self.statusBar().showMessage("Enrichment enabled" if checked else "Enrichment disabled", 4000)

    def _run(self, job: Callable[[], AnalysisResult], item: EvidenceItem) -> None:
        assert self.case
        self._busy = True
        self._current_item = item
        self.case.log(
            "analyze_start",
            item_id=item.item_id,
            offline=self._offline(),
            enrich=self.enrich_action.isChecked(),
            agency_domains=self.settings.agency_domains,
        )
        self.statusBar().showMessage(f"Analysing {item.item_id}…")
        worker = AnalysisWorker(job)
        # Keep the signal holder alive and connect to real slots so delivery is
        # queued onto the GUI thread (a bare lambda would run in the worker thread).
        self._worker_signals = worker.signals
        worker.signals.finished.connect(self._done, Qt.ConnectionType.QueuedConnection)
        worker.signals.failed.connect(self._failed, Qt.ConnectionType.QueuedConnection)
        self.pool.start(worker)

    @Slot(object)
    def _done(self, result: AnalysisResult) -> None:
        item = self._current_item
        self._busy = False
        if self.case:
            self.case.log(
                "analyze_done",
                item_id=item.item_id,
                findings=len(result.findings),
                skipped=result.skipped_checks,
                warnings=len(result.email.warnings),
                high=sum(1 for f in result.findings if f.severity.value == "high"),
                enriched=result.enrichment is not None,
                risk=result.enrichment.risk.score if result.enrichment and result.enrichment.risk else None,
                lookups=result.enrichment.lookups_performed if result.enrichment else 0,
            )
        self._show_result(result)
        self.tab_audit.refresh()
        self.statusBar().showMessage(
            f"{item.item_id}: {len(result.findings)} findings"
            + (f"; skipped {', '.join(result.skipped_checks)}" if result.skipped_checks else "")
        )

    @Slot(str)
    def _failed(self, message: str) -> None:
        item = self._current_item
        self._busy = False
        if self.case:
            self.case.log("analyze_failed", item_id=item.item_id, error=message)
            self.tab_audit.refresh()
        QMessageBox.critical(self, "Analysis failed", message)
        self.statusBar().showMessage("Analysis failed")

    def _show_result(self, result: AnalysisResult) -> None:
        self._last_result = result
        pe = result.email
        self.tab_summary.show(result)
        self.tab_findings.show(result)
        self.tab_hops.show(pe)
        self.tab_auth.show(pe)
        self.tab_links.show(pe)
        self.tab_attachments.show(pe)
        self.tab_headers.show(pe)
        self.tab_enrichment.show(result.enrichment)
        self.tab_legal.show(result.enrichment)
        self.tab_report.set_context(result, self.case, self._current_item, self.settings)
        self.stack.setCurrentWidget(self.tabs)

    # ------------------------------------------------------------ Settings
    def open_settings(self) -> None:
        dlg = SettingsDialog(self.settings, self)
        if dlg.exec() == SettingsDialog.DialogCode.Accepted:
            self.offline_action.setChecked(not self.settings.dns_enabled)
            if self.case:
                self.case.log(
                    "settings_changed",
                    agency_domains=self.settings.agency_domains,
                    dns_enabled=self.settings.dns_enabled,
                    active_features_enabled=self.settings.active_features_enabled,
                )
                self.tab_audit.refresh()

    # ----------------------------------------------------------- Drag/drop
    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        md = event.mimeData()
        if md.hasUrls() and any(Path(u.toLocalFile()).suffix.lower() in ACCEPTED_SUFFIXES for u in md.urls()):
            event.acceptProposedAction()
            self.dropzone.set_active(True)
        elif md.hasText() and "Received:" in md.text():
            event.acceptProposedAction()
            self.dropzone.set_active(True)

    def dragLeaveEvent(self, event: QDragLeaveEvent) -> None:  # noqa: N802
        self.dropzone.set_active(False)

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        self.dropzone.set_active(False)
        md = event.mimeData()
        if md.hasUrls():
            for u in md.urls():
                p = Path(u.toLocalFile())
                if p.is_file() and p.suffix.lower() in ACCEPTED_SUFFIXES:
                    self.ingest_path(p)
                    return
        if md.hasText() and "Received:" in md.text():
            if not self._ensure_case():
                return
            assert self.case
            item = self.case.intake_text(md.text(), "dropped headers")
            self._refresh_evidence()
            self._run(
                text_job(md.text(), item.filename, self.settings, self._offline(), **self._enrich_opts()),
                item,
            )
