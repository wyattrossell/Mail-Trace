"""Case setup, header paste, settings and About dialogs."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from mailtrace_core import __version__
from mailtrace_core.case.settings import (
    Settings,
    delete_api_key,
    get_api_key,
    save_settings,
    set_api_key,
)
from mailtrace_core.updates import RELEASES_PAGE


class CaseDialog(QDialog):
    """Collects the case number, examiner and agency before any intake."""

    def __init__(
        self,
        default_base: str,
        parent: QWidget | None = None,
        default_examiner: str = "",
        default_agency: str = "",
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("New case")
        self.setMinimumWidth(480)
        form = QFormLayout(self)
        form.setSpacing(10)
        self.case_number = QLineEdit()
        self.case_number.setPlaceholderText("e.g. 26-001234")
        self.examiner = QLineEdit(default_examiner)
        self.examiner.setPlaceholderText("Name and rank as it should appear in the report")
        self.agency = QLineEdit(default_agency)
        self.base_dir = QLineEdit(default_base)
        browse = QPushButton("Browse\u2026")
        browse.clicked.connect(self._browse)
        row = QHBoxLayout()
        row.addWidget(self.base_dir)
        row.addWidget(browse)
        form.addRow("Case number", self.case_number)
        form.addRow("Examiner", self.examiner)
        form.addRow("Agency", self.agency)
        form.addRow("Case folder root", row)
        note = QLabel(
            "A folder named after the case number is created under the root. "
            "Every action is logged with these details and a UTC timestamp."
        )
        note.setObjectName("muted")
        note.setWordWrap(True)
        form.addRow(note)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def _browse(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Choose case folder root", self.base_dir.text())
        if d:
            self.base_dir.setText(d)

    def _accept(self) -> None:
        if not all(w.text().strip() for w in (self.case_number, self.examiner, self.agency, self.base_dir)):
            QMessageBox.warning(self, "Missing information", "All fields are required.")
            return
        self.accept()

    def values(self) -> tuple[Path, str, str, str]:
        return (
            Path(self.base_dir.text().strip()),
            self.case_number.text().strip(),
            self.examiner.text().strip(),
            self.agency.text().strip(),
        )


class PasteDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Paste raw headers")
        self.resize(760, 520)
        lay = QVBoxLayout(self)
        hint = QLabel(
            "Paste the full header block (for example from Gmail's \u201cShow original\u201d "
            "or Outlook's \u201cInternet headers\u201d). Including the body enables DKIM "
            "re-verification and link extraction."
        )
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        self.label = QLineEdit("pasted headers")
        self.text = QPlainTextEdit()
        self.text.setPlaceholderText("Received: from ...")
        self.text.setStyleSheet("font-family: Cascadia Mono, Consolas, monospace;")
        form = QFormLayout()
        form.addRow("Label", self.label)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(hint)
        lay.addLayout(form)
        lay.addWidget(self.text, 1)
        lay.addWidget(buttons)

    def values(self) -> tuple[str, str]:
        return self.text.toPlainText(), self.label.text().strip() or "pasted headers"


class SettingsDialog(QDialog):
    PROVIDERS = (
        ("virustotal", "VirusTotal"),
        ("abuseipdb", "AbuseIPDB"),
        ("urlhaus", "URLhaus (abuse.ch Auth-Key)"),
        ("safebrowsing", "Google Safe Browsing"),
        ("ipinfo", "ipinfo.io token (optional)"),
    )

    def __init__(self, settings: Settings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("Settings")
        self.resize(700, 620)
        lay = QVBoxLayout(self)
        tabs = QTabWidget()
        lay.addWidget(tabs, 1)

        # ------------------------------------------------ Examiner & agency
        ex = QWidget()
        ef = QFormLayout(ex)
        self.default_examiner = QLineEdit(settings.default_examiner)
        self.default_examiner.setPlaceholderText("pre-filled in New Case and used on reports without a case")
        self.default_agency = QLineEdit(settings.default_agency)
        self.reporter_email = QLineEdit(settings.reporter_email)
        self.reporter_phone = QLineEdit(settings.reporter_phone)
        self.report_agency_name = QLineEdit(settings.report_agency_name)
        self.report_agency_name.setPlaceholderText("defaults to the case agency")
        self.report_agency_line2 = QLineEdit(settings.report_agency_line2)
        self.report_agency_line2.setPlaceholderText("unit, address or contact line")
        self.report_logo_path = QLineEdit(settings.report_logo_path)
        logo_row = QHBoxLayout()
        logo_row.addWidget(self.report_logo_path)
        b_logo = QPushButton("Browse\u2026")
        b_logo.clicked.connect(self._browse_logo)
        logo_row.addWidget(b_logo)
        self.report_classification = QLineEdit(settings.report_classification)
        self.report_footer_note = QLineEdit(settings.report_footer_note)
        self.case_base = QLineEdit(settings.case_base_dir)
        ef.addRow(self._h("Examiner defaults"))
        ef.addRow("Examiner name / rank", self.default_examiner)
        ef.addRow("Agency", self.default_agency)
        ef.addRow("Examiner email (drafts)", self.reporter_email)
        ef.addRow("Examiner phone (drafts)", self.reporter_phone)
        ef.addRow("Default case root", self.case_base)
        ef.addRow(self._h("Report header"))
        ef.addRow("Agency name on reports", self.report_agency_name)
        ef.addRow("Header line 2", self.report_agency_line2)
        ef.addRow("Logo (PNG/JPG)", logo_row)
        ef.addRow("Classification banner", self.report_classification)
        ef.addRow("Footer note", self.report_footer_note)
        tabs.addTab(ex, "Examiner && agency")

        # --------------------------------------------------------- Watchlist
        wl = QWidget()
        wf = QFormLayout(wl)
        self.agency_domains = QLineEdit(", ".join(settings.agency_domains))
        self.agency_domains.setPlaceholderText("agency.gov, agency-mail.gov")
        self.recipient_domains = QLineEdit(", ".join(settings.trusted_recipient_domains))
        self.recipient_domains.setPlaceholderText("domains whose mail servers are recipient-side")
        self.brands = QPlainTextEdit("\n".join(settings.impersonated_brands))
        wf.addRow("Agency domains", self.agency_domains)
        wf.addRow("Recipient domains", self.recipient_domains)
        wf.addRow("Impersonated brands\n(one domain per line)", self.brands)
        note = QLabel(
            "Lookalike and display-name checks compare sender and link domains against the agency "
            "domains and this brand list."
        )
        note.setObjectName("muted")
        note.setWordWrap(True)
        wf.addRow(note)
        tabs.addTab(wl, "Watchlist")

        # ----------------------------------------------------------- Network
        net = QWidget()
        nl = QVBoxLayout(net)
        self.dns_enabled = QCheckBox("Allow passive DNS lookups (SPF, DKIM, DMARC records)")
        self.dns_enabled.setChecked(settings.dns_enabled)
        self.update_check_enabled = QCheckBox(
            "Check GitHub for new MailTrace releases (once per day, never installs)"
        )
        self.update_check_enabled.setChecked(settings.update_check_enabled)
        upd_note = QLabel(
            "Turn this off on air-gapped or evidence-network machines. The check sends one request to "
            "api.github.com with no case data."
        )
        upd_note.setObjectName("muted")
        upd_note.setWordWrap(True)
        self.active = QCheckBox("Enable ACTIVE techniques (URL fetching, connecting to sender hosts)")
        self.active.setChecked(settings.active_features_enabled)
        warn = QLabel(
            "<b>Warning.</b> Active techniques contact adversary-controlled infrastructure. "
            "They can tip off the sender, trigger payloads, alter web-side evidence, and expose "
            "the examiner's network. Keep this off unless a supervisor has approved it for this case. "
            "Every active action is recorded in the audit log."
        )
        warn.setWordWrap(True)
        warn.setStyleSheet("color: #ef5350; background: transparent;")
        nl.addWidget(self.dns_enabled)
        nl.addSpacing(8)
        nl.addWidget(self.update_check_enabled)
        nl.addWidget(upd_note)
        nl.addSpacing(16)
        nl.addWidget(self.active)
        nl.addWidget(warn)
        nl.addStretch(1)
        tabs.addTab(net, "Network")

        # -------------------------------------------------------- Enrichment
        enr = QWidget()
        rf = QFormLayout(enr)
        self.enrichment_enabled = QCheckBox("Run enrichment after analysis (toolbar toggle)")
        self.enrichment_enabled.setChecked(settings.enrichment_enabled)
        self.geoip_city = QLineEdit(settings.geoip_city_db)
        self.geoip_city.setPlaceholderText("C:/path/to/GeoLite2-City.mmdb")
        self.geoip_asn = QLineEdit(settings.geoip_asn_db)
        self.geoip_asn.setPlaceholderText("C:/path/to/GeoLite2-ASN.mmdb")
        city_row = QHBoxLayout()
        city_row.addWidget(self.geoip_city)
        b1 = QPushButton("Browse\u2026")
        b1.clicked.connect(lambda: self._browse_mmdb(self.geoip_city))
        city_row.addWidget(b1)
        asn_row = QHBoxLayout()
        asn_row.addWidget(self.geoip_asn)
        b2 = QPushButton("Browse\u2026")
        b2.clicked.connect(lambda: self._browse_mmdb(self.geoip_asn))
        asn_row.addWidget(b2)
        self.rdap_enabled = QCheckBox("RDAP lookups (IP network owner, domain registrar and creation date)")
        self.rdap_enabled.setChecked(settings.rdap_enabled)
        self.whois_fallback = QCheckBox("Port-43 WHOIS fallback when a registry has no RDAP")
        self.whois_fallback.setChecked(settings.whois_fallback)
        self.ipinfo_enabled = QCheckBox("ipinfo.io geolocation/ASN (optional token on the API keys tab)")
        self.ipinfo_enabled.setChecked(settings.ipinfo_enabled)
        self.tor_exit_check = QCheckBox("Check IPs against the public Tor exit list")
        self.tor_exit_check.setChecked(settings.tor_exit_check)
        self.reputation_enabled = QCheckBox("Reputation APIs (AbuseIPDB, VirusTotal, URLhaus, Safe Browsing)")
        self.reputation_enabled.setChecked(settings.reputation_enabled)
        enr_note = QLabel(
            "GeoLite2 databases are supplied by you under MaxMind's licence and read offline. "
            "Reputation providers only receive indicators already in the message (IPs, domains, URLs, "
            "attachment hashes); no file content is ever uploaded. All answers are cached per case."
        )
        enr_note.setObjectName("muted")
        enr_note.setWordWrap(True)
        rf.addRow(self.enrichment_enabled)
        rf.addRow("GeoLite2 City", city_row)
        rf.addRow("GeoLite2 ASN", asn_row)
        for cb in (
            self.rdap_enabled,
            self.whois_fallback,
            self.ipinfo_enabled,
            self.tor_exit_check,
            self.reputation_enabled,
        ):
            rf.addRow(cb)
        rf.addRow(enr_note)
        tabs.addTab(enr, "Enrichment")

        # ---------------------------------------------------------- API keys
        keys = QWidget()
        kf = QFormLayout(keys)
        intro = QLabel(
            "Keys are stored in Windows Credential Manager, never in a config file. "
            "Leave a field blank to keep the stored key; use Clear to remove it."
        )
        intro.setObjectName("muted")
        intro.setWordWrap(True)
        kf.addRow(intro)
        self.key_fields: dict[str, QLineEdit] = {}
        for pid, label in self.PROVIDERS:
            edit = QLineEdit()
            edit.setEchoMode(QLineEdit.EchoMode.Password)
            edit.setPlaceholderText("stored" if get_api_key(pid) else "not set")
            clear = QPushButton("Clear")
            clear.clicked.connect(lambda _=False, p=pid, e=edit: self._clear_key(p, e))
            row = QHBoxLayout()
            row.addWidget(edit, 1)
            row.addWidget(clear)
            kf.addRow(label, row)
            self.key_fields[pid] = edit
        tabs.addTab(keys, "API keys")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    @staticmethod
    def _h(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("h2")
        return lbl

    def _browse_logo(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose logo", self.report_logo_path.text(), "Images (*.png *.jpg *.jpeg)"
        )
        if path:
            self.report_logo_path.setText(path)

    def _browse_mmdb(self, edit: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose GeoLite2 database", edit.text(), "MaxMind DB (*.mmdb)"
        )
        if path:
            edit.setText(path)

    def _clear_key(self, provider: str, edit: QLineEdit) -> None:
        delete_api_key(provider)
        edit.clear()
        edit.setPlaceholderText("not set")

    @staticmethod
    def _csv(text: str) -> list[str]:
        return [t.strip().lower() for t in text.split(",") if t.strip()]

    def _save(self) -> None:
        if self.active.isChecked() and not self.settings.active_features_enabled:
            answer = QMessageBox.warning(
                self,
                "Enable active techniques?",
                "This allows MailTrace to contact sender infrastructure. Confirm that this is "
                "authorised for your current case.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                self.active.setChecked(False)
                return
        s = self.settings
        s.default_examiner = self.default_examiner.text().strip()
        s.default_agency = self.default_agency.text().strip()
        s.report_default_examiner = s.default_examiner
        s.reporter_name = s.default_examiner
        s.reporter_email = self.reporter_email.text().strip()
        s.reporter_phone = self.reporter_phone.text().strip()
        s.case_base_dir = self.case_base.text().strip()
        s.report_agency_name = self.report_agency_name.text().strip()
        s.report_agency_line2 = self.report_agency_line2.text().strip()
        s.report_logo_path = self.report_logo_path.text().strip()
        s.report_classification = self.report_classification.text().strip()
        s.report_footer_note = self.report_footer_note.text().strip()
        s.agency_domains = self._csv(self.agency_domains.text())
        s.trusted_recipient_domains = self._csv(self.recipient_domains.text())
        s.impersonated_brands = [
            b.strip().lower() for b in self.brands.toPlainText().splitlines() if b.strip()
        ]
        s.dns_enabled = self.dns_enabled.isChecked()
        s.update_check_enabled = self.update_check_enabled.isChecked()
        s.active_features_enabled = self.active.isChecked()
        s.enrichment_enabled = self.enrichment_enabled.isChecked()
        s.geoip_city_db = self.geoip_city.text().strip()
        s.geoip_asn_db = self.geoip_asn.text().strip()
        s.rdap_enabled = self.rdap_enabled.isChecked()
        s.whois_fallback = self.whois_fallback.isChecked()
        s.ipinfo_enabled = self.ipinfo_enabled.isChecked()
        s.tor_exit_check = self.tor_exit_check.isChecked()
        s.reputation_enabled = self.reputation_enabled.isChecked()
        for pid, edit in self.key_fields.items():
            if edit.text().strip() and not set_api_key(pid, edit.text().strip()):
                QMessageBox.warning(self, "Credential store", f"Could not store the {pid} key.")
        save_settings(s)
        self.accept()


class AboutDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("About MailTrace")
        lay = QVBoxLayout(self)
        text = QLabel(
            f"<h2 style='margin:0'>MailTrace {__version__}</h2>"
            "<p>Passive forensic analysis of phishing and fraud email for law-enforcement investigators.</p>"
            "<p>Findings are analytical aids. Every conclusion carries a confidence label and must be "
            "verified by the investigator before it is relied upon in a charging decision "
            "or court filing.</p>"
            f"<p>Releases and source: <code>{RELEASES_PAGE}</code></p>"
        )
        text.setTextFormat(Qt.TextFormat.RichText)
        text.setWordWrap(True)
        text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(text)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        lay.addWidget(buttons)
