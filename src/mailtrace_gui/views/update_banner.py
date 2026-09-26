"""Non-intrusive update banner shown above the workspace when a newer release exists."""

from __future__ import annotations

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QTextBrowser, QVBoxLayout

from mailtrace_core.updates import UpdateCheckResult
from mailtrace_gui.theme.styles import Palette


class UpdateBanner(QFrame):
    def __init__(self, palette: Palette) -> None:
        super().__init__()
        self.p = palette
        self.setObjectName("panel")
        self.setVisible(False)
        self._result: UpdateCheckResult | None = None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 8, 14, 8)
        row = QHBoxLayout()
        self.text = QLabel()
        self.text.setTextFormat(Qt.TextFormat.RichText)
        self.text.setWordWrap(True)
        self.text.setStyleSheet("background: transparent;")
        row.addWidget(self.text, 1)
        self.btn_notes = QPushButton("Release notes")
        self.btn_notes.setCheckable(True)
        self.btn_notes.toggled.connect(self._toggle_notes)
        self.btn_hash = QPushButton("Copy SHA-256")
        self.btn_hash.clicked.connect(self._copy_hash)
        self.btn_download = QPushButton("Download")
        self.btn_download.setObjectName("primary")
        self.btn_download.clicked.connect(self._download)
        self.btn_dismiss = QPushButton("Dismiss")
        self.btn_dismiss.clicked.connect(lambda: self.setVisible(False))
        for b in (self.btn_notes, self.btn_hash, self.btn_download, self.btn_dismiss):
            row.addWidget(b)
        outer.addLayout(row)
        self.notes = QTextBrowser()
        self.notes.setOpenExternalLinks(False)
        self.notes.setMaximumHeight(180)
        self.notes.setVisible(False)
        outer.addWidget(self.notes)

    def show_result(self, res: UpdateCheckResult) -> None:
        self._result = res
        if res.status != "update_available":
            self.setVisible(False)
            return
        p = self.p
        sums = ""
        if res.sha256sums:
            sums = (
                f" <span style='color:{p.text_muted}'>SHA-256 of the download is published in SHA256SUMS; "
                "use Copy SHA-256 to verify after downloading.</span>"
            )
        self.text.setText(
            f"<b>MailTrace {res.latest_version} is available</b> "
            f"<span style='color:{p.text_muted}'>(you have {res.current_version}"
            + (f", released {res.published_at[:10]}" if res.published_at else "")
            + ")</span>."
            + sums
            + " <span style='color:{p.text_muted}'>Nothing is installed automatically.</span>".replace(
                "{p.text_muted}", p.text_muted
            )
        )
        self.btn_hash.setVisible(bool(res.sha256sums))
        self.notes.setMarkdown(res.release_notes or "_No release notes provided._")
        if res.sha256sums:
            self.notes.setMarkdown(
                (res.release_notes or "")
                + "\n\n**Expected SHA-256**\n\n"
                + "\n".join(f"- `{h}`  {n}" for n, h in res.sha256sums.items())
            )
        self.btn_notes.setChecked(False)
        self.setVisible(True)

    def _toggle_notes(self, on: bool) -> None:
        self.notes.setVisible(on)

    def _copy_hash(self) -> None:
        if not self._result or not self._result.sha256sums:
            return
        text = "\n".join(f"{h}  {n}" for n, h in self._result.sha256sums.items())
        QGuiApplication.clipboard().setText(text)
        self.btn_hash.setText("Copied")

    def _download(self) -> None:
        if self._result:
            QDesktopServices.openUrl(QUrl(self._result.release_url))
