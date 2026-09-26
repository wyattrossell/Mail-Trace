"""Update prompt: asks the user, downloads the verified installer, hands off to it."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, QUrl, Signal, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from mailtrace_core.updates import (
    UpdateCheckResult,
    UpdateDownloadError,
    download_installer,
    installer_asset,
    launch_installer,
)
from mailtrace_gui.theme.styles import Palette, badge_html


class UpdateDialog(QDialog):
    """Modal prompt shown when a newer release exists.

    ``choice`` after ``exec()`` is ``install``, ``later`` or ``skip``.
    """

    def __init__(self, res: UpdateCheckResult, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.res = res
        self.choice = "later"
        self.setWindowTitle("Update available")
        self.setMinimumWidth(560)
        lay = QVBoxLayout(self)
        p = palette
        asset = installer_asset(res)
        head = QLabel(
            f"<h3 style='margin:0'>MailTrace {res.latest_version} is available</h3>"
            f"<div style='color:{p.text_muted}'>You have {res.current_version}"
            + (f" · released {res.published_at[:10]}" if res.published_at else "")
            + "</div>"
        )
        head.setTextFormat(Qt.TextFormat.RichText)
        lay.addWidget(head)
        notes = QTextBrowser()
        notes.setOpenExternalLinks(True)
        notes.setMaximumHeight(220)
        notes.setMarkdown(res.release_notes or "_No release notes provided._")
        lay.addWidget(notes)
        if asset is None:
            verify = (
                f"<span style='color:{p.medium}'>This release has no Windows installer attached. "
                "Use Open release page to download it manually.</span>"
            )
        elif asset.sha256:
            verify = (
                f"Installer <code>{asset.name}</code> ({asset.size / 1e6:.0f} MB). "
                f"{badge_html('SHA-256 verified before it runs', p.confirmed)}<br>"
                f"<span style='color:{p.text_muted};font-family:monospace;font-size:8pt'>{asset.sha256}</span>"
            )
        else:
            verify = (
                f"<span style='color:{p.high}'>The release publishes no SHA256SUMS entry for the installer, "
                "so MailTrace will not run it automatically. Use Open release page instead.</span>"
            )
        vl = QLabel(verify)
        vl.setTextFormat(Qt.TextFormat.RichText)
        vl.setWordWrap(True)
        vl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(vl)
        note = QLabel(
            "Installing closes MailTrace, replaces the program files in place, and refreshes the Start "
            "Menu and desktop shortcuts. Cases, settings and API keys are not touched."
        )
        note.setObjectName("muted")
        note.setWordWrap(True)
        lay.addWidget(note)

        buttons = QDialogButtonBox()
        self.btn_install = QPushButton("Download and install")
        self.btn_install.setObjectName("primary")
        self.btn_install.setEnabled(bool(asset and asset.sha256))
        btn_page = QPushButton("Open release page")
        btn_later = QPushButton("Later")
        btn_skip = QPushButton("Skip this version")
        buttons.addButton(self.btn_install, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton(btn_page, QDialogButtonBox.ButtonRole.ActionRole)
        buttons.addButton(btn_skip, QDialogButtonBox.ButtonRole.DestructiveRole)
        buttons.addButton(btn_later, QDialogButtonBox.ButtonRole.RejectRole)
        self.btn_install.clicked.connect(lambda: self._done("install"))
        btn_page.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(res.release_url)))
        btn_skip.clicked.connect(lambda: self._done("skip"))
        btn_later.clicked.connect(lambda: self._done("later"))
        lay.addWidget(buttons)

    def _done(self, choice: str) -> None:
        self.choice = choice
        self.accept()


class _DownloadSignals(QObject):
    progress = Signal(int, int)
    finished = Signal(object)
    failed = Signal(str)


class _DownloadJob(QRunnable):
    def __init__(self, res: UpdateCheckResult, dest_dir: Path) -> None:
        super().__init__()
        self.signals = _DownloadSignals()
        self._res = res
        self._dest = dest_dir
        self.setAutoDelete(True)

    @Slot()
    def run(self) -> None:
        try:
            path = download_installer(self._res, self._dest, progress=self.signals.progress.emit)
            self.signals.finished.emit(path)
        except UpdateDownloadError as exc:
            self.signals.failed.emit(str(exc))
        except Exception as exc:  # noqa: BLE001
            self.signals.failed.emit(f"{type(exc).__name__}: {exc}")


def run_update(
    res: UpdateCheckResult, parent: QWidget, log: Callable[..., None], quit_app: Callable[[], None]
) -> None:
    """Download the installer with a progress dialog, verify it, launch it, and quit."""
    dest_dir = Path.home() / "Downloads" / "MailTrace-updates"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dlg = QProgressDialog("Downloading MailTrace update…", "Cancel", 0, 100, parent)
    dlg.setWindowTitle("Updating MailTrace")
    dlg.setWindowModality(Qt.WindowModality.ApplicationModal)
    dlg.setMinimumDuration(0)
    dlg.setValue(0)
    job = _DownloadJob(res, dest_dir)
    keep = {"signals": job.signals}  # keep the QObject alive until we are done

    def on_progress(done: int, total: int) -> None:
        if dlg.wasCanceled():
            return
        dlg.setValue(int(done * 100 / total) if total else 0)
        dlg.setLabelText(
            f"Downloading MailTrace {res.latest_version}… {done / 1e6:.0f} / {total / 1e6:.0f} MB"
        )

    def on_finished(path: object) -> None:
        cancelled = dlg.wasCanceled()  # read before close(): closing a QProgressDialog cancels it
        dlg.setValue(100)
        dlg.close()
        keep.clear()
        if cancelled:
            log("update_download_cancelled", version=res.latest_version)
            return
        log("update_installer_verified", version=res.latest_version, path=str(path))
        try:
            launch_installer(Path(str(path)))
        except OSError as exc:
            QMessageBox.critical(parent, "Update", f"The installer could not be started: {exc}")
            return
        log("update_installer_launched", version=res.latest_version)
        quit_app()

    def on_failed(msg: str) -> None:
        dlg.close()
        keep.clear()
        log("update_download_failed", version=res.latest_version, error=msg)
        QMessageBox.warning(
            parent,
            "Update not installed",
            msg + "\n\nNothing was changed. You can download the release manually from the release page.",
        )

    job.signals.progress.connect(on_progress, Qt.ConnectionType.QueuedConnection)
    job.signals.finished.connect(on_finished, Qt.ConnectionType.QueuedConnection)
    job.signals.failed.connect(on_failed, Qt.ConnectionType.QueuedConnection)
    log("update_download_started", version=res.latest_version)
    QThreadPool.globalInstance().start(job)
