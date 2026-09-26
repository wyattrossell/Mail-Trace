"""Application entry point for the MailTrace desktop GUI."""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from mailtrace_core import __version__
from mailtrace_gui.main_window import MainWindow


def _icon_path() -> Path | None:
    """Bundled icon next to the frozen executable, or the repository asset in development."""
    candidates = [
        Path(getattr(sys, "_MEIPASS", "")) / "assets" / "mailtrace.ico",
        Path(sys.executable).parent / "assets" / "mailtrace.ico",
        Path(__file__).resolve().parents[2] / "assets" / "mailtrace.ico",
    ]
    return next((c for c in candidates if c.is_file()), None)


def main(argv: list[str] | None = None) -> int:
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("MailTrace")
    app.setApplicationVersion(__version__)
    app.setOrganizationName("MailTrace")
    app.setStyle("Fusion")
    icon = _icon_path()
    if icon is not None:
        app.setWindowIcon(QIcon(str(icon)))
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
