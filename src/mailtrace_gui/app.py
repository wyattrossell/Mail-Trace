"""Application entry point for the MailTrace desktop GUI."""

from __future__ import annotations

import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from mailtrace_core import __version__
from mailtrace_gui.main_window import MainWindow


def main(argv: list[str] | None = None) -> int:
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("MailTrace")
    app.setApplicationVersion(__version__)
    app.setOrganizationName("MailTrace")
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
