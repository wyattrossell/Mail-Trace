"""Landing panel: drag a message here, open a file, or paste headers."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

ACCEPTED_SUFFIXES = {".eml", ".msg", ".txt", ".hdr", ".headers"}


class DropZone(QWidget):
    open_requested = Signal()
    paste_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(48, 48, 48, 48)
        self.frame = QFrame()
        self.frame.setObjectName("dropzone")
        self.frame.setProperty("active", "false")
        lay = QVBoxLayout(self.frame)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.setSpacing(12)

        icon = QLabel("✉")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setStyleSheet("font-size: 44pt; background: transparent;")
        title = QLabel("Drop an email here")
        title.setObjectName("h1")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("background: transparent;")
        sub = QLabel(
            ".eml, Outlook .msg, or a .txt of raw headers.\n"
            "The original file is hashed and copied into the case; it is never modified."
        )
        sub.setObjectName("muted")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet("background: transparent;")

        buttons = QHBoxLayout()
        buttons.setAlignment(Qt.AlignmentFlag.AlignCenter)
        open_btn = QPushButton("Open file…")
        open_btn.setObjectName("primary")
        open_btn.clicked.connect(self.open_requested.emit)
        paste_btn = QPushButton("Paste headers…")
        paste_btn.clicked.connect(self.paste_requested.emit)
        buttons.addWidget(open_btn)
        buttons.addWidget(paste_btn)

        note = QLabel(
            "Passive analysis only: no URLs are fetched, no attachments are opened, "
            "and no connection is made to sender infrastructure."
        )
        note.setObjectName("muted")
        note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        note.setWordWrap(True)
        note.setStyleSheet("background: transparent;")

        for w in (icon, title, sub):
            lay.addWidget(w)
        lay.addLayout(buttons)
        lay.addSpacing(16)
        lay.addWidget(note)
        outer.addWidget(self.frame)

    def set_active(self, active: bool) -> None:
        self.frame.setProperty("active", "true" if active else "false")
        self.frame.style().unpolish(self.frame)
        self.frame.style().polish(self.frame)
