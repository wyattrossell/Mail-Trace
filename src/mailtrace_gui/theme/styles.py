"""Colour tokens and Qt style sheets for the dark and light themes."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Palette:
    name: str
    bg: str
    surface: str
    surface_alt: str
    border: str
    text: str
    text_muted: str
    accent: str
    accent_text: str
    selection: str
    high: str
    medium: str
    low: str
    info: str
    confirmed: str
    likely: str
    unverified: str
    trusted_bg: str
    warn_bg: str
    mono: str = "Cascadia Mono, Consolas, 'Courier New', monospace"


DARK = Palette(
    name="dark",
    bg="#15181d",
    surface="#1d2127",
    surface_alt="#242931",
    border="#2f353f",
    text="#e4e7ec",
    text_muted="#8f97a6",
    accent="#5b9cff",
    accent_text="#0b1220",
    selection="#2b4a7a",
    high="#ef5350",
    medium="#f5a524",
    low="#4fa3ff",
    info="#8f97a6",
    confirmed="#3ecf8e",
    likely="#f5a524",
    unverified="#9aa3b2",
    trusted_bg="#1c2a22",
    warn_bg="#2d2618",
)

LIGHT = Palette(
    name="light",
    bg="#f3f5f8",
    surface="#ffffff",
    surface_alt="#eef1f5",
    border="#d5dae2",
    text="#1c2128",
    text_muted="#5f6877",
    accent="#2563eb",
    accent_text="#ffffff",
    selection="#cfe0ff",
    high="#c62828",
    medium="#b26a00",
    low="#1565c0",
    info="#5f6877",
    confirmed="#1b8a4c",
    likely="#b26a00",
    unverified="#6b7280",
    trusted_bg="#e9f6ee",
    warn_bg="#fff6e0",
)


def build_qss(p: Palette) -> str:
    return f"""
QWidget {{
    background: {p.bg};
    color: {p.text};
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 10pt;
}}
QMainWindow::separator {{ background: {p.border}; width: 1px; height: 1px; }}
QToolBar {{
    background: {p.surface};
    border-bottom: 1px solid {p.border};
    padding: 4px 8px;
    spacing: 6px;
}}
QToolBar QToolButton {{
    background: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 6px 10px;
    color: {p.text};
}}
QToolBar QToolButton:hover {{ background: {p.surface_alt}; border-color: {p.border}; }}
QToolBar QToolButton:checked {{ background: {p.selection}; border-color: {p.accent}; }}
QStatusBar {{ background: {p.surface}; border-top: 1px solid {p.border}; color: {p.text_muted}; }}
QDockWidget {{ titlebar-close-icon: none; titlebar-normal-icon: none; }}
QDockWidget::title {{
    background: {p.surface};
    padding: 8px 12px;
    border-bottom: 1px solid {p.border};
    font-weight: 600;
}}
QFrame#card, QFrame#panel {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-radius: 8px;
}}
QLabel#h1 {{ font-size: 16pt; font-weight: 600; }}
QLabel#h2 {{ font-size: 12pt; font-weight: 600; }}
QLabel#muted {{ color: {p.text_muted}; }}
QLabel#mono {{ font-family: {p.mono}; }}
QTabWidget::pane {{ border: 1px solid {p.border}; border-radius: 6px; background: {p.surface}; top: -1px; }}
QTabBar::tab {{
    background: transparent;
    color: {p.text_muted};
    padding: 8px 16px;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{ color: {p.text}; border-bottom: 2px solid {p.accent}; }}
QTabBar::tab:hover {{ color: {p.text}; }}
QTableWidget, QTreeWidget, QListWidget, QPlainTextEdit, QTextEdit, QLineEdit, QComboBox {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-radius: 6px;
    selection-background-color: {p.selection};
    selection-color: {p.text};
    gridline-color: {p.border};
    alternate-background-color: {p.surface_alt};
}}
QLineEdit, QComboBox, QPlainTextEdit {{ padding: 6px 8px; }}
QLineEdit:focus, QPlainTextEdit:focus {{ border-color: {p.accent}; }}
QHeaderView::section {{
    background: {p.surface_alt};
    color: {p.text_muted};
    padding: 6px 8px;
    border: none;
    border-bottom: 1px solid {p.border};
    border-right: 1px solid {p.border};
    font-weight: 600;
}}
QTableWidget::item, QTreeWidget::item {{ padding: 4px 6px; }}
QPushButton {{
    background: {p.surface_alt};
    border: 1px solid {p.border};
    border-radius: 6px;
    padding: 7px 14px;
}}
QPushButton:hover {{ border-color: {p.accent}; }}
QPushButton#primary {{
    background: {p.accent}; color: {p.accent_text}; border-color: {p.accent}; font-weight: 600;
}}
QPushButton#danger {{ border-color: {p.high}; color: {p.high}; }}
QCheckBox::indicator {{ width: 16px; height: 16px; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {p.border}; border-radius: 5px; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: {p.text_muted}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {p.border}; border-radius: 5px; min-width: 24px; }}
QSplitter::handle {{ background: {p.border}; }}
QToolTip {{ background: {p.surface_alt}; color: {p.text}; border: 1px solid {p.border}; padding: 4px; }}
QMessageBox QLabel {{ background: transparent; }}
QFrame#dropzone {{
    background: {p.surface};
    border: 2px dashed {p.border};
    border-radius: 12px;
}}
QFrame#dropzone[active="true"] {{ border-color: {p.accent}; background: {p.surface_alt}; }}
QLabel#badge {{ border-radius: 4px; padding: 2px 8px; font-weight: 600; font-size: 9pt; }}
"""


def badge_html(text: str, color: str, fg: str = "#0b1220") -> str:
    return (
        f'<span style="background:{color};color:{fg};border-radius:4px;'
        f'padding:2px 8px;font-weight:600;font-size:9pt;">{text}</span>'
    )
