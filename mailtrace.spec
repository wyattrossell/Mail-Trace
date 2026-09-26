# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: one-folder build with the GUI (windowed) and CLI (console) executables.

Build with:  pyinstaller mailtrace.spec --noconfirm
Output:      dist/MailTrace/   (zip this folder for distribution)
"""

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH)
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
from mailtrace_core import __version__  # noqa: E402

datas = [
    (str(SRC / "mailtrace_core" / "enrichment" / "data" / "legal_process_targets.json"), "mailtrace_core/enrichment/data"),
    (str(SRC / "mailtrace_core" / "reporting" / "templates" / "report.html.j2"), "mailtrace_core/reporting/templates"),
    (str(ROOT / "docs" / "methodology.md"), "docs"),
    (str(ROOT / "assets" / "mailtrace.ico"), "assets"),
]
datas += collect_data_files("reportlab", includes=["fonts/*"])

hiddenimports = [
    "keyring.backends.Windows",
    "keyring.backends.null",
    "dkim",
    "dns.resolver",
    "dns.reversename",
    "geoip2.database",
    "extract_msg",
    "jinja2",
    "reportlab.graphics",
    "packaging.version",
]
hiddenimports += collect_submodules("mailtrace_core")
hiddenimports += collect_submodules("mailtrace_gui")

excludes = ["tkinter", "matplotlib", "numpy", "PIL.ImageQt", "pytest", "IPython"]

block_cipher = None

gui_a = Analysis(
    [str(SRC / "mailtrace_gui" / "app.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)
cli_a = Analysis(
    [str(SRC / "mailtrace_cli" / "main.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes + ["PySide6"],
    noarchive=False,
)
# Two independent analyses collected into one folder: shared DLLs are de-duplicated
# by COLLECT, and each executable keeps its own entry script.

gui_pyz = PYZ(gui_a.pure, gui_a.zipped_data, cipher=block_cipher)
gui_exe = EXE(
    gui_pyz,
    gui_a.scripts,
    [],
    exclude_binaries=True,
    name="MailTrace",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon=str(ROOT / "assets" / "mailtrace.ico") if (ROOT / "assets" / "mailtrace.ico").exists() else None,
    version=str(ROOT / "build" / "version_info.txt") if (ROOT / "build" / "version_info.txt").exists() else None,
)
cli_pyz = PYZ(cli_a.pure, cli_a.zipped_data, cipher=block_cipher)
cli_exe = EXE(
    cli_pyz,
    cli_a.scripts,
    [],
    exclude_binaries=True,
    name="mailtrace-cli",  # "mailtrace.exe" would collide with MailTrace.exe on a case-insensitive filesystem
    debug=False,
    strip=False,
    upx=False,
    console=True,
    icon=str(ROOT / "assets" / "mailtrace.ico") if (ROOT / "assets" / "mailtrace.ico").exists() else None,
)
coll = COLLECT(
    gui_exe,
    gui_a.binaries,
    gui_a.zipfiles,
    gui_a.datas,
    cli_exe,
    cli_a.binaries,
    cli_a.zipfiles,
    cli_a.datas,
    strip=False,
    upx=False,
    name="MailTrace",
)
