"""The core package must never import a GUI toolkit."""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import mailtrace_core

FORBIDDEN = ("PySide6", "PyQt5", "PyQt6", "tkinter", "wx")


def test_core_has_no_gui_dependency() -> None:
    """Import every core module in a fresh interpreter and check no GUI toolkit came along."""
    code = (
        "import importlib, pkgutil, sys, mailtrace_core;"
        "[importlib.import_module(m.name) for m in pkgutil.walk_packages(mailtrace_core.__path__, 'mailtrace_core.')];"
        "loaded = {n.split('.')[0] for n in sys.modules};"
        f"bad = [b for b in {FORBIDDEN!r} if b in loaded];"
        "print('BAD=' + ','.join(bad))"
    )
    env = dict(os.environ, PYTHONPATH=str(pathlib.Path(mailtrace_core.__file__).parents[1]))
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, check=True)
    assert out.stdout.strip() == "BAD=", out.stdout


def test_core_source_never_mentions_pyside() -> None:
    import pathlib

    root = pathlib.Path(mailtrace_core.__file__).parent
    for py in root.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        for bad in FORBIDDEN:
            assert f"import {bad}" not in text and f"from {bad}" not in text, py
