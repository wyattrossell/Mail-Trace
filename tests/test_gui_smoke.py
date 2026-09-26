"""Headless GUI smoke test: window builds, ingest runs off-thread, tabs populate, drafts exist.

Runs on Windows only; the Linux CI runner lacks the system libraries QtWebEngine needs.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="GUI smoke test runs on Windows only")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PySide6 = pytest.importorskip("PySide6")


@pytest.fixture(scope="module")
def app():  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _pump(app, predicate, timeout: float = 30.0) -> None:  # type: ignore[no-untyped-def]
    deadline = time.time() + timeout
    while not predicate() and time.time() < deadline:
        app.processEvents()
        time.sleep(0.02)


def test_window_ingests_and_reports(app, samples_dir: Path, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import mailtrace_gui.main_window as mw
    from mailtrace_core.case.audit import read_audit_log
    from mailtrace_core.case.manager import Case
    from mailtrace_core.updates import UpdateCheckResult

    monkeypatch.setattr(
        mw, "check_for_updates", lambda **kw: UpdateCheckResult(status="skipped", current_version="0")
    )
    monkeypatch.setattr("os.startfile", lambda p: None, raising=False)
    w = mw.MainWindow()
    case = Case.create(tmp_path / "cases", "26-GUI", "Det. Example", "Example PD")
    w._set_case(case)
    w.offline_action.setChecked(True)
    w.enrich_action.setChecked(True)
    w.ingest_path(samples_dir / "02_spoofed_bank_spf_fail.eml")
    _pump(app, lambda: not w._busy)
    assert not w._busy and w._last_result is not None
    assert w.stack.currentWidget() is w.tabs
    assert w.tab_hops.table.rowCount() == 3 and w.tab_links.table.rowCount() >= 3
    assert w.tab_findings.tree.topLevelItemCount() >= 3
    assert w._last_result.enrichment is not None and w.tab_enrichment.ips.rowCount() >= 1
    assert w.evidence_list.count() == 1
    rt = w.tab_report
    assert rt.report is not None and [d.kind for d in rt._drafts][:3] == ["ic3", "ftc", "apwg"]
    rt.generate("json", ask=False)
    assert list(case.report_dir.glob("*.json"))
    rt.draft_list.setCurrentRow(2)
    rt.copy_draft()
    assert app.clipboard().text().startswith("To: reportphishing@apwg.org")
    actions = [e.action for e in read_audit_log(case.root / "audit.jsonl")]
    for expected in (
        "intake",
        "analyze_start",
        "analyze_done",
        "report_prepared",
        "report_generated",
        "draft_copied",
    ):
        assert expected in actions, expected
    w._toggle_theme()
    assert w.tab_findings.tree.topLevelItemCount() >= 3  # result survives a theme rebuild
    w.close()
