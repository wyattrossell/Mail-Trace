"""Background execution so DNS, RDAP and API lookups never freeze the interface."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QRunnable, Signal, Slot

from mailtrace_core.analysis.engine import analyze
from mailtrace_core.case.settings import Settings
from mailtrace_core.models import AnalysisResult, ParsedEmail
from mailtrace_core.parsing import parse_file, parse_raw_headers
from mailtrace_core.util import netguard


class WorkerSignals(QObject):
    finished = Signal(object)
    failed = Signal(str)


class AnalysisWorker(QRunnable):
    """Parses, analyses and optionally enriches one evidence item off the UI thread."""

    def __init__(self, job: Callable[[], AnalysisResult]) -> None:
        super().__init__()
        self.signals = WorkerSignals()
        self._job = job
        self.setAutoDelete(True)

    @Slot()
    def run(self) -> None:
        try:
            self.signals.finished.emit(self._job())
        except Exception as exc:  # noqa: BLE001 - surfaced to the user
            self.signals.failed.emit(f"{type(exc).__name__}: {exc}")


def _resolver(offline: bool) -> Any:
    if offline:
        return None
    from mailtrace_core.enrichment.dns_lookup import DnsResolver

    return DnsResolver()


def _finish(
    pe: ParsedEmail, settings: Settings, offline: bool, enrich: bool, cache_path: Path | None, resolver: Any
) -> AnalysisResult:
    result = analyze(pe, settings)
    if enrich:
        from mailtrace_core.enrichment.http import HttpClient
        from mailtrace_core.enrichment.runner import run_enrichment

        http = None if offline else HttpClient()
        try:
            run_enrichment(result, settings, cache_path=cache_path, resolver=resolver, http=http)
        finally:
            if http is not None:
                http.close()
    return result


def file_job(
    path: Path, settings: Settings, offline: bool, *, enrich: bool = False, cache_path: Path | None = None
) -> Callable[[], AnalysisResult]:
    def _run() -> AnalysisResult:
        netguard.set_offline(offline)
        resolver = _resolver(offline)
        pe = parse_file(path, settings, resolver)
        return _finish(pe, settings, offline, enrich, cache_path, resolver)

    return _run


def text_job(
    text: str,
    name: str,
    settings: Settings,
    offline: bool,
    *,
    enrich: bool = False,
    cache_path: Path | None = None,
) -> Callable[[], AnalysisResult]:
    def _run() -> AnalysisResult:
        netguard.set_offline(offline)
        resolver = _resolver(offline)
        pe = parse_raw_headers(text, name, settings, resolver)
        return _finish(pe, settings, offline, enrich, cache_path, resolver)

    return _run
