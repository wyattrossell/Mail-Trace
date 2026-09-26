"""Report generation: build a Report, render it as PDF, HTML or JSON, and record it."""

from __future__ import annotations

from pathlib import Path

from mailtrace_core.case.manager import Case
from mailtrace_core.reporting.builder import build_report
from mailtrace_core.reporting.models import Report
from mailtrace_core.util.hashing import hash_file

FORMATS = ("pdf", "html", "json")


def render(report: Report, fmt: str) -> bytes:
    fmt = fmt.lower()
    if fmt == "pdf":
        from mailtrace_core.reporting.pdf_renderer import render_pdf

        return render_pdf(report)
    if fmt == "html":
        from mailtrace_core.reporting.html_renderer import render_html

        return render_html(report).encode("utf-8")
    if fmt == "json":
        from mailtrace_core.reporting.json_export import render_json

        return render_json(report).encode("utf-8")
    raise ValueError(f"unknown report format {fmt!r}; choose one of {FORMATS}")


def default_filename(report: Report, fmt: str) -> str:
    return f"{report.meta.report_id}.{fmt.lower()}"


def write_report(report: Report, fmt: str, path: Path, case: Case | None = None) -> tuple[Path, str]:
    """Render to ``path`` and return ``(path, sha256)``; logs to the case audit trail when given."""
    data = render(report, fmt)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    sha, md5 = hash_file(path)
    if case is not None:
        case.log(
            "report_generated",
            report_id=report.meta.report_id,
            format=fmt.lower(),
            path=str(path),
            size=len(data),
            sha256=sha,
            md5=md5,
            verdict=report.verdict.label,
            verdict_confidence=report.verdict.confidence.value,
        )
    return path, sha


__all__ = ["FORMATS", "build_report", "default_filename", "render", "write_report"]
