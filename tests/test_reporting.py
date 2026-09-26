"""Report building and the three renderers, with and without enrichment."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from pypdf import PdfReader

from mailtrace_core.analysis.engine import analyze
from mailtrace_core.case.audit import read_audit_log
from mailtrace_core.case.manager import Case
from mailtrace_core.enrichment import context as ctx_mod
from mailtrace_core.enrichment.http import HttpClient
from mailtrace_core.enrichment.legal_process import default_table_path, load_table
from mailtrace_core.enrichment.runner import run_enrichment
from mailtrace_core.models import Confidence
from mailtrace_core.reporting import build_report, default_filename, render, write_report
from mailtrace_core.reporting.html_renderer import render_html
from mailtrace_core.reporting.json_export import report_dict
from mailtrace_core.reporting.route_diagram import route_drawing, route_svg
from mailtrace_core.reporting.verdict import assess
from mailtrace_core.util import netguard
from tests.test_runner_end_to_end import make_handler


@pytest.fixture
def enriched_case(parse_sample, settings, resolver, tmp_path: Path):  # type: ignore[no-untyped-def]
    netguard.set_offline(False)
    for k in ctx_mod.DEFAULT_INTERVALS:
        ctx_mod.DEFAULT_INTERVALS[k] = 0.0
    case = Case.create(tmp_path / "cases", "26-001234", "Det. R. Example", "Example County SO")
    item = case.intake(Path(__file__).resolve().parents[1] / "sample_emails" / "02_spoofed_bank_spf_fail.eml")
    from mailtrace_core.parsing import parse_file

    pe = parse_file(Path(item.stored_path), settings, resolver)
    result = analyze(pe, settings)
    http = HttpClient(transport=httpx.MockTransport(make_handler([])))
    run_enrichment(
        result,
        settings,
        cache_path=case.working_dir / "c.json",
        resolver=resolver,
        http=http,
        key_reader=lambda p: f"key-{p}",
        legal_table=load_table(default_table_path()),
    )
    settings.report_agency_line2 = "Cyber Crimes Unit"
    settings.report_footer_note = "Draft - not for release"
    return case, item, result


def test_verdicts(parse_sample, settings) -> None:  # type: ignore[no-untyped-def]
    clean = analyze(parse_sample("01_clean_legitimate.eml"), settings)
    v = assess(clean)
    assert v.label.startswith("No significant") and v.confidence is Confidence.UNVERIFIED
    assert (
        "cryptographically authenticated" in v.sender_assessment
        and v.sender_confidence is Confidence.CONFIRMED
    )

    spoof = analyze(parse_sample("02_spoofed_bank_spf_fail.eml"), settings)
    v = assess(spoof)
    assert v.confidence is Confidence.CONFIRMED and "phishing or fraud attempt" in v.label
    assert "DMARC" in v.sender_assessment and v.sender_confidence is Confidence.CONFIRMED
    assert v.basis

    look = analyze(parse_sample("07_agency_lookalike_domain.eml"), settings)
    v = assess(look)
    assert "false identity" in v.sender_assessment

    offline = analyze(parse_sample("05_hop_timestamp_anomalies.eml", offline=True), settings)
    v = assess(offline)
    assert v.sender_confidence is Confidence.UNVERIFIED


def test_build_report_without_case(parse_sample, settings) -> None:  # type: ignore[no-untyped-def]
    result = analyze(parse_sample("03_deceptive_links.eml", offline=True), settings)
    settings.report_default_examiner = "Examiner X"
    rep = build_report(result, settings)
    assert rep.meta.report_id.startswith("MT-NOCASE-") and rep.meta.examiner == "Examiner X"
    assert rep.evidence == [] and rep.audit_entries == []
    assert any("not performed because" in p for p in rep.executive_summary)
    assert any("No enrichment" in lim for lim in rep.limitations)
    assert any("skipped" in lim for lim in rep.limitations)
    assert rep.key_observations and rep.settings_snapshot["dns_enabled"] is True


def test_render_all_formats_with_case(enriched_case, settings) -> None:  # type: ignore[no-untyped-def]
    case, item, result = enriched_case
    rep = build_report(result, settings, case, item)
    assert rep.meta.report_id.startswith("MT-26-001234-")
    assert rep.meta.agency_name == "Example County SO" and rep.meta.agency_line2 == "Cyber Crimes Unit"
    assert rep.evidence[0].sha256 == item.sha256
    assert any("Registration records attribute" in p for p in rep.executive_summary)
    assert any("risk score is" in p for p in rep.executive_summary)

    html = render_html(rep)
    for needle in (
        "Email Forensic Analysis Report",
        rep.meta.report_id,
        item.sha256,
        "<svg",
        "hxxps[:]//",
        "Legal process targets",
        "2703(f)",
        "Appendix A. Audit log",
        "Risk score",
        "Cyber Crimes Unit",
        "Draft - not for release",
        "examplebank[.]test",
    ):
        assert needle in html, needle
    assert "https://examplebank-secure-verify.test" not in html  # never live links
    assert "<script" not in html

    data = report_dict(rep)
    assert data["schema_version"] == 1 and data["meta"]["report_id"] == rep.meta.report_id
    assert data["result"]["enrichment"]["risk"]["score"] == result.enrichment.risk.score
    assert "raw_bytes" not in data["result"]["email"]
    json.dumps(data)

    pdf = render(rep, "pdf")
    assert pdf.startswith(b"%PDF")
    reader = PdfReader(__import__("io").BytesIO(pdf))
    assert len(reader.pages) >= 5
    first = reader.pages[0].extract_text()
    last = reader.pages[-1].extract_text()
    assert "Report ID" in first and rep.meta.report_id in first
    assert f"Page 1 of {len(reader.pages)}" in first
    assert f"Page {len(reader.pages)} of {len(reader.pages)}" in last
    assert "Example County SO" in first and "MailTrace v" in first
    assert "LAW ENFORCEMENT SENSITIVE" in first and "Draft - not for release" in first
    body = "".join(p.extract_text() for p in reader.pages)
    for needle in (
        "Executive summary",
        "Delivery route",
        "Authentication",
        "Findings and spoofing",
        "Legal process targets",
        "Limitations",
        "Audit log",
        item.sha256[:20],
        "hxxps[:]//",
    ):
        assert needle in body, needle


def test_write_report_logs_and_hashes(enriched_case, settings) -> None:  # type: ignore[no-untyped-def]
    case, item, result = enriched_case
    rep = build_report(result, settings, case, item)
    for fmt in ("pdf", "html", "json"):
        path, sha = write_report(rep, fmt, case.report_dir / default_filename(rep, fmt), case)
        assert path.exists() and len(sha) == 64
    entries = [e for e in read_audit_log(case.root / "audit.jsonl") if e.action == "report_generated"]
    assert [e.details["format"] for e in entries] == ["pdf", "html", "json"]
    assert entries[0].details["report_id"] == rep.meta.report_id and len(entries[0].details["sha256"]) == 64
    with pytest.raises(ValueError):
        render(rep, "docx")


def test_route_diagram_svg_and_drawing(parse_sample) -> None:  # type: ignore[no-untyped-def]
    pe = parse_sample("05_hop_timestamp_anomalies.eml", offline=True)
    svg = route_svg(pe.hops, "det.example@examplecounty-sheriff.gov.test")
    assert svg.startswith("<svg") and svg.count("<rect") == len(pe.hops) + 2
    assert "stroke-dasharray" in svg and "(unverified)" in svg and "192[.]168[.]1[.]5" in svg
    d = route_drawing(pe.hops, "mailbox", max_width=400)
    assert d.width <= 400 + 1
    assert route_svg([], None).count("<rect") == 1


def test_html_escapes_hostile_content(settings) -> None:
    from mailtrace_core.parsing import parse_bytes

    raw = (
        b'From: "<script>alert(1)</script>" <a@b.test>\r\nSubject: <img src=x onerror=alert(1)>\r\n'
        b"Date: Mon, 14 Sep 2026 14:00:00 +0000\r\n\r\nbody"
    )
    result = analyze(parse_bytes(raw, "x.eml", settings, None), settings)
    html = render_html(build_report(result, settings))
    assert "<script>alert" not in html and "&lt;script&gt;" in html
    assert "onerror=alert" not in html.replace("&lt;", "<") or "&lt;img" in html
    pdf = render(build_report(result, settings), "pdf")
    assert pdf.startswith(b"%PDF")
