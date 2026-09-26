from __future__ import annotations

import email
import email.policy
from pathlib import Path
from urllib.parse import unquote

import httpx

from mailtrace_core.analysis.engine import analyze
from mailtrace_core.enrichment import context as ctx_mod
from mailtrace_core.enrichment.http import HttpClient
from mailtrace_core.enrichment.legal_process import default_table_path, load_table
from mailtrace_core.enrichment.runner import run_enrichment
from mailtrace_core.reporting import build_report
from mailtrace_core.reporting.drafts import (
    APWG_ADDRESS,
    abuse_drafts,
    all_drafts,
    apwg_draft,
    draft_as_text,
    ftc_draft,
    ic3_draft,
    mailto_url,
    write_eml_draft,
)
from mailtrace_core.util import netguard
from tests.test_runner_end_to_end import make_handler

SAMPLE = Path(__file__).resolve().parents[1] / "sample_emails" / "02_spoofed_bank_spf_fail.eml"


def _report(parse_sample, settings, resolver, enrich: bool):  # type: ignore[no-untyped-def]
    result = analyze(parse_sample("02_spoofed_bank_spf_fail.eml", offline=not enrich), settings)
    if enrich:
        netguard.set_offline(False)
        for k in ctx_mod.DEFAULT_INTERVALS:
            ctx_mod.DEFAULT_INTERVALS[k] = 0.0
        http = HttpClient(transport=httpx.MockTransport(make_handler([])))
        run_enrichment(
            result,
            settings,
            resolver=resolver,
            http=http,
            key_reader=lambda p: f"key-{p}",
            legal_table=load_table(default_table_path()),
        )
    settings.reporter_name = "Det. R. Example"
    settings.reporter_email = "rexample@agency.test"
    settings.report_default_examiner = "Det. R. Example"
    return build_report(result, settings)


def test_ic3_and_ftc_fields(parse_sample, settings, resolver) -> None:  # type: ignore[no-untyped-def]
    rep = _report(parse_sample, settings, resolver, enrich=False)
    ic3 = ic3_draft(rep, settings)
    fields = {f: v for _, f, v in ic3.fields}
    assert ic3.to == [] and "ic3.gov" in ic3.notes
    assert fields["Email address used by the subject"] == "alerts@examplebank.test"
    assert "examplebank.verification@gmail.com" in fields["Other email addresses (Reply-To / Return-Path)"]
    assert fields["IP address"] == "198.51.100.77"
    assert "https://examplebank-secure-verify.test/login" in fields["Website / URL(s)"]
    assert "phishing or fraud" in fields["Description of incident"]
    assert "[complainant" in fields["Name / address / phone / email"]  # never invented
    assert fields["Date of incident"] == "09/15/2026"
    assert "IC3 complaint data" in ic3.subject and "[Subject information] IP address:" in ic3.body

    ftc = ftc_draft(rep, settings)
    ff = {f: v for _, f, v in ftc.fields}
    assert ff["How did they contact you?"] == "Email" and ff["Email address"] == "alerts@examplebank.test"
    assert ff["Website"].startswith("https://examplebank-secure-verify.test")


def test_apwg_draft_and_eml_file(parse_sample, settings, resolver, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    rep = _report(parse_sample, settings, resolver, enrich=False)
    d = apwg_draft(rep, settings, str(SAMPLE))
    assert d.to == [APWG_ADDRESS] and d.attachments == [str(SAMPLE)]
    assert "hxxps[:]//examplebank-secure-verify[.]test/login" in d.body
    assert "https://examplebank-secure-verify.test" not in d.body  # defanged in email bodies
    assert "Det. R. Example" in d.body and "rexample@agency.test" in d.body

    out = write_eml_draft(d, tmp_path / "drafts" / "apwg.eml", from_addr="rexample@agency.test")
    msg = email.message_from_bytes(out.read_bytes(), policy=email.policy.default)
    assert msg["X-Unsent"] == "1" and msg["To"] == APWG_ADDRESS and msg["From"] == "rexample@agency.test"
    parts = [p for p in msg.walk() if p.get_filename()]
    assert len(parts) == 1 and parts[0].get_filename() == SAMPLE.name
    assert parts[0].get_content_type() == "message/rfc822"

    url = mailto_url(d)
    assert url.startswith(f"mailto:{APWG_ADDRESS}?subject=")
    assert "Phishing report: URGENT" in unquote(url)
    text = draft_as_text(d)
    assert text.startswith(f"To: {APWG_ADDRESS}") and "Attachments: " + SAMPLE.name in text


def test_abuse_drafts_from_enrichment(parse_sample, settings, resolver) -> None:  # type: ignore[no-untyped-def]
    rep = _report(parse_sample, settings, resolver, enrich=True)
    drafts = abuse_drafts(rep, settings, str(SAMPLE))
    kinds = {(d.kind, d.to[0]) for d in drafts}
    assert ("abuse-registrar", "abuse@namecheap.com") in kinds
    assert ("abuse-hosting", "abuse@bulkhost.test") in kinds
    assert len({d.to[0] for d in drafts}) == len(drafts)  # one draft per contact
    reg = next(d for d in drafts if d.kind == "abuse-registrar")
    assert "2703(f)" in reg.body and "used as the sender identity" in reg.body
    assert "Preserve all account" in reg.body and reg.attachments == [str(SAMPLE)]
    assert all("Confirm it is current" in d.notes for d in drafts)


def test_all_drafts_without_enrichment_has_no_abuse(parse_sample, settings, resolver) -> None:  # type: ignore[no-untyped-def]
    rep = _report(parse_sample, settings, resolver, enrich=False)
    drafts = all_drafts(rep, settings, None)
    assert [d.kind for d in drafts] == ["ic3", "ftc", "apwg"]
    assert drafts[2].attachments == []
