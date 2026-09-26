"""Run the full parse + rules pipeline over every synthetic sample."""

from __future__ import annotations

import json

from mailtrace_core.analysis.engine import analyze
from mailtrace_core.models import Confidence, Severity, to_jsonable


def _ids(result) -> list[str]:
    return [f.rule_id for f in result.findings]


def _find(result, rule_id: str):
    return [f for f in result.findings if f.rule_id == rule_id]


def test_01_clean_passes_everything(parse_sample, settings) -> None:
    pe = parse_sample("01_clean_legitimate.eml")
    assert [h.trusted for h in pe.hops] == [False, True, True]
    assert pe.origin_candidates[0].ip == "203.0.113.25"
    assert pe.origin_candidates[0].confidence is Confidence.LIKELY
    assert pe.auth.spf and pe.auth.spf.result == "pass"
    assert pe.auth.dkim and pe.auth.dkim.result == "pass"
    assert pe.auth.dmarc and pe.auth.dmarc.result == "pass" and pe.auth.dmarc.policy == "reject"
    assert pe.attachments[0].detected_type == "pdf" and not pe.attachments[0].type_mismatch
    r = analyze(pe, settings)
    assert all(f.severity is Severity.INFO for f in r.findings), _ids(r)
    assert r.skipped_checks == []


def test_02_spoofed_bank(parse_sample, settings) -> None:
    pe = parse_sample("02_spoofed_bank_spf_fail.eml")
    assert pe.origin_candidates[0].ip == "198.51.100.77"
    assert pe.origin_candidates[0].confidence is Confidence.LIKELY
    forged = [c for c in pe.origin_candidates if c.ip == "203.0.113.99"]
    assert forged and forged[0].confidence is Confidence.UNVERIFIED
    assert pe.hops[0].trusted is False and "below trust boundary" in pe.hops[0].trust_reason
    assert pe.auth.spf and pe.auth.spf.result == "fail"
    assert pe.auth.dmarc and pe.auth.dmarc.result == "fail" and pe.auth.dmarc.policy == "reject"
    r = analyze(pe, settings)
    ids = _ids(r)
    for expected in ("SM-001", "SM-002", "UD-001", "AU-001", "AU-002", "AU-004", "HA-005"):
        assert expected in ids, (expected, ids)
    sm002 = _find(r, "SM-002")[0]
    assert sm002.severity is Severity.HIGH and sm002.confidence is Confidence.CONFIRMED
    assert "gmail.com" in sm002.evidence[1].value.replace("[.]", ".")
    assert any("tracking pixel" in w for w in pe.warnings)


def test_03_deceptive_links(parse_sample, settings) -> None:
    pe = parse_sample("03_deceptive_links.eml")
    hosts = {u.host for u in pe.urls}
    assert "login.rnicrosoft.example" in hosts
    assert "xn--pypal-4ve.example" in hosts
    assert "203.0.113.200" in hosts and "bit.ly" in hosts
    assert all("[.]" in u.defanged for u in pe.urls if u.scheme != "mailto")
    r = analyze(pe, settings)
    ids = _ids(r)
    assert ids.count("UD-001") == 2
    kinds = {f.explanation.split(".")[0] for f in _find(r, "UD-002")}
    assert {"Lookalike type: homoglyph", "Lookalike type: idn", "Lookalike type: affix"} <= kinds
    for expected in ("UD-003", "UD-004", "UD-005", "UD-006", "UD-007", "SM-004", "SM-006"):
        assert expected in ids, (expected, ids)
    assert any(u.display_mismatch and u.host == "paypal-notices.example" for u in pe.urls)


def test_04_attachments(parse_sample, settings) -> None:
    pe = parse_sample("04_attachment_disguise.eml")
    by_name = {a.filename: a for a in pe.attachments}
    assert by_name["Invoice_88213.pdf"].type_mismatch
    assert by_name["Invoice_88213.pdf"].detected_type == "pe-executable"
    assert not by_name["terms.pdf"].type_mismatch
    assert by_name["Invoice_88213.pdf.exe"].sha256 == by_name["Invoice_88213.pdf"].sha256
    r = analyze(pe, settings)
    ids = _ids(r)
    assert ids.count("AT-001") == 2 and ids.count("AT-002") == 2
    assert "AT-003" in ids and "AT-004" in ids and "AT-005" in ids
    high = [f for f in r.findings if f.severity is Severity.HIGH]
    assert all(f.confidence is Confidence.CONFIRMED for f in high if f.rule_id.startswith("AT"))


def test_05_hop_anomalies(parse_sample, settings) -> None:
    pe = parse_sample("05_hop_timestamp_anomalies.eml")
    assert len(pe.hops) == 4
    # hop 1 claims to be three days *before* hop 0; hop 2 is then three days later.
    assert any("out of order" in a for a in pe.hops[1].anomalies)
    assert any("implausibly long" in a for a in pe.hops[2].anomalies)
    assert pe.origin_candidates[0].ip == "198.51.100.90"
    assert any(c.ip == "192.168.1.5" and c.is_private for c in pe.origin_candidates)
    r = analyze(pe, settings)
    ids = _ids(r)
    assert "HA-001" in ids and "HA-002" in ids and "HA-003" in ids


def test_06_free_mail_impersonation(parse_sample, settings) -> None:
    pe = parse_sample("06_free_mail_impersonation.eml")
    assert pe.auth.spf and pe.auth.spf.result == "pass"
    assert pe.auth.dmarc and pe.auth.dmarc.result == "pass"
    r = analyze(pe, settings)
    ids = _ids(r)
    assert "SM-005" in ids
    agency = [f for f in _find(r, "SM-004") if "agency" in f.title]
    assert agency and agency[0].confidence is Confidence.LIKELY
    assert "AU-005" not in ids  # reported and verified agree


def test_07_agency_lookalike(parse_sample, settings) -> None:
    pe = parse_sample("07_agency_lookalike_domain.eml")
    r = analyze(pe, settings)
    sm = _find(r, "SM-006")
    assert sm and "agency" in sm[0].title and sm[0].severity is Severity.HIGH
    assert "typo" in sm[0].explanation
    assert _find(r, "UD-002")


def test_08_pasted_headers(parse_sample, settings) -> None:
    pe = parse_sample("08_pasted_headers_only.txt")
    assert pe.subject == "Your package could not be delivered"
    assert [h.trusted for h in pe.hops] == [False, True, True]
    assert pe.origin_candidates[0].ip == "198.51.100.31"
    assert pe.auth.spf and pe.auth.spf.result == "softfail"
    assert pe.auth.dkim and pe.auth.dkim.result == "none"
    r = analyze(pe, settings)
    ids = _ids(r)
    assert "SM-004" in ids  # "USPS Package Center" from a non-usps domain
    assert "AU-001" in ids and "AU-005" not in ids
    assert not pe.urls


def test_09_dkim_tampered(parse_sample, settings) -> None:
    pe = parse_sample("09_dkim_body_tampered.eml")
    assert pe.auth.dkim and pe.auth.dkim.result == "fail"
    assert "body hash" in pe.auth.dkim.detail
    # SPF still aligns, so DMARC legitimately passes; DKIM alignment alone is lost.
    assert pe.auth.dmarc and pe.auth.dmarc.result == "pass"
    assert pe.auth.dmarc.dkim_aligned is False and pe.auth.dmarc.spf_aligned is True
    r = analyze(pe, settings)
    ids = _ids(r)
    assert "AU-003" in ids and "AU-005" in ids
    au5 = [f for f in r.findings if f.rule_id == "AU-005"]
    assert any("DKIM" in f.title for f in au5)


def test_10_inline_image(parse_sample, settings) -> None:
    pe = parse_sample("10_inline_image_and_pixel.eml")
    assert pe.attachments[0].is_inline and pe.attachments[0].filename == "logo.png"
    assert any("tracking pixel" in w for w in pe.warnings)
    assert not any(u.raw.startswith("cid:") for u in pe.urls)


def test_offline_mode_marks_skips(parse_sample, settings) -> None:
    pe = parse_sample("01_clean_legitimate.eml", offline=True)
    assert set(pe.auth.skipped_checks) == {"spf", "dkim", "dmarc"}
    r = analyze(pe, settings)
    assert set(r.skipped_checks) == {"spf", "dkim", "dmarc"}
    assert pe.hops and pe.urls  # everything local still works


def test_every_finding_has_confidence_and_evidence_shape(parse_sample, settings) -> None:
    for name in ("02_spoofed_bank_spf_fail.eml", "03_deceptive_links.eml", "04_attachment_disguise.eml"):
        r = analyze(parse_sample(name), settings)
        for f in r.findings:
            assert isinstance(f.confidence, Confidence)
            assert f.explanation
            assert f.rule_id != "ENGINE-ERR", f
        json.dumps(to_jsonable(r))  # serialisable
