from __future__ import annotations

from mailtrace_core.enrichment.models import (
    DomainEnrichment,
    EnrichmentReport,
    IpEnrichment,
    ReputationVerdict,
)
from mailtrace_core.enrichment.risk import band_for, compute_risk
from mailtrace_core.models import (
    Address,
    AnalysisResult,
    Confidence,
    DkimVerification,
    DmarcVerification,
    Finding,
    ParsedEmail,
    Severity,
    SourceFormat,
)


def _result(*findings: Finding) -> AnalysisResult:
    pe = ParsedEmail(source_format=SourceFormat.EML, source_name="x")
    pe.from_ = Address("", "a@sender.test")
    return AnalysisResult(email=pe, findings=list(findings))


def _f(rule: str, sev: Severity, conf: Confidence) -> Finding:
    return Finding(rule, f"{rule} title", conf, sev, "why")


def test_bands() -> None:
    assert band_for(0) == "low" and band_for(19) == "low"
    assert band_for(20) == "moderate" and band_for(45) == "high" and band_for(70) == "critical"


def test_findings_only_with_cap_and_repeat_bonus() -> None:
    r = _result(
        _f("UD-001", Severity.HIGH, Confidence.CONFIRMED),
        _f("UD-001", Severity.HIGH, Confidence.CONFIRMED),
        _f("SM-002", Severity.HIGH, Confidence.CONFIRMED),
        _f("AT-001", Severity.HIGH, Confidence.CONFIRMED),
        _f("HA-001", Severity.MEDIUM, Confidence.CONFIRMED),
        _f("AU-002", Severity.INFO, Confidence.CONFIRMED),
    )
    risk = compute_risk(r, None)
    names = {f.name.split(" ")[0]: f for f in risk.factors}
    assert names["UD-001"].points == 22 and "2 occurrences" in names["UD-001"].evidence
    assert "AU-002" not in names  # info findings never score
    assert risk.score == 60 and risk.band == "high"
    assert any("capped at 60" in n for n in risk.notes)
    assert any("no enrichment" in n for n in risk.notes)


def test_enrichment_factors_and_mitigation() -> None:
    r = _result(_f("SM-001", Severity.MEDIUM, Confidence.CONFIRMED))
    report = EnrichmentReport(
        domains=[
            DomainEnrichment(
                domain="sender.test", roles=["sender From"], created="2026-09-22", age_days=4, is_new=True
            ),
            DomainEnrichment(
                domain="link.test",
                roles=["url host"],
                age_days=3000,
                reputation=[ReputationVerdict("virustotal", "link.test", "domain", "malicious", "9/70")],
            ),
        ],
        ips=[
            IpEnrichment(
                ip="198.51.100.200", roles=["origin (likely): x"], tor=True, flag_reasons=["Tor exit list"]
            )
        ],
        url_reputation=[
            ReputationVerdict("safebrowsing", "https://link.test/", "url", "malicious", "SOCIAL_ENGINEERING")
        ],
        skipped=["abuseipdb: no API key stored"],
    )
    risk = compute_risk(r, report)
    by_source = {}
    for f in risk.factors:
        by_source.setdefault(f.source, 0)
        by_source[f.source] += f.points
    assert by_source["findings"] == 10
    assert by_source["domain"] == 15
    assert by_source["ip"] == 10
    assert by_source["reputation"] == 30
    assert risk.score == 50  # 10 + min(55, 40)
    assert risk.band == "high"
    assert any("capped at 40" in n for n in risk.notes) and any("abuseipdb" in n for n in risk.notes)


def test_mitigation_lowers_score() -> None:
    r = _result(_f("HA-005", Severity.LOW, Confidence.CONFIRMED))
    r.email.auth.dkim = DkimVerification("sender.test", "s", "pass")
    r.email.auth.dmarc = DmarcVerification("sender.test", "pass")
    report = EnrichmentReport(
        domains=[
            DomainEnrichment(
                domain="sender.test",
                roles=["sender From"],
                age_days=4000,
                is_new=False,
                reputation=[
                    ReputationVerdict("virustotal", "sender.test", "domain", "clean", "0/70"),
                    ReputationVerdict("urlhaus", "sender.test", "domain", "clean", ""),
                ],
            ),
        ]
    )
    risk = compute_risk(r, report)
    assert risk.score == 0 and risk.band == "low"
    assert {f.source for f in risk.factors} == {"findings", "mitigation"}
    assert sum(f.points for f in risk.factors if f.source == "mitigation") == -10
