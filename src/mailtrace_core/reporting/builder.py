"""Assemble a :class:`Report` from a case, its evidence and an analysis result."""

from __future__ import annotations

import hashlib
from dataclasses import asdict
from pathlib import Path

from mailtrace_core import __version__
from mailtrace_core.case.audit import read_audit_log
from mailtrace_core.case.manager import Case
from mailtrace_core.case.settings import Settings
from mailtrace_core.models import AnalysisResult, EvidenceItem
from mailtrace_core.reporting import summary, verdict
from mailtrace_core.reporting.models import Report, ReportMeta
from mailtrace_core.util.timeutil import iso_utc, now_utc


def make_report_id(case_number: str | None, evidence_sha256: str | None) -> str:
    stamp = now_utc().strftime("%Y%m%d-%H%M%S")
    seed = f"{case_number or 'nocase'}|{evidence_sha256 or ''}|{stamp}"
    short = hashlib.sha256(seed.encode()).hexdigest()[:6].upper()
    prefix = (case_number or "NOCASE").replace("/", "-").replace(" ", "")[:24]
    return f"MT-{prefix}-{stamp}-{short}"


def _settings_snapshot(settings: Settings) -> dict[str, object]:
    keep = (
        "agency_domains",
        "trusted_recipient_domains",
        "dns_enabled",
        "enrichment_enabled",
        "rdap_enabled",
        "whois_fallback",
        "ipinfo_enabled",
        "tor_exit_check",
        "reputation_enabled",
        "geoip_city_db",
        "geoip_asn_db",
        "active_features_enabled",
    )
    d = asdict(settings)
    return {k: d[k] for k in keep if k in d}


def build_report(
    result: AnalysisResult,
    settings: Settings,
    case: Case | None = None,
    evidence: EvidenceItem | None = None,
) -> Report:
    ev_list = [evidence] if evidence else (case.manifest() if case else [])
    v = verdict.assess(result)
    meta = ReportMeta(
        report_id=make_report_id(
            case.meta.case_number if case else None, evidence.sha256 if evidence else None
        ),
        generated_at=iso_utc(),
        tool_version=__version__,
        agency_name=settings.report_agency_name or (case.meta.agency if case else ""),
        agency_line2=settings.report_agency_line2,
        logo_path=settings.report_logo_path
        if settings.report_logo_path and Path(settings.report_logo_path).is_file()
        else "",
        classification=settings.report_classification,
        footer_note=settings.report_footer_note,
        examiner=case.meta.examiner if case else settings.report_default_examiner,
        case_number=case.meta.case_number if case else "",
        case_agency=case.meta.agency if case else "",
        case_root=str(case.root) if case else "",
    )
    audit = [e.to_dict() for e in read_audit_log(case.root / "audit.jsonl")] if case else []
    return Report(
        meta=meta,
        evidence=ev_list,
        result=result,
        verdict=v,
        executive_summary=summary.executive_summary(result, v),
        key_observations=summary.key_observations(result),
        limitations=summary.limitations(result),
        audit_entries=audit,
        settings_snapshot=_settings_snapshot(settings),
    )
