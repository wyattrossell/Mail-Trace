"""Report model shared by the HTML, PDF and JSON renderers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mailtrace_core.models import AnalysisResult, Confidence, EvidenceItem


@dataclass(slots=True)
class Verdict:
    """The headline assessment. Always paired with a confidence and its basis."""

    label: str
    confidence: Confidence
    sender_assessment: str
    sender_confidence: Confidence
    basis: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ReportMeta:
    report_id: str
    generated_at: str
    tool_version: str
    agency_name: str
    agency_line2: str
    logo_path: str
    classification: str
    footer_note: str
    examiner: str
    case_number: str
    case_agency: str
    case_root: str


@dataclass(slots=True)
class Report:
    meta: ReportMeta
    evidence: list[EvidenceItem]
    result: AnalysisResult
    verdict: Verdict
    executive_summary: list[str]
    key_observations: list[str]
    limitations: list[str]
    audit_entries: list[dict[str, Any]]
    settings_snapshot: dict[str, Any] = field(default_factory=dict)
