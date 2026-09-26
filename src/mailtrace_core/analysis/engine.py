"""Runs every rule module over a parsed email and collects findings.

Rules are plain functions ``(email, settings) -> list[Finding]``. They must
be deterministic and must not touch the network; anything needing DNS has
already been resolved into ``email.auth`` by the parsing pipeline.
"""

from __future__ import annotations

from collections.abc import Callable

from mailtrace_core.analysis.rules import (
    attachment_risk,
    auth_failures,
    header_anomalies,
    sender_mismatch,
    url_deception,
)
from mailtrace_core.case.settings import Settings
from mailtrace_core.models import AnalysisResult, Confidence, Finding, ParsedEmail, Severity

Rule = Callable[[ParsedEmail, Settings], list[Finding]]

RULES: list[Rule] = [
    sender_mismatch.run,
    url_deception.run,
    attachment_risk.run,
    header_anomalies.run,
    auth_failures.run,
]

_SEV_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}
_CONF_ORDER = {Confidence.CONFIRMED: 0, Confidence.LIKELY: 1, Confidence.UNVERIFIED: 2}


def analyze(pe: ParsedEmail, settings: Settings) -> AnalysisResult:
    findings: list[Finding] = []
    for rule in RULES:
        try:
            findings.extend(rule(pe, settings))
        except Exception as exc:  # noqa: BLE001 - one broken rule must not sink the report
            findings.append(
                Finding(
                    rule_id="ENGINE-ERR",
                    title=f"rule {rule.__module__.rsplit('.', 1)[-1]} failed",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.INFO,
                    explanation=f"{type(exc).__name__}: {exc}. Its checks were not applied.",
                    category="engine",
                )
            )
    findings.sort(key=lambda f: (_SEV_ORDER[f.severity], _CONF_ORDER[f.confidence], f.rule_id))
    return AnalysisResult(email=pe, findings=findings, skipped_checks=list(pe.auth.skipped_checks))
