"""Derive the headline verdict from findings, authentication and enrichment.

The rules are deliberately simple and visible so the examiner can explain
why the report says what it says. The verdict never asserts who sent the
message; it characterises the message and the sender identity claims.
"""

from __future__ import annotations

from mailtrace_core.models import AnalysisResult, Confidence, Finding, Severity
from mailtrace_core.reporting.models import Verdict
from mailtrace_core.util.defang import defang_url

_DECEPTION_RULES = {"UD-001", "UD-002", "UD-006", "AT-001", "AT-004", "SM-004", "SM-006", "SM-005", "AT-002"}
_SPOOF_RULES = {"SM-001", "SM-002", "SM-004", "SM-006", "AU-002", "AU-004", "HA-001"}


def _strongest(findings: list[Finding]) -> list[Finding]:
    order = {Confidence.CONFIRMED: 0, Confidence.LIKELY: 1, Confidence.UNVERIFIED: 2}
    sev = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}
    return sorted(findings, key=lambda f: (sev[f.severity], order[f.confidence]))


def assess(result: AnalysisResult) -> Verdict:
    findings = [f for f in result.findings if f.severity is not Severity.INFO]
    basis: list[str] = []
    rep = result.enrichment

    high_conf = [f for f in findings if f.severity is Severity.HIGH and f.confidence is Confidence.CONFIRMED]
    high_likely = [f for f in findings if f.severity is Severity.HIGH and f.confidence is Confidence.LIKELY]
    med_conf = [f for f in findings if f.severity is Severity.MEDIUM and f.confidence is Confidence.CONFIRMED]
    deception = [f for f in findings if f.rule_id in _DECEPTION_RULES]
    malicious_rep = []
    if rep is not None:
        for d in rep.domains:
            malicious_rep += [v for v in d.reputation if v.verdict == "malicious"]
        for ip in rep.ips:
            malicious_rep += [v for v in ip.reputation if v.verdict == "malicious"]
        malicious_rep += [
            v for v in rep.url_reputation + rep.attachment_reputation if v.verdict == "malicious"
        ]

    if (len(high_conf) >= 1 and deception) or len(high_conf) >= 2 or malicious_rep:
        label = "Message exhibits indicators of a phishing or fraud attempt"
        conf = Confidence.CONFIRMED
    elif high_conf or high_likely or len(med_conf) >= 2:
        label = "Message exhibits indicators consistent with phishing or fraud"
        conf = Confidence.LIKELY
    elif findings:
        label = "Message shows anomalies that warrant follow-up"
        conf = Confidence.UNVERIFIED
    else:
        label = "No significant indicators of phishing or fraud were found"
        conf = Confidence.UNVERIFIED

    for f in _strongest(findings)[:5]:
        basis.append(f"{f.title} ({f.severity.value}, {f.confidence.value})")
    for v in malicious_rep[:3]:
        target = defang_url(v.target) if v.target_type == "url" else v.target
        basis.append(f"{v.provider} reports {v.target_type} {target[:70]} as malicious ({v.summary})")

    # ---- sender identity
    auth = result.email.auth
    spoof = [f for f in findings if f.rule_id in _SPOOF_RULES]
    dmarc_pass = bool(auth.dmarc and auth.dmarc.result == "pass")
    dkim_pass = bool(auth.dkim and auth.dkim.result == "pass")
    spf_fail = bool(auth.spf and auth.spf.result in {"fail", "softfail"})
    dmarc_fail = bool(auth.dmarc and auth.dmarc.result == "fail")
    lookalike = [f for f in findings if f.rule_id == "SM-006"]
    impersonation = [f for f in findings if f.rule_id in {"SM-004", "SM-005"}]

    if dmarc_fail and (spf_fail or not dkim_pass) and result.email.from_:
        sender = f"The From address ({result.email.from_.address}) is not authenticated: the message fails the domain owner's DMARC policy"
        sconf = Confidence.CONFIRMED
    elif lookalike or impersonation:
        sender = "The sender presents a false identity (lookalike domain or impersonating display name)"
        sconf = (
            Confidence.LIKELY
            if any(f.confidence is Confidence.LIKELY for f in lookalike + impersonation)
            else Confidence.CONFIRMED
        )
    elif dmarc_pass and dkim_pass:
        sender = "The From domain is cryptographically authenticated (DKIM aligned, DMARC pass); the account itself may still be compromised or abusive"
        sconf = Confidence.CONFIRMED
    elif spoof:
        sender = "Sender identity is inconsistent across headers and could not be verified"
        sconf = Confidence.UNVERIFIED
    elif auth.skipped_checks:
        sender = "Sender identity was not verified (authentication checks skipped)"
        sconf = Confidence.UNVERIFIED
    else:
        sender = "No evidence that the sender identity is false; not independently confirmed"
        sconf = Confidence.UNVERIFIED

    return Verdict(
        label=label, confidence=conf, sender_assessment=sender, sender_confidence=sconf, basis=basis
    )
