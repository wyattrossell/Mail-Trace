"""Findings from reported and independently verified SPF/DKIM/DMARC."""

from __future__ import annotations

from mailtrace_core.case.settings import Settings
from mailtrace_core.models import Confidence, Evidence, Finding, ParsedEmail, Severity

_FAIL = {"fail", "softfail", "permerror"}


def run(pe: ParsedEmail, settings: Settings) -> list[Finding]:
    out: list[Finding] = []
    auth = pe.auth

    # Reported results (assertions by the receiving server)
    for r in auth.reported:
        method = r.method
        if method.startswith("arc:"):
            continue
        if method in {"spf", "dkim", "dmarc"} and r.result in _FAIL | {"none"}:
            sev = Severity.HIGH if (method == "dmarc" and r.result == "fail") else Severity.MEDIUM
            if r.result == "none":
                sev = Severity.LOW
            out.append(
                Finding(
                    rule_id="AU-001",
                    title=f"Receiving server reported {method.upper()} {r.result}",
                    confidence=Confidence.CONFIRMED,
                    severity=sev,
                    category="authentication",
                    explanation=f"Authentication-Results from '{r.authserv_id}' recorded "
                    f"{method}={r.result}. This is the receiving server's assertion; see the "
                    "independent re-verification below.",
                    evidence=[Evidence("header:Authentication-Results", r.raw)],
                )
            )

    # Independent SPF
    spf = auth.spf
    if spf and spf.result not in {"skipped"}:
        if spf.result == "pass":
            out.append(
                Finding(
                    rule_id="AU-002",
                    title="SPF verified independently: pass",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.INFO,
                    category="authentication",
                    explanation=f"Connecting IP {spf.client_ip} is authorised by {spf.domain}'s SPF "
                    f"record (matched {spf.matched_mechanism}).",
                    evidence=[Evidence(f"dns:TXT:{spf.domain}", spf.record or "")],
                )
            )
        elif spf.result in _FAIL:
            out.append(
                Finding(
                    rule_id="AU-002",
                    title=f"SPF verified independently: {spf.result}",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.HIGH if spf.result == "fail" else Severity.MEDIUM,
                    category="authentication",
                    explanation=f"Connecting IP {spf.client_ip} is not authorised to send for "
                    f"{spf.domain}. {spf.detail}".strip(),
                    evidence=[
                        Evidence(f"dns:TXT:{spf.domain}", spf.record or "(no record)"),
                        Evidence("origin", spf.client_ip or ""),
                    ],
                )
            )
        elif spf.result == "none":
            out.append(
                Finding(
                    rule_id="AU-002",
                    title="Sender domain publishes no SPF record",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.LOW,
                    category="authentication",
                    explanation=f"{spf.domain} has no SPF record; anyone can send as this domain "
                    "without SPF failing.",
                    evidence=[Evidence(f"dns:TXT:{spf.domain}", "(none)")],
                )
            )
        elif spf.result == "temperror":
            out.append(
                Finding(
                    rule_id="AU-002",
                    title="SPF could not be evaluated (DNS error)",
                    confidence=Confidence.UNVERIFIED,
                    severity=Severity.INFO,
                    category="authentication",
                    explanation=spf.detail,
                )
            )

    # Independent DKIM
    dk = auth.dkim
    if dk and dk.result not in {"skipped", "none"}:
        if dk.result == "pass":
            out.append(
                Finding(
                    rule_id="AU-003",
                    title=f"DKIM signature verified: d={dk.domain}",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.INFO,
                    category="authentication",
                    explanation=f"The signature by {dk.domain} (selector {dk.selector}) verifies "
                    f"against the published key. Signed headers: {', '.join(dk.signed_headers)}. "
                    "This proves the signed content was not altered after signing by that domain; "
                    "it does not by itself prove the From header is honest unless the domains align.",
                    evidence=[Evidence(f"dns:TXT:{dk.selector}._domainkey.{dk.domain}", "key present")],
                )
            )
        else:
            out.append(
                Finding(
                    rule_id="AU-003",
                    title=f"DKIM signature did not verify: {dk.result}",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.MEDIUM if dk.result == "fail" else Severity.LOW,
                    category="authentication",
                    explanation=dk.detail + ". A failed signature means the message was modified "
                    "in transit, the key was rotated, or the signature is forged. It does not "
                    "identify who modified it.",
                    evidence=[Evidence("header:DKIM-Signature", f"d={dk.domain} s={dk.selector}")],
                )
            )
    elif dk and dk.result == "none":
        out.append(
            Finding(
                rule_id="AU-003",
                title="Message carries no DKIM signature",
                confidence=Confidence.CONFIRMED,
                severity=Severity.LOW,
                category="authentication",
                explanation="Unsigned mail cannot be tied cryptographically to any domain.",
            )
        )

    # DMARC
    dm = auth.dmarc
    if dm and dm.result not in {"skipped"}:
        if dm.result == "fail":
            out.append(
                Finding(
                    rule_id="AU-004",
                    title=f"DMARC fails for {dm.domain} (policy p={dm.policy})",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.HIGH if dm.policy in {"reject", "quarantine"} else Severity.MEDIUM,
                    category="authentication",
                    explanation=f"Neither SPF nor DKIM aligned with the From domain. {dm.detail}. "
                    + (
                        "The domain owner asked receivers to reject such mail; delivery implies the "
                        "receiving server did not enforce it."
                        if dm.policy == "reject"
                        else ""
                    ),
                    evidence=[Evidence(f"dns:TXT:_dmarc.{dm.domain}", dm.record or "")],
                )
            )
        elif dm.result == "pass":
            out.append(
                Finding(
                    rule_id="AU-004",
                    title=f"DMARC passes for {dm.domain}",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.INFO,
                    category="authentication",
                    explanation=dm.detail,
                    evidence=[Evidence(f"dns:TXT:_dmarc.{dm.domain}", dm.record or "")],
                )
            )
        elif dm.result == "none":
            out.append(
                Finding(
                    rule_id="AU-004",
                    title=f"No DMARC policy for {dm.domain}",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.LOW,
                    category="authentication",
                    explanation="Without DMARC, receivers have no instruction to reject spoofed mail "
                    "for this domain.",
                )
            )

    # Disagreement between reported and verified
    for method, ver in (("spf", spf), ("dkim", dk), ("dmarc", dm)):
        if ver is None or ver.result in {"skipped", "temperror", "none"}:
            continue
        rep = next((r for r in auth.reported if r.method == method), None)
        if rep is None or rep.result in {"none", "temperror"}:
            continue
        if (rep.result == "pass") != (ver.result == "pass"):
            out.append(
                Finding(
                    rule_id="AU-005",
                    title=f"{method.upper()}: reported '{rep.result}' but independent check says "
                    f"'{ver.result}'",
                    confidence=Confidence.LIKELY,
                    severity=Severity.MEDIUM,
                    category="authentication",
                    explanation="The Authentication-Results header disagrees with our own "
                    "evaluation. Causes include DNS records changing since delivery, a different "
                    "connecting IP being evaluated, or a forged Authentication-Results header.",
                    evidence=[
                        Evidence("header:Authentication-Results", rep.raw),
                        Evidence("verification", f"{method}={ver.result}: {ver.detail}"),
                    ],
                )
            )

    if not auth.reported and (dk is None or dk.result == "none"):
        out.append(
            Finding(
                rule_id="AU-006",
                title="No authentication information at all",
                confidence=Confidence.CONFIRMED,
                severity=Severity.LOW,
                category="authentication",
                explanation="No Authentication-Results header and no DKIM signature. Common for "
                "pasted headers that were trimmed, and for mail from poorly configured servers.",
            )
        )
    return out
