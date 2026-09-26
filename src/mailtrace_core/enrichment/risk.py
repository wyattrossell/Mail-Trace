"""Transparent risk score.

The score is a triage aid, not evidence. Every point is attributable to a
named factor with the observation behind it, so the breakdown can be shown
next to the number. Rule findings contribute up to 60 points, enrichment
signals up to 40, and verified-good signals can subtract a little.
"""

from __future__ import annotations

from mailtrace_core.enrichment.models import EnrichmentReport, RiskFactor, RiskScore
from mailtrace_core.models import AnalysisResult, Confidence, Severity
from mailtrace_core.util.defang import defang_url
from mailtrace_core.util.timeutil import iso_utc

_FINDING_POINTS: dict[tuple[Severity, Confidence], int] = {
    (Severity.HIGH, Confidence.CONFIRMED): 20,
    (Severity.HIGH, Confidence.LIKELY): 14,
    (Severity.HIGH, Confidence.UNVERIFIED): 6,
    (Severity.MEDIUM, Confidence.CONFIRMED): 10,
    (Severity.MEDIUM, Confidence.LIKELY): 7,
    (Severity.MEDIUM, Confidence.UNVERIFIED): 3,
    (Severity.LOW, Confidence.CONFIRMED): 4,
    (Severity.LOW, Confidence.LIKELY): 3,
    (Severity.LOW, Confidence.UNVERIFIED): 1,
}
FINDINGS_CAP = 60
ENRICHMENT_CAP = 40

BANDS = ((70, "critical"), (45, "high"), (20, "moderate"), (0, "low"))


def band_for(score: int) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "low"


def compute_risk(result: AnalysisResult, report: EnrichmentReport | None) -> RiskScore:
    factors: list[RiskFactor] = []
    notes: list[str] = []

    # ---- rule findings (one factor per rule id, strongest instance counts, plus repeats)
    by_rule: dict[str, list] = {}
    for f in result.findings:
        if f.severity is Severity.INFO:
            continue
        by_rule.setdefault(f.rule_id, []).append(f)
    findings_total = 0
    for rule_id, fs in sorted(by_rule.items()):
        fs.sort(key=lambda f: _FINDING_POINTS.get((f.severity, f.confidence), 0), reverse=True)
        top = fs[0]
        pts = _FINDING_POINTS.get((top.severity, top.confidence), 0)
        if len(fs) > 1:
            pts += min(len(fs) - 1, 3) * 2
        factors.append(
            RiskFactor(
                name=f"{rule_id} {top.title}",
                points=pts,
                max_points=20,
                evidence=f"{top.severity.value}/{top.confidence.value}"
                + (f", {len(fs)} occurrences" if len(fs) > 1 else ""),
                source="findings",
            )
        )
        findings_total += pts
    if findings_total > FINDINGS_CAP:
        notes.append(f"rule findings totalled {findings_total}; capped at {FINDINGS_CAP}")
    findings_total = min(findings_total, FINDINGS_CAP)

    # ---- enrichment signals
    enrich_total = 0
    if report is not None:
        pe = result.email
        sender_regs = set()
        for a in [pe.from_, pe.return_path, *pe.reply_to]:
            if a and a.domain:
                sender_regs.add(a.domain)
        for d in report.domains:
            if d.is_new:
                is_sender = any(d.domain == s or d.domain.endswith("." + s) for s in sender_regs)
                pts = 15 if is_sender else 10
                factors.append(
                    RiskFactor(
                        name=f"newly registered domain {d.domain}",
                        points=pts,
                        max_points=15,
                        evidence=f"created {d.created} ({d.age_days} days ago)",
                        source="domain",
                    )
                )
                enrich_total += pts
            for v in d.reputation:
                if v.verdict == "malicious":
                    factors.append(
                        RiskFactor(f"{v.provider}: {d.domain} malicious", 15, 15, v.summary, "reputation")
                    )
                    enrich_total += 15
                elif v.verdict == "suspicious":
                    factors.append(
                        RiskFactor(f"{v.provider}: {d.domain} suspicious", 6, 15, v.summary, "reputation")
                    )
                    enrich_total += 6
        for ip in report.ips:
            is_origin = any(r.startswith("origin") for r in ip.roles)
            label = "originating IP" if is_origin else "IP"
            if ip.tor:
                factors.append(
                    RiskFactor(
                        f"{label} {ip.ip} is a Tor exit",
                        10 if is_origin else 4,
                        10,
                        "; ".join(ip.flag_reasons),
                        "ip",
                    )
                )
                enrich_total += 10 if is_origin else 4
            elif ip.vpn or ip.proxy:
                factors.append(
                    RiskFactor(
                        f"{label} {ip.ip} is VPN/proxy",
                        8 if is_origin else 3,
                        10,
                        "; ".join(ip.flag_reasons),
                        "ip",
                    )
                )
                enrich_total += 8 if is_origin else 3
            elif ip.hosting and is_origin:
                factors.append(
                    RiskFactor(
                        f"originating IP {ip.ip} is hosting/cloud space",
                        5,
                        10,
                        "; ".join(ip.flag_reasons) or (ip.asn_org or ""),
                        "ip",
                    )
                )
                enrich_total += 5
            for v in ip.reputation:
                if v.verdict == "malicious":
                    factors.append(
                        RiskFactor(f"{v.provider}: {ip.ip} malicious", 12, 15, v.summary, "reputation")
                    )
                    enrich_total += 12
                elif v.verdict == "suspicious":
                    factors.append(
                        RiskFactor(f"{v.provider}: {ip.ip} suspicious", 5, 15, v.summary, "reputation")
                    )
                    enrich_total += 5
        for v in report.url_reputation:
            if v.verdict == "malicious":
                factors.append(
                    RiskFactor(f"{v.provider}: URL flagged", 15, 15, defang_url(v.target)[:80], "reputation")
                )
                enrich_total += 15
            elif v.verdict == "suspicious":
                factors.append(
                    RiskFactor(
                        f"{v.provider}: URL suspicious", 6, 15, defang_url(v.target)[:80], "reputation"
                    )
                )
                enrich_total += 6
        for v in report.attachment_reputation:
            if v.verdict == "malicious":
                factors.append(
                    RiskFactor(
                        f"{v.provider}: attachment hash known malicious",
                        20,
                        20,
                        f"{v.target[:16]}… {v.summary}",
                        "reputation",
                    )
                )
                enrich_total += 20
        if enrich_total > ENRICHMENT_CAP:
            notes.append(f"enrichment signals totalled {enrich_total}; capped at {ENRICHMENT_CAP}")
        enrich_total = min(enrich_total, ENRICHMENT_CAP)
        if report.skipped:
            notes.append(
                "some enrichment providers were skipped; score may be understated: "
                + ", ".join(sorted(set(p.split(":")[0] for p in report.skipped)))
            )
    else:
        notes.append("no enrichment performed; score reflects message-internal findings only")

    # ---- mitigation
    mitigation = 0
    auth = result.email.auth
    if auth.dmarc and auth.dmarc.result == "pass" and auth.dkim and auth.dkim.result == "pass":
        mitigation += 5
        factors.append(
            RiskFactor(
                "DMARC and DKIM verified for the From domain",
                -5,
                0,
                f"dkim d={auth.dkim.domain}",
                "mitigation",
            )
        )
    if report is not None:
        old_sender = [
            d
            for d in report.domains
            if d.age_days is not None
            and d.age_days > 365 * 2
            and any(r.startswith("sender") for r in d.roles)
        ]
        if old_sender:
            mitigation += 3
            factors.append(
                RiskFactor(
                    "sender domain registered more than two years ago",
                    -3,
                    0,
                    f"{old_sender[0].domain}: {old_sender[0].age_days} days",
                    "mitigation",
                )
            )
        clean_hits = sum(1 for d in report.domains for v in d.reputation if v.verdict == "clean")
        clean_hits += sum(1 for ip in report.ips for v in ip.reputation if v.verdict == "clean")
        if clean_hits >= 2 and enrich_total == 0:
            mitigation += 2
            factors.append(
                RiskFactor("multiple clean reputation answers", -2, 0, f"{clean_hits} clean", "mitigation")
            )

    score = max(0, min(100, findings_total + enrich_total - mitigation))
    return RiskScore(score=score, band=band_for(score), factors=factors, notes=notes, computed_at=iso_utc())
