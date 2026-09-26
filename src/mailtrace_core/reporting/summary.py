"""Plain-language executive summary and limitations, written for non-specialists."""

from __future__ import annotations

from mailtrace_core.models import AnalysisResult, Confidence, Severity, SourceFormat
from mailtrace_core.reporting.models import Verdict
from mailtrace_core.util.defang import defang_email, defang_ip

_CONF_WORDS = {
    Confidence.CONFIRMED: "This is directly observable in the message and its records.",
    Confidence.LIKELY: "This is a strong inference; an innocent explanation is possible but unlikely.",
    Confidence.UNVERIFIED: "This is an initial assessment that has not been independently confirmed.",
}


def _fmt_date(result: AnalysisResult) -> str:
    pe = result.email
    if pe.date:
        return pe.date.strftime("%d %B %Y at %H:%M %Z").replace("UTC", "UTC")
    return pe.header("Date") or "an unknown date"


def executive_summary(result: AnalysisResult, verdict: Verdict) -> list[str]:
    pe = result.email
    paras: list[str] = []
    to = ", ".join(defang_email(a.address) for a in pe.to) or "the recipient"
    frm = pe.from_
    who = "an unknown sender"
    if frm:
        who = (
            f'"{frm.display_name}" ({defang_email(frm.address)})'
            if frm.display_name
            else defang_email(frm.address)
        )
    paras.append(
        f"This report documents the examination of an email message delivered to {to} on {_fmt_date(pe and result)}. "
        f"The message presents itself as coming from {who}"
        + (f' with the subject "{pe.subject}".' if pe.subject else ".")
    )
    paras.append(
        f"Assessment: {verdict.label}. Confidence: {verdict.confidence.value}. {_CONF_WORDS[verdict.confidence]}"
    )
    paras.append(
        f"Sender identity: {verdict.sender_assessment}. Confidence: {verdict.sender_confidence.value}."
    )

    origin = next((c for c in pe.origin_candidates if c.confidence is Confidence.LIKELY), None)
    rep = result.enrichment
    if origin:
        sentence = (
            f"The message was handed to the recipient's mail system by the internet address "
            f"{defang_ip(origin.ip)}. This is the most reliable indication of where the message came from; "
            "it may be the sender's own connection, a mail provider, or a server the sender controls or has compromised."
        )
        if rep:
            ipinfo = next((i for i in rep.ips if i.ip == origin.ip), None)
            if ipinfo and (ipinfo.asn_org or ipinfo.country):
                where = ", ".join(x for x in (ipinfo.city, ipinfo.region, ipinfo.country) if x)
                sentence += f" Registration records attribute this address to {ipinfo.asn_org or ipinfo.network_name or 'an unidentified network'}"
                sentence += f" ({where})." if where else "."
                if ipinfo.tor:
                    sentence += " The address is a Tor exit node, which anonymises the true origin."
                elif ipinfo.vpn or ipinfo.proxy:
                    sentence += (
                        " The address belongs to a VPN or proxy service, which conceals the true origin."
                    )
                elif ipinfo.hosting:
                    sentence += " The address is in hosting or cloud provider space rather than a consumer connection."
        paras.append(sentence)
    elif pe.hops:
        paras.append(
            "No hop in the delivery chain could be tied to the recipient's own mail infrastructure, so the "
            "originating internet address could not be established with confidence."
        )
    else:
        paras.append("The message carries no delivery-chain headers, so its route could not be traced.")

    auth = pe.auth
    if auth.skipped_checks and len(auth.skipped_checks) == 3:
        paras.append(
            "Sender-authentication checks (SPF, DKIM, DMARC) were not performed because the analysis ran without "
            "network access. They can be re-run when DNS is available."
        )
    else:
        bits = []
        if auth.spf:
            bits.append(f"SPF {auth.spf.result}")
        if auth.dkim:
            bits.append(f"DKIM {auth.dkim.result}")
        if auth.dmarc:
            bits.append(f"DMARC {auth.dmarc.result}")
        paras.append(
            "Independent re-checking of the sender-authentication records gave: " + ", ".join(bits) + ". "
            "A 'pass' means the sending server was authorised by the domain owner; a 'fail' means it was not; "
            "'none' means the domain publishes nothing to check."
        )

    if rep and rep.risk:
        paras.append(
            f"The automated risk score is {rep.risk.score} of 100 ({rep.risk.band}). The score is a triage "
            "aid derived from the factors listed in the technical sections, not evidence in itself."
        )
    if pe.attachments:
        risky = [
            a
            for a in pe.attachments
            if a.type_mismatch
            or any(n for n in a.notes if "executable" in n or "disguise" in n or "double extension" in n)
        ]
        if risky:
            paras.append(
                f"The message carried {len(pe.attachments)} attachment(s); {len(risky)} of them are disguised or "
                "executable and should be treated as potentially malicious. No attachment was opened during this examination."
            )
    return paras


def key_observations(result: AnalysisResult) -> list[str]:
    out: list[str] = []
    for f in result.findings:
        if f.severity in {Severity.HIGH, Severity.MEDIUM}:
            out.append(f"{f.title} [{f.confidence.value}]")
    if result.enrichment:
        for d in result.enrichment.domains:
            if d.is_new:
                out.append(
                    f"Domain {d.domain} was registered only {d.age_days} day(s) before the message [confirmed]"
                )
    return out[:12]


def limitations(result: AnalysisResult) -> list[str]:
    pe = result.email
    out: list[str] = [
        "All analysis was passive: no link was visited, no attachment was opened or executed, and no connection "
        "was made to the sender's infrastructure. Findings describe the message and public records only.",
        "Attribution of an IP address or domain to an organisation is taken from public registry records "
        "(RDAP/WHOIS, routing registries). It identifies the responsible network or registrar, not a person.",
    ]
    if pe.source_format is SourceFormat.MSG:
        out.append(
            "The evidence was an Outlook .msg file, which does not preserve the original wire format. DKIM "
            "signatures therefore could not be re-verified and transport headers may be incomplete."
        )
    if pe.source_format is SourceFormat.RAW_HEADERS:
        out.append(
            "The evidence was a pasted header block. Body-dependent checks (links, attachments, DKIM body hash) "
            "were limited to what was included in the paste."
        )
    if result.skipped_checks:
        out.append(
            "Authentication checks skipped: "
            + ", ".join(result.skipped_checks)
            + " (offline or DNS disabled). Results may differ when re-run online."
        )
    untrusted = [h for h in pe.hops if not h.trusted]
    if untrusted:
        out.append(
            f"{len(untrusted)} of {len(pe.hops)} delivery hops were written by parties outside the recipient's "
            "infrastructure and could have been fabricated; they are reported as unverified."
        )
    if result.enrichment:
        if result.enrichment.skipped:
            out.append("Enrichment providers not consulted: " + "; ".join(result.enrichment.skipped) + ".")
        if any(t.verify_before_use for t in result.enrichment.legal_targets):
            out.append(
                "Legal-process contacts are taken from a locally maintained table and must be verified against "
                "each provider's current published guidelines before process is served."
            )
        out.append(
            "Hosting/VPN/Tor classification combines published lists with keyword heuristics; a heuristic "
            "match is indicated as such and is not proof."
        )
    else:
        out.append(
            "No enrichment (geolocation, registration records, reputation) was performed for this report."
        )
    out.append(
        "DNS and reputation answers reflect the state of those services at the time of analysis, which may "
        "differ from their state when the message was delivered."
    )
    return out
