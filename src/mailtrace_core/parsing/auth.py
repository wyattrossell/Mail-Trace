"""Authentication orchestration: reported results plus independent checks."""

from __future__ import annotations

from mailtrace_core.enrichment.dns_lookup import Resolver
from mailtrace_core.models import AuthenticationSummary, Confidence, ParsedEmail, SourceFormat
from mailtrace_core.parsing.auth_results import parse_all
from mailtrace_core.parsing.dkim_verify import verify_dkim
from mailtrace_core.parsing.dmarc import check_dmarc
from mailtrace_core.parsing.spf import check_spf


def connecting_ip(pe: ParsedEmail) -> str | None:
    """The IP SPF should be evaluated against: the first external hop, if known."""
    for c in pe.origin_candidates:
        if "first external hop" in c.source and c.confidence is Confidence.LIKELY:
            return c.ip
    return None


def mailfrom_domain(pe: ParsedEmail) -> str | None:
    if pe.return_path and pe.return_path.address:
        return pe.return_path.domain or None
    if pe.from_:
        return pe.from_.domain or None
    return None


def verify_authentication(pe: ParsedEmail, resolver: Resolver | None) -> AuthenticationSummary:
    summary = AuthenticationSummary(reported=parse_all(pe.headers))
    from_domain = pe.from_.domain if pe.from_ else None

    if resolver is None:
        summary.skipped_checks.extend(["spf", "dkim", "dmarc"])

    raw = pe.raw_bytes
    if pe.source_format is SourceFormat.RAW_HEADERS and not (pe.body_text or pe.body_html):
        raw = b""  # body missing: a DKIM body hash cannot be recomputed
    summary.dkim = verify_dkim(raw, pe.headers, resolver, from_domain)
    if summary.dkim.result == "skipped" and "dkim" not in summary.skipped_checks:
        summary.skipped_checks.append("dkim")

    ip = connecting_ip(pe)
    summary.spf = check_spf(ip, mailfrom_domain(pe), resolver)
    if summary.spf.result == "skipped" and "spf" not in summary.skipped_checks:
        summary.skipped_checks.append("spf")

    summary.dmarc = check_dmarc(from_domain, summary.spf, summary.dkim, resolver)
    if summary.dmarc.result == "skipped" and "dmarc" not in summary.skipped_checks:
        summary.skipped_checks.append("dmarc")
    return summary
