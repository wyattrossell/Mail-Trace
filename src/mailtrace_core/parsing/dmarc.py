"""DMARC (RFC 7489) record lookup and alignment evaluation."""

from __future__ import annotations

from mailtrace_core.enrichment.dns_lookup import DnsTempError, Resolver
from mailtrace_core.models import DkimVerification, DmarcVerification, SpfVerification
from mailtrace_core.parsing.urls import registrable_domain


def parse_dmarc_record(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            tags[k.strip().lower()] = v.strip()
    return tags


def fetch_dmarc(domain: str, resolver: Resolver) -> tuple[str | None, str | None]:
    """Return ``(record, domain_it_was_found_at)``; falls back to the org domain."""
    for cand in _candidates(domain):
        txts = resolver.txt(f"_dmarc.{cand}")
        recs = [t for t in txts if t.lower().replace(" ", "").startswith("v=dmarc1")]
        if recs:
            return recs[0], cand
    return None, None


def _candidates(domain: str) -> list[str]:
    org = registrable_domain(domain)
    return [domain] if org == domain else [domain, org]


def aligned(a: str | None, b: str | None, mode: str) -> bool:
    if not a or not b:
        return False
    a, b = a.lower(), b.lower()
    if mode == "s":
        return a == b
    return registrable_domain(a) == registrable_domain(b)


def check_dmarc(
    from_domain: str | None,
    spf: SpfVerification | None,
    dkim: DkimVerification | None,
    resolver: Resolver | None,
) -> DmarcVerification:
    if resolver is None:
        return DmarcVerification(from_domain, "skipped", detail="DNS disabled or offline")
    if not from_domain:
        return DmarcVerification(from_domain, "skipped", detail="no From domain")
    try:
        record, found_at = fetch_dmarc(from_domain.lower(), resolver)
    except DnsTempError as exc:
        return DmarcVerification(from_domain, "temperror", detail=f"DNS failure: {exc}")
    if record is None:
        return DmarcVerification(
            from_domain, "none", detail="no DMARC record published for domain or organisation"
        )
    tags = parse_dmarc_record(record)
    policy = tags.get("p", "none").lower()
    if found_at != from_domain.lower() and "sp" in tags:
        policy = tags["sp"].lower()
    adkim = tags.get("adkim", "r").lower()[:1] or "r"
    aspf = tags.get("aspf", "r").lower()[:1] or "r"

    spf_ok = bool(spf and spf.result == "pass" and aligned(spf.domain, from_domain, aspf))
    dkim_ok = bool(dkim and dkim.result == "pass" and aligned(dkim.domain, from_domain, adkim))
    result = "pass" if (spf_ok or dkim_ok) else "fail"
    parts = []
    if spf is None or spf.result == "skipped":
        parts.append("SPF not evaluated")
    else:
        parts.append(f"SPF {spf.result}" + (", aligned" if spf_ok else ", not aligned"))
    if dkim is None or dkim.result == "skipped":
        parts.append("DKIM not evaluated")
    else:
        parts.append(f"DKIM {dkim.result}" + (", aligned" if dkim_ok else ", not aligned"))
    if (spf is None or spf.result == "skipped") and (dkim is None or dkim.result == "skipped"):
        result = "skipped"
        parts.append("no underlying authentication could be evaluated")
    return DmarcVerification(
        domain=from_domain,
        result=result,
        record=record,
        policy=policy,
        spf_aligned=spf_ok if spf and spf.result != "skipped" else None,
        dkim_aligned=dkim_ok if dkim and dkim.result != "skipped" else None,
        alignment_spf=aspf,
        alignment_dkim=adkim,
        detail="; ".join(parts) + f"; record found at {found_at}",
    )
