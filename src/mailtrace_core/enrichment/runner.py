"""Orchestrates every enrichment provider over an analysed message.

Targets are taken from the parsed email: originating-IP candidates and hop
IPs, the sender-identity domains, every URL host, attachment hashes. Each
provider is called through :class:`Context` so caching, rate limiting and
the passive-network policy are applied uniformly, and every consultation is
recorded as a :class:`Lookup` on the record it enriched.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mailtrace_core.case.settings import Settings
from mailtrace_core.enrichment import dns_records, geoip, legal_process, rdap, reputation, whois
from mailtrace_core.enrichment.base import EnrichmentCache
from mailtrace_core.enrichment.context import Context
from mailtrace_core.enrichment.dns_lookup import Resolver
from mailtrace_core.enrichment.http import HttpClient
from mailtrace_core.enrichment.models import (
    DomainEnrichment,
    EnrichmentReport,
    IpEnrichment,
    LookupStatus,
    ReputationVerdict,
)
from mailtrace_core.enrichment.risk import compute_risk
from mailtrace_core.models import AnalysisResult, Confidence, ParsedEmail
from mailtrace_core.parsing.headers import _ip_is_private
from mailtrace_core.parsing.urls import registrable_domain
from mailtrace_core.util.timeutil import iso_utc


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
        return True
    except ValueError:
        return False


def collect_ip_targets(pe: ParsedEmail, limit: int) -> dict[str, list[str]]:
    """``ip -> roles`` in priority order (origin candidates first)."""
    targets: dict[str, list[str]] = {}

    def add(ip: str | None, role: str) -> None:
        if not ip or _ip_is_private(ip):
            return
        targets.setdefault(ip, [])
        if role not in targets[ip]:
            targets[ip].append(role)

    for c in pe.origin_candidates:
        label = "origin (likely)" if c.confidence is Confidence.LIKELY else "origin candidate (unverified)"
        add(c.ip, f"{label}: {c.source}")
    for hop in pe.hops:
        add(hop.from_ip, f"hop {hop.index}" + (" trusted" if hop.trusted else " unverified"))
    return dict(list(targets.items())[:limit])


def collect_domain_targets(pe: ParsedEmail, limit: int) -> dict[str, list[str]]:
    targets: dict[str, list[str]] = {}

    def add(domain: str | None, role: str) -> None:
        if not domain or _is_ip(domain):
            return
        d = domain.lower().rstrip(".")
        targets.setdefault(d, [])
        if role not in targets[d]:
            targets[d].append(role)

    if pe.from_:
        add(pe.from_.domain, "sender From")
    if pe.return_path:
        add(pe.return_path.domain, "sender Return-Path")
    for r in pe.reply_to:
        add(r.domain, "sender Reply-To")
    if pe.sender:
        add(pe.sender.domain, "sender Sender header")
    for u in pe.urls:
        if u.scheme in {"http", "https", "ftp", None} and u.host:
            add(u.host, "url host")
    return dict(list(targets.items())[:limit])


def _enrich_ip(
    ip: str, roles: list[str], ctx: Context, readers: geoip.GeoReaders | None, tor_list: set[str] | None
) -> IpEnrichment:
    rec = IpEnrichment(ip=ip, roles=roles, is_private=_ip_is_private(ip))

    names, lk = dns_records.reverse_dns(ip, ctx)
    rec.lookups.append(lk)
    rec.reverse_dns = names or []

    geo, lk = geoip.geolite_lookup(ip, readers, ctx)
    rec.lookups.append(lk)
    if geo:
        rec.geo_source = "GeoLite2"
        rec.country, rec.region, rec.city = geo.get("country"), geo.get("region"), geo.get("city")
        rec.latitude, rec.longitude = geo.get("latitude"), geo.get("longitude")
        rec.asn, rec.asn_org = geo.get("asn"), geo.get("asn_org")

    info, lk = geoip.ipinfo_lookup(ip, ctx)
    rec.lookups.append(lk)
    if info:
        rec.geo_source = rec.geo_source or "ipinfo.io"
        rec.country = rec.country or info.get("country")
        rec.region = rec.region or info.get("region")
        rec.city = rec.city or info.get("city")
        rec.asn = rec.asn or info.get("asn")
        rec.asn_org = rec.asn_org or info.get("asn_org")
        if info.get("hostname") and info["hostname"] not in rec.reverse_dns:
            rec.reverse_dns.append(str(info["hostname"]))

    net, lk = rdap.rdap_ip(ip, ctx)
    rec.lookups.append(lk)
    if net:
        rec.network_handle, rec.network_name = net.get("handle"), net.get("name")
        rec.network_cidr, rec.network_country = net.get("cidr"), net.get("country")
        rec.rdap_registry = net.get("registry")
        rec.abuse_contacts = list(net.get("abuse_contacts") or [])
        rec.isp = rec.isp or net.get("org")

    usage = None
    verdict, lk, raw = reputation.abuseipdb_ip(ip, ctx)
    rec.lookups.append(lk)
    if verdict:
        rec.reputation.append(verdict)
        usage = str(raw.get("usageType") or "") if raw else None
        rec.isp = rec.isp or (raw.get("isp") if raw else None)
    verdict, lk = reputation.vt_ip(ip, ctx)
    rec.lookups.append(lk)
    if verdict:
        rec.reputation.append(verdict)

    rec.hosting, rec.vpn, rec.proxy, rec.tor, rec.flag_reasons = geoip.classify(
        rec.asn_org,
        rec.isp,
        rec.reverse_dns,
        rec.network_name,
        info,
        tor_list,
        ip,
        usage,
    )
    return rec


def _enrich_domain(
    domain: str, roles: list[str], ctx: Context, whois_query: whois.QueryFn | None
) -> DomainEnrichment:
    rec = DomainEnrichment(domain=domain, roles=roles)
    reg = registrable_domain(domain)

    recs, lk = dns_records.domain_records(domain, ctx)
    rec.lookups.append(lk)
    if recs:
        rec.a, rec.mx, rec.ns = (
            list(recs.get("a") or []),
            list(recs.get("mx") or []),
            list(recs.get("ns") or []),
        )

    data, lk = rdap.rdap_domain(reg, ctx)
    rec.lookups.append(lk)
    if data is None and lk.status in {LookupStatus.NOT_FOUND, LookupStatus.ERROR, LookupStatus.SKIPPED}:
        data, lk2 = whois.whois_domain(reg, ctx, whois_query) if whois_query else whois.whois_domain(reg, ctx)
        rec.lookups.append(lk2)
    if data:
        rec.whois_source = data.get("source")
        rec.registrar = data.get("registrar")
        rec.registrar_iana_id = data.get("registrar_iana_id")
        rec.registrar_abuse_email = data.get("registrar_abuse_email")
        rec.registrar_abuse_phone = data.get("registrar_abuse_phone")
        rec.registrant_org = data.get("registrant_org")
        rec.registrant_country = data.get("registrant_country")
        rec.created, rec.updated, rec.expires = data.get("created"), data.get("updated"), data.get("expires")
        rec.statuses = list(data.get("statuses") or [])
        rec.nameservers = list(data.get("nameservers") or [])
        rec.age_days, rec.is_new = rdap.is_new_domain(rec.created)

    verdict, lk = reputation.vt_domain(reg, ctx)
    rec.lookups.append(lk)
    if verdict:
        rec.reputation.append(verdict)
    verdict, lk = reputation.urlhaus_host(domain, ctx)
    rec.lookups.append(lk)
    if verdict:
        rec.reputation.append(verdict)
    return rec


def run_enrichment(
    result: AnalysisResult,
    settings: Settings,
    *,
    cache_path: Path | None = None,
    resolver: Resolver | None = None,
    http: HttpClient | None = None,
    geo_readers: geoip.GeoReaders | None = None,
    whois_query: whois.QueryFn | None = None,
    legal_table: dict[str, Any] | None = None,
    key_reader: Callable[[str], str | None] | None = None,
) -> EnrichmentReport:
    """Enrich ``result`` in place (sets ``result.enrichment``) and return the report."""
    report = EnrichmentReport(started_at=iso_utc())
    pe = result.email
    cache = EnrichmentCache(cache_path, settings.enrichment_cache_ttl_hours)
    ctx = Context(settings=settings, cache=cache, http=http, resolver=resolver)
    if key_reader is not None:
        ctx.key_reader = key_reader
    readers = geo_readers
    if readers is None and (settings.geoip_city_db or settings.geoip_asn_db):
        readers = geoip.GeoReaders(settings.geoip_city_db, settings.geoip_asn_db)
    if http is None:
        ctx.skipped.setdefault("network", "offline: only local GeoLite2 lookups possible")
    if resolver is None:
        ctx.skipped.setdefault("dns", "offline")

    try:
        tor_list, lk = geoip.tor_exit_ips(ctx)

        # Domains first so URL-host A records can be added as IP targets.
        domain_targets = collect_domain_targets(pe, settings.max_enrich_domains)
        for domain, roles in domain_targets.items():
            report.domains.append(_enrich_domain(domain, roles, ctx, whois_query))

        ip_targets = collect_ip_targets(pe, settings.max_enrich_ips)
        for d in report.domains:
            if any(r == "url host" for r in d.roles):
                for a in d.a[:2]:
                    if not _ip_is_private(a) and len(ip_targets) < settings.max_enrich_ips:
                        ip_targets.setdefault(a, [])
                        role = f"url host {d.domain}"
                        if role not in ip_targets[a]:
                            ip_targets[a].append(role)
        for ip, roles in ip_targets.items():
            report.ips.append(_enrich_ip(ip, roles, ctx, readers, tor_list))

        # URLs
        urls = []
        for u in pe.urls:
            if u.scheme in {"http", "https"} and u.normalized not in urls:
                urls.append(u.normalized)
        urls = urls[: settings.max_enrich_urls]
        for url in urls:
            for fn in (reputation.vt_url, reputation.urlhaus_url):
                v, lk = fn(url, ctx)
                if v:
                    report.url_reputation.append(v)
                elif lk.status not in {LookupStatus.SKIPPED, LookupStatus.NOT_FOUND}:
                    report.url_reputation.append(
                        ReputationVerdict(
                            lk.provider, url, "url", "unknown", lk.status.value, lk.detail, "", lk.fetched_at
                        )
                    )
        sb, lk = reputation.safebrowsing_urls(urls, ctx)
        report.url_reputation.extend(sb)

        # Attachments by hash only
        for att in pe.attachments:
            if not att.size:
                continue
            for fn in (reputation.vt_hash, reputation.urlhaus_hash):
                v, lk = fn(att.sha256, ctx)
                if v:
                    v.detail = f"{att.filename}; {v.detail}".strip("; ")
                    report.attachment_reputation.append(v)

        table = legal_table or legal_process.load_table()
        report.legal_targets = legal_process.map_targets(pe, report, table)
        report.preservation_note = legal_process.preservation_note(table)
    finally:
        if readers is not None and geo_readers is None:
            readers.close()

    report.skipped = sorted(f"{k}: {v}" for k, v in ctx.skipped.items())
    report.lookups_performed = ctx.lookups_performed
    report.lookups_cached = ctx.lookups_cached
    report.finished_at = iso_utc()
    report.risk = compute_risk(result, report)
    result.enrichment = report
    return report
