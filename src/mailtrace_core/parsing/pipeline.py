"""End-to-end parse: load, walk hops, mark trust, find origin, inventory, authenticate."""

from __future__ import annotations

from pathlib import Path

from mailtrace_core.case.settings import Settings
from mailtrace_core.enrichment.dns_lookup import Resolver
from mailtrace_core.models import ParsedEmail, SourceFormat
from mailtrace_core.parsing import headers as hdr
from mailtrace_core.parsing.auth import verify_authentication
from mailtrace_core.parsing.body import extract_from_bodies
from mailtrace_core.parsing.loader import load_eml_bytes, load_path, load_raw_headers


def recipient_domains(pe: ParsedEmail, settings: Settings) -> set[str]:
    doms: set[str] = {d.lower() for d in settings.trusted_recipient_domains if d}
    for a in [*pe.to, *pe.cc]:
        if a.domain:
            doms.add(a.domain)
    for name in ("Delivered-To", "X-Original-To", "Envelope-To", "X-Envelope-To"):
        for v in pe.header_all(name):
            v = v.strip().strip("<>")
            if "@" in v:
                doms.add(v.rpartition("@")[2].lower())
    return doms


def enrich(pe: ParsedEmail, settings: Settings, resolver: Resolver | None = None) -> ParsedEmail:
    """Populate hops, trust, origin candidates, URLs and authentication in place."""
    pe.hops = hdr.build_hops(pe.header_all("Received"))
    boundary = hdr.mark_trust(pe.hops, recipient_domains(pe, settings))
    pe.warnings.extend(hdr.check_against_date_header(pe.hops, pe.date))
    pe.origin_candidates = hdr.origin_candidates(pe.hops, boundary, pe.headers)
    if not pe.hops and pe.source_format is not SourceFormat.MSG:
        pe.warnings.append("no Received headers: hop analysis unavailable")

    extraction = extract_from_bodies(pe.body_text, pe.body_html, shorteners=settings.url_shorteners)
    pe.urls = extraction.urls
    pe.warnings.extend(extraction.warnings)
    if extraction.pixels:
        pe.warnings.append(f"{len(extraction.pixels)} tracking pixel(s) in HTML body")

    pe.auth = verify_authentication(pe, resolver)
    return pe


def parse_file(path: Path, settings: Settings, resolver: Resolver | None = None) -> ParsedEmail:
    return enrich(load_path(Path(path)), settings, resolver)


def parse_bytes(data: bytes, name: str, settings: Settings, resolver: Resolver | None = None) -> ParsedEmail:
    return enrich(load_eml_bytes(data, name), settings, resolver)


def parse_raw_headers(
    text: str, name: str, settings: Settings, resolver: Resolver | None = None
) -> ParsedEmail:
    return enrich(load_raw_headers(text, name), settings, resolver)
