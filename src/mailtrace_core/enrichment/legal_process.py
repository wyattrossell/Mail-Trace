"""Map observed infrastructure to legal-process contacts.

The table ships as package data and is copied to the operator's settings
folder on first use; the operator's copy is the one that is loaded, so
they can correct or extend it without touching the application.
"""

from __future__ import annotations

import json
import shutil
from importlib import resources
from pathlib import Path
from typing import Any

from mailtrace_core.case.settings import settings_dir
from mailtrace_core.enrichment.models import (
    DomainEnrichment,
    EnrichmentReport,
    IpEnrichment,
    LegalProcessTarget,
)
from mailtrace_core.models import ParsedEmail
from mailtrace_core.parsing.urls import registrable_domain

USER_FILE_NAME = "legal_process_targets.json"


def default_table_path() -> Path:
    return Path(str(resources.files("mailtrace_core.enrichment").joinpath("data", USER_FILE_NAME)))


def user_table_path() -> Path:
    return settings_dir() / USER_FILE_NAME


def load_table(path: Path | None = None) -> dict[str, Any]:
    """Load the operator's table, seeding it from the packaged default if absent."""
    target = path or user_table_path()
    if not target.exists():
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(default_table_path(), target)
        except OSError:
            target = default_table_path()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = json.loads(default_table_path().read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "providers" not in data:
        data = json.loads(default_table_path().read_text(encoding="utf-8"))
    return data


def _suffix_match(host: str | None, suffixes: list[str]) -> str | None:
    if not host:
        return None
    h = host.lower().rstrip(".")
    for s in suffixes:
        s = s.lower().lstrip(".")
        if h == s or h.endswith("." + s):
            return s
    return None


def _kw_match(text: str | None, keywords: list[str]) -> str | None:
    if not text:
        return None
    low = text.lower()
    for kw in keywords:
        if kw.lower() in low:
            return kw
    return None


def _entry(p: dict[str, Any], role: str, matched_on: str) -> LegalProcessTarget:
    return LegalProcessTarget(
        provider_key=str(p.get("key", "")),
        provider_name=str(p.get("name", "")),
        role=role,
        matched_on=matched_on,
        portal=str(p.get("portal") or ""),
        email=str(p.get("email") or ""),
        phone=str(p.get("phone") or ""),
        guidelines_url=str(p.get("guidelines_url") or ""),
        jurisdiction=str(p.get("jurisdiction") or ""),
        records_available=[str(r) for r in p.get("records_available", []) or []],
        notes=str(p.get("notes") or ""),
        verify_before_use=bool(p.get("verify_before_use", True)),
        last_verified=p.get("last_verified"),
    )


def _match_ip(p: dict[str, Any], ip: IpEnrichment) -> str | None:
    m = p.get("match", {})
    for label, text in (("asn_org", ip.asn_org), ("isp", ip.isp), ("network_name", ip.network_name)):
        kw = _kw_match(text, m.get("asn_orgs", []))
        if kw:
            return f"{label}: {text}"
    for host in ip.reverse_dns:
        s = _suffix_match(host, m.get("hostnames", []))
        if s:
            return f"reverse DNS: {host}"
    return None


def _match_domain(p: dict[str, Any], d: DomainEnrichment) -> tuple[str | None, str | None]:
    """Returns (mailbox-provider match, registrar match)."""
    m = p.get("match", {})
    mailbox = None
    s = _suffix_match(d.domain, m.get("domains", []))
    if s:
        mailbox = f"domain: {d.domain}"
    else:
        for mx in d.mx:
            s = _suffix_match(mx, m.get("hostnames", []))
            if s:
                mailbox = f"MX host: {mx}"
                break
    registrar = None
    kw = _kw_match(d.registrar, m.get("registrars", []))
    if kw:
        registrar = f"registrar: {d.registrar}"
    return mailbox, registrar


def _ip_role(ip: IpEnrichment) -> str:
    if any(r.startswith("origin (likely)") for r in ip.roles):
        return "originating IP owner"
    if any(r.startswith("origin candidate") for r in ip.roles):
        return "owner of unverified origin-candidate IP"
    if any(r.startswith("url host") for r in ip.roles):
        return "hosting provider of linked site"
    return "owner of relay IP"


def map_targets(pe: ParsedEmail, report: EnrichmentReport, table: dict[str, Any]) -> list[LegalProcessTarget]:
    providers = [p for p in table.get("providers", []) if isinstance(p, dict)]
    out: list[LegalProcessTarget] = []
    seen: set[tuple[str, str]] = set()

    def add(t: LegalProcessTarget) -> None:
        key = (t.provider_key, t.role)
        if key not in seen:
            seen.add(key)
            out.append(t)

    sender_domains = {a.domain for a in [pe.from_, pe.return_path, *pe.reply_to] if a and a.domain}
    sender_regs = {registrable_domain(d) for d in sender_domains}

    for ip in report.ips:
        role = _ip_role(ip)
        matched = False
        for p in providers:
            hit = _match_ip(p, ip)
            if hit:
                add(_entry(p, role, f"{ip.ip} ({hit})"))
                matched = True
                break
        if not matched and ip.abuse_contacts and not ip.is_private:
            add(
                LegalProcessTarget(
                    provider_key=f"rdap:{ip.network_handle or ip.ip}",
                    provider_name=ip.network_name or ip.asn_org or "Network owner (from RDAP)",
                    role=role,
                    matched_on=f"{ip.ip} RDAP abuse contact",
                    email=ip.abuse_contacts[0],
                    jurisdiction=ip.network_country or ip.country or "",
                    records_available=[
                        "Customer/subscriber assigned this IP at the given time",
                        "Ask the registry-listed abuse contact who the legal-process contact is",
                    ],
                    notes="No curated entry for this network; the RDAP abuse mailbox is the starting point. "
                    "Confirm the correct legal-process channel before sending compulsory process.",
                    verify_before_use=True,
                )
            )

    for d in report.domains:
        is_sender = registrable_domain(d.domain) in sender_regs
        for p in providers:
            mailbox, registrar = _match_domain(p, d)
            if mailbox and is_sender:
                add(_entry(p, "sender mailbox provider", f"{d.domain} ({mailbox})"))
            if registrar:
                role = "registrar of sender domain" if is_sender else "registrar of linked domain"
                add(_entry(p, role, f"{d.domain} ({registrar})"))
        if d.registrar and not any(t.matched_on.startswith(d.domain) and "registrar" in t.role for t in out):
            role = "registrar of sender domain" if is_sender else "registrar of linked domain"
            add(
                LegalProcessTarget(
                    provider_key=f"registrar:{d.registrar_iana_id or d.registrar}",
                    provider_name=d.registrar,
                    role=role,
                    matched_on=f"{d.domain} (registrar from RDAP/WHOIS)",
                    email=d.registrar_abuse_email or "",
                    phone=d.registrar_abuse_phone or "",
                    records_available=[
                        "Registrant identity behind privacy service",
                        "Payment method",
                        "Registration and login IP addresses",
                    ],
                    notes="No curated entry for this registrar; the registrar abuse contact from the "
                    "registration record is the starting point for preservation and for locating "
                    "the legal-process channel.",
                    verify_before_use=True,
                )
            )
    return out


def preservation_note(table: dict[str, Any]) -> str:
    return str((table.get("_meta") or {}).get("preservation_note") or "")


def process_tiers(table: dict[str, Any]) -> dict[str, str]:
    tiers = (table.get("_meta") or {}).get("process_tiers") or {}
    return {str(k): str(v) for k, v in tiers.items()}
