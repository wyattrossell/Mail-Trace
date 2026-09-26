"""Passive DNS records for domains (A/MX/NS) and reverse DNS for IPs, cached."""

from __future__ import annotations

from typing import Any

from mailtrace_core.enrichment.context import Context, ProviderAnswer
from mailtrace_core.enrichment.dns_lookup import DnsTempError
from mailtrace_core.enrichment.models import Lookup, LookupStatus


def domain_records(domain: str, ctx: Context) -> tuple[dict[str, list[str]] | None, Lookup]:
    if ctx.resolver is None:
        return None, ctx.skip("dns", domain, "offline")

    def call() -> ProviderAnswer:
        assert ctx.resolver is not None
        try:
            rec: dict[str, Any] = {
                "a": ctx.resolver.a(domain),
                "mx": ctx.resolver.mx(domain),
                "ns": ctx.resolver.ns(domain),
            }
        except DnsTempError as exc:
            return ProviderAnswer(LookupStatus.ERROR, detail=f"DNS failure: {exc}")
        if not any(rec.values()):
            return ProviderAnswer(LookupStatus.NOT_FOUND, detail="no A/MX/NS records", value=rec)
        return ProviderAnswer(LookupStatus.OK, value=rec)

    return ctx.cached_call("dns", f"domain:{domain}", call, ttl_hours=6)


def reverse_dns(ip: str, ctx: Context) -> tuple[list[str] | None, Lookup]:
    if ctx.resolver is None:
        return None, ctx.skip("dns", ip, "offline")

    def call() -> ProviderAnswer:
        assert ctx.resolver is not None
        try:
            names = ctx.resolver.ptr(ip)
        except DnsTempError as exc:
            return ProviderAnswer(LookupStatus.ERROR, detail=f"DNS failure: {exc}")
        if not names:
            return ProviderAnswer(LookupStatus.NOT_FOUND, detail="no PTR record")
        return ProviderAnswer(LookupStatus.OK, value=names)

    return ctx.cached_call("dns", f"ptr:{ip}", call, ttl_hours=6)
