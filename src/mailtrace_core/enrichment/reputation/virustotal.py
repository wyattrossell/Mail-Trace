"""VirusTotal API v3, read-only object lookups. Key required (free: 4 req/min).

Files are looked up by SHA-256 only. There is deliberately no upload path.
"""

from __future__ import annotations

import base64
from typing import Any

from mailtrace_core.enrichment.context import Context, ProviderAnswer
from mailtrace_core.enrichment.models import Lookup, LookupStatus, ReputationVerdict
from mailtrace_core.util.netguard import NetCategory

PROVIDER = "virustotal"
BASE = "https://www.virustotal.com/api/v3"


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")


def _verdict(target: str, ttype: str, attrs: dict[str, Any], fetched_at: str, link: str) -> ReputationVerdict:
    stats = attrs.get("last_analysis_stats") or {}
    mal = int(stats.get("malicious") or 0)
    sus = int(stats.get("suspicious") or 0)
    total = sum(int(v or 0) for v in stats.values()) if stats else 0
    if mal >= 3:
        verdict = "malicious"
    elif mal >= 1 or sus >= 2:
        verdict = "suspicious"
    elif total:
        verdict = "clean"
    else:
        verdict = "unknown"
    bits = []
    if attrs.get("reputation") is not None:
        bits.append(f"community reputation {attrs['reputation']}")
    if attrs.get("meaningful_name"):
        bits.append(f"name: {attrs['meaningful_name']}")
    label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
    if label:
        bits.append(f"label: {label}")
    if isinstance(attrs.get("categories"), dict) and attrs["categories"]:
        cats = sorted(set(str(v) for v in attrs["categories"].values()))[:3]
        bits.append("categories: " + ", ".join(cats))
    if attrs.get("last_analysis_date"):
        bits.append(f"last analysis epoch {attrs['last_analysis_date']}")
    return ReputationVerdict(
        provider=PROVIDER,
        target=target,
        target_type=ttype,
        verdict=verdict,
        summary=f"{mal} malicious / {sus} suspicious of {total}",
        detail="; ".join(bits),
        link=link,
        fetched_at=fetched_at,
    )


def _lookup(
    ctx: Context, target: str, ttype: str, path: str, link: str
) -> tuple[ReputationVerdict | None, Lookup]:
    if not ctx.settings.reputation_enabled:
        return None, ctx.skip(PROVIDER, target, "reputation lookups disabled in settings")
    if ctx.http is None:
        return None, ctx.skip(PROVIDER, target, "offline")
    key = ctx.key(PROVIDER)
    if not key:
        return None, ctx.skip(PROVIDER, target, "no API key stored")

    def call() -> ProviderAnswer:
        assert ctx.http is not None
        resp = ctx.http.get(f"{BASE}/{path}", NetCategory.REPUTATION_API, headers={"x-apikey": key})
        if resp.status == 429:
            return ProviderAnswer(LookupStatus.RATE_LIMITED, retry_after=resp.retry_after)
        if resp.status == 404:
            return ProviderAnswer(LookupStatus.NOT_FOUND, detail="not in VirusTotal (never submitted)")
        if resp.status in {401, 403}:
            return ProviderAnswer(LookupStatus.ERROR, detail="API key rejected")
        if resp.status >= 400 or not isinstance(resp.json, dict):
            return ProviderAnswer(LookupStatus.ERROR, detail=f"HTTP {resp.status}")
        attrs = (resp.json.get("data") or {}).get("attributes") or {}
        keep = {
            k: attrs.get(k)
            for k in (
                "last_analysis_stats",
                "reputation",
                "meaningful_name",
                "popular_threat_classification",
                "categories",
                "last_analysis_date",
            )
        }
        return ProviderAnswer(LookupStatus.OK, value=keep)

    raw, lk = ctx.cached_call(PROVIDER, f"{ttype}:{target}", call)
    if raw is None:
        if lk.status is LookupStatus.NOT_FOUND:
            return ReputationVerdict(
                PROVIDER, target, ttype, "unknown", "not in VirusTotal", lk.detail, link, lk.fetched_at
            ), lk
        return None, lk
    return _verdict(target, ttype, raw, lk.fetched_at, link), lk


def check_ip(ip: str, ctx: Context) -> tuple[ReputationVerdict | None, Lookup]:
    return _lookup(ctx, ip, "ip", f"ip_addresses/{ip}", f"https://www.virustotal.com/gui/ip-address/{ip}")


def check_domain(domain: str, ctx: Context) -> tuple[ReputationVerdict | None, Lookup]:
    return _lookup(
        ctx, domain, "domain", f"domains/{domain}", f"https://www.virustotal.com/gui/domain/{domain}"
    )


def check_url(url: str, ctx: Context) -> tuple[ReputationVerdict | None, Lookup]:
    uid = url_id(url)
    return _lookup(ctx, url, "url", f"urls/{uid}", f"https://www.virustotal.com/gui/url/{uid}")


def check_hash(sha256: str, ctx: Context) -> tuple[ReputationVerdict | None, Lookup]:
    return _lookup(ctx, sha256, "hash", f"files/{sha256}", f"https://www.virustotal.com/gui/file/{sha256}")
