"""AbuseIPDB v2 ``check`` endpoint. Key required (free tier: 1000 checks/day)."""

from __future__ import annotations

from typing import Any

from mailtrace_core.enrichment.context import Context, ProviderAnswer
from mailtrace_core.enrichment.models import Lookup, LookupStatus, ReputationVerdict
from mailtrace_core.util.netguard import NetCategory

PROVIDER = "abuseipdb"
URL = "https://api.abuseipdb.com/api/v2/check"


def _verdict(ip: str, d: dict[str, Any], fetched_at: str) -> ReputationVerdict:
    score = int(d.get("abuseConfidenceScore") or 0)
    reports = int(d.get("totalReports") or 0)
    if score >= 75:
        verdict = "malicious"
    elif score >= 25 or reports >= 5:
        verdict = "suspicious"
    else:
        verdict = "clean"
    detail_bits = [f"confidence {score}%", f"{reports} report(s)"]
    if d.get("usageType"):
        detail_bits.append(f"usage: {d['usageType']}")
    if d.get("isp"):
        detail_bits.append(f"ISP: {d['isp']}")
    if d.get("isTor"):
        detail_bits.append("Tor")
    if d.get("lastReportedAt"):
        detail_bits.append(f"last report {d['lastReportedAt']}")
    return ReputationVerdict(
        provider=PROVIDER,
        target=ip,
        target_type="ip",
        verdict=verdict,
        summary=f"{score}% / {reports} reports",
        detail="; ".join(detail_bits),
        link=f"https://www.abuseipdb.com/check/{ip}",
        fetched_at=fetched_at,
    )


def check_ip(ip: str, ctx: Context) -> tuple[ReputationVerdict | None, Lookup, dict[str, Any] | None]:
    """Returns ``(verdict, lookup, raw)``; raw carries usageType for hosting classification."""
    if not ctx.settings.reputation_enabled:
        return None, ctx.skip(PROVIDER, ip, "reputation lookups disabled in settings"), None
    if ctx.http is None:
        return None, ctx.skip(PROVIDER, ip, "offline"), None
    key = ctx.key(PROVIDER)
    if not key:
        return None, ctx.skip(PROVIDER, ip, "no API key stored"), None

    def call() -> ProviderAnswer:
        assert ctx.http is not None
        resp = ctx.http.get(
            URL,
            NetCategory.REPUTATION_API,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
        )
        if resp.status == 429:
            return ProviderAnswer(LookupStatus.RATE_LIMITED, retry_after=resp.retry_after)
        if resp.status in {401, 403}:
            return ProviderAnswer(LookupStatus.ERROR, detail="API key rejected")
        if resp.status >= 400 or not isinstance(resp.json, dict) or "data" not in resp.json:
            return ProviderAnswer(LookupStatus.ERROR, detail=f"HTTP {resp.status}")
        return ProviderAnswer(LookupStatus.OK, value=resp.json["data"])

    raw, lk = ctx.cached_call(PROVIDER, ip, call)
    if raw is None:
        return None, lk, None
    return _verdict(ip, raw, lk.fetched_at), lk, raw
