"""abuse.ch URLhaus query API (host, url, payload-by-hash). Auth-Key required."""

from __future__ import annotations

from typing import Any

from mailtrace_core.enrichment.context import Context, ProviderAnswer
from mailtrace_core.enrichment.models import Lookup, LookupStatus, ReputationVerdict
from mailtrace_core.util.netguard import NetCategory

PROVIDER = "urlhaus"
BASE = "https://urlhaus-api.abuse.ch/v1"


def _query(
    ctx: Context, target: str, ttype: str, endpoint: str, form: dict[str, str]
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
        resp = ctx.http.post(
            f"{BASE}/{endpoint}/", NetCategory.REPUTATION_API, data=form, headers={"Auth-Key": key}
        )
        if resp.status == 429:
            return ProviderAnswer(LookupStatus.RATE_LIMITED, retry_after=resp.retry_after)
        if resp.status in {401, 403}:
            return ProviderAnswer(LookupStatus.ERROR, detail="API key rejected")
        if resp.status >= 400 or not isinstance(resp.json, dict):
            return ProviderAnswer(LookupStatus.ERROR, detail=f"HTTP {resp.status}")
        qs = str(resp.json.get("query_status", ""))
        if qs == "no_results":
            return ProviderAnswer(LookupStatus.NOT_FOUND, detail="not listed")
        if qs != "ok":
            return ProviderAnswer(LookupStatus.ERROR, detail=f"query_status={qs}")
        j: dict[str, Any] = resp.json
        keep = {
            "threat": j.get("threat"),
            "url_status": j.get("url_status"),
            "tags": j.get("tags"),
            "signature": j.get("signature"),
            "file_type": j.get("file_type"),
            "firstseen": j.get("firstseen"),
            "url_count": j.get("url_count"),
            "blacklists": j.get("blacklists"),
            "reference": j.get("urlhaus_reference"),
            "urls": [
                {"url": u.get("url"), "status": u.get("url_status"), "threat": u.get("threat")}
                for u in (j.get("urls") or [])[:5]
                if isinstance(u, dict)
            ],
        }
        return ProviderAnswer(LookupStatus.OK, value=keep)

    raw, lk = ctx.cached_call(PROVIDER, f"{ttype}:{target}", call)
    if raw is None:
        if lk.status is LookupStatus.NOT_FOUND:
            return ReputationVerdict(
                PROVIDER, target, ttype, "clean", "not listed", "", "", lk.fetched_at
            ), lk
        return None, lk
    online = raw.get("url_status") == "online" or any(
        u.get("status") == "online" for u in raw.get("urls") or []
    )
    verdict = "malicious"
    bits = []
    if raw.get("threat"):
        bits.append(f"threat: {raw['threat']}")
    if raw.get("signature"):
        bits.append(f"signature: {raw['signature']}")
    if raw.get("url_count"):
        bits.append(f"{raw['url_count']} URL(s) recorded")
    if raw.get("tags"):
        bits.append("tags: " + ", ".join(map(str, raw["tags"][:5])))
    if raw.get("firstseen"):
        bits.append(f"first seen {raw['firstseen']}")
    bits.append("currently online" if online else "offline/unknown status")
    return ReputationVerdict(
        provider=PROVIDER,
        target=target,
        target_type=ttype,
        verdict=verdict,
        summary="listed on URLhaus",
        detail="; ".join(bits),
        link=str(raw.get("reference") or ""),
        fetched_at=lk.fetched_at,
    ), lk


def check_host(host: str, ctx: Context) -> tuple[ReputationVerdict | None, Lookup]:
    return _query(ctx, host, "domain", "host", {"host": host})


def check_url(url: str, ctx: Context) -> tuple[ReputationVerdict | None, Lookup]:
    return _query(ctx, url, "url", "url", {"url": url})


def check_hash(sha256: str, ctx: Context) -> tuple[ReputationVerdict | None, Lookup]:
    return _query(ctx, sha256, "hash", "payload", {"sha256_hash": sha256})
