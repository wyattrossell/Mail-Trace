"""Google Safe Browsing Lookup API v4 (``threatMatches:find``). Key required.

The Lookup API sends the URLs to Google in the request. That is a query to
a reputation service, not a fetch of the URL, but it does disclose the
indicator to a third party; the examiner enables it knowingly.
"""

from __future__ import annotations

from mailtrace_core.enrichment.context import Context, ProviderAnswer
from mailtrace_core.enrichment.models import Lookup, LookupStatus, ReputationVerdict
from mailtrace_core.util.netguard import NetCategory

PROVIDER = "safebrowsing"
URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


def check_urls(urls: list[str], ctx: Context) -> tuple[list[ReputationVerdict], Lookup]:
    """One batched request for up to 500 URLs; returns a verdict per URL."""
    urls = list(dict.fromkeys(u for u in urls if u))[:500]
    target = f"{len(urls)} url(s)"
    if not urls:
        return [], ctx.skip(PROVIDER, target, "no URLs")
    if not ctx.settings.reputation_enabled:
        return [], ctx.skip(PROVIDER, target, "reputation lookups disabled in settings")
    if ctx.http is None:
        return [], ctx.skip(PROVIDER, target, "offline")
    key = ctx.key(PROVIDER)
    if not key:
        return [], ctx.skip(PROVIDER, target, "no API key stored")

    def call() -> ProviderAnswer:
        assert ctx.http is not None
        body = {
            "client": {"clientId": "mailtrace", "clientVersion": "0.1"},
            "threatInfo": {
                "threatTypes": THREATS,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls],
            },
        }
        resp = ctx.http.post(URL, NetCategory.REPUTATION_API, params={"key": key}, json_body=body)
        if resp.status == 429:
            return ProviderAnswer(LookupStatus.RATE_LIMITED, retry_after=resp.retry_after)
        if resp.status in {400, 401, 403}:
            return ProviderAnswer(
                LookupStatus.ERROR, detail=f"API key rejected or bad request (HTTP {resp.status})"
            )
        if resp.status >= 400 or not isinstance(resp.json, dict):
            return ProviderAnswer(LookupStatus.ERROR, detail=f"HTTP {resp.status}")
        matches: dict[str, list[str]] = {}
        for m in resp.json.get("matches", []) or []:
            u = str((m.get("threat") or {}).get("url", ""))
            matches.setdefault(u, []).append(str(m.get("threatType", "")))
        return ProviderAnswer(LookupStatus.OK, value=matches)

    cache_key = "|".join(sorted(urls))
    matches, lk = ctx.cached_call(PROVIDER, cache_key, call, ttl_hours=6)
    if matches is None:
        return [], lk
    verdicts = []
    for u in urls:
        hit = matches.get(u)
        verdicts.append(
            ReputationVerdict(
                provider=PROVIDER,
                target=u,
                target_type="url",
                verdict="malicious" if hit else "clean",
                summary=", ".join(hit) if hit else "no match",
                detail="Google Safe Browsing lists this URL" if hit else "",
                link="https://transparencyreport.google.com/safe-browsing/search?url=" + u,
                fetched_at=lk.fetched_at,
            )
        )
    return verdicts, lk
