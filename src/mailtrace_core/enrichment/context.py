"""Per-run context shared by every provider: settings, cache, HTTP, DNS, keys, limits."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from mailtrace_core.case.settings import Settings, get_api_key
from mailtrace_core.enrichment.base import EnrichmentCache, RateLimiter, lookup
from mailtrace_core.enrichment.dns_lookup import Resolver
from mailtrace_core.enrichment.http import HttpClient, HttpError
from mailtrace_core.enrichment.models import Lookup, LookupStatus
from mailtrace_core.util.netguard import NetworkBlocked

# Conservative spacing between calls per provider (seconds). Free tiers:
# VirusTotal 4/min, AbuseIPDB 1000/day, ipinfo 50k/month, URLhaus generous,
# RDAP servers vary and some throttle aggressively.
DEFAULT_INTERVALS: dict[str, float] = {
    "rdap": 0.5,
    "whois": 1.0,
    "ipinfo": 0.2,
    "virustotal": 15.5,
    "abuseipdb": 0.5,
    "urlhaus": 0.5,
    "safebrowsing": 0.2,
    "torexits": 0.0,
    "dns": 0.0,
}


@dataclass(slots=True)
class ProviderAnswer:
    """What a provider callable returns to :meth:`Context.cached_call`."""

    status: LookupStatus
    value: Any = None
    detail: str = ""
    retry_after: float = 60.0


@dataclass
class Context:
    settings: Settings
    cache: EnrichmentCache
    http: HttpClient | None = None
    resolver: Resolver | None = None
    keys: dict[str, str | None] = field(default_factory=dict)
    limiters: dict[str, RateLimiter] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)
    """provider -> reason, recorded the first time a provider is skipped."""
    lookups_performed: int = 0
    lookups_cached: int = 0
    key_reader: Callable[[str], str | None] = get_api_key

    def key(self, provider: str) -> str | None:
        if provider not in self.keys:
            self.keys[provider] = self.key_reader(provider)
        return self.keys[provider]

    def limiter(self, provider: str) -> RateLimiter:
        if provider not in self.limiters:
            self.limiters[provider] = RateLimiter(DEFAULT_INTERVALS.get(provider, 1.0))
        return self.limiters[provider]

    def skip(self, provider: str, target: str, reason: str) -> Lookup:
        self.skipped.setdefault(provider, reason)
        return lookup(provider, target, LookupStatus.SKIPPED, reason)

    def cached_call(
        self,
        provider: str,
        target: str,
        fn: Callable[[], ProviderAnswer],
        *,
        ttl_hours: float | None = None,
    ) -> tuple[Any, Lookup]:
        """Run ``fn`` unless the cache already holds an answer for this target.

        Handles rate limiting, network-policy blocks and transport errors so
        providers only have to parse responses. Both OK and NOT_FOUND answers
        are cached; errors are not.
        """
        hit = self.cache.get(provider, target, ttl_hours)
        if hit is not None:
            value, fetched_at = hit
            self.lookups_cached += 1
            if isinstance(value, dict) and value.get("__status__") == "not_found":
                return None, lookup(provider, target, LookupStatus.NOT_FOUND, "cached", fetched_at, True)
            return value, lookup(provider, target, LookupStatus.OK, "cached", fetched_at, True)

        limiter = self.limiter(provider)
        if not limiter.wait():
            return None, lookup(
                provider, target, LookupStatus.RATE_LIMITED, "provider backed off earlier in this run"
            )
        try:
            answer = fn()
        except NetworkBlocked as exc:
            return None, self.skip(provider, target, str(exc))
        except HttpError as exc:
            return None, lookup(provider, target, LookupStatus.ERROR, str(exc))
        except Exception as exc:  # noqa: BLE001 - a provider bug must not abort enrichment
            return None, lookup(provider, target, LookupStatus.ERROR, f"{type(exc).__name__}: {exc}")
        self.lookups_performed += 1
        if answer.status is LookupStatus.RATE_LIMITED:
            limiter.back_off(answer.retry_after)
            return None, lookup(provider, target, answer.status, answer.detail or "HTTP 429")
        if answer.status is LookupStatus.OK:
            fetched = self.cache.put(provider, target, answer.value)
            return answer.value, lookup(provider, target, answer.status, answer.detail, fetched)
        if answer.status is LookupStatus.NOT_FOUND:
            fetched = self.cache.put(provider, target, {"__status__": "not_found"})
            return None, lookup(provider, target, answer.status, answer.detail, fetched)
        return None, lookup(provider, target, answer.status, answer.detail)
