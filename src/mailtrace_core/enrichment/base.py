"""Shared plumbing for enrichment providers: cache, rate limiting, status helpers."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from mailtrace_core.enrichment.models import Lookup, LookupStatus
from mailtrace_core.util.timeutil import iso_utc


class RateLimiter:
    """Minimum spacing between calls to one provider, shared across threads.

    ``min_interval`` seconds must elapse between consecutive calls. A
    provider that answers 429 also calls :meth:`back_off` so subsequent
    calls in the same run are skipped instead of hammering the API.
    """

    def __init__(self, min_interval: float, sleep: Callable[[float], None] = time.sleep) -> None:
        self.min_interval = min_interval
        self._sleep = sleep
        self._lock = threading.Lock()
        self._last = 0.0
        self.blocked_until = 0.0

    def wait(self) -> bool:
        """Block until a call is allowed. Returns False if the provider is backed off."""
        with self._lock:
            now = time.monotonic()
            if now < self.blocked_until:
                return False
            delay = self._last + self.min_interval - now
            if delay > 0:
                self._sleep(delay)
            self._last = time.monotonic()
            return True

    def back_off(self, seconds: float) -> None:
        with self._lock:
            self.blocked_until = max(self.blocked_until, time.monotonic() + seconds)


class EnrichmentCache:
    """JSON cache keyed by ``provider`` and ``target`` with a per-entry TTL.

    Backed by a file inside the case's ``working/`` folder so repeated
    analyses of the same evidence do not repeat external lookups, and so the
    report can state exactly when each answer was obtained. With no path it
    is memory-only.
    """

    def __init__(self, path: Path | None, default_ttl_hours: float = 24.0) -> None:
        self.path = path
        self.default_ttl = timedelta(hours=default_ttl_hours)
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, Any]] = {}
        self.hits = 0
        self.misses = 0
        if path and path.exists():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self._data = {}

    @staticmethod
    def _key(provider: str, target: str) -> str:
        return f"{provider}|{target.lower()}"

    def get(self, provider: str, target: str, ttl_hours: float | None = None) -> tuple[Any, str] | None:
        """Return ``(value, fetched_at_iso)`` or None if absent/expired."""
        ttl = timedelta(hours=ttl_hours) if ttl_hours is not None else self.default_ttl
        with self._lock:
            entry = self._data.get(self._key(provider, target))
            if not entry:
                self.misses += 1
                return None
            fetched = datetime.fromisoformat(entry["fetched_at"].replace("Z", "+00:00"))
            if datetime.now(tz=UTC) - fetched > ttl:
                self.misses += 1
                return None
            self.hits += 1
            return entry["value"], entry["fetched_at"]

    def put(self, provider: str, target: str, value: Any) -> str:
        fetched_at = iso_utc()
        with self._lock:
            self._data[self._key(provider, target)] = {"fetched_at": fetched_at, "value": value}
            self._flush()
        return fetched_at

    def _flush(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, indent=1), encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass  # cache is an optimisation; never fail analysis over it

    def __len__(self) -> int:
        return len(self._data)


def lookup(
    provider: str,
    target: str,
    status: LookupStatus,
    detail: str = "",
    fetched_at: str | None = None,
    cached: bool = False,
) -> Lookup:
    return Lookup(
        provider=provider,
        target=target,
        status=status,
        detail=detail,
        fetched_at=fetched_at or iso_utc(),
        cached=cached,
    )


def skipped(provider: str, target: str, reason: str) -> Lookup:
    return lookup(provider, target, LookupStatus.SKIPPED, reason)


HOSTING_KEYWORDS = (
    "hosting",
    "host ",
    "hosted",
    "cloud",
    "datacenter",
    "data center",
    "data-center",
    "server",
    "vps",
    "dedicated",
    "colocation",
    "colo",
    "digitalocean",
    "linode",
    "vultr",
    "hetzner",
    "ovh",
    "amazon",
    "aws",
    "google cloud",
    "azure",
    "microsoft corporation",
    "alibaba",
    "tencent",
    "contabo",
    "choopa",
    "m247",
    "leaseweb",
    "psychz",
    "quadranet",
    "hostwinds",
    "ionos",
    "godaddy",
    "namecheap",
    "scaleway",
    "online s.a.s",
    "oracle",
    "rackspace",
    "liquid web",
    "hostinger",
    "bluehost",
    "hostgator",
    "dreamhost",
    "a2 hosting",
    "inmotion",
    "cogent",
    "zenlayer",
    "servermania",
    "hivelocity",
    "worldstream",
    "packet",
    "equinix",
    "kamatera",
    "upcloud",
    "cloudflare",
    "fastly",
    "akamai",
    "limelight",
    "stackpath",
    "hurricane electric",
)

VPN_KEYWORDS = (
    "vpn",
    "nordvpn",
    "expressvpn",
    "surfshark",
    "private internet access",
    "proton vpn",
    "mullvad",
    "cyberghost",
    "ipvanish",
    "windscribe",
    "hide.me",
    "purevpn",
    "tunnelbear",
    "torguard",
    "privatevpn",
    "datacamp limited",
    "m247",
    "packethub",
    "clouvider",
    "cdn77",
    "anonymous",
    "proxy",
)

TOR_KEYWORDS = ("tor exit", "tor-exit", "torexit", "tor relay", "onion")


def classify_infrastructure(*texts: str | None) -> tuple[bool | None, bool | None, bool | None, list[str]]:
    """Heuristic ``(hosting, vpn, tor, reasons)`` from org names and hostnames.

    A None means no evidence either way; False is only asserted by data
    sources that make the claim explicitly (e.g. ipinfo privacy fields).
    """
    blob = " ".join(t.lower() for t in texts if t)
    reasons: list[str] = []
    hosting = vpn = tor = None
    for kw in TOR_KEYWORDS:
        if kw in blob:
            tor = True
            reasons.append(f"'{kw}' in organisation/hostname")
            break
    for kw in VPN_KEYWORDS:
        if kw in blob:
            vpn = True
            reasons.append(f"'{kw.strip()}' in organisation/hostname")
            break
    for kw in HOSTING_KEYWORDS:
        if kw in blob:
            hosting = True
            reasons.append(f"'{kw.strip()}' in organisation/hostname")
            break
    return hosting, vpn, tor, reasons
