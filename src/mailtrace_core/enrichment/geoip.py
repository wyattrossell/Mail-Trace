"""IP geolocation and ownership: offline MaxMind GeoLite2, optional ipinfo.io, Tor exits.

The operator supplies the GeoLite2 databases (MaxMind licence). Nothing is
downloaded on their behalf. ipinfo.io is optional and works with or without
a token; the ``privacy`` block (VPN/proxy/Tor/hosting) is only present on
paid plans, so hosting/VPN detection also falls back to name heuristics.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from mailtrace_core.enrichment.base import classify_infrastructure
from mailtrace_core.enrichment.context import Context, ProviderAnswer
from mailtrace_core.enrichment.models import Lookup, LookupStatus
from mailtrace_core.util.netguard import NetCategory

TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"


class GeoReaders:
    """Wraps GeoLite2 City and ASN readers; tolerant of either being absent."""

    def __init__(
        self, city_path: str | None, asn_path: str | None, opener: Callable[[str], Any] | None = None
    ) -> None:
        self.city = None
        self.asn = None
        self.errors: list[str] = []
        opener = opener or self._open
        for attr, path in (("city", city_path), ("asn", asn_path)):
            if not path:
                continue
            if not Path(path).is_file():
                self.errors.append(f"{attr} database not found: {path}")
                continue
            try:
                setattr(self, attr, opener(path))
            except Exception as exc:  # noqa: BLE001
                self.errors.append(f"{attr} database unreadable: {exc}")

    @staticmethod
    def _open(path: str) -> Any:
        import geoip2.database

        return geoip2.database.Reader(path)

    @property
    def available(self) -> bool:
        return self.city is not None or self.asn is not None

    def lookup(self, ip: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.city is not None:
            try:
                r = self.city.city(ip)
                out.update(
                    {
                        "country": r.country.iso_code,
                        "region": (r.subdivisions.most_specific.name if r.subdivisions else None),
                        "city": r.city.name,
                        "latitude": r.location.latitude,
                        "longitude": r.location.longitude,
                    }
                )
            except Exception:  # noqa: BLE001 - AddressNotFoundError and friends
                pass
        if self.asn is not None:
            try:
                r = self.asn.asn(ip)
                out.update({"asn": r.autonomous_system_number, "asn_org": r.autonomous_system_organization})
            except Exception:  # noqa: BLE001
                pass
        return out

    def close(self) -> None:
        for r in (self.city, self.asn):
            if r is not None:
                try:
                    r.close()
                except Exception:  # noqa: BLE001
                    pass


def geolite_lookup(ip: str, readers: GeoReaders | None, ctx: Context) -> tuple[dict[str, Any] | None, Lookup]:
    from mailtrace_core.enrichment.base import lookup

    if readers is None or not readers.available:
        reason = (
            "; ".join(readers.errors) if readers and readers.errors else "GeoLite2 database not configured"
        )
        return None, ctx.skip("geolite2", ip, reason)
    data = readers.lookup(ip)
    if not data:
        return None, lookup("geolite2", ip, LookupStatus.NOT_FOUND, "address not in database")
    return data, lookup("geolite2", ip, LookupStatus.OK, "offline database")


def _parse_ipinfo(data: dict[str, Any]) -> dict[str, Any]:
    org = str(data.get("org") or "")
    asn = None
    asn_org = org or None
    if org.upper().startswith("AS"):
        num, _, rest = org.partition(" ")
        try:
            asn = int(num[2:])
            asn_org = rest or None
        except ValueError:
            pass
    privacy = data.get("privacy") if isinstance(data.get("privacy"), dict) else {}
    return {
        "hostname": data.get("hostname"),
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country"),
        "asn": asn,
        "asn_org": asn_org,
        "vpn": privacy.get("vpn") if privacy else None,
        "proxy": privacy.get("proxy") if privacy else None,
        "tor": privacy.get("tor") if privacy else None,
        "hosting": privacy.get("hosting") if privacy else None,
        "anycast": data.get("anycast"),
    }


def ipinfo_lookup(ip: str, ctx: Context) -> tuple[dict[str, Any] | None, Lookup]:
    if not ctx.settings.ipinfo_enabled:
        return None, ctx.skip("ipinfo", ip, "ipinfo.io disabled in settings")
    if ctx.http is None:
        return None, ctx.skip("ipinfo", ip, "offline")

    def call() -> ProviderAnswer:
        assert ctx.http is not None
        params = {"token": ctx.key("ipinfo")} if ctx.key("ipinfo") else None
        resp = ctx.http.get(f"https://ipinfo.io/{ip}/json", NetCategory.GEOIP_API, params=params)
        if resp.status == 429:
            return ProviderAnswer(LookupStatus.RATE_LIMITED, retry_after=resp.retry_after)
        if resp.status == 404 or (isinstance(resp.json, dict) and resp.json.get("bogon")):
            return ProviderAnswer(LookupStatus.NOT_FOUND, detail="bogon / not found")
        if resp.status >= 400 or not isinstance(resp.json, dict):
            return ProviderAnswer(LookupStatus.ERROR, detail=f"HTTP {resp.status}")
        return ProviderAnswer(
            LookupStatus.OK,
            value=_parse_ipinfo(resp.json),
            detail="authenticated" if params else "unauthenticated",
        )

    return ctx.cached_call("ipinfo", ip, call)


def tor_exit_ips(ctx: Context) -> tuple[set[str] | None, Lookup]:
    """The public Tor exit list, cached for 24 h. Returns None when unavailable."""
    if not ctx.settings.tor_exit_check:
        return None, ctx.skip("torexits", "list", "Tor exit check disabled in settings")
    if ctx.http is None:
        return None, ctx.skip("torexits", "list", "offline")

    def call() -> ProviderAnswer:
        assert ctx.http is not None
        resp = ctx.http.get(TOR_EXIT_LIST_URL, NetCategory.REPUTATION_API, headers={"Accept": "text/plain"})
        if resp.status == 429:
            return ProviderAnswer(LookupStatus.RATE_LIMITED, retry_after=resp.retry_after)
        if resp.status >= 400:
            return ProviderAnswer(LookupStatus.ERROR, detail=f"HTTP {resp.status}")
        ips = [line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")]
        return ProviderAnswer(LookupStatus.OK, value=ips, detail=f"{len(ips)} exits")

    value, lk = ctx.cached_call("torexits", "list", call)
    return (set(value) if value else None), lk


def classify(
    asn_org: str | None,
    isp: str | None,
    rdns: list[str],
    network_name: str | None,
    ipinfo: dict[str, Any] | None,
    tor_list: set[str] | None,
    ip: str,
    abuseipdb_usage: str | None = None,
) -> tuple[bool | None, bool | None, bool | None, bool | None, list[str]]:
    """Combine explicit signals with heuristics into (hosting, vpn, proxy, tor, reasons)."""
    hosting, vpn, tor, reasons = classify_infrastructure(asn_org, isp, network_name, *rdns)
    proxy: bool | None = None
    if ipinfo:
        for key in ("hosting", "vpn", "tor", "proxy"):
            if ipinfo.get(key) is True:
                reasons.append(f"ipinfo.io privacy flag: {key}")
        hosting = ipinfo.get("hosting") if ipinfo.get("hosting") is not None else hosting
        vpn = ipinfo.get("vpn") if ipinfo.get("vpn") is not None else vpn
        tor = ipinfo.get("tor") if ipinfo.get("tor") is not None else tor
        proxy = ipinfo.get("proxy") if ipinfo.get("proxy") is not None else proxy
    if tor_list is not None:
        if ip in tor_list:
            tor = True
            reasons.append("listed on the Tor Project exit list")
        elif tor is None:
            tor = False
    if abuseipdb_usage:
        low = abuseipdb_usage.lower()
        if any(k in low for k in ("hosting", "data center", "content delivery")):
            hosting = True
            reasons.append(f"AbuseIPDB usage type: {abuseipdb_usage}")
    return hosting, vpn, proxy, tor, reasons
