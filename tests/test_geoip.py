from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import httpx

from mailtrace_core.case.settings import Settings
from mailtrace_core.enrichment.base import EnrichmentCache
from mailtrace_core.enrichment.context import Context
from mailtrace_core.enrichment.geoip import GeoReaders, classify, geolite_lookup, ipinfo_lookup, tor_exit_ips
from mailtrace_core.enrichment.http import HttpClient
from mailtrace_core.enrichment.models import LookupStatus
from mailtrace_core.util import netguard


class _FakeReader:
    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.closed = False

    def city(self, ip: str):  # type: ignore[no-untyped-def]
        if ip.startswith("198."):
            raise ValueError("AddressNotFoundError")
        return SimpleNamespace(
            country=SimpleNamespace(iso_code="US"),
            subdivisions=SimpleNamespace(most_specific=SimpleNamespace(name="Virginia")),
            city=SimpleNamespace(name="Ashburn"),
            location=SimpleNamespace(latitude=39.0, longitude=-77.5),
        )

    def asn(self, ip: str):  # type: ignore[no-untyped-def]
        return SimpleNamespace(autonomous_system_number=64500, autonomous_system_organization="Bulk Host LLC")

    def close(self) -> None:
        self.closed = True


def test_geo_readers_with_fake_databases(tmp_path: Path) -> None:
    city = tmp_path / "city.mmdb"
    asn = tmp_path / "asn.mmdb"
    city.write_bytes(b"x")
    asn.write_bytes(b"x")
    readers = GeoReaders(str(city), str(asn), opener=lambda p: _FakeReader(Path(p).stem))
    assert readers.available and not readers.errors
    ctx = Context(settings=Settings(), cache=EnrichmentCache(None))
    data, lk = geolite_lookup("203.0.113.5", readers, ctx)
    assert lk.status is LookupStatus.OK and data["country"] == "US" and data["asn"] == 64500
    data, lk = geolite_lookup("198.51.100.1", readers, ctx)
    assert data["asn_org"] == "Bulk Host LLC" and "country" not in data
    readers.close()
    assert readers.city.closed


def test_geo_readers_missing_file_reports_reason(tmp_path: Path) -> None:
    readers = GeoReaders(str(tmp_path / "missing.mmdb"), None)
    assert not readers.available and "not found" in readers.errors[0]
    ctx = Context(settings=Settings(), cache=EnrichmentCache(None))
    _, lk = geolite_lookup("203.0.113.5", readers, ctx)
    assert lk.status is LookupStatus.SKIPPED and "not found" in ctx.skipped["geolite2"]
    _, lk = geolite_lookup("203.0.113.5", None, ctx)
    assert lk.status is LookupStatus.SKIPPED


def _http(handler) -> HttpClient:  # type: ignore[no-untyped-def]
    netguard.set_offline(False)
    return HttpClient(transport=httpx.MockTransport(handler))


def test_ipinfo_parse_and_token() -> None:
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        return httpx.Response(
            200,
            json={
                "ip": "203.0.113.5",
                "hostname": "vps.cheaphost.test",
                "city": "Ashburn",
                "region": "Virginia",
                "country": "US",
                "org": "AS64500 Bulk Host LLC",
                "privacy": {"vpn": False, "proxy": False, "tor": False, "hosting": True},
            },
        )

    ctx = Context(settings=Settings(), cache=EnrichmentCache(None), http=_http(handler))
    ctx.key_reader = lambda p: "tok123" if p == "ipinfo" else None
    ctx.limiter("ipinfo").min_interval = 0
    data, lk = ipinfo_lookup("203.0.113.5", ctx)
    assert lk.status is LookupStatus.OK and lk.detail == "authenticated"
    assert data["asn"] == 64500 and data["asn_org"] == "Bulk Host LLC" and data["hosting"] is True
    assert "token=tok123" in seen[0]


def test_ipinfo_bogon_and_disabled() -> None:
    ctx = Context(
        settings=Settings(),
        cache=EnrichmentCache(None),
        http=_http(lambda r: httpx.Response(200, json={"ip": "10.0.0.1", "bogon": True})),
    )
    ctx.key_reader = lambda _p: None
    ctx.limiter("ipinfo").min_interval = 0
    _, lk = ipinfo_lookup("10.0.0.1", ctx)
    assert lk.status is LookupStatus.NOT_FOUND
    ctx2 = Context(settings=Settings(ipinfo_enabled=False), cache=EnrichmentCache(None), http=ctx.http)
    _, lk = ipinfo_lookup("1.2.3.4", ctx2)
    assert lk.status is LookupStatus.SKIPPED


def test_tor_list_and_classify() -> None:
    ctx = Context(
        settings=Settings(),
        cache=EnrichmentCache(None),
        http=_http(lambda r: httpx.Response(200, text="# exits\n198.51.100.200\n203.0.113.7\n")),
    )
    exits, lk = tor_exit_ips(ctx)
    assert lk.status is LookupStatus.OK and exits == {"198.51.100.200", "203.0.113.7"}
    hosting, vpn, proxy, tor, reasons = classify("Bulk Host LLC", None, [], None, None, exits, "203.0.113.7")
    assert tor is True and hosting is True and any("Tor Project" in r for r in reasons)
    hosting, vpn, proxy, tor, _ = classify(
        "Example ISP",
        None,
        ["dsl-1.example-isp.test"],
        None,
        {"vpn": True, "proxy": False, "tor": None, "hosting": False},
        exits,
        "203.0.113.9",
    )
    assert vpn is True and proxy is False and hosting is False and tor is False
    hosting, _, _, _, reasons = classify(
        None, None, [], None, None, None, "1.1.1.1", "Data Center/Web Hosting/Transit"
    )
    assert hosting is True and any("AbuseIPDB" in r for r in reasons)
