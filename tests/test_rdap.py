from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx

from mailtrace_core.case.settings import Settings
from mailtrace_core.enrichment.base import EnrichmentCache
from mailtrace_core.enrichment.context import Context
from mailtrace_core.enrichment.http import HttpClient
from mailtrace_core.enrichment.models import LookupStatus
from mailtrace_core.enrichment.rdap import (
    age_days,
    is_new_domain,
    parse_date,
    parse_domain_rdap,
    parse_ip_rdap,
    rdap_domain,
    rdap_ip,
)
from mailtrace_core.util import netguard


def _recent(days: int) -> str:
    return (datetime.now(tz=UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


DOMAIN_JSON = {
    "objectClassName": "domain",
    "ldhName": "EXAMPLEBANK-SECURE-VERIFY.TEST",
    "status": ["client transfer prohibited", "add period"],
    "events": [
        {"eventAction": "registration", "eventDate": _recent(4)},
        {"eventAction": "expiration", "eventDate": "2027-09-20T00:00:00Z"},
        {"eventAction": "last changed", "eventDate": _recent(4)},
    ],
    "nameservers": [{"ldhName": "dns1.registrar-servers.test."}, {"ldhName": "dns2.registrar-servers.test"}],
    "entities": [
        {
            "objectClassName": "entity",
            "handle": "1068",
            "roles": ["registrar"],
            "publicIds": [{"type": "IANA Registrar ID", "identifier": "1068"}],
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]],
            ],
            "entities": [
                {
                    "objectClassName": "entity",
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "Abuse Desk"],
                            ["tel", {"type": "voice"}, "uri", "tel:+1.5555550100"],
                            ["email", {}, "text", "abuse@example-registrar.test"],
                        ],
                    ],
                }
            ],
        },
        {
            "objectClassName": "entity",
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["fn", {}, "text", "Withheld for Privacy"],
                    ["org", {}, "text", "Privacy Service Ltd"],
                    ["adr", {"cc": "IS"}, "text", ["", "", "", "", "", "", "IS"]],
                ],
            ],
        },
    ],
}

IP_JSON = {
    "objectClassName": "ip network",
    "handle": "NET-198-51-100-0-1",
    "name": "BULKHOST-NET",
    "startAddress": "198.51.100.0",
    "endAddress": "198.51.100.255",
    "cidr0_cidrs": [{"v4prefix": "198.51.100.0", "length": 24}],
    "country": "US",
    "type": "DIRECT ALLOCATION",
    "port43": "whois.arin.net",
    "entities": [
        {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Bulk Host LLC"]]]},
        {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@bulkhost.test"]]]},
    ],
}


def test_parse_domain() -> None:
    d = parse_domain_rdap(DOMAIN_JSON)
    assert d["domain"] == "examplebank-secure-verify.test"
    assert d["registrar"] == "Example Registrar, Inc." and d["registrar_iana_id"] == "1068"
    assert d["registrar_abuse_email"] == "abuse@example-registrar.test"
    assert d["registrar_abuse_phone"] == "+1.5555550100"
    assert d["registrant_org"] == "Privacy Service Ltd" and d["registrant_country"] == "IS"
    assert d["nameservers"] == ["dns1.registrar-servers.test", "dns2.registrar-servers.test"]
    assert d["expires"].startswith("2027-09-20")
    days, new = is_new_domain(d["created"])
    assert days == 4 and new is True


def test_parse_ip() -> None:
    d = parse_ip_rdap(IP_JSON)
    assert d["handle"] == "NET-198-51-100-0-1" and d["cidr"] == "198.51.100.0/24"
    assert d["org"] == "Bulk Host LLC" and d["abuse_contacts"] == ["abuse@bulkhost.test"]
    assert d["registry"] == "ARIN" and d["country"] == "US"


def test_dates() -> None:
    assert parse_date("2024-01-02T03:04:05Z") == datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert parse_date("2024-01-02") == datetime(2024, 1, 2, tzinfo=UTC)
    assert parse_date("15-Mar-2019") == datetime(2019, 3, 15, tzinfo=UTC)
    assert parse_date("garbage") is None and age_days(None) is None
    assert is_new_domain("2001-01-01") == (age_days("2001-01-01"), False)


def _ctx(handler) -> Context:  # type: ignore[no-untyped-def]
    netguard.set_offline(False)
    ctx = Context(
        settings=Settings(),
        cache=EnrichmentCache(None),
        http=HttpClient(transport=httpx.MockTransport(handler)),
    )
    ctx.limiter("rdap").min_interval = 0
    return ctx


def test_rdap_domain_via_http_and_cache() -> None:
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        if req.url.path.startswith("/domain/"):
            return httpx.Response(200, json=DOMAIN_JSON)
        return httpx.Response(404, json={"errorCode": 404})

    ctx = _ctx(handler)
    data, lk = rdap_domain("examplebank-secure-verify.test", ctx)
    assert lk.status is LookupStatus.OK and data and data["registrar"].startswith("Example Registrar")
    data, lk = rdap_domain("examplebank-secure-verify.test", ctx)
    assert lk.cached and len(seen) == 1
    data, lk = rdap_ip("203.0.113.5", ctx)
    assert data is None and lk.status is LookupStatus.NOT_FOUND
    assert seen[-1] == "https://rdap.org/ip/203.0.113.5"


def test_rdap_rate_limit_and_error() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if "ip/1.1.1.1" in str(req.url):
            return httpx.Response(429, headers={"Retry-After": "120"})
        return httpx.Response(500)

    ctx = _ctx(handler)
    _, lk = rdap_ip("1.1.1.1", ctx)
    assert lk.status is LookupStatus.RATE_LIMITED
    _, lk = rdap_ip("2.2.2.2", ctx)
    assert lk.status is LookupStatus.RATE_LIMITED  # backed off for the rest of the run
    ctx2 = _ctx(handler)
    _, lk = rdap_ip("2.2.2.2", ctx2)
    assert lk.status is LookupStatus.ERROR and "500" in lk.detail


def test_rdap_offline_is_skipped() -> None:
    ctx = Context(settings=Settings(), cache=EnrichmentCache(None), http=None)
    data, lk = rdap_domain("a.test", ctx)
    assert data is None and lk.status is LookupStatus.SKIPPED and ctx.skipped["rdap"] == "offline"
