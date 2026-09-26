from __future__ import annotations

from mailtrace_core.case.settings import Settings
from mailtrace_core.enrichment.base import EnrichmentCache
from mailtrace_core.enrichment.context import Context
from mailtrace_core.enrichment.dns_lookup import StaticResolver
from mailtrace_core.enrichment.models import LookupStatus
from mailtrace_core.enrichment.whois import parse_whois, whois_domain

IANA = "refer:        whois.nic.test\n\ndomain:       TEST\n"
REGISTRY = """Domain Name: PHISH-LOGIN.TEST
Registry Domain ID: D1234-TEST
Registrar WHOIS Server: whois.example-registrar.test
Registrar URL: http://www.example-registrar.test
Updated Date: 2026-09-20T10:00:00Z
Creation Date: 2026-09-19T09:30:00Z
Registry Expiry Date: 2027-09-19T09:30:00Z
Registrar: Example Registrar, Inc.
Registrar IANA ID: 1068
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: addPeriod https://icann.org/epp#addPeriod
Name Server: DNS1.REGISTRAR-SERVERS.TEST
Name Server: DNS2.REGISTRAR-SERVERS.TEST
"""
REGISTRAR = """Domain Name: phish-login.test
Registrar Abuse Contact Email: abuse@example-registrar.test
Registrar Abuse Contact Phone: +1.5555550100
Registrant Organization: Privacy service provided by Withheld for Privacy ehf
Registrant Country: IS
"""


def test_parse_whois() -> None:
    d = parse_whois(REGISTRY + REGISTRAR)
    assert d["registrar"] == "Example Registrar, Inc." and d["registrar_iana_id"] == "1068"
    assert d["created"] == "2026-09-19T09:30:00Z" and d["expires"].startswith("2027")
    assert d["registrar_abuse_email"] == "abuse@example-registrar.test"
    assert d["registrant_country"] == "IS"
    assert d["nameservers"] == ["dns1.registrar-servers.test", "dns2.registrar-servers.test"]
    assert "clientTransferProhibited" in d["statuses"]


def _ctx() -> Context:
    ctx = Context(settings=Settings(), cache=EnrichmentCache(None), resolver=StaticResolver())
    ctx.limiter("whois").min_interval = 0
    return ctx


def test_whois_domain_follows_referrals() -> None:
    calls: list[tuple[str, str]] = []

    def query(server: str, q: str) -> str:
        calls.append((server, q))
        if server == "whois.iana.org":
            return IANA
        if server == "whois.nic.test":
            return REGISTRY
        if server == "whois.example-registrar.test":
            return REGISTRAR
        raise AssertionError(server)

    ctx = _ctx()
    data, lk = whois_domain("phish-login.test", ctx, query)
    assert lk.status is LookupStatus.OK and data
    assert data["registrar_abuse_email"] == "abuse@example-registrar.test"
    assert data["server"] == "whois.nic.test" and data["source"] == "whois"
    assert [c[0] for c in calls] == ["whois.iana.org", "whois.nic.test", "whois.example-registrar.test"]
    data, lk = whois_domain("phish-login.test", ctx, query)
    assert lk.cached and len(calls) == 3


def test_whois_no_match_and_no_server() -> None:
    def query(server: str, q: str) -> str:
        if server == "whois.iana.org":
            return IANA if q == "test" else "% no whois server\n"
        return 'No match for "NOPE.TEST".\n'

    ctx = _ctx()
    _, lk = whois_domain("nope.test", ctx, query)
    assert lk.status is LookupStatus.NOT_FOUND and "no match" in lk.detail
    _, lk = whois_domain("x.invalid", ctx, query)
    assert lk.status is LookupStatus.NOT_FOUND and "IANA" in lk.detail


def test_whois_disabled() -> None:
    ctx = Context(settings=Settings(whois_fallback=False), cache=EnrichmentCache(None))
    _, lk = whois_domain("a.test", ctx, lambda s, q: "")
    assert lk.status is LookupStatus.SKIPPED
