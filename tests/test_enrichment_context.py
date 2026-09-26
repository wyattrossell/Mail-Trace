from __future__ import annotations

import httpx

from mailtrace_core.case.settings import Settings
from mailtrace_core.enrichment.base import EnrichmentCache
from mailtrace_core.enrichment.context import Context, ProviderAnswer
from mailtrace_core.enrichment.http import HttpClient, HttpError
from mailtrace_core.enrichment.models import LookupStatus
from mailtrace_core.util import netguard


def _ctx(http: HttpClient | None = None) -> Context:
    c = Context(settings=Settings(), cache=EnrichmentCache(None), http=http)
    c.key_reader = lambda _p: None
    for lim in ("rdap", "x"):
        c.limiter(lim).min_interval = 0
    return c


def test_ok_answers_are_cached() -> None:
    ctx = _ctx()
    calls = []

    def fn() -> ProviderAnswer:
        calls.append(1)
        return ProviderAnswer(LookupStatus.OK, value={"a": 1})

    v1, lk1 = ctx.cached_call("x", "t", fn)
    v2, lk2 = ctx.cached_call("x", "t", fn)
    assert v1 == v2 == {"a": 1}
    assert lk1.cached is False and lk2.cached is True
    assert len(calls) == 1 and ctx.lookups_performed == 1 and ctx.lookups_cached == 1


def test_not_found_is_cached_as_not_found() -> None:
    ctx = _ctx()
    fn = lambda: ProviderAnswer(LookupStatus.NOT_FOUND, detail="nope")  # noqa: E731
    v, lk = ctx.cached_call("x", "t", fn)
    assert v is None and lk.status is LookupStatus.NOT_FOUND
    v, lk = ctx.cached_call("x", "t", lambda: ProviderAnswer(LookupStatus.OK, value=1))
    assert v is None and lk.status is LookupStatus.NOT_FOUND and lk.cached


def test_rate_limited_backs_off_provider() -> None:
    ctx = _ctx()
    v, lk = ctx.cached_call("x", "a", lambda: ProviderAnswer(LookupStatus.RATE_LIMITED, retry_after=30))
    assert lk.status is LookupStatus.RATE_LIMITED
    v, lk = ctx.cached_call("x", "b", lambda: ProviderAnswer(LookupStatus.OK, value=1))
    assert v is None and lk.status is LookupStatus.RATE_LIMITED and "backed off" in lk.detail


def test_errors_and_blocks() -> None:
    ctx = _ctx()

    def boom() -> ProviderAnswer:
        raise HttpError("connect failed")

    v, lk = ctx.cached_call("x", "t", boom)
    assert lk.status is LookupStatus.ERROR and "connect failed" in lk.detail

    def blocked() -> ProviderAnswer:
        raise netguard.NetworkBlocked("offline mode")

    v, lk = ctx.cached_call("x", "t2", blocked)
    assert lk.status is LookupStatus.SKIPPED and ctx.skipped["x"] == "offline mode"

    def bug() -> ProviderAnswer:
        raise KeyError("oops")

    v, lk = ctx.cached_call("x", "t3", bug)
    assert lk.status is LookupStatus.ERROR and "KeyError" in lk.detail


def test_http_client_respects_netguard_and_parses_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True}, headers={"Retry-After": "5"})

    client = HttpClient(transport=httpx.MockTransport(handler))
    netguard.set_offline(False)
    resp = client.get("https://rdap.org/ip/203.0.113.1", netguard.NetCategory.RDAP)
    assert resp.status == 200 and resp.json == {"ok": True} and resp.retry_after == 5.0
    assert client.requests_made == 1
    netguard.set_offline(True)
    try:
        client.get("https://rdap.org/ip/203.0.113.1", netguard.NetCategory.RDAP)
        raise AssertionError("expected NetworkBlocked")
    except netguard.NetworkBlocked:
        pass


def test_http_client_never_allows_active_categories() -> None:
    client = HttpClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    netguard.set_offline(False)
    try:
        client.get("https://evil.example/", netguard.NetCategory.URL_FETCH)
        raise AssertionError("expected NetworkBlocked")
    except netguard.NetworkBlocked as exc:
        assert "active technique" in str(exc)
    assert client.requests_made == 0
