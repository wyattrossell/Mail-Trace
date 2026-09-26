from __future__ import annotations

import httpx

from mailtrace_core.case.settings import Settings
from mailtrace_core.enrichment import reputation
from mailtrace_core.enrichment.base import EnrichmentCache
from mailtrace_core.enrichment.context import Context
from mailtrace_core.enrichment.http import HttpClient
from mailtrace_core.enrichment.models import LookupStatus
from mailtrace_core.enrichment.reputation.virustotal import url_id
from mailtrace_core.util import netguard


def _ctx(handler, keys: bool = True, settings: Settings | None = None) -> Context:  # type: ignore[no-untyped-def]
    netguard.set_offline(False)
    ctx = Context(
        settings=settings or Settings(),
        cache=EnrichmentCache(None),
        http=HttpClient(transport=httpx.MockTransport(handler)),
    )
    ctx.key_reader = (lambda p: f"key-{p}") if keys else (lambda _p: None)
    for p in ("abuseipdb", "virustotal", "urlhaus", "safebrowsing"):
        ctx.limiter(p).min_interval = 0
    return ctx


def test_abuseipdb_verdicts_and_headers() -> None:
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["key"] = req.headers.get("Key")
        ip = req.url.params["ipAddress"]
        score = {"198.51.100.77": 100, "203.0.113.5": 30, "203.0.113.25": 0}[ip]
        return httpx.Response(
            200,
            json={
                "data": {
                    "ipAddress": ip,
                    "abuseConfidenceScore": score,
                    "totalReports": score // 10,
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Bulk Host",
                    "isTor": False,
                }
            },
        )

    ctx = _ctx(handler)
    v, lk, raw = reputation.abuseipdb_ip("198.51.100.77", ctx)
    assert (
        v
        and v.verdict == "malicious"
        and raw["usageType"].startswith("Data Center")
        and seen["key"] == "key-abuseipdb"
    )
    assert reputation.abuseipdb_ip("203.0.113.5", ctx)[0].verdict == "suspicious"
    assert reputation.abuseipdb_ip("203.0.113.25", ctx)[0].verdict == "clean"


def test_abuseipdb_without_key_is_skipped() -> None:
    ctx = _ctx(lambda r: httpx.Response(200), keys=False)
    v, lk, _ = reputation.abuseipdb_ip("1.2.3.4", ctx)
    assert v is None and lk.status is LookupStatus.SKIPPED and ctx.skipped["abuseipdb"] == "no API key stored"
    assert ctx.http.requests_made == 0


def test_virustotal_objects() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.method == "GET" and req.headers["x-apikey"] == "key-virustotal"
        path = req.url.path
        if path.endswith("/files/" + "a" * 64):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 40,
                                "suspicious": 2,
                                "harmless": 0,
                                "undetected": 20,
                            },
                            "meaningful_name": "invoice.exe",
                            "popular_threat_classification": {"suggested_threat_label": "trojan.agent"},
                        }
                    }
                },
            )
        if "/domains/" in path:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 1,
                                "suspicious": 0,
                                "harmless": 60,
                                "undetected": 10,
                            },
                            "reputation": -5,
                            "categories": {"x": "phishing"},
                        }
                    }
                },
            )
        if "/urls/" in path:
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
        if "/ip_addresses/" in path:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 0,
                                "suspicious": 0,
                                "harmless": 70,
                                "undetected": 20,
                            }
                        }
                    }
                },
            )
        return httpx.Response(500)

    ctx = _ctx(handler)
    v, lk = reputation.vt_hash("a" * 64, ctx)
    assert v.verdict == "malicious" and "trojan.agent" in v.detail and v.summary.startswith("40 malicious")
    v, lk = reputation.vt_domain("paypal-notices.example", ctx)
    assert v.verdict == "suspicious" and "phishing" in v.detail
    v, lk = reputation.vt_url("https://login.rnicrosoft.example/verify", ctx)
    assert v.verdict == "unknown" and lk.status is LookupStatus.NOT_FOUND
    v, lk = reputation.vt_ip("203.0.113.25", ctx)
    assert v.verdict == "clean"
    assert url_id("http://a.test/") == "aHR0cDovL2EudGVzdC8"


def test_virustotal_never_posts_and_respects_disable() -> None:
    posted = []
    ctx = _ctx(
        lambda r: (posted.append(r.method), httpx.Response(200, json={"data": {"attributes": {}}}))[1],
        settings=Settings(reputation_enabled=False),
    )
    v, lk = reputation.vt_hash("b" * 64, ctx)
    assert lk.status is LookupStatus.SKIPPED and posted == []


def test_urlhaus_host_url_payload() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.method == "POST" and req.headers["Auth-Key"] == "key-urlhaus"
        body = req.content.decode()
        if "host=" in body:
            return httpx.Response(
                200,
                json={
                    "query_status": "ok",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/host/x/",
                    "firstseen": "2026-09-01 10:00:00 UTC",
                    "url_count": "3",
                    "urls": [{"url": "http://x/a", "url_status": "online", "threat": "malware_download"}],
                },
            )
        if "url=" in body:
            return httpx.Response(200, json={"query_status": "no_results"})
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "signature": "AgentTesla",
                "file_type": "exe",
                "urlhaus_reference": "https://urlhaus.abuse.ch/browse.php?search=x",
            },
        )

    ctx = _ctx(handler)
    v, _ = reputation.urlhaus_host("cheaphost.test", ctx)
    assert v.verdict == "malicious" and "currently online" in v.detail and "3 URL" in v.detail
    v, lk = reputation.urlhaus_url("https://a.test/", ctx)
    assert v.verdict == "clean" and lk.status is LookupStatus.NOT_FOUND
    v, _ = reputation.urlhaus_hash("c" * 64, ctx)
    assert v.verdict == "malicious" and "AgentTesla" in v.detail


def test_safebrowsing_batch() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.params["key"] == "key-safebrowsing"
        import json

        body = json.loads(req.content)
        urls = [e["url"] for e in body["threatInfo"]["threatEntries"]]
        assert len(urls) == 2
        return httpx.Response(
            200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": urls[0]}}]}
        )

    ctx = _ctx(handler)
    verdicts, lk = reputation.safebrowsing_urls(
        ["https://bad.test/", "https://good.test/", "https://bad.test/"], ctx
    )
    assert lk.status is LookupStatus.OK
    assert [v.verdict for v in verdicts] == ["malicious", "clean"]
    assert verdicts[0].summary == "SOCIAL_ENGINEERING"
    assert reputation.safebrowsing_urls([], ctx)[0] == []


def test_rate_limit_propagates() -> None:
    ctx = _ctx(lambda r: httpx.Response(429, headers={"Retry-After": "30"}))
    v, lk = reputation.vt_domain("a.test", ctx)
    assert v is None and lk.status is LookupStatus.RATE_LIMITED
    v, lk = reputation.vt_domain("b.test", ctx)
    assert lk.status is LookupStatus.RATE_LIMITED and ctx.http.requests_made == 1
