"""Full enrichment over synthetic samples with every provider mocked."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from mailtrace_core.analysis.engine import analyze
from mailtrace_core.enrichment.http import HttpClient
from mailtrace_core.enrichment.legal_process import default_table_path, load_table
from mailtrace_core.enrichment.models import LookupStatus
from mailtrace_core.enrichment.runner import collect_domain_targets, collect_ip_targets, run_enrichment
from mailtrace_core.models import to_jsonable
from mailtrace_core.util import netguard


def _recent(days: int) -> str:
    return (datetime.now(tz=UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rdap_domain(name: str, days: int, registrar: str = "NameCheap, Inc.") -> dict:
    return {
        "ldhName": name.upper(),
        "events": [{"eventAction": "registration", "eventDate": _recent(days)}],
        "nameservers": [{"ldhName": "dns1.registrar-servers.test"}],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", registrar]]],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": "1068"}],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": ["vcard", [["email", {}, "text", "abuse@namecheap.com"]]],
                    }
                ],
            }
        ],
    }


def _rdap_ip(ip: str, name: str, org: str) -> dict:
    return {
        "handle": f"NET-{ip}",
        "name": name,
        "cidr0_cidrs": [{"v4prefix": ip.rsplit(".", 1)[0] + ".0", "length": 24}],
        "country": "US",
        "port43": "whois.arin.net",
        "entities": [
            {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", org]]]},
            {
                "roles": ["abuse"],
                "vcardArray": ["vcard", [["email", {}, "text", f"abuse@{name.lower()}.test"]]],
            },
        ],
    }


def make_handler(log: list[str]):  # type: ignore[no-untyped-def]
    def handler(req: httpx.Request) -> httpx.Response:
        host, path = req.url.host, req.url.path
        log.append(f"{req.method} {host}{path}")
        if host == "rdap.org":
            if path.startswith("/domain/"):
                name = path.split("/")[-1]
                if name == "examplebank.test":
                    return httpx.Response(200, json=_rdap_domain(name, 4000, "MarkMonitor Inc."))
                if name == "mailer-relay.test":
                    return httpx.Response(200, json=_rdap_domain(name, 9))
                if name == "examplebank-secure-verify.test":
                    return httpx.Response(200, json=_rdap_domain(name, 2))
                return httpx.Response(404)
            ip = path.split("/")[-1]
            if ip == "198.51.100.77":
                return httpx.Response(200, json=_rdap_ip(ip, "BULKHOST", "Bulk Host LLC"))
            return httpx.Response(200, json=_rdap_ip(ip, "TESTNET", "Test Net Org"))
        if host == "ipinfo.io":
            ip = path.split("/")[1]
            org = "AS64500 Bulk Host LLC" if ip.startswith("198.51") else "AS64501 Example ISP"
            return httpx.Response(200, json={"ip": ip, "country": "US", "city": "Ashburn", "org": org})
        if host == "check.torproject.org":
            return httpx.Response(200, text="203.0.113.99\n")
        if host == "api.abuseipdb.com":
            ip = req.url.params["ipAddress"]
            score = 90 if ip == "198.51.100.77" else 0
            return httpx.Response(
                200,
                json={
                    "data": {
                        "abuseConfidenceScore": score,
                        "totalReports": 12,
                        "usageType": "Data Center/Web Hosting/Transit",
                        "isp": "Bulk Host",
                    }
                },
            )
        if host == "www.virustotal.com":
            if "/urls/" in path:
                return httpx.Response(
                    200,
                    json={
                        "data": {
                            "attributes": {
                                "last_analysis_stats": {
                                    "malicious": 8,
                                    "suspicious": 1,
                                    "harmless": 50,
                                    "undetected": 10,
                                }
                            }
                        }
                    },
                )
            if "/files/" in path:
                return httpx.Response(404)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 0,
                                "suspicious": 0,
                                "harmless": 70,
                                "undetected": 10,
                            }
                        }
                    }
                },
            )
        if host == "urlhaus-api.abuse.ch":
            return httpx.Response(200, json={"query_status": "no_results"})
        if host == "safebrowsing.googleapis.com":
            body = json.loads(req.content)
            urls = [e["url"] for e in body["threatInfo"]["threatEntries"]]
            bad = [u for u in urls if "secure-verify" in u]
            return httpx.Response(
                200,
                json={"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": u}} for u in bad]},
            )
        return httpx.Response(500, text=f"unexpected {host}{path}")

    return handler


def test_target_collection(parse_sample) -> None:  # type: ignore[no-untyped-def]
    pe = parse_sample("02_spoofed_bank_spf_fail.eml")
    ips = collect_ip_targets(pe, 10)
    assert list(ips)[0] == "198.51.100.77" and ips["198.51.100.77"][0].startswith("origin (likely)")
    assert "203.0.113.99" in ips and any("unverified" in r for r in ips["203.0.113.99"])
    assert "192.0.2.10" in ips  # public hop IP inside recipient infrastructure
    doms = collect_domain_targets(pe, 20)
    assert {"examplebank.test", "mailer-relay.test", "gmail.com", "examplebank-secure-verify.test"} <= set(
        doms
    )
    assert "sender Reply-To" in doms["gmail.com"] and "url host" in doms["examplebank-secure-verify.test"]


def test_full_enrichment_and_cache_reuse(parse_sample, settings, resolver, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    netguard.set_offline(False)
    pe = parse_sample("02_spoofed_bank_spf_fail.eml")
    result = analyze(pe, settings)
    log: list[str] = []
    http = HttpClient(transport=httpx.MockTransport(make_handler(log)))
    keys = lambda p: f"key-{p}"  # noqa: E731
    cache_path = tmp_path / "enrichment_cache.json"
    from mailtrace_core.enrichment import context as ctx_mod

    for p in ctx_mod.DEFAULT_INTERVALS:
        ctx_mod.DEFAULT_INTERVALS[p] = 0.0

    report = run_enrichment(
        result,
        settings,
        cache_path=cache_path,
        resolver=resolver,
        http=http,
        key_reader=keys,
        legal_table=load_table(default_table_path()),
    )
    assert result.enrichment is report

    origin = next(ip for ip in report.ips if ip.ip == "198.51.100.77")
    assert origin.roles[0].startswith("origin (likely)")
    assert origin.asn == 64500 and origin.asn_org == "Bulk Host LLC" and origin.country == "US"
    assert origin.network_name == "BULKHOST" and origin.abuse_contacts == ["abuse@bulkhost.test"]
    assert origin.hosting is True and origin.tor is False
    assert {v.provider: v.verdict for v in origin.reputation} == {
        "abuseipdb": "malicious",
        "virustotal": "clean",
    }
    forged = next(ip for ip in report.ips if ip.ip == "203.0.113.99")
    assert forged.tor is True and any("Tor Project" in r for r in forged.flag_reasons)

    doms = {d.domain: d for d in report.domains}
    assert doms["mailer-relay.test"].is_new is True and doms["mailer-relay.test"].age_days == 9
    assert (
        doms["examplebank.test"].is_new is False and doms["examplebank.test"].registrar == "MarkMonitor Inc."
    )
    assert doms["examplebank-secure-verify.test"].registrar_abuse_email == "abuse@namecheap.com"
    assert doms["gmail.com"].lookups and any(
        lk.status is LookupStatus.NOT_FOUND for lk in doms["gmail.com"].lookups if lk.provider == "rdap"
    )

    url_verdicts = {(v.provider, v.verdict) for v in report.url_reputation}
    assert ("virustotal", "malicious") in url_verdicts and ("safebrowsing", "malicious") in url_verdicts
    assert report.attachment_reputation == []  # sample has no attachments

    roles = {(t.provider_key, t.role) for t in report.legal_targets}
    assert ("google", "sender mailbox provider") in roles  # Reply-To is gmail.com
    assert ("namecheap", "registrar of linked domain") in roles
    assert ("namecheap", "registrar of sender domain") in roles  # mailer-relay.test is the Return-Path
    assert any(k.startswith("rdap:NET-198.51.100.77") for k, _ in roles)
    assert "2703(f)" in report.preservation_note

    assert report.risk and report.risk.band in {"high", "critical"}
    sources = {f.source for f in report.risk.factors}
    assert {"findings", "domain", "ip", "reputation"} <= sources
    assert not [s for s in report.skipped if not s.startswith("geolite2")]
    assert report.lookups_performed > 10 and report.lookups_cached < report.lookups_performed
    json.dumps(to_jsonable(result))

    # Second run: everything comes from the case cache, no HTTP at all.
    made = http.requests_made
    report2 = run_enrichment(
        analyze(parse_sample("02_spoofed_bank_spf_fail.eml"), settings),
        settings,
        cache_path=cache_path,
        resolver=resolver,
        http=http,
        key_reader=keys,
        legal_table=load_table(default_table_path()),
    )
    assert http.requests_made == made
    assert report2.lookups_performed == 0
    assert report2.lookups_cached == report.lookups_performed + report.lookups_cached
    assert report2.risk.score == report.risk.score


def test_offline_enrichment_reports_skips(parse_sample, settings) -> None:  # type: ignore[no-untyped-def]
    pe = parse_sample("03_deceptive_links.eml", offline=True)
    result = analyze(pe, settings)
    report = run_enrichment(
        result,
        settings,
        cache_path=None,
        resolver=None,
        http=None,
        key_reader=lambda _p: None,
        legal_table=load_table(default_table_path()),
    )
    assert report.ips and report.domains
    assert all(lk.status is LookupStatus.SKIPPED for ip in report.ips for lk in ip.lookups)
    assert any(s.startswith("network: offline") for s in report.skipped)
    assert any(s.startswith("geolite2:") for s in report.skipped)
    assert report.legal_targets == []
    assert report.risk and any("skipped" in n for n in report.risk.notes)
    assert report.risk.score > 0  # message-internal findings still count


def test_no_keys_means_reputation_skipped_not_failed(parse_sample, settings, resolver) -> None:  # type: ignore[no-untyped-def]
    netguard.set_offline(False)
    log: list[str] = []
    http = HttpClient(transport=httpx.MockTransport(make_handler(log)))
    result = analyze(parse_sample("07_agency_lookalike_domain.eml"), settings)
    report = run_enrichment(
        result,
        settings,
        resolver=resolver,
        http=http,
        key_reader=lambda _p: None,
        legal_table=load_table(default_table_path()),
    )
    assert not any(
        "abuseipdb" in line or "virustotal" in line or "urlhaus" in line or "safebrowsing" in line
        for line in log
    )
    skipped = {s.split(":")[0] for s in report.skipped}
    assert {"abuseipdb", "virustotal", "urlhaus", "safebrowsing"} <= skipped
    assert all(ip.reputation == [] for ip in report.ips)
    assert any(ip.asn_org for ip in report.ips)  # ipinfo unauthenticated still worked
