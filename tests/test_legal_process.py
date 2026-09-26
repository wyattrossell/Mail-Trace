from __future__ import annotations

import json
from pathlib import Path

from mailtrace_core.enrichment.legal_process import (
    default_table_path,
    load_table,
    map_targets,
    preservation_note,
    process_tiers,
)
from mailtrace_core.enrichment.models import DomainEnrichment, EnrichmentReport, IpEnrichment
from mailtrace_core.models import Address, ParsedEmail, SourceFormat


def _pe(from_addr: str = "sheriff.example.office@gmail.com") -> ParsedEmail:
    pe = ParsedEmail(source_format=SourceFormat.EML, source_name="x")
    pe.from_ = Address("", from_addr)
    pe.return_path = Address("", from_addr)
    return pe


def test_default_table_is_well_formed() -> None:
    table = load_table(default_table_path())
    keys = [p["key"] for p in table["providers"]]
    assert len(keys) == len(set(keys)) and "google" in keys and "namecheap" in keys
    for p in table["providers"]:
        assert p["name"] and isinstance(p["match"], dict) and p["records_available"]
        assert p["verify_before_use"] is True
        assert p["guidelines_url"] or p["email"] or p["portal"]
    assert "2703(f)" in preservation_note(table) and "90 days" in preservation_note(table)
    assert "content" in process_tiers(table)


def test_user_copy_is_seeded_and_preferred(tmp_path: Path) -> None:
    user = tmp_path / "legal.json"
    table = load_table(user)
    assert user.exists() and len(table["providers"]) >= 10
    data = json.loads(user.read_text())
    data["providers"] = [data["providers"][0]]
    user.write_text(json.dumps(data))
    assert len(load_table(user)["providers"]) == 1
    user.write_text("{broken")
    assert len(load_table(user)["providers"]) >= 10  # falls back to packaged default


def test_map_origin_provider_and_mailbox_and_registrar() -> None:
    table = load_table(default_table_path())
    report = EnrichmentReport(
        ips=[
            IpEnrichment(
                ip="209.85.220.41",
                roles=["origin (likely): hop:0 first external hop"],
                asn_org="GOOGLE",
                reverse_dns=["mail-sor-f41.google.com"],
            )
        ],
        domains=[
            DomainEnrichment(domain="gmail.com", roles=["sender From"], registrar="MarkMonitor Inc."),
            DomainEnrichment(
                domain="paypal-notices.example",
                roles=["url host"],
                registrar="NameCheap, Inc.",
                registrar_abuse_email="abuse@namecheap.com",
            ),
        ],
    )
    targets = map_targets(_pe(), report, table)
    by = {(t.provider_key, t.role): t for t in targets}
    assert ("google", "originating IP owner") in by
    assert "asn_org: GOOGLE" in by[("google", "originating IP owner")].matched_on
    assert ("google", "sender mailbox provider") in by
    assert ("namecheap", "registrar of linked domain") in by
    # MarkMonitor has no curated entry -> generic registrar fallback for the sender domain
    generic = [t for t in targets if t.provider_key.startswith("registrar:")]
    assert (
        generic
        and generic[0].role == "registrar of sender domain"
        and generic[0].provider_name == "MarkMonitor Inc."
    )
    assert all(t.verify_before_use for t in targets)


def test_rdap_abuse_fallback_for_unknown_network() -> None:
    table = load_table(default_table_path())
    report = EnrichmentReport(
        ips=[
            IpEnrichment(
                ip="198.51.100.77",
                roles=["origin (likely): x"],
                asn_org="Bulk Host LLC",
                network_handle="NET-198-51-100-0-1",
                network_name="BULKHOST-NET",
                network_country="US",
                abuse_contacts=["abuse@bulkhost.test"],
            )
        ]
    )
    targets = map_targets(_pe("a@examplebank.test"), report, table)
    assert len(targets) == 1
    t = targets[0]
    assert t.provider_key == "rdap:NET-198-51-100-0-1" and t.email == "abuse@bulkhost.test"
    assert t.role == "originating IP owner" and "RDAP abuse contact" in t.matched_on


def test_url_host_role_and_dedupe() -> None:
    table = load_table(default_table_path())
    report = EnrichmentReport(
        ips=[
            IpEnrichment(ip="104.16.0.1", roles=["url host paypal-notices.example"], asn_org="CLOUDFLARENET"),
            IpEnrichment(
                ip="104.16.0.2", roles=["url host collect.paypal-notices.example"], asn_org="CLOUDFLARENET"
            ),
        ]
    )
    targets = map_targets(_pe(), report, table)
    assert [(t.provider_key, t.role) for t in targets] == [("cloudflare", "hosting provider of linked site")]
