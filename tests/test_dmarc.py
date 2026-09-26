from __future__ import annotations

from mailtrace_core.enrichment.dns_lookup import StaticResolver
from mailtrace_core.models import DkimVerification, SpfVerification
from mailtrace_core.parsing.dmarc import aligned, check_dmarc, parse_dmarc_record


def _spf(result: str, domain: str) -> SpfVerification:
    return SpfVerification(domain=domain, client_ip="203.0.113.1", result=result)


def _dkim(result: str, domain: str) -> DkimVerification:
    return DkimVerification(domain=domain, selector="s", result=result)


def test_parse_record() -> None:
    tags = parse_dmarc_record("v=DMARC1; p=reject; sp=quarantine; adkim=s; rua=mailto:x@y.test")
    assert tags["p"] == "reject" and tags["sp"] == "quarantine" and tags["adkim"] == "s"


def test_alignment_modes() -> None:
    assert aligned("mail.a.test", "a.test", "r")
    assert not aligned("mail.a.test", "a.test", "s")
    assert aligned("a.test", "a.test", "s")
    assert not aligned("b.test", "a.test", "r")


def test_pass_via_spf_relaxed() -> None:
    r = StaticResolver({("_dmarc.a.test", "TXT"): ["v=DMARC1; p=reject"]})
    res = check_dmarc("a.test", _spf("pass", "bounce.a.test"), _dkim("none", None), r)
    assert res.result == "pass" and res.spf_aligned is True and res.policy == "reject"


def test_fail_strict_alignment() -> None:
    r = StaticResolver({("_dmarc.a.test", "TXT"): ["v=DMARC1; p=quarantine; aspf=s"]})
    res = check_dmarc("a.test", _spf("pass", "bounce.a.test"), _dkim("fail", "a.test"), r)
    assert res.result == "fail" and res.spf_aligned is False and res.dkim_aligned is False


def test_pass_via_dkim_only() -> None:
    r = StaticResolver({("_dmarc.a.test", "TXT"): ["v=DMARC1; p=none"]})
    res = check_dmarc("a.test", _spf("fail", "other.test"), _dkim("pass", "a.test"), r)
    assert res.result == "pass" and res.dkim_aligned is True


def test_org_domain_fallback_uses_sp() -> None:
    r = StaticResolver({("_dmarc.a.test", "TXT"): ["v=DMARC1; p=none; sp=reject"]})
    res = check_dmarc("sub.a.test", _spf("fail", "x.test"), _dkim("none", None), r)
    assert res.result == "fail" and res.policy == "reject"
    assert "record found at a.test" in res.detail


def test_none_temperror_skipped() -> None:
    r = StaticResolver({("_dmarc.t.test", "TXT"): ["__TEMPERROR__"]})
    assert check_dmarc("none.test", None, None, r).result == "none"
    assert check_dmarc("t.test", None, None, r).result == "temperror"
    assert check_dmarc("a.test", None, None, None).result == "skipped"
    assert check_dmarc(None, None, None, r).result == "skipped"


def test_skipped_when_nothing_evaluable() -> None:
    r = StaticResolver({("_dmarc.a.test", "TXT"): ["v=DMARC1; p=reject"]})
    res = check_dmarc(
        "a.test",
        SpfVerification("a.test", None, "skipped"),
        DkimVerification("a.test", "s", "skipped"),
        r,
    )
    assert res.result == "skipped" and res.policy == "reject"
