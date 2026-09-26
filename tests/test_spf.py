from __future__ import annotations

from mailtrace_core.enrichment.dns_lookup import StaticResolver
from mailtrace_core.parsing.spf import check_spf


def _r(**txt: list[str]) -> StaticResolver:
    records: dict[tuple[str, str], list[str]] = {}
    for key, vals in txt.items():
        # key like TXT__example_test -> ("example.test", "TXT")
        rtype, _, name = key.partition("__")
        records[(name.replace("_", "."), rtype)] = vals
    return StaticResolver(records)


def test_ip4_pass_and_fail() -> None:
    r = StaticResolver({("a.test", "TXT"): ["v=spf1 ip4:203.0.113.0/24 -all"]})
    assert check_spf("203.0.113.9", "a.test", r).result == "pass"
    res = check_spf("198.51.100.9", "a.test", r)
    assert res.result == "fail" and res.matched_mechanism == "-all"
    assert res.record == "v=spf1 ip4:203.0.113.0/24 -all"


def test_softfail_neutral_and_none() -> None:
    r = StaticResolver(
        {
            ("soft.test", "TXT"): ["v=spf1 ~all"],
            ("neutral.test", "TXT"): ["v=spf1 ?all"],
            ("norecord.test", "TXT"): ["some other txt"],
            ("noterm.test", "TXT"): ["v=spf1 ip4:1.2.3.4"],
        }
    )
    assert check_spf("203.0.113.1", "soft.test", r).result == "softfail"
    assert check_spf("203.0.113.1", "neutral.test", r).result == "neutral"
    assert check_spf("203.0.113.1", "norecord.test", r).result == "none"
    assert check_spf("203.0.113.1", "noterm.test", r).result == "neutral"


def test_a_and_mx_mechanisms() -> None:
    r = StaticResolver(
        {
            ("a.test", "TXT"): ["v=spf1 a mx:mail.a.test a:alt.a.test/24 -all"],
            ("a.test", "A"): ["203.0.113.10"],
            ("mail.a.test", "MX"): ["mx1.a.test"],
            ("mx1.a.test", "A"): ["203.0.113.20"],
            ("alt.a.test", "A"): ["198.51.100.1"],
        }
    )
    assert check_spf("203.0.113.10", "a.test", r).matched_mechanism == "+a"
    assert check_spf("203.0.113.20", "a.test", r).matched_mechanism == "+mx:mail.a.test"
    assert check_spf("198.51.100.200", "a.test", r).matched_mechanism == "+a:alt.a.test/24"
    assert check_spf("192.0.2.1", "a.test", r).result == "fail"


def test_include_and_redirect() -> None:
    r = StaticResolver(
        {
            ("a.test", "TXT"): ["v=spf1 include:_spf.b.test -all"],
            ("_spf.b.test", "TXT"): ["v=spf1 ip4:203.0.113.0/24 -all"],
            ("gmail.test", "TXT"): ["v=spf1 redirect=_spf.g.test"],
            ("_spf.g.test", "TXT"): ["v=spf1 ip4:209.85.128.0/17 ~all"],
        }
    )
    assert check_spf("203.0.113.5", "a.test", r).result == "pass"
    assert check_spf("198.51.100.5", "a.test", r).result == "fail"
    res = check_spf("209.85.220.41", "gmail.test", r)
    assert res.result == "pass" and "redirect=_spf.g.test" in (res.matched_mechanism or "")
    assert check_spf("1.1.1.1", "gmail.test", r).result == "softfail"


def test_ipv6() -> None:
    r = StaticResolver({("a.test", "TXT"): ["v=spf1 ip6:2001:db8::/32 -all"]})
    assert check_spf("2001:db8::1", "a.test", r).result == "pass"
    assert check_spf("203.0.113.1", "a.test", r).result == "fail"


def test_permerror_cases() -> None:
    r = StaticResolver(
        {
            ("multi.test", "TXT"): ["v=spf1 -all", "v=spf1 +all"],
            ("badinc.test", "TXT"): ["v=spf1 include:missing.test -all"],
            ("unknown.test", "TXT"): ["v=spf1 foo:bar -all"],
        }
    )
    assert check_spf("203.0.113.1", "multi.test", r).result == "permerror"
    assert check_spf("203.0.113.1", "badinc.test", r).result == "permerror"
    assert check_spf("203.0.113.1", "unknown.test", r).result == "permerror"


def test_lookup_limit() -> None:
    records = {
        ("loop.test", "TXT"): ["v=spf1 " + " ".join(f"include:i{n}.test" for n in range(12)) + " -all"]
    }
    for n in range(12):
        records[(f"i{n}.test", "TXT")] = ["v=spf1 ip4:10.9.9.9 -all"]
    res = check_spf("203.0.113.1", "loop.test", StaticResolver(records))
    assert res.result == "permerror" and "10" in res.detail


def test_temperror_and_skipped() -> None:
    r = StaticResolver({("t.test", "TXT"): ["__TEMPERROR__"]})
    assert check_spf("203.0.113.1", "t.test", r).result == "temperror"
    assert check_spf("203.0.113.1", "t.test", None).result == "skipped"
    assert check_spf(None, "t.test", r).result == "skipped"
    assert check_spf("203.0.113.1", None, r).result == "skipped"


def test_macro_noted_not_fatal() -> None:
    r = StaticResolver({("m.test", "TXT"): ["v=spf1 exists:%{i}.rbl.test ip4:203.0.113.1 -all"]})
    res = check_spf("203.0.113.1", "m.test", r)
    assert res.result == "pass" and "macro" in res.detail
