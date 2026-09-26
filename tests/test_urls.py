from __future__ import annotations

from mailtrace_core.parsing.urls import (
    build_url_record,
    decode_idn,
    find_urls_in_text,
    normalize_url,
    registrable_domain,
)
from mailtrace_core.util.defang import defang_email, defang_ip, defang_url


def test_find_urls_in_text() -> None:
    text = (
        "Visit https://a.test/path?x=1. Also www.b.test/x, and (http://c.test/p_(q)) "
        "plus ftp://d.test/file. Not this: mailto:x@y.test"
    )
    found = find_urls_in_text(text)
    assert found == [
        "https://a.test/path?x=1",
        "www.b.test/x",
        "http://c.test/p_(q)",
        "ftp://d.test/file",
    ]


def test_normalize() -> None:
    assert normalize_url("HTTPS://Login.Example.TEST:443/Path") == (
        "https://login.example.test/Path",
        "login.example.test",
        "https",
    )
    assert normalize_url("www.b.test")[0] == "http://www.b.test/"
    assert normalize_url("http://user:pw@evil.test/x")[1] == "evil.test"
    assert normalize_url("http://[2001:db8::1]:8080/")[1] == "[2001:db8::1]"


def test_defang() -> None:
    assert defang_url("https://evil.example/login?x=1.2") == "hxxps[:]//evil[.]example/login?x=1.2"
    assert defang_url("http://203.0.113.5/x") == "hxxp[:]//203[.]0[.]113[.]5/x"
    assert defang_url("mailto:a@b.test") == "mailto[:]a[@]b[.]test"
    assert defang_ip("2001:db8::1") == "2001[:]db8[:][:]1"
    assert defang_email("a.b@c.test") == "a[.]b[@]c[.]test"


def test_idn() -> None:
    is_idn, uni = decode_idn("xn--pypal-4ve.example")
    assert is_idn and uni == "pаypal.example"
    assert decode_idn("plain.example") == (False, None)


def test_record_flags() -> None:
    rec = build_url_record("https://bit.ly/abc", "html-href", display_text="click", shorteners=["bit.ly"])
    assert rec.is_shortener and not rec.display_mismatch
    rec = build_url_record("http://203.0.113.5/", "text")
    assert rec.is_ip_host
    rec = build_url_record(
        "https://login.rnicrosoft.example/x", "html-href", display_text="https://www.microsoft.com/account"
    )
    assert rec.display_mismatch and rec.host == "login.rnicrosoft.example"
    rec = build_url_record("https://a.test/x", "html-href", display_text="Click here")
    assert not rec.display_mismatch
    rec = build_url_record("https://a.test/x", "html-href", display_text="https://a.test/x")
    assert not rec.display_mismatch
    rec = build_url_record("https://www.paypal.com@evil.test/login", "html-href", display_text="paypal.com")
    assert rec.host == "evil.test" and rec.display_mismatch


def test_registrable_domain() -> None:
    assert registrable_domain("a.b.example.com") == "example.com"
    assert registrable_domain("mail.example.co.uk") == "example.co.uk"
    assert registrable_domain("examplecounty-sheriff.gov.test") == "examplecounty-sheriff.gov.test"
    assert registrable_domain("mx1.examplecounty-sheriff.gov.test") == "examplecounty-sheriff.gov.test"
    assert registrable_domain("example.com") == "example.com"
