from __future__ import annotations

from mailtrace_core.parsing.auth_results import (
    best_reported,
    parse_all,
    parse_authentication_results,
)

GMAIL = (
    "mx.recipient.test; dkim=neutral (body hash did not verify) header.i=@shipping.test "
    "header.s=k1 header.b=abcd1234; spf=softfail (best guess record for domain of "
    "noreply@shipping.test does not designate 198.51.100.31 as permitted sender) "
    "smtp.mailfrom=noreply@shipping.test; dmarc=fail (p=NONE sp=NONE dis=NONE) "
    "header.from=shipping.test"
)
MICROSOFT = (
    "spf=pass (sender IP is 203.0.113.25) smtp.mailfrom=example-corp.test; dkim=pass "
    "(signature was verified) header.d=example-corp.test;dmarc=pass action=none "
    "header.from=example-corp.test;compauth=pass reason=100"
)
QUOTED = 'mx.test; spf=fail reason="mechanism -all matched; ip 1.2.3.4" smtp.mailfrom=a.test'


def test_gmail_style() -> None:
    res = parse_authentication_results(GMAIL)
    by = {r.method: r for r in res}
    assert set(by) == {"dkim", "spf", "dmarc"}
    assert by["dkim"].result == "neutral"
    assert by["dkim"].properties["header.i"] == "@shipping.test"
    assert by["spf"].result == "softfail"
    assert by["spf"].properties["smtp.mailfrom"] == "noreply@shipping.test"
    assert by["dmarc"].properties["header.from"] == "shipping.test"
    assert all(r.authserv_id == "mx.recipient.test" for r in res)


def test_microsoft_style_without_authserv_and_with_compauth() -> None:
    # No authserv-id: first segment is the spf result itself. We still get the rest.
    res = parse_authentication_results("host.test; " + MICROSOFT)
    by = {r.method: r for r in res}
    assert by["spf"].result == "pass"
    assert by["dkim"].properties["header.d"] == "example-corp.test"
    assert by["dmarc"].properties["action"] == "none"
    assert by["compauth"].reason == "100"


def test_quoted_reason_with_semicolon() -> None:
    res = parse_authentication_results(QUOTED)
    assert len(res) == 1
    assert res[0].reason == "mechanism -all matched; ip 1.2.3.4"
    assert res[0].properties["smtp.mailfrom"] == "a.test"


def test_none_and_empty() -> None:
    assert parse_authentication_results("mx.test; none") == []
    assert parse_authentication_results("") == []


def test_parse_all_tags_arc_results() -> None:
    headers = [
        ("Authentication-Results", "mx.test; spf=pass smtp.mailfrom=a.test"),
        ("ARC-Authentication-Results", "i=1; mx.other; dkim=pass header.d=b.test"),
        ("Subject", "x"),
    ]
    res = parse_all(headers)
    methods = [r.method for r in res]
    assert methods == ["spf", "arc:dkim"]
    assert best_reported(res, "spf") is res[0]
    assert best_reported(res, "dkim") is None
