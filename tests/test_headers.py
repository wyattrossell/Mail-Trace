from __future__ import annotations

from datetime import UTC, datetime

from mailtrace_core.models import Confidence
from mailtrace_core.parsing.headers import (
    build_hops,
    check_against_date_header,
    mark_trust,
    origin_candidates,
    parse_received,
    split_clauses,
)

POSTFIX = (
    "from mail.example-corp.test (mail.example-corp.test [203.0.113.25]) by "
    "mx1.recipient.test (Postfix) with ESMTPS id 4XyZ for <det@recipient.test>; "
    "Mon, 14 Sep 2026 14:02:13 +0000 (UTC)"
)
EXIM = (
    "from [198.51.100.7] (helo=bulk-01.sender.test) by mx.recipient.test with esmtp "
    "(Exim 4.96) id 1abc-00 for det@recipient.test; Mon, 14 Sep 2026 14:02:20 +0000"
)
GOOGLE_INTERNAL = "by 2002:a05:6a10:1234:b0:1:2:3 with SMTP id abc; Wed, 23 Sep 2026 10:00:05 -0700 (PDT)"
MICROSOFT = (
    "from AB1PR01MB1234.prod.example.test (2603:10b6:208:1::20) by "
    "CD2PR01MB5678.prod.example.test (2603:10b6:208:2::15) with Microsoft SMTP Server "
    "(version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7000.30; "
    "Mon, 14 Sep 2026 14:02:14 +0000"
)
ENVELOPE_COMMENT = (
    "from unknown (HELO mailer) (envelope-from <bounce@x.test>) (203.0.113.9) "
    "by smtp.recipient.test with SMTP; 14 Sep 2026 14:02:19 -0000"
)


def test_split_clauses_ignores_keywords_in_comments() -> None:
    clauses, date = split_clauses(ENVELOPE_COMMENT)
    assert clauses["from"].startswith("unknown")
    assert clauses["by"].startswith("smtp.recipient.test")
    assert date == "14 Sep 2026 14:02:19 -0000"


def test_postfix_style() -> None:
    hop = parse_received(POSTFIX, 0)
    assert hop.from_host == "mail.example-corp.test"
    assert hop.from_helo == "mail.example-corp.test"
    assert hop.from_ip == "203.0.113.25"
    assert hop.by_host == "mx1.recipient.test"
    assert hop.protocol == "ESMTPS"
    assert hop.hop_id == "4XyZ"
    assert hop.for_addr == "det@recipient.test"
    assert hop.timestamp == datetime(2026, 9, 14, 14, 2, 13, tzinfo=UTC)
    assert hop.anomalies == []


def test_exim_style_bracketed_ip_and_helo() -> None:
    hop = parse_received(EXIM, 0)
    assert hop.from_ip == "198.51.100.7"
    assert hop.from_helo == "bulk-01.sender.test"
    assert hop.from_host is None
    assert hop.by_host == "mx.recipient.test"
    assert hop.protocol == "esmtp"


def test_google_internal_hop_has_no_from() -> None:
    hop = parse_received(GOOGLE_INTERNAL, 0)
    assert hop.from_host is None and hop.from_ip is None
    assert hop.by_host == "2002:a05:6a10:1234:b0:1:2:3"
    assert hop.timestamp is not None and hop.timestamp.utcoffset().total_seconds() == -7 * 3600


def test_microsoft_style_ipv6_in_parens() -> None:
    hop = parse_received(MICROSOFT, 0)
    assert hop.from_host == "AB1PR01MB1234.prod.example.test"
    assert hop.from_ip == "2603:10b6:208:1::20"
    assert hop.by_host == "CD2PR01MB5678.prod.example.test"
    assert hop.protocol is not None and hop.protocol.startswith("Microsoft SMTP Server")


def test_unknown_host_flagged() -> None:
    hop = parse_received(ENVELOPE_COMMENT, 0)
    assert hop.from_ip == "203.0.113.9"
    assert any("unknown" in a for a in hop.anomalies)


def test_missing_timestamp_is_anomaly() -> None:
    hop = parse_received("from a.test by b.test with ESMTP id 1", 0)
    assert "no timestamp" in hop.anomalies


def test_build_hops_reverses_order_and_computes_delays() -> None:
    newest_first = [
        "from b.test (b.test [203.0.113.2]) by c.test with ESMTP id 3; Mon, 14 Sep 2026 14:00:30 +0000",
        "from a.test (a.test [203.0.113.1]) by b.test with ESMTP id 2; Mon, 14 Sep 2026 14:00:10 +0000",
        "from [10.0.0.5] by a.test with ESMTPA id 1; Mon, 14 Sep 2026 14:00:00 +0000",
    ]
    hops = build_hops(newest_first)
    assert [h.by_host for h in hops] == ["a.test", "b.test", "c.test"]
    assert hops[0].delay_seconds is None
    assert hops[1].delay_seconds == 10.0
    assert hops[2].delay_seconds == 20.0
    assert all(not h.anomalies for h in hops)


def test_out_of_order_and_implausible_delay_flagged() -> None:
    newest_first = [
        "from c.test (c.test [203.0.113.3]) by d.test with ESMTP id 4; Sat, 19 Sep 2026 12:00:10 +0000",
        "from b.test (b.test [203.0.113.2]) by c.test with ESMTP id 3; Sat, 19 Sep 2026 12:00:09 +0000",
        "from a.test (a.test [203.0.113.1]) by b.test with ESMTP id 2; Wed, 16 Sep 2026 11:59:00 +0000",
        "from [192.168.1.5] by a.test with ESMTPA id 1; Sat, 19 Sep 2026 11:30:00 +0000",
    ]
    hops = build_hops(newest_first)
    assert hops[1].delay_seconds is not None and hops[1].delay_seconds < 0
    assert any("out of order" in a for a in hops[1].anomalies)
    assert any("implausibly long delay" in a for a in hops[2].anomalies)


def test_minor_skew_is_not_out_of_order() -> None:
    newest_first = [
        "from a.test (a.test [203.0.113.1]) by b.test with ESMTP id 2; Mon, 14 Sep 2026 14:00:00 +0000",
        "from [10.0.0.5] by a.test with ESMTPA id 1; Mon, 14 Sep 2026 14:00:30 +0000",
    ]
    hops = build_hops(newest_first)
    assert any("minor clock skew" in a for a in hops[1].anomalies)
    assert not any("out of order" in a for a in hops[1].anomalies)


def test_date_header_checks() -> None:
    hops = build_hops(
        [
            "from a.test (a.test [203.0.113.1]) by b.test with ESMTP id 2; Mon, 14 Sep 2026 14:00:00 +0000",
        ]
    )
    late_date = datetime(2026, 9, 14, 16, 0, tzinfo=UTC)
    w = check_against_date_header(hops, late_date)
    assert any("AFTER the earliest Received" in x for x in w)
    fine = check_against_date_header(hops, datetime(2026, 9, 14, 13, 59, tzinfo=UTC))
    assert fine == []


def _chain() -> list:
    return build_hops(
        [
            "from mx1.recipient.test (mx1.recipient.test [192.0.2.10]) by store.recipient.test with ESMTP id 3; Mon, 14 Sep 2026 14:00:30 +0000",
            "from srv.bulkhost.test (srv.bulkhost.test [198.51.100.77]) by mx1.recipient.test with ESMTPS id 2; Mon, 14 Sep 2026 14:00:10 +0000",
            "from mail.bank.test (mail.bank.test [203.0.113.99]) by srv.bulkhost.test with ESMTP id 1; Mon, 14 Sep 2026 14:00:00 +0000",
        ]
    )


def test_trust_boundary_with_recipient_domain() -> None:
    hops = _chain()
    boundary = mark_trust(hops, {"recipient.test"})
    assert boundary == 1
    assert [h.trusted for h in hops] == [False, True, True]
    assert "recipient domain" in hops[1].trust_reason
    assert "below trust boundary" in hops[0].trust_reason


def test_trust_boundary_without_recipient_domain_anchors_on_final_hop() -> None:
    hops = _chain()
    boundary = mark_trust(hops, set())
    assert boundary == 1  # final hop assumed, then same-domain hop extends the run
    assert hops[2].trusted and hops[1].trusted and not hops[0].trusted


def test_internal_no_from_hops_extend_trust() -> None:
    hops = build_hops(
        [
            GOOGLE_INTERNAL,
            "from vps.cheaphost.test (vps.cheaphost.test [198.51.100.31]) by mx.recipient.test with ESMTPS id g; Wed, 23 Sep 2026 10:00:04 -0700",
            "from localhost (localhost [127.0.0.1]) by vps.cheaphost.test with ESMTP id 4; Wed, 23 Sep 2026 17:00:01 +0000",
        ]
    )
    boundary = mark_trust(hops, {"recipient.test"})
    assert boundary == 1
    assert [h.trusted for h in hops] == [False, True, True]


def test_origin_candidates_rank_first_external_hop() -> None:
    hops = _chain()
    boundary = mark_trust(hops, {"recipient.test"})
    headers = [("X-Originating-IP", "[203.0.113.55]"), ("From", "x@y.test")]
    cands = origin_candidates(hops, boundary, headers)
    ips = [(c.ip, c.confidence) for c in cands]
    assert ips[0] == ("198.51.100.77", Confidence.LIKELY)
    assert ("203.0.113.99", Confidence.UNVERIFIED) in ips  # forged-looking earliest hop
    assert ("203.0.113.55", Confidence.UNVERIFIED) in ips  # X-Originating-IP
    assert all(not c.is_private for c in cands)


def test_private_boundary_ip_is_marked() -> None:
    hops = build_hops(
        [
            "from internal.recipient.test (internal.recipient.test [10.1.1.1]) by mx.recipient.test with ESMTP id 2; Mon, 14 Sep 2026 14:00:10 +0000",
            "from [172.16.0.9] by internal.recipient.test with ESMTP id 1; Mon, 14 Sep 2026 14:00:00 +0000",
        ]
    )
    boundary = mark_trust(hops, {"recipient.test"})
    cands = origin_candidates(hops, boundary, [])
    assert cands and all(c.is_private for c in cands)
    assert cands[0].confidence is Confidence.UNVERIFIED
