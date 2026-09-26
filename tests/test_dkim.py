from __future__ import annotations

from pathlib import Path

import dkim
import pytest

from mailtrace_core.enrichment.dns_lookup import StaticResolver
from mailtrace_core.parsing.dkim_verify import parse_signature_tags, verify_dkim
from mailtrace_core.parsing.loader import load_eml_bytes

KEYS = Path(__file__).resolve().parents[1] / "sample_emails" / "keys"

PLAIN = (
    b"From: a@signer.test\r\nTo: b@recipient.test\r\nSubject: hello\r\n"
    b"Date: Mon, 14 Sep 2026 14:00:00 +0000\r\nMessage-ID: <1@signer.test>\r\n\r\nbody text\r\n"
)


@pytest.fixture(scope="module")
def key() -> bytes:
    return (KEYS / "test_dkim_private.pem").read_bytes().replace(b"\r\n", b"\n")


@pytest.fixture(scope="module")
def pub() -> str:
    return (KEYS / "test_dkim_public.b64").read_text().strip()


@pytest.fixture
def signed(key: bytes) -> bytes:
    sig = dkim.sign(
        PLAIN,
        b"sel",
        b"signer.test",
        key,
        include_headers=[b"from", b"to", b"subject", b"date", b"message-id"],
    )
    return sig + PLAIN


def _resolver(pub: str) -> StaticResolver:
    return StaticResolver({("sel._domainkey.signer.test", "TXT"): [f"v=DKIM1; k=rsa; p={pub}"]})


def test_parse_signature_tags() -> None:
    tags = parse_signature_tags("v=1; a=rsa-sha256; d=signer.test; s=sel;\r\n h=from : to;\r\n b=ab cd")
    assert (
        tags["d"] == "signer.test" and tags["s"] == "sel" and tags["h"] == "from:to" and tags["b"] == "abcd"
    )


def test_pass(signed: bytes, pub: str) -> None:
    pe = load_eml_bytes(signed)
    res = verify_dkim(pe.raw_bytes, pe.headers, _resolver(pub), "signer.test")
    assert res.result == "pass"
    assert res.domain == "signer.test" and res.selector == "sel"
    assert "from" in res.signed_headers


def test_pass_with_lf_line_endings(signed: bytes, pub: str) -> None:
    lf = signed.replace(b"\r\n", b"\n")
    pe = load_eml_bytes(lf)
    assert verify_dkim(pe.raw_bytes, pe.headers, _resolver(pub), "signer.test").result == "pass"


def test_body_tamper_fails(signed: bytes, pub: str) -> None:
    tampered = signed.replace(b"body text", b"body TEXT")
    pe = load_eml_bytes(tampered)
    res = verify_dkim(pe.raw_bytes, pe.headers, _resolver(pub), "signer.test")
    assert res.result == "fail" and "body hash" in res.detail


def test_header_tamper_fails(signed: bytes, pub: str) -> None:
    tampered = signed.replace(b"Subject: hello", b"Subject: hullo")
    pe = load_eml_bytes(tampered)
    assert verify_dkim(pe.raw_bytes, pe.headers, _resolver(pub), "signer.test").result == "fail"


def test_missing_key_is_permerror_or_fail(signed: bytes) -> None:
    pe = load_eml_bytes(signed)
    res = verify_dkim(pe.raw_bytes, pe.headers, StaticResolver({}), "signer.test")
    assert res.result in {"permerror", "fail"}


def test_temperror(signed: bytes) -> None:
    pe = load_eml_bytes(signed)
    r = StaticResolver({("sel._domainkey.signer.test", "TXT"): ["__TEMPERROR__"]})
    assert verify_dkim(pe.raw_bytes, pe.headers, r, "signer.test").result == "temperror"


def test_no_signature_and_skipped(pub: str) -> None:
    pe = load_eml_bytes(PLAIN)
    assert verify_dkim(pe.raw_bytes, pe.headers, _resolver(pub)).result == "none"


def test_skipped_without_bytes_or_resolver(signed: bytes, pub: str) -> None:
    pe = load_eml_bytes(signed)
    assert verify_dkim(b"", pe.headers, _resolver(pub)).result == "skipped"
    assert verify_dkim(pe.raw_bytes, pe.headers, None).result == "skipped"


def test_prefers_aligned_signature(key: bytes, pub: str) -> None:
    sig_other = dkim.sign(PLAIN, b"sel", b"other.test", key, include_headers=[b"from"])
    sig_signer = dkim.sign(PLAIN, b"sel", b"signer.test", key, include_headers=[b"from"])
    msg = sig_other + sig_signer + PLAIN
    pe = load_eml_bytes(msg)
    r = StaticResolver(
        {
            ("sel._domainkey.signer.test", "TXT"): [f"v=DKIM1; k=rsa; p={pub}"],
            ("sel._domainkey.other.test", "TXT"): [f"v=DKIM1; k=rsa; p={pub}"],
        }
    )
    res = verify_dkim(pe.raw_bytes, pe.headers, r, "signer.test")
    assert res.result == "pass" and res.domain == "signer.test"
    assert "2 signature(s)" in res.detail
