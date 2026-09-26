from __future__ import annotations

import sys
import types
from datetime import UTC, datetime
from pathlib import Path

from mailtrace_core.models import SourceFormat
from mailtrace_core.parsing.loader import (
    decode_header_value,
    load_eml_bytes,
    load_msg_path,
    load_path,
    load_raw_headers,
    parse_addresses,
)


def test_decode_header_value() -> None:
    assert decode_header_value("=?UTF-8?B?WW91ciBwYWNrYWdl?=") == "Your package"
    assert decode_header_value("plain\r\n\tfolded") == "plain folded"
    assert decode_header_value("=?bogus?Q?x?=") == "=?bogus?Q?x?="


def test_parse_addresses() -> None:
    addrs = parse_addresses('"Example Bank" <alerts@bank.test>, other@x.test')
    assert addrs[0].display_name == "Example Bank" and addrs[0].address == "alerts@bank.test"
    assert addrs[0].domain == "bank.test"
    assert addrs[1].display_name == "" and addrs[1].address == "other@x.test"
    assert parse_addresses(None) == []


def test_load_eml(samples_dir: Path) -> None:
    pe = load_eml_bytes((samples_dir / "02_spoofed_bank_spf_fail.eml").read_bytes(), "02")
    assert pe.source_format is SourceFormat.EML
    assert pe.from_ and pe.from_.display_name == "Example Bank Security"
    assert pe.reply_to[0].address == "examplebank.verification@gmail.com"
    assert pe.return_path and pe.return_path.address == "bounce-4471@mailer-relay.test"
    assert pe.subject and pe.subject.startswith("URGENT")
    assert pe.date == datetime(2026, 9, 15, 8, 14, tzinfo=UTC)
    assert len(pe.header_all("Received")) == 3
    assert "unusual sign-in" in pe.body_text
    assert "<html>" in pe.body_html
    assert pe.raw_bytes.startswith(b"Received:")


def test_load_raw_headers_with_junk_prefix_and_encoded_subject(samples_dir: Path) -> None:
    text = "Some webmail chrome text\n\n" + (samples_dir / "08_pasted_headers_only.txt").read_text()
    pe = load_raw_headers(text, "pasted")
    assert pe.source_format is SourceFormat.RAW_HEADERS
    assert pe.subject == "Your package could not be delivered"
    assert pe.from_ and pe.from_.display_name == "USPS Package Center"
    assert len(pe.header_all("Received")) == 3
    assert any("headers only" in w for w in pe.warnings)


def test_load_path_dispatch(samples_dir: Path) -> None:
    assert load_path(samples_dir / "08_pasted_headers_only.txt").source_format is SourceFormat.RAW_HEADERS
    assert load_path(samples_dir / "01_clean_legitimate.eml").source_format is SourceFormat.EML


def test_empty_return_path() -> None:
    pe = load_eml_bytes(b"Return-Path: <>\r\nFrom: a@b.test\r\n\r\nx")
    assert pe.return_path is not None and pe.return_path.address == ""


class _FakeAtt:
    def __init__(self, name: str, data: bytes, mimetype: str) -> None:
        self.longFilename = name
        self.shortFilename = name
        self.data = data
        self.mimetype = mimetype


class _FakeMsg:
    def __init__(self, header_text: str) -> None:
        self.headerText = header_text
        self.subject = "MAPI subject"
        self.sender = '"MAPI Sender" <mapi@sender.test>'
        self.to = "det@recipient.test"
        self.cc = ""
        self.date = None
        self.messageId = "<mapi-1@sender.test>"
        self.body = "text body from mapi"
        self.htmlBody = b"<p>html from mapi <a href='https://x.test/a'>x</a></p>"
        self.attachments = [_FakeAtt("report.pdf", b"MZ\x90\x00" + b"\x00" * 20, "application/pdf")]
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _install_fake_extract_msg(monkeypatch, header_text: str) -> list[_FakeMsg]:
    created: list[_FakeMsg] = []

    def open_msg(path: str) -> _FakeMsg:
        m = _FakeMsg(header_text)
        created.append(m)
        return m

    mod = types.ModuleType("extract_msg")
    mod.openMsg = open_msg  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "extract_msg", mod)
    return created


def test_load_msg_with_transport_headers(monkeypatch, tmp_path: Path) -> None:
    hdr = (
        "Received: from a.test (a.test [203.0.113.1]) by mx.recipient.test with ESMTP id 1; "
        'Mon, 14 Sep 2026 14:00:00 +0000\r\nFrom: "Hdr Sender" <hdr@sender.test>\r\n'
        "To: det@recipient.test\r\nSubject: header subject\r\n"
        "Date: Mon, 14 Sep 2026 13:59:00 +0000\r\nMessage-ID: <h1@sender.test>\r\n"
    )
    created = _install_fake_extract_msg(monkeypatch, hdr)
    p = tmp_path / "m.msg"
    p.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
    pe = load_msg_path(p)
    assert pe.source_format is SourceFormat.MSG
    assert pe.from_ and pe.from_.address == "hdr@sender.test"
    assert pe.subject == "header subject"
    assert len(pe.header_all("Received")) == 1
    assert pe.body_text == "text body from mapi" and "html from mapi" in pe.body_html
    assert pe.attachments[0].filename == "report.pdf" and pe.attachments[0].type_mismatch
    assert pe.raw_bytes == b"" and any("DKIM re-verification not possible" in w for w in pe.warnings)
    assert created[0].closed


def test_load_msg_without_transport_headers_falls_back_to_mapi(monkeypatch, tmp_path: Path) -> None:
    _install_fake_extract_msg(monkeypatch, "")
    p = tmp_path / "m.msg"
    p.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
    pe = load_path(p)
    assert pe.source_format is SourceFormat.MSG
    assert pe.subject == "MAPI subject"
    assert pe.from_ and pe.from_.address == "mapi@sender.test"
    assert pe.message_id == "<mapi-1@sender.test>"
    assert any("no transport headers" in w for w in pe.warnings)
