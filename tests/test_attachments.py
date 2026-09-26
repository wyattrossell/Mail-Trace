from __future__ import annotations

import hashlib
from email.message import EmailMessage

from mailtrace_core.parsing.attachments import inventory_attachments, record_from_bytes

MZ = b"MZ\x90\x00" + b"\x00" * 60
PDF = b"%PDF-1.7\n%x\n"


def _msg_with(*parts: tuple[bytes, str, str, str]) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = "a@b.test"
    msg.set_content("body")
    for data, maintype, subtype, name in parts:
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return msg


def test_hashes_and_sizes() -> None:
    msg = _msg_with((PDF, "application", "pdf", "doc.pdf"))
    (rec,) = inventory_attachments(msg)
    assert rec.filename == "doc.pdf" and rec.size == len(PDF)
    assert rec.sha256 == hashlib.sha256(PDF).hexdigest()
    assert rec.md5 == hashlib.md5(PDF).hexdigest()  # noqa: S324
    assert rec.detected_type == "pdf" and rec.declared_type == "application/pdf"
    assert not rec.type_mismatch and rec.notes == []


def test_pe_disguised_as_pdf() -> None:
    msg = _msg_with((MZ, "application", "pdf", "Invoice.pdf"))
    (rec,) = inventory_attachments(msg)
    assert rec.detected_type == "pe-executable" and rec.type_mismatch
    assert any("content is pe-executable" in n for n in rec.notes)


def test_double_extension_and_executable() -> None:
    msg = _msg_with((MZ, "application", "octet-stream", "Invoice.pdf.exe"))
    (rec,) = inventory_attachments(msg)
    assert rec.extension == "exe" and not rec.type_mismatch
    assert any("double extension" in n for n in rec.notes)
    assert any("executable or script" in n for n in rec.notes)


def test_rtlo_filename() -> None:
    msg = _msg_with((b"\x89PNG\r\n\x1a\n" + b"\x00" * 8, "image", "png", "photo‮fdp.exe"))
    (rec,) = inventory_attachments(msg)
    assert any("right-to-left override" in n for n in rec.notes)
    assert rec.type_mismatch  # png bytes, .exe extension


def test_zip_family_and_macros() -> None:
    zipped = b"PK\x03\x04" + b"\x00" * 30
    msg = _msg_with(
        (zipped, "application", "zip", "a.zip"),
        (zipped, "application", "vnd.openxmlformats-officedocument.wordprocessingml.document", "a.docx"),
        (zipped, "application", "vnd.ms-word.document.macroEnabled.12", "a.docm"),
    )
    recs = {r.filename: r for r in inventory_attachments(msg)}
    assert recs["a.zip"].detected_type == "zip" and not recs["a.zip"].type_mismatch
    assert not recs["a.docx"].type_mismatch
    assert any("macros" in n for n in recs["a.docm"].notes)
    assert any("archive" in n for n in recs["a.zip"].notes)


def test_path_components_are_stripped() -> None:
    msg = _msg_with((PDF, "application", "pdf", "..\\..\\Windows\\evil.pdf"))
    (rec,) = inventory_attachments(msg)
    assert rec.filename == "evil.pdf"


def test_inline_image_with_cid_is_recorded() -> None:
    msg = EmailMessage()
    msg["From"] = "a@b.test"
    msg.set_content("x")
    msg.add_alternative("<html><img src='cid:l1'></html>", subtype="html")
    msg.get_payload()[1].add_related(
        b"\x89PNG\r\n\x1a\n" + b"\x00" * 8,
        maintype="image",
        subtype="png",
        cid="<l1>",
        filename="logo.png",
        disposition="inline",
    )
    (rec,) = inventory_attachments(msg)
    assert rec.is_inline and rec.content_id == "<l1>" and rec.detected_type == "png"


def test_record_from_bytes_for_msg_sources() -> None:
    rec = record_from_bytes("report.pdf", MZ, "application/pdf", index=3)
    assert rec.type_mismatch and rec.part_index == 3 and rec.detected_type == "pe-executable"
    rec = record_from_bytes("", b"", None)
    assert rec.filename.startswith("unnamed") and rec.size == 0
