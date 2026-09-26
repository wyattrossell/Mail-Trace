"""Attachment inventory: names, sizes, hashes, declared vs detected type.

Payloads are decoded from their transfer encoding into memory only to hash
them and read the first few bytes. Nothing is written to disk, opened with an
application, or rendered.
"""

from __future__ import annotations

import re
from email.message import EmailMessage, Message
from pathlib import PurePosixPath, PureWindowsPath

from mailtrace_core.models import AttachmentRecord
from mailtrace_core.util.hashing import hash_bytes

# (magic bytes, offset, detected type label, extensions that legitimately use it)
_MAGIC: list[tuple[bytes, int, str, frozenset[str]]] = [
    (b"%PDF-", 0, "pdf", frozenset({"pdf"})),
    (
        b"PK\x03\x04",
        0,
        "zip",
        frozenset(
            {
                "zip",
                "docx",
                "xlsx",
                "pptx",
                "jar",
                "apk",
                "odt",
                "ods",
                "odp",
                "xlsm",
                "docm",
                "pptm",
                "vsdx",
                "epub",
                "xpi",
                "one",
            }
        ),
    ),
    (b"PK\x05\x06", 0, "zip", frozenset({"zip"})),
    (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        0,
        "ole-compound",
        frozenset({"doc", "xls", "ppt", "msg", "msi", "pub", "vsd", "dot", "xlt", "pot"}),
    ),
    (b"MZ", 0, "pe-executable", frozenset({"exe", "dll", "scr", "sys", "cpl", "ocx", "com"})),
    (b"\x7fELF", 0, "elf-executable", frozenset({"elf", "so", "bin"})),
    (b"\x89PNG\r\n\x1a\n", 0, "png", frozenset({"png"})),
    (b"\xff\xd8\xff", 0, "jpeg", frozenset({"jpg", "jpeg", "jfif"})),
    (b"GIF87a", 0, "gif", frozenset({"gif"})),
    (b"GIF89a", 0, "gif", frozenset({"gif"})),
    (b"BM", 0, "bmp", frozenset({"bmp"})),
    (b"RIFF", 0, "riff", frozenset({"webp", "wav", "avi"})),
    (b"{\\rtf", 0, "rtf", frozenset({"rtf"})),
    (b"Rar!\x1a\x07", 0, "rar", frozenset({"rar"})),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z", frozenset({"7z"})),
    (b"\x1f\x8b", 0, "gzip", frozenset({"gz", "tgz"})),
    (b"BZh", 0, "bzip2", frozenset({"bz2"})),
    (b"\xfd7zXZ\x00", 0, "xz", frozenset({"xz"})),
    (b"ustar", 257, "tar", frozenset({"tar"})),
    (b"ISc(", 0, "cab-installshield", frozenset({"cab"})),
    (b"MSCF", 0, "ms-cabinet", frozenset({"cab"})),
    (b"\x00\x00\x01\x00", 0, "ico", frozenset({"ico"})),
    (b"%!PS", 0, "postscript", frozenset({"ps", "eps"})),
    (b"SQLite format 3\x00", 0, "sqlite", frozenset({"db", "sqlite", "sqlite3"})),
    (b"\xca\xfe\xba\xbe", 0, "java-class", frozenset({"class"})),
    (b"OggS", 0, "ogg", frozenset({"ogg", "oga", "ogv"})),
    (b"ID3", 0, "mp3", frozenset({"mp3"})),
    (b"\x00\x00\x00\x14ftyp", 0, "mp4", frozenset({"mp4", "m4a", "m4v", "mov"})),
    (b"\x00\x00\x00\x18ftyp", 0, "mp4", frozenset({"mp4", "m4a", "m4v", "mov"})),
    (b"\x00\x00\x00\x20ftyp", 0, "mp4", frozenset({"mp4", "m4a", "m4v", "mov"})),
    (b"ITSF", 0, "chm", frozenset({"chm"})),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", 0, "lnk-shortcut", frozenset({"lnk"})),
    (b"\x00\x00\x00\x00\x00\x00\x00\x00", 0, "zeros", frozenset()),
]

EXECUTABLE_EXTENSIONS = frozenset(
    {
        "exe",
        "scr",
        "pif",
        "com",
        "bat",
        "cmd",
        "ps1",
        "vbs",
        "vbe",
        "js",
        "jse",
        "wsf",
        "wsh",
        "hta",
        "msi",
        "msp",
        "cpl",
        "jar",
        "lnk",
        "iso",
        "img",
        "vhd",
        "vhdx",
        "reg",
        "chm",
        "dll",
        "sys",
        "application",
        "gadget",
        "inf",
        "scf",
        "url",
        "one",
        "svg",
    }
)

MACRO_EXTENSIONS = frozenset({"docm", "xlsm", "pptm", "dotm", "xltm", "potm", "doc", "xls", "ppt"})

_RTLO = "‮"
_ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿]")


def _sniff(data: bytes) -> str | None:
    for magic, offset, label, _ in _MAGIC:
        if data[offset : offset + len(magic)] == magic:
            return label
    head = data[:512].lstrip()
    low = head.lower()
    if low.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script")):
        return "html"
    if low.startswith((b"<?xml", b"<svg")):
        return "xml"
    if head.startswith(b"#!"):
        return "script"
    return None


def _expected_exts(label: str) -> frozenset[str]:
    out: set[str] = set()
    for _, _, lbl, exts in _MAGIC:
        if lbl == label:
            out |= exts
    if label == "html":
        out |= {"html", "htm", "hta", "shtml"}
    if label == "xml":
        out |= {"xml", "svg", "xhtml", "rss"}
    return frozenset(out)


def _filename_of(part: Message, index: int) -> tuple[str, list[str]]:
    notes: list[str] = []
    name = part.get_filename()
    if not name:
        name = f"unnamed-part-{index}"
        notes.append("no filename declared")
    # Keep only the final component so path tricks cannot leak.
    name = PureWindowsPath(PurePosixPath(name).name).name
    if _RTLO in name:
        notes.append("filename contains right-to-left override character (extension disguise)")
    if _ZERO_WIDTH.search(name):
        notes.append("filename contains zero-width characters")
    return name, notes


def _extension(filename: str) -> str | None:
    clean = _ZERO_WIDTH.sub("", filename.replace(_RTLO, ""))
    if "." not in clean:
        return None
    return clean.rpartition(".")[2].lower() or None


def _double_extension(filename: str) -> bool:
    parts = filename.lower().split(".")
    if len(parts) < 3:
        return False
    return parts[-1] in EXECUTABLE_EXTENSIONS and parts[-2] in {
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "jpg",
        "jpeg",
        "png",
        "txt",
        "zip",
        "html",
    }


def _payload_bytes(part: Message) -> bytes:
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes):
        return payload
    if payload is None:
        return b""
    return str(payload).encode("utf-8", "replace")


def is_attachment_part(part: Message) -> bool:
    if part.is_multipart():
        return False
    disposition = (part.get_content_disposition() or "").lower()
    if disposition == "attachment":
        return True
    if part.get_filename():
        return True
    ctype = part.get_content_type()
    if disposition == "inline" and not ctype.startswith("text/"):
        return True
    if part.get("Content-ID") and not ctype.startswith("text/"):
        return True
    return False


def inventory_attachments(msg: Message | EmailMessage) -> list[AttachmentRecord]:
    """Walk every MIME part and record anything that is an attachment."""
    records: list[AttachmentRecord] = []
    for index, part in enumerate(msg.walk()):
        if not is_attachment_part(part):
            continue
        data = _payload_bytes(part)
        sha, md5 = hash_bytes(data)
        filename, notes = _filename_of(part, index)
        ext = _extension(filename)
        detected = _sniff(data)
        declared = part.get_content_type()
        disposition = part.get_content_disposition()
        mismatch = False
        if detected and detected != "zeros":
            expected = _expected_exts(detected)
            if ext and expected and ext not in expected:
                mismatch = True
                notes.append(f"content is {detected} but extension is .{ext}")
        if ext in EXECUTABLE_EXTENSIONS:
            notes.append(f".{ext} is an executable or script type")
        if ext in MACRO_EXTENSIONS:
            notes.append(f".{ext} can carry macros")
        if _double_extension(filename):
            notes.append("double extension (document-looking name ending in executable type)")
        if detected in {"pe-executable", "elf-executable", "lnk-shortcut", "chm"}:
            notes.append(f"detected {detected} content")
        if detected == "zip" and ext in {"zip", "jar", "apk"}:
            notes.append("archive: contents not inspected (passive mode)")
        if not data:
            notes.append("empty payload")
        records.append(
            AttachmentRecord(
                filename=filename,
                size=len(data),
                sha256=sha,
                md5=md5,
                declared_type=declared,
                detected_type=detected,
                extension=ext,
                type_mismatch=mismatch,
                disposition=disposition,
                content_id=part.get("Content-ID"),
                is_inline=(disposition == "inline") or bool(part.get("Content-ID")),
                part_index=index,
                notes=notes,
            )
        )
    return records


def record_from_bytes(
    filename: str, data: bytes, declared_type: str | None, *, index: int = 0
) -> AttachmentRecord:
    """Build a record for a non-MIME attachment (e.g. from an Outlook .msg)."""
    sha, md5 = hash_bytes(data)
    notes: list[str] = []
    name = PureWindowsPath(PurePosixPath(filename or f"unnamed-{index}").name).name
    if _RTLO in name:
        notes.append("filename contains right-to-left override character (extension disguise)")
    ext = _extension(name)
    detected = _sniff(data)
    mismatch = False
    if detected and detected != "zeros":
        expected = _expected_exts(detected)
        if ext and expected and ext not in expected:
            mismatch = True
            notes.append(f"content is {detected} but extension is .{ext}")
    if ext in EXECUTABLE_EXTENSIONS:
        notes.append(f".{ext} is an executable or script type")
    if ext in MACRO_EXTENSIONS:
        notes.append(f".{ext} can carry macros")
    if _double_extension(name):
        notes.append("double extension (document-looking name ending in executable type)")
    return AttachmentRecord(
        filename=name,
        size=len(data),
        sha256=sha,
        md5=md5,
        declared_type=declared_type,
        detected_type=detected,
        extension=ext,
        type_mismatch=mismatch,
        part_index=index,
        notes=notes,
    )
