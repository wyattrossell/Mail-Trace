from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from mailtrace_core.case.audit import read_audit_log, verify_audit_log
from mailtrace_core.case.manager import Case, IntegrityError, safe_case_id, sniff_format
from mailtrace_core.models import SourceFormat


def _make_case(tmp_path: Path) -> Case:
    return Case.create(tmp_path / "cases", "26-001234/A", "Det. R. Example", "Example County SO")


def test_create_lays_out_folders_and_logs(tmp_path: Path) -> None:
    case = _make_case(tmp_path)
    assert case.root.name == "26-001234_A"
    for sub in ("original", "working", "report"):
        assert (case.root / sub).is_dir()
    assert (case.root / "case.json").exists()
    entries = read_audit_log(case.root / "audit.jsonl")
    assert [e.action for e in entries] == ["case_created"]
    assert entries[0].agency == "Example County SO"


def test_create_requires_fields(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        Case.create(tmp_path, "", "x", "y")
    with pytest.raises(ValueError):
        Case.create(tmp_path, "1", " ", "y")


def test_intake_hashes_copies_and_never_touches_source(tmp_path: Path, samples_dir: Path) -> None:
    case = _make_case(tmp_path)
    src = tmp_path / "evidence.eml"
    src.write_bytes((samples_dir / "01_clean_legitimate.eml").read_bytes())
    before = src.stat()
    expected_sha = hashlib.sha256(src.read_bytes()).hexdigest()
    expected_md5 = hashlib.md5(src.read_bytes()).hexdigest()  # noqa: S324

    item = case.intake(src)

    assert item.sha256 == expected_sha and item.md5 == expected_md5
    assert item.item_id == "E001"
    assert item.source_format is SourceFormat.EML
    assert src.stat().st_mtime == before.st_mtime and src.stat().st_size == before.st_size
    stored = Path(item.stored_path)
    assert stored.exists() and stored.read_bytes() == src.read_bytes()
    assert not os.access(stored, os.W_OK), "stored copy should be read-only"
    assert case.manifest()[0].sha256 == expected_sha
    actions = [e.action for e in read_audit_log(case.root / "audit.jsonl")]
    assert actions == ["case_created", "intake"]
    assert verify_audit_log(case.root / "audit.jsonl")[0]


def test_intake_ids_increment_and_verify(tmp_path: Path, samples_dir: Path) -> None:
    case = _make_case(tmp_path)
    a = case.intake(samples_dir / "01_clean_legitimate.eml")
    b = case.intake(samples_dir / "08_pasted_headers_only.txt")
    assert (a.item_id, b.item_id) == ("E001", "E002")
    assert b.source_format is SourceFormat.RAW_HEADERS
    assert case.verify_item(a) and case.verify_item(b)


def test_verify_detects_modified_copy(tmp_path: Path, samples_dir: Path) -> None:
    case = _make_case(tmp_path)
    item = case.intake(samples_dir / "01_clean_legitimate.eml")
    p = Path(item.stored_path)
    p.chmod(0o600)
    p.write_bytes(b"tampered")
    assert case.verify_item(item) is False
    last = read_audit_log(case.root / "audit.jsonl")[-1]
    assert last.action == "verify" and last.details["ok"] is False


def test_intake_text(tmp_path: Path) -> None:
    case = _make_case(tmp_path)
    text = "From: a@example.test\nSubject: hi\n"
    item = case.intake_text(text, "gmail show original")
    assert item.sha256 == hashlib.sha256(text.encode()).hexdigest()
    assert Path(item.stored_path).read_text(encoding="utf-8") == text
    assert item.source_format is SourceFormat.RAW_HEADERS


def test_open_existing_case(tmp_path: Path) -> None:
    case = _make_case(tmp_path)
    again = Case.open(case.root)
    assert again.meta.case_number == "26-001234/A"
    assert [e.action for e in read_audit_log(case.root / "audit.jsonl")] == [
        "case_created",
        "case_opened",
    ]


def test_duplicate_case_refused(tmp_path: Path) -> None:
    _make_case(tmp_path)
    with pytest.raises(FileExistsError):
        _make_case(tmp_path)


def test_sniff_format(tmp_path: Path) -> None:
    ole = tmp_path / "x.dat"
    ole.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 8)
    assert sniff_format(ole) is SourceFormat.MSG
    txt = tmp_path / "h.txt"
    txt.write_text("Received: x")
    assert sniff_format(txt) is SourceFormat.RAW_HEADERS
    eml = tmp_path / "m.eml"
    eml.write_text("From: x")
    assert sniff_format(eml) is SourceFormat.EML


def test_safe_case_id() -> None:
    assert safe_case_id("  26/001 234 ") == "26_001_234"
    assert safe_case_id("...") == "case"


def test_integrity_error_type() -> None:
    assert issubclass(IntegrityError, RuntimeError)
