"""Case folders and evidence intake.

Layout of a case directory::

    <base>/<case_id>/
        case.json          case metadata
        audit.jsonl        append-only hash-chained audit log
        original/          read-only copies of ingested files + manifest.json
        working/           scratch space for analysis output
        report/            rendered reports

The source file passed to :meth:`Case.intake` is only ever opened for
reading. The copy in ``original/`` is hashed again after copying, compared to
the source hash, and then marked read-only.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
from datetime import datetime
from pathlib import Path

from mailtrace_core.case.audit import AuditLog
from mailtrace_core.models import CaseMeta, EvidenceItem, SourceFormat, to_jsonable
from mailtrace_core.util.hashing import hash_bytes, hash_file
from mailtrace_core.util.timeutil import iso_utc, now_utc

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


class IntegrityError(RuntimeError):
    """Raised when a stored copy does not match its recorded hash."""


def safe_case_id(case_number: str) -> str:
    cid = _UNSAFE.sub("_", case_number.strip()).strip("._")
    return cid or "case"


def sniff_format(path: Path, head: bytes | None = None) -> SourceFormat:
    """Decide how to parse a file from magic bytes first, extension second."""
    if head is None:
        with path.open("rb") as fh:
            head = fh.read(8)
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return SourceFormat.MSG
    ext = path.suffix.lower()
    if ext == ".msg":
        return SourceFormat.MSG
    if ext in {".txt", ".hdr", ".headers"}:
        return SourceFormat.RAW_HEADERS
    return SourceFormat.EML


class Case:
    def __init__(self, root: Path, meta: CaseMeta) -> None:
        self.root = root
        self.meta = meta
        self.original_dir = root / "original"
        self.working_dir = root / "working"
        self.report_dir = root / "report"
        self.manifest_path = self.original_dir / "manifest.json"
        self.audit = AuditLog(root / "audit.jsonl", meta.case_number, meta.examiner, meta.agency)

    # ---------------------------------------------------------------- lifecycle
    @classmethod
    def create(cls, base_dir: Path, case_number: str, examiner: str, agency: str) -> Case:
        if not case_number.strip():
            raise ValueError("case number is required")
        if not examiner.strip():
            raise ValueError("examiner name is required")
        if not agency.strip():
            raise ValueError("agency is required")
        case_id = safe_case_id(case_number)
        root = base_dir / case_id
        if root.exists():
            raise FileExistsError(f"case folder already exists: {root}")
        for sub in ("original", "working", "report"):
            (root / sub).mkdir(parents=True)
        meta = CaseMeta(
            case_number=case_number.strip(),
            examiner=examiner.strip(),
            agency=agency.strip(),
            created_at=now_utc(),
            case_id=case_id,
        )
        (root / "case.json").write_text(json.dumps(to_jsonable(meta), indent=2), encoding="utf-8")
        (root / "original" / "manifest.json").write_text("[]", encoding="utf-8")
        case = cls(root, meta)
        case.audit.record("case_created", case_root=str(root))
        return case

    @classmethod
    def open(cls, root: Path) -> Case:
        data = json.loads((root / "case.json").read_text(encoding="utf-8"))
        meta = CaseMeta(
            case_number=data["case_number"],
            examiner=data["examiner"],
            agency=data["agency"],
            created_at=datetime.fromisoformat(data["created_at"]),
            case_id=data["case_id"],
        )
        case = cls(root, meta)
        case.audit.record("case_opened")
        return case

    # ------------------------------------------------------------------ intake
    def _next_item_id(self) -> str:
        return f"E{len(self.manifest()) + 1:03d}"

    def manifest(self) -> list[EvidenceItem]:
        if not self.manifest_path.exists():
            return []
        raw = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        items: list[EvidenceItem] = []
        for d in raw:
            items.append(
                EvidenceItem(
                    item_id=d["item_id"],
                    original_path=d["original_path"],
                    stored_path=d["stored_path"],
                    filename=d["filename"],
                    size=int(d["size"]),
                    sha256=d["sha256"],
                    md5=d["md5"],
                    ingested_at=datetime.fromisoformat(d["ingested_at"]),
                    source_format=SourceFormat(d["source_format"]),
                )
            )
        return items

    def _append_manifest(self, item: EvidenceItem) -> None:
        items = [to_jsonable(i) for i in self.manifest()]
        items.append(to_jsonable(item))
        self.manifest_path.write_text(json.dumps(items, indent=2), encoding="utf-8")

    @staticmethod
    def _set_read_only(path: Path) -> None:
        mode = path.stat().st_mode
        path.chmod(mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))

    def intake(self, source: Path) -> EvidenceItem:
        """Copy ``source`` into the case, hash before and after, and log it.

        The source file is opened read-only and never written to.
        """
        source = Path(source)
        if not source.is_file():
            raise FileNotFoundError(source)
        sha_src, md5_src = hash_file(source)
        size = source.stat().st_size
        fmt = sniff_format(source)
        item_id = self._next_item_id()
        safe_name = _UNSAFE.sub("_", source.name)
        dest = self.original_dir / f"{item_id}_{safe_name}"
        shutil.copyfile(source, dest)
        sha_dst, md5_dst = hash_file(dest)
        if (sha_src, md5_src) != (sha_dst, md5_dst):
            dest.unlink(missing_ok=True)
            self.audit.record(
                "intake_failed",
                source=str(source),
                reason="hash mismatch after copy",
                sha256_source=sha_src,
                sha256_copy=sha_dst,
            )
            raise IntegrityError("copied file hash does not match source; intake aborted")
        self._set_read_only(dest)
        item = EvidenceItem(
            item_id=item_id,
            original_path=str(source.resolve()),
            stored_path=str(dest),
            filename=source.name,
            size=size,
            sha256=sha_src,
            md5=md5_src,
            ingested_at=now_utc(),
            source_format=fmt,
        )
        self._append_manifest(item)
        self.audit.record(
            "intake",
            item_id=item_id,
            source=item.original_path,
            stored=item.stored_path,
            size=size,
            sha256=sha_src,
            md5=md5_src,
            source_format=fmt.value,
        )
        return item

    def intake_text(self, text: str, label: str = "pasted_headers") -> EvidenceItem:
        """Store pasted raw headers/text as evidence, hashed exactly as given."""
        data = text.encode("utf-8")
        sha, md5 = hash_bytes(data)
        item_id = self._next_item_id()
        filename = f"{_UNSAFE.sub('_', label)}.txt"
        dest = self.original_dir / f"{item_id}_{filename}"
        dest.write_bytes(data)
        sha_dst, _ = hash_file(dest)
        if sha_dst != sha:
            dest.unlink(missing_ok=True)
            raise IntegrityError("stored text hash does not match; intake aborted")
        self._set_read_only(dest)
        item = EvidenceItem(
            item_id=item_id,
            original_path="<pasted>",
            stored_path=str(dest),
            filename=filename,
            size=len(data),
            sha256=sha,
            md5=md5,
            ingested_at=now_utc(),
            source_format=SourceFormat.RAW_HEADERS,
        )
        self._append_manifest(item)
        self.audit.record(
            "intake_text",
            item_id=item_id,
            stored=item.stored_path,
            size=len(data),
            sha256=sha,
            md5=md5,
        )
        return item

    def verify_item(self, item: EvidenceItem) -> bool:
        """Re-hash the stored copy and compare to the manifest. Logged either way."""
        path = Path(item.stored_path)
        if not path.exists():
            self.audit.record("verify_failed", item_id=item.item_id, reason="missing")
            return False
        sha, md5 = hash_file(path)
        ok = sha == item.sha256 and md5 == item.md5
        self.audit.record(
            "verify",
            item_id=item.item_id,
            ok=ok,
            sha256_expected=item.sha256,
            sha256_actual=sha,
        )
        return ok

    def log(self, action: str, **details: object) -> None:
        self.audit.record(action, **details)

    def __repr__(self) -> str:
        return f"Case({self.meta.case_number!r}, {self.root})"


def _touch_utc_marker(path: Path) -> None:  # pragma: no cover - helper for tooling
    path.write_text(iso_utc(), encoding="utf-8")
    os.utime(path)
