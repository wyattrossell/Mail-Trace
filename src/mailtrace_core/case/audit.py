"""Append-only, hash-chained audit log.

Each line of ``audit.jsonl`` is one JSON object. Every entry carries the
SHA-256 of the previous entry (``prev_hash``) and its own ``entry_hash`` over
its canonical JSON form. Editing, deleting or reordering any line breaks the
chain, which :func:`verify_audit_log` detects.

The log is opened in append mode only. Nothing in this module can truncate
or rewrite it.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mailtrace_core.util.timeutil import iso_utc

GENESIS_HASH = "0" * 64


@dataclass(slots=True)
class AuditEntry:
    seq: int
    timestamp_utc: str
    case_number: str
    examiner: str
    agency: str
    action: str
    details: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp_utc": self.timestamp_utc,
            "case_number": self.case_number,
            "examiner": self.examiner,
            "agency": self.agency,
            "action": self.action,
            "details": self.details,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def compute_entry_hash(payload_without_hash: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload_without_hash)).hexdigest()


class AuditLog:
    """Writer for a case's audit log. One instance per open case."""

    def __init__(self, path: Path, case_number: str, examiner: str, agency: str) -> None:
        self.path = path
        self.case_number = case_number
        self.examiner = examiner
        self.agency = agency
        self._lock = threading.Lock()
        self._seq, self._last_hash = self._tail_state()

    def _tail_state(self) -> tuple[int, str]:
        """Return ``(last_seq, last_hash)`` from the existing file, or genesis."""
        if not self.path.exists():
            return 0, GENESIS_HASH
        last: dict[str, Any] | None = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)
        if last is None:
            return 0, GENESIS_HASH
        return int(last["seq"]), str(last["entry_hash"])

    def record(self, action: str, **details: Any) -> AuditEntry:
        """Append one entry. Thread-safe. Returns the entry written."""
        with self._lock:
            seq = self._seq + 1
            payload: dict[str, Any] = {
                "seq": seq,
                "timestamp_utc": iso_utc(),
                "case_number": self.case_number,
                "examiner": self.examiner,
                "agency": self.agency,
                "action": action,
                "details": details,
                "prev_hash": self._last_hash,
            }
            entry_hash = compute_entry_hash(payload)
            entry = AuditEntry(**payload, entry_hash=entry_hash)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry.to_dict(), ensure_ascii=True) + "\n")
                fh.flush()
            self._seq = seq
            self._last_hash = entry_hash
            return entry


def read_audit_log(path: Path) -> list[AuditEntry]:
    entries: list[AuditEntry] = []
    if not path.exists():
        return entries
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(AuditEntry(**json.loads(line)))
    return entries


def verify_audit_log(path: Path) -> tuple[bool, list[str]]:
    """Walk the chain. Returns ``(ok, problems)``; problems is empty when ok."""
    problems: list[str] = []
    prev_hash = GENESIS_HASH
    expected_seq = 1
    for entry in read_audit_log(path):
        if entry.seq != expected_seq:
            problems.append(f"seq {entry.seq}: expected seq {expected_seq} (gap or reorder)")
        if entry.prev_hash != prev_hash:
            problems.append(f"seq {entry.seq}: prev_hash does not match previous entry")
        payload = entry.to_dict()
        del payload["entry_hash"]
        if compute_entry_hash(payload) != entry.entry_hash:
            problems.append(f"seq {entry.seq}: entry_hash mismatch (content altered)")
        prev_hash = entry.entry_hash
        expected_seq = entry.seq + 1
    return not problems, problems
