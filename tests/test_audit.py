from __future__ import annotations

import json
from pathlib import Path

from mailtrace_core.case.audit import GENESIS_HASH, AuditLog, read_audit_log, verify_audit_log


def _log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl", "26-000001", "Det. Example", "Example PD")


def test_entries_chain_from_genesis(tmp_path: Path) -> None:
    log = _log(tmp_path)
    e1 = log.record("case_created", root="x")
    e2 = log.record("intake", item_id="E001")
    assert e1.seq == 1 and e1.prev_hash == GENESIS_HASH
    assert e2.seq == 2 and e2.prev_hash == e1.entry_hash
    assert e1.case_number == "26-000001" and e1.examiner == "Det. Example" and e1.agency == "Example PD"
    assert e1.timestamp_utc.endswith("Z")
    ok, problems = verify_audit_log(log.path)
    assert ok and problems == []


def test_reopen_continues_chain(tmp_path: Path) -> None:
    log = _log(tmp_path)
    log.record("a")
    last = log.record("b")
    again = _log(tmp_path)
    e3 = again.record("c")
    assert e3.seq == 3 and e3.prev_hash == last.entry_hash
    assert verify_audit_log(log.path)[0]


def test_tampered_content_is_detected(tmp_path: Path) -> None:
    log = _log(tmp_path)
    log.record("intake", sha256="aaa")
    log.record("verify", ok=True)
    lines = log.path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["details"]["sha256"] = "bbb"
    lines[0] = json.dumps(entry)
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, problems = verify_audit_log(log.path)
    assert not ok
    assert any("entry_hash mismatch" in p for p in problems)

    # A smarter attacker recomputes the entry hash; the next entry's prev_hash
    # then no longer matches, so the chain still breaks.
    from mailtrace_core.case.audit import compute_entry_hash

    payload = dict(entry)
    del payload["entry_hash"]
    entry["entry_hash"] = compute_entry_hash(payload)
    lines[0] = json.dumps(entry)
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, problems = verify_audit_log(log.path)
    assert not ok
    assert any("prev_hash" in p for p in problems)
    assert not any("seq 1" in p for p in problems)


def test_deleted_line_is_detected(tmp_path: Path) -> None:
    log = _log(tmp_path)
    for i in range(3):
        log.record("step", i=i)
    lines = log.path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, problems = verify_audit_log(log.path)
    assert not ok and any("gap or reorder" in p for p in problems)


def test_read_back_matches(tmp_path: Path) -> None:
    log = _log(tmp_path)
    log.record("x", nested={"a": [1, 2]})
    entries = read_audit_log(log.path)
    assert entries[0].details == {"nested": {"a": [1, 2]}}
