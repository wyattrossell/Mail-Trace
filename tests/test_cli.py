from __future__ import annotations

import json
from pathlib import Path

from mailtrace_cli.main import main


def test_analyze_offline_prints_summary(samples_dir: Path, capsys) -> None:
    rc = main(["analyze", str(samples_dir / "02_spoofed_bank_spf_fail.eml"), "--offline"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Received chain (3 hops" in out
    assert "198[.]51[.]100[.]77" in out
    assert "skipped: spf, dkim, dmarc" in out
    assert "SM-002" in out


def test_analyze_json(samples_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    rc = main(["analyze", str(samples_dir / "03_deceptive_links.eml"), "--offline", "--json", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["email"]["source_format"] == "eml"
    assert any(f["rule_id"] == "UD-001" for f in data["findings"])
    assert "raw_bytes" not in data["email"]


def test_case_workflow(samples_dir: Path, tmp_path: Path, capsys) -> None:
    base = tmp_path / "cases"
    assert (
        main(["new-case", "--base", str(base), "--number", "26-9", "--examiner", "E", "--agency", "A"]) == 0
    )
    case_dir = base / "26-9"
    assert main(["intake", str(case_dir), str(samples_dir / "01_clean_legitimate.eml")]) == 0
    assert "E001" in capsys.readouterr().out
    assert (
        main(
            ["analyze", str(samples_dir / "04_attachment_disguise.eml"), "--case", str(case_dir), "--offline"]
        )
        == 0
    )
    assert main(["audit-verify", str(case_dir)]) == 0
    assert "chain intact" in capsys.readouterr().out
    # tamper
    log = case_dir / "audit.jsonl"
    log.write_text(log.read_text(encoding="utf-8").replace('"intake"', '"intkae"', 1), encoding="utf-8")
    assert main(["audit-verify", str(case_dir)]) == 2


def test_paste_from_stdin(samples_dir: Path, monkeypatch, capsys) -> None:
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO((samples_dir / "08_pasted_headers_only.txt").read_text()))
    assert main(["paste", "--offline"]) == 0
    assert "USPS Package Center" in capsys.readouterr().out


def test_missing_file_returns_1(tmp_path: Path) -> None:
    assert main(["analyze", str(tmp_path / "nope.eml"), "--offline"]) == 1
