from __future__ import annotations

import json
from pathlib import Path

from mailtrace_cli.main import main
from mailtrace_core.case.audit import read_audit_log


def test_report_all_formats_into_case(samples_dir: Path, tmp_path: Path, capsys) -> None:
    base = tmp_path / "cases"
    assert (
        main(["new-case", "--base", str(base), "--number", "26-7", "--examiner", "E", "--agency", "A"]) == 0
    )
    case_dir = base / "26-7"
    rc = main(
        [
            "report",
            str(samples_dir / "03_deceptive_links.eml"),
            "--case",
            str(case_dir),
            "--offline",
            "--agency-domain",
            "examplecounty-sheriff.gov.test",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    files = sorted(p.suffix for p in (case_dir / "report").iterdir())
    assert files == [".html", ".json", ".pdf"]
    assert "report id MT-26-7-" in out and "sha256=" in out
    data = json.loads(next((case_dir / "report").glob("*.json")).read_text(encoding="utf-8"))
    assert data["meta"]["case_number"] == "26-7" and data["evidence"][0]["item_id"] == "E001"
    actions = [e.action for e in read_audit_log(case_dir / "audit.jsonl")]
    assert actions.count("report_generated") == 3 and "intake" in actions


def test_report_single_format_to_file(samples_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "r.pdf"
    assert (
        main(
            [
                "report",
                str(samples_dir / "01_clean_legitimate.eml"),
                "--offline",
                "--format",
                "pdf",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    assert out.read_bytes().startswith(b"%PDF")


def test_draft_command(samples_dir: Path, tmp_path: Path, capsys) -> None:
    base = tmp_path / "cases"
    assert (
        main(["new-case", "--base", str(base), "--number", "26-8", "--examiner", "E", "--agency", "A"]) == 0
    )
    case_dir = base / "26-8"
    rc = main(
        ["draft", str(samples_dir / "02_spoofed_bank_spf_fail.eml"), "--case", str(case_dir), "--offline"]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "IC3 complaint" in out and "[Subject information] Email address used by the subject:" in out
    assert "alerts@examplebank.test" in out
    assert "saved unsent draft" in out
    drafts = list((case_dir / "report" / "drafts").glob("apwg-*.eml"))
    assert len(drafts) == 1
    raw = drafts[0].read_bytes()
    assert b"X-Unsent: 1" in raw and b"reportphishing@apwg.org" in raw and b"message/rfc822" in raw
    actions = [e.action for e in read_audit_log(case_dir / "audit.jsonl")]
    assert "draft_saved_eml" in actions and "draft_printed" in actions
    assert (
        main(
            [
                "draft",
                str(samples_dir / "02_spoofed_bank_spf_fail.eml"),
                "--offline",
                "--kind",
                "ic3",
                "--out",
                str(tmp_path / "d"),
            ]
        )
        == 0
    )
    assert "FTC" not in capsys.readouterr().out
