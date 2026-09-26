"""Attachment risk indicators from names, magic bytes and hashes only."""

from __future__ import annotations

from mailtrace_core.case.settings import Settings
from mailtrace_core.models import Confidence, Evidence, Finding, ParsedEmail, Severity


def run(pe: ParsedEmail, settings: Settings) -> list[Finding]:
    out: list[Finding] = []
    for a in pe.attachments:
        ev = [
            Evidence(
                f"attachment:{a.part_index}",
                a.filename,
                f"sha256={a.sha256} size={a.size} declared={a.declared_type} "
                f"detected={a.detected_type or 'unknown'}",
            ),
        ]
        if a.type_mismatch:
            out.append(
                Finding(
                    rule_id="AT-001",
                    title=f"Attachment content does not match its extension: {a.filename}",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.HIGH,
                    category="attachments",
                    explanation=f"Magic bytes identify the file as {a.detected_type}, but the name "
                    f"ends in .{a.extension}. Renaming a payload to look harmless is a classic delivery "
                    "technique.",
                    evidence=ev,
                )
            )
        for note in a.notes:
            if "right-to-left override" in note or "double extension" in note:
                out.append(
                    Finding(
                        rule_id="AT-004",
                        title=f"Filename disguise technique: {a.filename}",
                        confidence=Confidence.CONFIRMED,
                        severity=Severity.HIGH,
                        category="attachments",
                        explanation=note,
                        evidence=ev,
                    )
                )
            elif note.endswith("is an executable or script type"):
                out.append(
                    Finding(
                        rule_id="AT-002",
                        title=f"Executable or script attachment: {a.filename}",
                        confidence=Confidence.CONFIRMED,
                        severity=Severity.HIGH,
                        category="attachments",
                        explanation=note + ". Not opened or executed.",
                        evidence=ev,
                    )
                )
            elif note.endswith("can carry macros"):
                out.append(
                    Finding(
                        rule_id="AT-003",
                        title=f"Macro-capable document attached: {a.filename}",
                        confidence=Confidence.CONFIRMED,
                        severity=Severity.MEDIUM,
                        category="attachments",
                        explanation=note + ". Macro presence was not checked (passive mode).",
                        evidence=ev,
                    )
                )
            elif note.startswith("archive:"):
                out.append(
                    Finding(
                        rule_id="AT-005",
                        title=f"Archive attached: {a.filename}",
                        confidence=Confidence.CONFIRMED,
                        severity=Severity.INFO,
                        category="attachments",
                        explanation=note,
                        evidence=ev,
                    )
                )
    return out
