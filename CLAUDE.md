# MailTrace — Project Brief

MailTrace is a Windows desktop tool for law enforcement investigators to analyze
phishing/fraud emails and produce a court-ready report.

## Stack

- Python 3.12
- PySide6 GUI — modern dark/light theme, clean professional look. Think forensic
  software, not a hobby app.
- Packaged with PyInstaller.
- Core analysis logic lives in a separate package with **no GUI dependency**, plus a
  CLI entry point, so it can be tested and scripted.

## Principles

### Evidence integrity
- On intake, compute SHA-256 and MD5 of the original file, copy it to a case working
  folder, and never modify the original.
- Log case number, examiner name, agency, and UTC timestamps for every action in an
  append-only audit log.

### Passive analysis by default
- Never fetch URLs, open attachments, or connect to sender infrastructure.
- DNS, RDAP/WHOIS, and third-party reputation APIs only.
- Any active feature must be off by default, behind a clearly warned setting.

### Honesty in findings
- Every conclusion is labeled with a confidence level (confirmed / likely /
  unverified) and the evidence it rests on.
- Never overstate attribution.

### Secrets
- API keys are stored in Windows Credential Manager via the `keyring` library, never
  in plain-text config.

### Graceful degradation
- Every external lookup is optional. The tool still produces a report offline, noting
  which checks were skipped.

### Code quality
- Type hints and docstrings throughout.
- pytest tests for all parsing logic.
- A sample-emails folder of synthetic test messages (no real PII).
