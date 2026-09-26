# MailTrace

Passive forensic analysis of phishing and fraud email for law-enforcement
investigators, producing court-ready reports with explicit confidence labels.

> **Disclaimer.** MailTrace is an analytical aid. Every finding, verdict and
> risk score it produces is labelled with a confidence level and the evidence
> it rests on, and every one of them must be verified by the investigator
> before it is relied on in a charging decision, affidavit, or court filing.
> Attribution of an IP address or domain identifies a network, registrar or
> provider, never a person. Legal-process contacts shipped with the tool are a
> starting point and must be confirmed against each provider's current
> guidelines.

## Screenshots

| Summary | Findings |
| --- | --- |
| ![Summary tab](docs/screenshots/summary.png) | ![Findings tab](docs/screenshots/findings.png) |

| Risk & enrichment | Report and Report Sender |
| --- | --- |
| ![Enrichment tab](docs/screenshots/enrichment.png) | ![Report tab](docs/screenshots/report.png) |

_Screenshots live in `docs/screenshots/`; replace the placeholders with captures
from your own build (synthetic samples only, never real case data)._

## Install

**Release build (Windows 10/11):** download `MailTrace-<version>-windows-x64.zip`
and `SHA256SUMS` from the [releases page](https://github.com/wyattrossell/Mail-Trace/releases),
verify the hash, unzip, and run `MailTrace.exe` (GUI) or `mailtrace-cli.exe` (CLI).

```
certutil -hashfile MailTrace-<version>-windows-x64.zip SHA256
```

**From source (Python 3.12):**

```
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -e .[gui,dev]
.venv\Scripts\python -m pytest
.venv\Scripts\mailtrace-gui
```

## Getting the message out of a mailbox

The tool needs the original message with its transport headers, not a
forward. Forwarding rewrites the headers and destroys the evidence.

- **Gmail (web):** open the message, click the three-dot menu, choose
  **Show original**, then **Download Original** (a `.eml`). Alternatively
  copy the whole page text and use **Paste headers** in MailTrace.
- **Outlook for Windows (classic):** drag the message from the message list
  onto the desktop or a folder to create a `.msg`, or use **File > Save As**
  and choose *Outlook Message Format*. For headers only: open the message,
  **File > Properties**, copy the *Internet headers* box.
- **New Outlook / Outlook on the web:** open the message, click the
  three-dot menu, **View > View message source** (or **Download** where
  offered) and save as `.eml`; or copy the source text and paste it.
- **Apple Mail:** select the message, **File > Save As**, format *Raw Message
  Source* (`.eml`).
- **Thunderbird:** right-click the message, **Save As** (`.eml`).
- **Microsoft 365 / Exchange admins:** export the mailbox item as `.eml`
  through eDiscovery or content search; MailTrace accepts `.eml` or `.msg`.

Drop the file on the MailTrace window. It is hashed and copied into the case
folder before anything is parsed; the original is never modified.

## What it does

- **Evidence handling:** SHA-256/MD5 on intake, read-only copy in the case
  folder, and an append-only, hash-chained audit log recording case number,
  examiner, agency and UTC time for every action.
- **Parsing:** `.eml`, Outlook `.msg`, and pasted headers. Received chain
  reconstructed origin-first with hop timing anomalies and a trust boundary;
  originating-IP candidates with provenance; SPF/DKIM/DMARC re-verified
  independently; spoofing, lookalike-domain, link and attachment indicators;
  everything displayed defanged.
- **Enrichment (optional, cached per case):** reverse DNS, offline GeoLite2,
  ipinfo.io, RDAP/WHOIS registrar and abuse contacts, domain age, Tor exit
  list, hosting/VPN heuristics, AbuseIPDB, VirusTotal (hash lookups only),
  URLhaus, Google Safe Browsing; a legal-process contact table and a
  transparent risk score.
- **Reports:** PDF, HTML and JSON from one model with agency header and logo,
  plain-language executive summary, verdict with confidence, technical
  sections, route diagram, limitations and the audit log appendix.
- **Report Sender:** IC3 and FTC field-by-field drafts, an APWG forward with
  the original attached, and abuse/preservation emails to the registrar and
  hosting provider. Drafts are copied, opened in the mail client or saved as
  unsent `.eml`; nothing is ever sent automatically.
- **Updates:** once a day (and on demand from *Help > Check for updates*)
  the tool asks GitHub whether a newer release exists and shows a banner
  with the notes and the published SHA-256. It never downloads or installs.
  Disable it in *Settings > Network* on air-gapped machines.

## Command line

```
mailtrace analyze suspicious.eml                       # parse + rules, DNS on
mailtrace analyze suspicious.eml --offline --json out.json
mailtrace analyze suspicious.eml --enrich --geoip-city D:\GeoLite2-City.mmdb
mailtrace new-case --base D:\Cases --number 26-001234 --examiner "Det. Example" --agency "Example PD"
mailtrace report suspicious.eml --case D:\Cases\26-001234 --enrich     # PDF+HTML+JSON into <case>/report
mailtrace draft  suspicious.eml --case D:\Cases\26-001234 --kind abuse # unsent .eml drafts
mailtrace audit-verify D:\Cases\26-001234
mailtrace check-updates --force
type headers.txt | mailtrace paste
```

## Limitations of email tracing

- **Only the recipient's own servers can be trusted.** Every `Received`
  header below the trust boundary was written by someone else and can be
  fabricated. MailTrace marks those hops unverified and never treats a
  forged-looking origin as fact.
- **The first external IP is not the sender's location.** It is the address
  that connected to the recipient's infrastructure: a mail provider, a
  relay, a VPN exit, a Tor node, a compromised server, or the sender's own
  connection. Geolocation describes the network, not a person or a desk.
- **Authentication passes prove alignment, not honesty.** A DKIM/DMARC pass
  shows the message came through the named domain's infrastructure. The
  account may be compromised, or the domain may itself be a lookalike.
- **Records change.** DNS and reputation answers reflect the moment of
  analysis, which may differ from the moment of delivery. Providers' logs
  age out, so preservation requests should go out early.
- **Passive only.** MailTrace never fetches links, opens attachments, or
  contacts sender infrastructure. What a link *does* is unknown until an
  authorised, sandboxed examination is performed elsewhere.
- **Heuristics are labelled.** Hosting/VPN flags, lookalike matches and the
  risk score are aids; the report says which observations they rest on.

## Repository layout

```
src/mailtrace_core/   analysis engine: no GUI dependency, fully testable
  case/               case folders, intake, hash-chained audit log, settings + keyring
  parsing/            loaders, Received chain, authentication, URLs, attachments
  enrichment/         GeoIP, RDAP/WHOIS, reputation APIs, legal-process table, risk score
  analysis/           rule engine and rules that emit Findings
  reporting/          report model, verdict, PDF/HTML/JSON renderers, drafts
  updates.py          GitHub release check
src/mailtrace_cli/    `mailtrace` command
src/mailtrace_gui/    PySide6 desktop application
sample_emails/        synthetic test messages + DNS fixtures (no real data)
tests/                pytest suite (all offline; providers are mocked)
scripts/              release build (PyInstaller + zip + SHA256SUMS)
.github/workflows/    CI on every push; release on version tags
```

## Releasing

1. Set `__version__` in `src/mailtrace_core/__init__.py`.
2. Commit, then tag `vX.Y.Z` and push the tag.
3. The release workflow runs the tests, builds `dist/MailTrace/` with
   PyInstaller, zips it, writes `SHA256SUMS`, and publishes a GitHub Release
   with both files attached. The in-app update check reads that release.

See [docs/methodology.md](docs/methodology.md) for what each check means and
how much weight it can bear.
