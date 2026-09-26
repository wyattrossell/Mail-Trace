# MailTrace methodology

This document explains what each check means and how much weight it can
bear, so an examiner can explain a finding under cross-examination.

## Confidence labels

| Label | Meaning |
| --- | --- |
| confirmed | Directly observable in the evidence. Two headers differ; a hash does not match; a DNS record says what it says. |
| likely | Strong indicator with a known innocent explanation. Stated as an inference, never as fact. |
| unverified | Suggestive only. Must be corroborated (subpoena, provider records, further analysis) before it is relied on. |

Confidence is about how sure we are of the *observation*. Severity is about
how much it matters to the investigation. A confirmed observation can be
low-severity, and a high-severity indicator can be unverified.

## Evidence handling

Intake hashes the original file (SHA-256 and MD5), copies it into the case's
`original/` folder, hashes the copy, refuses the intake if the two differ, and
marks the copy read-only. The original path is never opened for writing. Each
step is logged to `audit.jsonl` with the case number, examiner, agency and a
UTC timestamp. Every entry includes the hash of the previous entry, so any
edit, deletion or reordering is detectable with `mailtrace audit-verify`.

## Received chain and originating IP

Each mail server prepends a `Received:` header, so the header order is newest
first. MailTrace reverses them so hop 0 is the earliest. Only the headers
written by the recipient's own infrastructure can be relied upon. MailTrace
marks a hop *trusted* when its `by` host belongs to the recipient's domain (or
a configured recipient domain), is the final delivery hop, or is a well-known
provider/gateway continuing an already-trusted run. The oldest trusted hop is
the *trust boundary*; the IP in its `from` clause is the address that
actually connected to the recipient's infrastructure. It is reported as the
first external hop with confidence *likely*: the connection is real, but the
host could be a relay, a compromised server, or a VPN exit.

Everything below the boundary was written by third parties and can be
fabricated freely. Headers such as `X-Originating-IP` are reported as
*unverified* for the same reason.

Timestamps are compared hop to hop. A hop earlier than its predecessor by more
than five minutes is out of order; small negative deltas are recorded as
clock skew. Gaps longer than 24 hours are flagged as implausible. The `Date`
header is compared with the earliest transit time.

## SPF, DKIM, DMARC

`Authentication-Results` records what the receiving server concluded at
delivery time. MailTrace treats it as a reported claim and re-checks:

- **DKIM** is recomputed with dkimpy over the message bytes exactly as
  ingested, fetching the public key from DNS. A pass proves the signed
  headers and body were not altered after signing by that domain. It does not
  prove the `From` is honest unless the signing domain aligns with it.
  Outlook `.msg` files do not preserve the wire format, so DKIM cannot be
  re-verified for them and the report says so.
- **SPF** is evaluated against the first-external-hop IP and the envelope
  sender's domain (`Return-Path`, falling back to `From`). Macros are not
  expanded and `ptr` is treated as non-matching; both are noted in the result.
- **DMARC** combines the two with the domain owner's published alignment and
  policy. A DMARC fail with `p=reject` that was still delivered means the
  receiver did not enforce the policy.

DNS records can change between delivery and analysis. When the independent
result disagrees with the reported one, both are shown and the disagreement
is a finding of its own.

## Spoofing indicators

Mismatches between `From`, `Return-Path`, `Reply-To` and `Sender` are
confirmed observations; their meaning depends on context (bulk mailers and
list software cause them legitimately). Display-name impersonation and
lookalike domains are compared against a watchlist of commonly impersonated
brands plus the examiner's agency domains. Lookalike detection folds visually
confusable characters (`rn` for `m`, Cyrillic `а` for Latin `a`, `1` for `l`),
decodes punycode, and applies small edit-distance thresholds. A lookalike
domain is never attributed to anyone without registration records.

## URLs and attachments

Links are gathered from plain text, HTML `href`/`src`/`action` attributes and
visible link text, then shown defanged (`hxxps[:]//evil[.]example`). MailTrace
never fetches them. Attachments are decoded in memory only to hash them and
read their leading bytes for type identification; they are never written to
disk as files, opened, or rendered. Archives are not expanded.

## Enrichment

Enrichment adds context from outside the message. Each answer is recorded
with the provider consulted, the time it was fetched, and whether it came
from the case cache, so the report can say exactly what was asked of whom.

- **Geolocation and ASN** come from the operator's own GeoLite2 database
  (offline) and optionally ipinfo.io. Geolocation of an IP is approximate and
  describes the network, not a person.
- **RDAP / WHOIS** gives the registry's record for a network or domain:
  owner or registrar, abuse contact, and registration dates. Privacy services
  usually hide the registrant; the registrar then holds the identity and is
  the legal-process target. A domain registered within the last 30 days is
  flagged because phishing infrastructure is typically short-lived.
- **Hosting / VPN / Tor flags** combine the public Tor exit list, provider
  privacy fields where available, and keyword heuristics on organisation and
  hostname. The reasons are stored with the flag; a heuristic match is not a
  proof.
- **Reputation services** report what other parties have observed about the
  same indicator. Absence of a listing means nothing. Attachments are looked
  up by SHA-256 only and are never uploaded.

## Legal-process mapping and the risk score

The legal-process table maps observed infrastructure to the entity that can
answer legal process and lists the records it can typically provide. It is
maintained by the examiner and every entry is marked *verify before use*: the
tool cannot know whether a portal or address is still current. A 2703(f)
preservation request should be sent as soon as a target is identified.

The risk score is a transparent sum of named factors, capped so that neither
message-internal findings nor external signals can dominate. It exists to
prioritise work, not to prove anything, and the report always shows the
factor list beside the number.

## Reports and verdict wording

The report's headline is chosen by visible rules in `reporting/verdict.py`:
a *confirmed* phishing/fraud assessment needs at least one confirmed
high-severity deception finding (or two confirmed high findings, or a
malicious reputation verdict); *likely* needs a confirmed or likely high
finding or two confirmed medium ones; anything less is *unverified*. The
sender-identity line is decided separately from DMARC, lookalike and
impersonation results. The verdict describes the message and the identity
claims, never a person. The basis list beneath it names the findings that
produced it so the reader can check each one in the technical sections.

Outgoing drafts are prepared, never sent. Web-form drafts (IC3, FTC) carry
raw indicators because the forms need them; email drafts carry defanged
indicators and attach the original message rather than quoting it inline.

## Passive by design

The network choke point in `mailtrace_core.util.netguard` allows only DNS,
RDAP and reputation-API categories. Any active category raises unless the
operator has enabled it in Settings after a warning, and the audit log
records the change.
