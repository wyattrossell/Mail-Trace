# Synthetic sample messages

Every message here is fabricated for testing. Names, addresses, domains and
IP addresses are fictional: domains use the reserved `.test` / `.example`
suffixes and `example-*` names, IPs come from the RFC 5737 documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Nothing here is
derived from a real message or real person.

| File | Exercises |
| --- | --- |
| `01_clean_legitimate.eml` | Well-formed chain, SPF/DKIM/DMARC all pass, DKIM signed with the test key |
| `02_spoofed_bank_spf_fail.eml` | Forged From, Return-Path elsewhere, Reply-To on webmail, forged early hop, HELO impersonation, tracking pixel, SPF fail, DMARC fail |
| `03_deceptive_links.eml` | href vs text mismatch, homoglyph (`rnicrosoft`), IDN/punycode host, bare IP, shortener, `user@host` trick, HTML form, hidden text |
| `04_attachment_disguise.eml` | PE masquerading as PDF, double extension, macro doc, archive, RTL-override filename |
| `05_hop_timestamp_anomalies.eml` | Out-of-order and implausibly delayed hops, Date after transit, private origin IP |
| `06_free_mail_impersonation.eml` | Gmail sender with official-sounding display name; all auth passes |
| `07_agency_lookalike_domain.eml` | Typo-squat of the configured agency domain |
| `08_pasted_headers_only.txt` | Webmail "show original" style headers with no body; encoded Subject |
| `09_dkim_body_tampered.eml` | Sample 01 with the body edited so DKIM fails |
| `10_inline_image_and_pixel.eml` | `multipart/related` inline image via `cid:`, CSS-sized tracking pixel |

`dns_fixtures.json` holds the DNS answers the tests use through a static
resolver so SPF, DKIM and DMARC evaluate deterministically offline.

`keys/` holds a throwaway RSA key used only to sign sample 01. It has never
been used for anything else.

Regenerate everything with:

    python sample_emails/generate_samples.py
