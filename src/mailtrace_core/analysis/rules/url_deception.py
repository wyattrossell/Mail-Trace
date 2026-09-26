"""Link-based deception indicators. Works only on the extracted URL inventory."""

from __future__ import annotations

from urllib.parse import urlsplit

from mailtrace_core.case.settings import Settings
from mailtrace_core.models import Confidence, Evidence, Finding, ParsedEmail, Severity
from mailtrace_core.parsing.lookalike import compare_domain
from mailtrace_core.parsing.urls import registrable_domain


def run(pe: ParsedEmail, settings: Settings) -> list[Finding]:
    out: list[Finding] = []
    seen_lookalike: set[str] = set()
    seen_ip: set[str] = set()
    seen_idn: set[str] = set()
    seen_short: set[str] = set()
    seen_userinfo: set[str] = set()

    for u in pe.urls:
        if u.scheme == "mailto":
            continue
        if u.display_mismatch:
            out.append(
                Finding(
                    rule_id="UD-001",
                    title="Link text shows a different destination than the real link",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.HIGH,
                    category="urls",
                    explanation="The visible text of the hyperlink is itself a URL or domain "
                    "that does not match where the link actually points.",
                    evidence=[
                        Evidence("html:a[href]", u.defanged),
                        Evidence("html:a text", u.display_text or ""),
                    ],
                )
            )
        host = u.host or ""
        if host and registrable_domain(host) not in seen_lookalike:
            match = compare_domain(host, settings.brand_watchlist)
            if match:
                seen_lookalike.add(registrable_domain(host))
                conf = (
                    Confidence.LIKELY
                    if match.kind in {"homoglyph", "idn", "brand-subdomain", "affix", "typo"}
                    else Confidence.UNVERIFIED
                )
                out.append(
                    Finding(
                        rule_id="UD-002",
                        title=f"Link host resembles {match.brand}",
                        confidence=conf,
                        severity=Severity.HIGH if match.kind in {"homoglyph", "idn"} else Severity.MEDIUM,
                        category="urls",
                        explanation=f"Lookalike type: {match.kind}. {match.detail}.",
                        evidence=[Evidence(f"url:{u.source}", u.defanged)],
                    )
                )
        if u.is_ip_host and host not in seen_ip:
            seen_ip.add(host)
            out.append(
                Finding(
                    rule_id="UD-003",
                    title="Link points to a bare IP address",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.MEDIUM,
                    category="urls",
                    explanation="Legitimate services almost never link to raw IP addresses; "
                    "phishing kits on compromised or rented hosts frequently do.",
                    evidence=[Evidence(f"url:{u.source}", u.defanged)],
                )
            )
        if u.is_idn and host not in seen_idn:
            seen_idn.add(host)
            out.append(
                Finding(
                    rule_id="UD-004",
                    title="Internationalised (punycode) domain in link",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.MEDIUM,
                    category="urls",
                    explanation="The host uses non-ASCII characters. Displayed form: "
                    f"{u.unicode_host or '(undecodable)'}. Often used for homoglyph attacks; "
                    "also legitimately used outside the Latin-script world.",
                    evidence=[Evidence(f"url:{u.source}", u.defanged)],
                )
            )
        if u.is_shortener and host not in seen_short:
            seen_short.add(host)
            out.append(
                Finding(
                    rule_id="UD-005",
                    title="Link uses a URL shortener",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.LOW,
                    category="urls",
                    explanation="The true destination is hidden behind a redirect service. "
                    "Not resolved (passive mode); the shortener operator can be subpoenaed.",
                    evidence=[Evidence(f"url:{u.source}", u.defanged)],
                )
            )
        try:
            raw = u.raw if "://" in u.raw else "http://" + u.raw
            netloc = urlsplit(raw).netloc  # normalized form has userinfo stripped
        except ValueError:
            netloc = ""
        if "@" in netloc and u.normalized not in seen_userinfo:
            seen_userinfo.add(u.normalized)
            out.append(
                Finding(
                    rule_id="UD-006",
                    title="Link contains a user@ prefix to disguise the real host",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.HIGH,
                    category="urls",
                    explanation="Everything before '@' in the authority is ignored by browsers; "
                    f"the browser will actually go to {u.host}.",
                    evidence=[Evidence(f"url:{u.source}", u.defanged)],
                )
            )

    if any(w.startswith("HTML body contains a <form>") for w in pe.warnings):
        out.append(
            Finding(
                rule_id="UD-007",
                title="HTML form embedded in the message body",
                confidence=Confidence.CONFIRMED,
                severity=Severity.MEDIUM,
                category="urls",
                explanation="Forms inside email are a credential-harvesting pattern; "
                "legitimate senders link to a website instead.",
                evidence=[
                    Evidence("url:html-action", u.defanged) for u in pe.urls if u.source == "html-action"
                ][:3],
            )
        )
    return out
