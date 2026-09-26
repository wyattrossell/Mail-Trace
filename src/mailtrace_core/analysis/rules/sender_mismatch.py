"""Spoofing indicators from the sender-identity headers."""

from __future__ import annotations

import re

from mailtrace_core.case.settings import Settings
from mailtrace_core.models import Address, Confidence, Evidence, Finding, ParsedEmail, Severity
from mailtrace_core.parsing.lookalike import compare_domain
from mailtrace_core.parsing.urls import registrable_domain
from mailtrace_core.util.defang import defang_email

_GENERIC_LABELS = {"office", "live", "cash", "mail", "one", "me", "zoom"}
"""Brand labels that are ordinary words; never matched inside display names."""

_EMBEDDED_ADDR_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.IGNORECASE)
_ORG_WORDS = re.compile(
    r"\b(bank|support|security|secure|billing|accounts?|payroll|invoice|helpdesk|help desk|"
    r"it dept|it department|admin|administrator|service|services|team|office|department|"
    r"police|sheriff|court|clerk|irs|treasury|customs|customer|notification|alert|"
    r"ceo|cfo|director|chief|president|manager|hr|human resources|inc|llc|ltd|corp|"
    r"government|gov|agency|county|city of|state of|federal|official)\b",
    re.IGNORECASE,
)


def _fmt(a: Address | None) -> str:
    if a is None:
        return "(none)"
    if a.display_name:
        return f'"{a.display_name}" <{defang_email(a.address)}>'
    return defang_email(a.address) or "<>"


def _kind_to_conf(kind: str) -> tuple[Confidence, Severity]:
    if kind in {"homoglyph", "idn"}:
        return Confidence.LIKELY, Severity.HIGH
    if kind in {"brand-subdomain", "affix", "typo"}:
        return Confidence.LIKELY, Severity.MEDIUM
    return Confidence.UNVERIFIED, Severity.LOW


def run(pe: ParsedEmail, settings: Settings) -> list[Finding]:
    out: list[Finding] = []
    frm = pe.from_
    if frm is None:
        return out
    from_dom = frm.domain
    from_reg = registrable_domain(from_dom) if from_dom else ""

    # SM-001 From vs Return-Path
    rp = pe.return_path
    if rp is not None and rp.address:
        rp_reg = registrable_domain(rp.domain)
        if rp_reg and from_reg and rp_reg != from_reg:
            out.append(
                Finding(
                    rule_id="SM-001",
                    title="Return-Path domain differs from From domain",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.MEDIUM,
                    category="sender",
                    explanation=(
                        "The envelope sender (where bounces go) is not the same organisation "
                        "as the visible From. Legitimate for mailing lists and bulk-mail "
                        "providers; also the signature of a spoofed From. Weigh with SPF/DMARC."
                    ),
                    evidence=[
                        Evidence("header:From", _fmt(frm)),
                        Evidence("header:Return-Path", _fmt(rp)),
                    ],
                )
            )

    # SM-002 Reply-To elsewhere
    for r in pe.reply_to:
        r_reg = registrable_domain(r.domain) if r.domain else ""
        if r_reg and r_reg != from_reg:
            free = r.domain in {d.lower() for d in settings.free_mail_domains}
            out.append(
                Finding(
                    rule_id="SM-002",
                    title="Reply-To directs replies to a different domain",
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.HIGH if free else Severity.MEDIUM,
                    category="sender",
                    explanation=(
                        "Replies will go somewhere other than the apparent sender. "
                        + ("The Reply-To is a free webmail account, a common fraud pattern. " if free else "")
                        + "Confirms intent to divert the conversation, not who the actor is."
                    ),
                    evidence=[
                        Evidence("header:From", _fmt(frm)),
                        Evidence("header:Reply-To", _fmt(r)),
                    ],
                )
            )

    # SM-003 Sender header
    if pe.sender and pe.sender.domain and registrable_domain(pe.sender.domain) != from_reg:
        out.append(
            Finding(
                rule_id="SM-003",
                title="Sender header differs from From",
                confidence=Confidence.CONFIRMED,
                severity=Severity.LOW,
                category="sender",
                explanation="The message was submitted on behalf of the From address by "
                "another party. Normal for delegated mailboxes and list software.",
                evidence=[
                    Evidence("header:From", _fmt(frm)),
                    Evidence("header:Sender", _fmt(pe.sender)),
                ],
            )
        )

    # SM-004 display-name impersonation
    name = frm.display_name or ""
    watch = settings.brand_watchlist
    m = _EMBEDDED_ADDR_RE.search(name)
    if m and m.group(0).lower() != frm.address.lower():
        out.append(
            Finding(
                rule_id="SM-004",
                title="Display name contains a different email address",
                confidence=Confidence.CONFIRMED,
                severity=Severity.HIGH,
                category="sender",
                explanation="The visible name is itself an email address that does not match "
                "the real sending address. Mail clients show the name, hiding the real address.",
                evidence=[Evidence("header:From", _fmt(frm))],
            )
        )
    name_l = name.lower()
    name_compact = re.sub(r"[^a-z0-9]", "", name_l)
    agency_set = {d.lower() for d in settings.agency_domains}
    for brand in watch:
        label = registrable_domain(brand).split(".")[0]
        if len(label) < 3 or label in _GENERIC_LABELS:
            continue
        if from_reg == registrable_domain(brand) or from_dom.endswith("." + brand):
            continue
        agency = brand in agency_set
        if agency:
            # Agency domains are usually multi-word ("examplecounty-sheriff"): compare
            # with separators removed so "Example County Sheriff" still matches.
            hit = len(label) >= 6 and label.replace("-", "") in name_compact
        else:
            hit = bool(re.search(rf"\b{re.escape(label)}\b", name_l))
        if hit:
            out.append(
                Finding(
                    rule_id="SM-004",
                    title=(
                        "Display name impersonates the examiner's agency"
                        if agency
                        else f"Display name references '{label}' but domain is not {brand}"
                    ),
                    confidence=Confidence.LIKELY,
                    severity=Severity.HIGH,
                    category="sender",
                    explanation="The visible name claims an organisation whose domain is on the "
                    "watchlist, while the actual address belongs to an unrelated domain.",
                    evidence=[Evidence("header:From", _fmt(frm), f"watchlist entry: {brand}")],
                )
            )
            break

    # SM-005 free-mail sender claiming to be an organisation
    if from_dom in {d.lower() for d in settings.free_mail_domains}:
        hit = _ORG_WORDS.search(name)
        brand_hit = any(
            re.search(rf"\b{re.escape(registrable_domain(b).split('.')[0])}\b", name_l)
            for b in watch
            if registrable_domain(b).split(".")[0] not in _GENERIC_LABELS
        )
        if hit or brand_hit:
            out.append(
                Finding(
                    rule_id="SM-005",
                    title="Free webmail sender presenting as an organisation",
                    confidence=Confidence.LIKELY,
                    severity=Severity.MEDIUM,
                    category="sender",
                    explanation=(
                        f"The address is on a consumer webmail service ({from_dom}) but the display "
                        f"name suggests an organisation ('{hit.group(0) if hit else 'brand name'}'). "
                        "Organisations rarely send official mail from free accounts."
                    ),
                    evidence=[Evidence("header:From", _fmt(frm))],
                )
            )

    # SM-006 lookalike domains in From / Reply-To / Return-Path
    checked: set[str] = set()
    for source, addr in [("From", frm), ("Return-Path", rp), *[("Reply-To", r) for r in pe.reply_to]]:
        if addr is None or not addr.domain or addr.domain in checked:
            continue
        checked.add(addr.domain)
        match = compare_domain(addr.domain, watch)
        if match:
            conf, sev = _kind_to_conf(match.kind)
            agency = match.brand in {d.lower() for d in settings.agency_domains}
            out.append(
                Finding(
                    rule_id="SM-006",
                    title=(
                        f"{source} domain imitates the examiner's agency domain"
                        if agency
                        else f"{source} domain resembles {match.brand}"
                    ),
                    confidence=conf,
                    severity=Severity.HIGH if agency else sev,
                    category="sender",
                    explanation=f"Lookalike type: {match.kind}. {match.detail}. "
                    "Ownership of the domain must be established through registration "
                    "records before attributing it to anyone.",
                    evidence=[Evidence(f"header:{source}", _fmt(addr))],
                )
            )
    return out
