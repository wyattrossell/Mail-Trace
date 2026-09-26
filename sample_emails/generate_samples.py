"""Regenerate the synthetic sample messages.

Every address, host, IP and name here is fictional. Domains use the reserved
``example.com`` / ``.example`` / ``.test`` names and IPs come from the RFC 5737
documentation ranges. The DKIM key in ``keys/`` exists only for these tests.

Run: ``python sample_emails/generate_samples.py``
"""

from __future__ import annotations

import json
import sys
from email.message import EmailMessage
from pathlib import Path

import idna

HERE = Path(__file__).resolve().parent
KEYS = HERE / "keys"
DNS_FIXTURES = HERE / "dns_fixtures.json"

# Fictional infrastructure -------------------------------------------------
RECIP_DOMAIN = "examplecounty-sheriff.gov.test"
RECIP_MX = f"mx1.{RECIP_DOMAIN}"
RECIP_MX_IP = "192.0.2.10"
RECIP_INTERNAL = f"mailstore.{RECIP_DOMAIN}"

CORP_DOMAIN = "example-corp.test"
CORP_MTA = f"mail.{CORP_DOMAIN}"
CORP_IP = "203.0.113.25"

ATTACKER_IP = "198.51.100.77"
ATTACKER_HELO = "srv-01.bulkhost.test"

BANK_DOMAIN = "examplebank.test"


def _received(
    from_host: str,
    from_ip: str,
    by_host: str,
    proto: str,
    hop_id: str,
    for_addr: str | None,
    when: str,
    helo: str | None = None,
) -> str:
    helo = helo or from_host
    line = f"from {helo} ({from_host} [{from_ip}]) by {by_host} with {proto} id {hop_id}"
    if for_addr:
        line += f" for <{for_addr}>"
    return f"{line}; {when}"


def _base(msg: EmailMessage, *, from_: str, to: str, subject: str, date: str, msgid: str) -> None:
    msg["From"] = from_
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = date
    msg["Message-ID"] = msgid
    msg["MIME-Version"] = "1.0"


def _prepend_received(msg: EmailMessage, lines: list[str]) -> None:
    """Add Received headers so the *first* in ``lines`` is the newest."""
    # EmailMessage appends; we want Received at the top, newest first.
    items = list(msg.items())
    for k in list(msg.keys()):
        del msg[k]
    for line in lines:
        msg["Received"] = line
    for k, v in items:
        msg[k] = v


def _as_bytes(msg: EmailMessage) -> bytes:
    return msg.as_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")


def sample_01_clean() -> tuple[str, bytes]:
    msg = EmailMessage()
    _base(
        msg,
        from_=f'"Records Department" <records@{CORP_DOMAIN}>',
        to=f"det.example@{RECIP_DOMAIN}",
        subject="Subpoena response - case 26-001234",
        date="Mon, 14 Sep 2026 14:02:11 +0000",
        msgid=f"<20260914140211.A1B2C3@{CORP_MTA}>",
    )
    msg.set_content(
        "Detective,\n\nAttached is the records response for your request.\n\n"
        f"Portal: https://records.{CORP_DOMAIN}/case/26-001234\n\nRegards,\nRecords Department\n"
    )
    msg.add_attachment(
        b"%PDF-1.4\n%synthetic test document\n",
        maintype="application",
        subtype="pdf",
        filename="records-response.pdf",
    )
    _prepend_received(
        msg,
        [
            _received(
                RECIP_MX,
                RECIP_MX_IP,
                RECIP_INTERNAL,
                "ESMTP",
                "int001",
                f"det.example@{RECIP_DOMAIN}",
                "Mon, 14 Sep 2026 14:02:15 +0000",
            ),
            _received(
                CORP_MTA,
                CORP_IP,
                RECIP_MX,
                "ESMTPS",
                "abc123",
                f"det.example@{RECIP_DOMAIN}",
                "Mon, 14 Sep 2026 14:02:13 +0000",
            ),
            f"from [10.20.30.40] (workstation-7.{CORP_DOMAIN} [10.20.30.40]) by {CORP_MTA} "
            f"with ESMTPSA id xyz789; Mon, 14 Sep 2026 14:02:12 +0000",
        ],
    )
    msg["Authentication-Results"] = (
        f"{RECIP_MX}; spf=pass (sender IP is {CORP_IP}) smtp.mailfrom={CORP_DOMAIN}; "
        f"dkim=pass header.d={CORP_DOMAIN} header.s=s2026; dmarc=pass action=none "
        f"header.from={CORP_DOMAIN}"
    )
    msg["Return-Path"] = f"<records@{CORP_DOMAIN}>"
    raw = _as_bytes(msg)
    return "01_clean_legitimate.eml", _dkim_sign(raw, CORP_DOMAIN, "s2026")


def _dkim_sign(raw: bytes, domain: str, selector: str) -> bytes:
    import dkim

    key = (KEYS / "test_dkim_private.pem").read_bytes().replace(b"\r\n", b"\n")
    sig = dkim.sign(
        raw,
        selector.encode(),
        domain.encode(),
        key,
        include_headers=[b"from", b"to", b"subject", b"date", b"message-id"],
        canonicalize=(b"relaxed", b"relaxed"),
    )
    return sig + raw


def sample_02_spoofed_bank() -> tuple[str, bytes]:
    msg = EmailMessage()
    _base(
        msg,
        from_=f'"Example Bank Security" <alerts@{BANK_DOMAIN}>',
        to=f"det.example@{RECIP_DOMAIN}",
        subject="URGENT: Unusual sign-in detected - verify your account",
        date="Tue, 15 Sep 2026 03:14:00 -0500",
        msgid="<9f8e7d6c@srv-01.bulkhost.test>",
    )
    msg["Reply-To"] = "examplebank.verification@gmail.com"
    msg["Return-Path"] = "<bounce-4471@mailer-relay.test>"
    msg["X-Mailer"] = "PHPMailer 6.9"
    msg["X-Originating-IP"] = "[198.51.100.77]"
    msg.set_content(
        "Dear Customer,\n\nWe detected an unusual sign-in. Verify within 24 hours or your "
        "account will be suspended:\nhttps://examplebank-secure-verify.test/login\n"
    )
    msg.add_alternative(
        "<html><body><p>Dear Customer,</p><p>We detected an unusual sign-in.</p>"
        f'<p><a href="https://examplebank-secure-verify.test/login">https://www.{BANK_DOMAIN}/secure</a></p>'
        '<img src="https://track.mailer-relay.test/o/4471.gif" width="1" height="1">'
        "</body></html>",
        subtype="html",
    )
    _prepend_received(
        msg,
        [
            _received(
                RECIP_MX,
                RECIP_MX_IP,
                RECIP_INTERNAL,
                "ESMTP",
                "int002",
                f"det.example@{RECIP_DOMAIN}",
                "Tue, 15 Sep 2026 08:14:09 +0000",
            ),
            _received(
                ATTACKER_HELO,
                ATTACKER_IP,
                RECIP_MX,
                "ESMTP",
                "def456",
                f"det.example@{RECIP_DOMAIN}",
                "Tue, 15 Sep 2026 08:14:08 +0000",
                helo=f"mail.{BANK_DOMAIN}",
            ),
            f"from mail.{BANK_DOMAIN} (mail.{BANK_DOMAIN} [203.0.113.99]) by srv-01.bulkhost.test "
            "with ESMTP id fake001; Tue, 15 Sep 2026 08:14:05 +0000",
        ],
    )
    msg["Authentication-Results"] = (
        f"{RECIP_MX}; spf=fail (sender IP is {ATTACKER_IP}) smtp.mailfrom=mailer-relay.test; "
        f"dkim=none; dmarc=fail action=quarantine header.from={BANK_DOMAIN}"
    )
    return "02_spoofed_bank_spf_fail.eml", _as_bytes(msg)


def sample_03_deceptive_links() -> tuple[str, bytes]:
    idn_host = idna.encode("pаypal.example").decode()  # Cyrillic 'а'
    msg = EmailMessage()
    _base(
        msg,
        from_='"PayPal" <service@paypal-notices.example>',
        to=f"det.example@{RECIP_DOMAIN}",
        subject="Your account has been limited",
        date="Wed, 16 Sep 2026 11:00:00 +0000",
        msgid="<lim-77@paypal-notices.example>",
    )
    msg["Return-Path"] = "<service@paypal-notices.example>"
    html = f"""<html><body>
<p>We noticed unusual activity. Please <a href="https://login.rnicrosoft.example/verify">https://www.microsoft.com/account</a> to continue.</p>
<p>Or use <a href="https://{idn_host}/signin">PayPal Sign In</a>.</p>
<p>Direct: <a href="http://203.0.113.200/pp/index.php">click here</a></p>
<p>Short: <a href="https://bit.ly/3xyzABC">update now</a></p>
<p>Hidden: <a href="https://www.paypal.com@paypal-notices.example/login">paypal.com</a></p>
<form action="https://collect.paypal-notices.example/submit" method="post">
<input name="user"><input name="pass" type="password"></form>
<div style="display:none">lorem ipsum filter padding text</div>
</body></html>"""
    msg.set_content("Your account has been limited. Visit https://login.rnicrosoft.example/verify")
    msg.add_alternative(html, subtype="html")
    _prepend_received(
        msg,
        [
            _received(
                RECIP_MX,
                RECIP_MX_IP,
                RECIP_INTERNAL,
                "ESMTP",
                "int003",
                f"det.example@{RECIP_DOMAIN}",
                "Wed, 16 Sep 2026 11:00:05 +0000",
            ),
            _received(
                "vps-9.cheaphost.test",
                "198.51.100.23",
                RECIP_MX,
                "ESMTPS",
                "ghi789",
                f"det.example@{RECIP_DOMAIN}",
                "Wed, 16 Sep 2026 11:00:04 +0000",
            ),
        ],
    )
    return "03_deceptive_links.eml", _as_bytes(msg)


def sample_04_attachments() -> tuple[str, bytes]:
    msg = EmailMessage()
    _base(
        msg,
        from_=f'"Accounts Payable" <ap@{CORP_DOMAIN}>',
        to=f"det.example@{RECIP_DOMAIN}",
        subject="Invoice 88213 attached",
        date="Thu, 17 Sep 2026 09:30:00 +0000",
        msgid="<inv-88213@vps-9.cheaphost.test>",
    )
    msg["Return-Path"] = "<ap@invoices-mailer.test>"
    msg.set_content("Please see the attached invoice.\n")
    mz = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + b"\x00" * 64
    msg.add_attachment(mz, maintype="application", subtype="pdf", filename="Invoice_88213.pdf")
    msg.add_attachment(mz, maintype="application", subtype="octet-stream", filename="Invoice_88213.pdf.exe")
    msg.add_attachment(
        b"PK\x03\x04" + b"\x00" * 30,
        maintype="application",
        subtype="vnd.ms-word.document.macroEnabled.12",
        filename="details.docm",
    )
    msg.add_attachment(
        b"PK\x03\x04" + b"\x00" * 30, maintype="application", subtype="zip", filename="scan.zip"
    )
    msg.add_attachment(b"%PDF-1.7\n%real pdf\n", maintype="application", subtype="pdf", filename="terms.pdf")
    msg.add_attachment(
        b"\x89PNG\r\n\x1a\n" + b"\x00" * 16, maintype="image", subtype="png", filename="photo‮fdp.exe"
    )
    _prepend_received(
        msg,
        [
            _received(
                RECIP_MX,
                RECIP_MX_IP,
                RECIP_INTERNAL,
                "ESMTP",
                "int004",
                f"det.example@{RECIP_DOMAIN}",
                "Thu, 17 Sep 2026 09:30:06 +0000",
            ),
            _received(
                "vps-9.cheaphost.test",
                "198.51.100.23",
                RECIP_MX,
                "ESMTPS",
                "jkl012",
                f"det.example@{RECIP_DOMAIN}",
                "Thu, 17 Sep 2026 09:30:05 +0000",
            ),
        ],
    )
    return "04_attachment_disguise.eml", _as_bytes(msg)


def sample_05_hop_anomalies() -> tuple[str, bytes]:
    msg = EmailMessage()
    _base(
        msg,
        from_='"Payroll" <payroll@example-corp.test>',
        to=f"det.example@{RECIP_DOMAIN}",
        subject="Direct deposit change confirmation",
        date="Sat, 19 Sep 2026 18:00:00 +0000",  # after the earliest Received
        msgid="<pay-1@example-corp.test>",
    )
    msg["Return-Path"] = "<payroll@example-corp.test>"
    msg.set_content("Your direct deposit details were updated.\n")
    _prepend_received(
        msg,
        [
            _received(
                RECIP_MX,
                RECIP_MX_IP,
                RECIP_INTERNAL,
                "ESMTP",
                "int005",
                f"det.example@{RECIP_DOMAIN}",
                "Sat, 19 Sep 2026 12:00:10 +0000",
            ),
            _received(
                "relay.bulkhost.test",
                "198.51.100.90",
                RECIP_MX,
                "ESMTP",
                "mno345",
                f"det.example@{RECIP_DOMAIN}",
                "Sat, 19 Sep 2026 12:00:09 +0000",
            ),
            # Claims to have been handled 3 days earlier, then a hop *after* it in the chain
            # timestamps earlier than this one: fabricated-looking history.
            f"from mail.example-corp.test (mail.example-corp.test [{CORP_IP}]) by relay.bulkhost.test "
            "with ESMTP id fake; Wed, 16 Sep 2026 11:59:00 +0000",
            "from [192.168.1.5] (unknown [192.168.1.5]) by mail.example-corp.test with ESMTPA id x; "
            "Sat, 19 Sep 2026 11:30:00 +0000",
        ],
    )
    return "05_hop_timestamp_anomalies.eml", _as_bytes(msg)


def sample_06_free_mail_impersonation() -> tuple[str, bytes]:
    msg = EmailMessage()
    _base(
        msg,
        from_='"Sheriff Pat Example - Example County Sheriff Office" <sheriff.example.office@gmail.com>',
        to=f"det.example@{RECIP_DOMAIN}",
        subject="Quick task - are you at your desk?",
        date="Mon, 21 Sep 2026 07:45:00 +0000",
        msgid="<CAExample123@mail.gmail.com>",
    )
    msg["Return-Path"] = "<sheriff.example.office@gmail.com>"
    msg.set_content(
        "I need you to purchase some gift cards for a recognition event. "
        "Reply with your cell number.\n\nSent from my iPhone\n"
    )
    _prepend_received(
        msg,
        [
            _received(
                RECIP_MX,
                RECIP_MX_IP,
                RECIP_INTERNAL,
                "ESMTP",
                "int006",
                f"det.example@{RECIP_DOMAIN}",
                "Mon, 21 Sep 2026 07:45:04 +0000",
            ),
            "from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by "
            f"{RECIP_MX} with ESMTPS id pqr678 for <det.example@{RECIP_DOMAIN}>; "
            "Mon, 21 Sep 2026 07:45:03 +0000",
        ],
    )
    msg["Authentication-Results"] = (
        f"{RECIP_MX}; spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; "
        "dmarc=pass header.from=gmail.com"
    )
    return "06_free_mail_impersonation.eml", _as_bytes(msg)


def sample_07_agency_lookalike() -> tuple[str, bytes]:
    look = "examplecounty-sherriff.gov.test"  # typo of the agency domain
    msg = EmailMessage()
    _base(
        msg,
        from_=f'"IT Help Desk" <helpdesk@{look}>',
        to=f"det.example@{RECIP_DOMAIN}",
        subject="Password expiry - action required",
        date="Tue, 22 Sep 2026 13:10:00 +0000",
        msgid=f"<pw-1@{look}>",
    )
    msg["Return-Path"] = f"<helpdesk@{look}>"
    msg.set_content(f"Your password expires today. Reset at https://portal.{look}/reset\n")
    _prepend_received(
        msg,
        [
            _received(
                RECIP_MX,
                RECIP_MX_IP,
                RECIP_INTERNAL,
                "ESMTP",
                "int007",
                f"det.example@{RECIP_DOMAIN}",
                "Tue, 22 Sep 2026 13:10:03 +0000",
            ),
            _received(
                f"mail.{look}",
                "198.51.100.150",
                RECIP_MX,
                "ESMTPS",
                "stu901",
                f"det.example@{RECIP_DOMAIN}",
                "Tue, 22 Sep 2026 13:10:02 +0000",
            ),
        ],
    )
    return "07_agency_lookalike_domain.eml", _as_bytes(msg)


def sample_08_pasted_headers() -> tuple[str, bytes]:
    text = f"""Delivered-To: det.example@{RECIP_DOMAIN}
Received: by 2002:a05:6a10:1234:b0:1:2:3 with SMTP id abc; Wed, 23 Sep 2026 10:00:05 -0700 (PDT)
X-Received: by 2002:a17:90b:1234:b0:2:3:4 with SMTP id def; Wed, 23 Sep 2026 10:00:04 -0700 (PDT)
Return-Path: <noreply@shipping-notice.test>
Received: from vps-3.cheaphost.test (vps-3.cheaphost.test. [198.51.100.31])
        by {RECIP_MX} with ESMTPS id ghi
        for <det.example@{RECIP_DOMAIN}>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Sep 2026 10:00:04 -0700 (PDT)
Authentication-Results: {RECIP_MX};
       dkim=neutral (body hash did not verify) header.i=@shipping-notice.test header.s=k1 header.b=abcd1234;
       spf=softfail (best guess record for domain of noreply@shipping-notice.test does not designate 198.51.100.31 as permitted sender) smtp.mailfrom=noreply@shipping-notice.test;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=shipping-notice.test
Received: from localhost (localhost [127.0.0.1]) by vps-3.cheaphost.test (Postfix) with ESMTP id 4Xyz; Wed, 23 Sep 2026 17:00:01 +0000 (UTC)
From: "USPS Package Center" <noreply@shipping-notice.test>
To: det.example@{RECIP_DOMAIN}
Subject: =?UTF-8?B?WW91ciBwYWNrYWdlIGNvdWxkIG5vdCBiZSBkZWxpdmVyZWQ=?=
Date: Wed, 23 Sep 2026 17:00:00 +0000
Message-ID: <pkg-1@vps-3.cheaphost.test>
X-Sender-IP: 198.51.100.31
"""
    return "08_pasted_headers_only.txt", text.encode("utf-8")


def sample_09_dkim_broken() -> tuple[str, bytes]:
    _, raw = sample_01_clean()
    tampered = raw.replace(b"Attached is the records response", b"Attached is the ALTERED response")
    assert tampered != raw
    return "09_dkim_body_tampered.eml", tampered


def sample_10_inline_image() -> tuple[str, bytes]:
    msg = EmailMessage()
    _base(
        msg,
        from_=f'"Newsletter" <news@{CORP_DOMAIN}>',
        to=f"det.example@{RECIP_DOMAIN}",
        subject="Monthly update",
        date="Thu, 24 Sep 2026 15:00:00 +0000",
        msgid=f"<news-9@{CORP_MTA}>",
    )
    msg["Return-Path"] = f"<news@{CORP_DOMAIN}>"
    msg.set_content("Monthly update. View online: https://news.example-corp.test/2026-09")
    msg.add_alternative(
        '<html><body><img src="cid:logo1"><p>Monthly update</p>'
        '<a href="https://news.example-corp.test/2026-09">View online</a>'
        '<img src="https://metrics.example-corp.test/open?id=9" style="width:1px;height:1px">'
        "</body></html>",
        subtype="html",
    )
    html_part = msg.get_payload()[1]
    html_part.add_related(
        b"\x89PNG\r\n\x1a\n" + b"\x00" * 8,
        maintype="image",
        subtype="png",
        cid="<logo1>",
        filename="logo.png",
        disposition="inline",
    )
    _prepend_received(
        msg,
        [
            _received(
                RECIP_MX,
                RECIP_MX_IP,
                RECIP_INTERNAL,
                "ESMTP",
                "int010",
                f"det.example@{RECIP_DOMAIN}",
                "Thu, 24 Sep 2026 15:00:03 +0000",
            ),
            _received(
                CORP_MTA,
                CORP_IP,
                RECIP_MX,
                "ESMTPS",
                "vwx234",
                f"det.example@{RECIP_DOMAIN}",
                "Thu, 24 Sep 2026 15:00:02 +0000",
            ),
        ],
    )
    return "10_inline_image_and_pixel.eml", _as_bytes(msg)


def dns_fixtures() -> dict[str, list[str]]:
    pub = (KEYS / "test_dkim_public.b64").read_text().strip()
    return {
        f"TXT {CORP_DOMAIN}": [f"v=spf1 ip4:{CORP_IP} mx -all"],
        f"MX {CORP_DOMAIN}": [CORP_MTA],
        f"A {CORP_MTA}": [CORP_IP],
        f"TXT s2026._domainkey.{CORP_DOMAIN}": [f"v=DKIM1; k=rsa; p={pub}"],
        f"TXT _dmarc.{CORP_DOMAIN}": ["v=DMARC1; p=reject; adkim=s; aspf=s"],
        f"TXT {BANK_DOMAIN}": ["v=spf1 ip4:203.0.113.0/24 include:_spf.bankmailer.test -all"],
        "TXT _spf.bankmailer.test": ["v=spf1 ip4:203.0.113.128/25 -all"],
        f"TXT _dmarc.{BANK_DOMAIN}": ["v=DMARC1; p=reject; rua=mailto:dmarc@examplebank.test"],
        "TXT mailer-relay.test": ["v=spf1 ip4:203.0.113.128/25 -all"],
        "TXT gmail.com": ["v=spf1 redirect=_spf.google.com"],
        "TXT _spf.google.com": ["v=spf1 ip4:209.85.128.0/17 ~all"],
        "TXT _dmarc.gmail.com": ["v=DMARC1; p=none; sp=quarantine"],
        "TXT shipping-notice.test": ["v=spf1 a mx ~all"],
        "A shipping-notice.test": ["203.0.113.60"],
        "MX shipping-notice.test": ["mx.shipping-notice.test"],
        "A mx.shipping-notice.test": ["203.0.113.61"],
        "TXT _dmarc.shipping-notice.test": ["v=DMARC1; p=none"],
        "TXT paypal-notices.example": [],
        "TXT examplecounty-sherriff.gov.test": ["v=spf1 ip4:198.51.100.150 -all"],
    }


def main() -> int:
    samples = [
        sample_01_clean(),
        sample_02_spoofed_bank(),
        sample_03_deceptive_links(),
        sample_04_attachments(),
        sample_05_hop_anomalies(),
        sample_06_free_mail_impersonation(),
        sample_07_agency_lookalike(),
        sample_08_pasted_headers(),
        sample_09_dkim_broken(),
        sample_10_inline_image(),
    ]
    for name, data in samples:
        (HERE / name).write_bytes(data)
        print(f"wrote {name} ({len(data)} bytes)")
    DNS_FIXTURES.write_text(json.dumps(dns_fixtures(), indent=2), encoding="utf-8")
    print(f"wrote {DNS_FIXTURES.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
