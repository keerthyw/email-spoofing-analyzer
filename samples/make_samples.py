#!/usr/bin/env python3
"""Generate the demo emails and the DNS fixture they are checked against.

All domains use the reserved .example TLD and all IPs come from documentation ranges
(RFC 5737), so nothing here points at a real organisation. DKIM keys are generated fresh
each run and only their public halves are kept (in dns_fixture.json).

Run from the repo root:  python samples/make_samples.py   (needs dkimpy and openssl)
"""

import base64
import json
import os
import subprocess

import dkim

HERE = os.path.dirname(os.path.abspath(__file__))


def new_key() -> tuple[bytes, str]:
    """Return (private key PEM, public key for a DKIM TXT record)."""
    pem = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True).stdout
    der = subprocess.run(["openssl", "rsa", "-pubout", "-outform", "DER"], input=pem,
                         capture_output=True, check=True).stdout
    return pem, base64.b64encode(der).decode()


def build(headers: list[tuple[str, str]], body: str) -> bytes:
    text = "".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n" + body.replace("\n", "\r\n")
    return text.encode()


def sign(msg: bytes, domain: str, selector: str, key: bytes) -> bytes:
    sig = dkim.sign(msg, selector.encode(), domain.encode(), key,
                    include_headers=[b"from", b"to", b"subject", b"date", b"message-id", b"reply-to"])
    return sig + msg


def prepend(msg: bytes, headers: list[tuple[str, str]]) -> bytes:
    """Add trace headers on top, the way each server along the route does."""
    return "".join(f"{k}: {v}\r\n" for k, v in headers).encode() + msg


def main():
    bank_key, bank_pub = new_key()
    fake_key, fake_pub = new_key()

    fixture = {
        "TXT": {
            "acmebank.example": ["v=spf1 ip4:203.0.113.0/28 include:_spf.mailer.example -all"],
            "_spf.mailer.example": ["v=spf1 ip4:192.0.2.64/27 ~all"],
            "_dmarc.acmebank.example": ["v=DMARC1; p=reject; rua=mailto:dmarc@acmebank.example"],
            "mail2024._domainkey.acmebank.example": [f"v=DKIM1; k=rsa; p={bank_pub}"],
            "bulkmail.example": ["v=spf1 ip4:198.51.100.0/24 ~all"],
            "acrnebank.example": ["v=spf1 a mx -all"],
            "_dmarc.acrnebank.example": ["v=DMARC1; p=none"],
            "s1._domainkey.acrnebank.example": [f"v=DKIM1; k=rsa; p={fake_pub}"],
        },
        "A": {"acrnebank.example": ["198.51.100.23"], "mx.acrnebank.example": ["198.51.100.24"]},
        "MX": {"acrnebank.example": ["mx.acrnebank.example"]},
    }

    # 1. Legitimate: sent from the bank's own server, DKIM-signed, SPF and DMARC pass.
    legit = build([
        ("From", "AcmeBank Alerts <alerts@acmebank.example>"),
        ("To", "keerthy@student.example"),
        ("Subject", "Your monthly statement is ready"),
        ("Date", "Sat, 17 Oct 2026 09:59:58 +0530"),
        ("Message-ID", "<20261017042958.7731@mail.acmebank.example>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ], "Hello,\n\nYour October statement is available in net banking.\n\nAcmeBank\n")
    legit = sign(legit, "acmebank.example", "mail2024", bank_key)
    legit = prepend(legit, [
        ("Return-Path", "<bounces@acmebank.example>"),
        ("Received", "from mail.acmebank.example (mail.acmebank.example [203.0.113.5])\r\n"
                     "\tby mx.student.example with ESMTPS id 4f1a2b; Sat, 17 Oct 2026 04:30:01 +0000"),
        ("Received", "from app07.internal.acmebank.example ([10.20.0.7])\r\n"
                     "\tby mail.acmebank.example with ESMTP id 99c1; Sat, 17 Oct 2026 04:29:59 +0000"),
    ])
    # Each server prepends its Received header, so the list above is written newest first.

    # 2. CEO fraud: claims to be the bank's CEO, sent through a bulk mailer, replies go to free mail.
    ceo = build([
        ("From", "Priya Sharma (CEO) <ceo@acmebank.example>"),
        ("Reply-To", "priya.ceo.office@freemail.example"),
        ("To", "finance-team@acmebank.example"),
        ("Subject", "Urgent: confidential wire transfer today"),
        ("Date", "Sat, 17 Oct 2026 11:02:10 +0530"),
        ("Message-ID", "<a8f3e1c2@bulkmail.example>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ], "Hi,\n\nI need you to process a wire transfer of Rs 18,40,000 before 3 pm today.\n"
       "I'm in meetings, so reply here only. Keep this confidential.\n\nPriya\n")
    ceo = prepend(ceo, [
        ("Return-Path", "<bounce-8812@bulkmail.example>"),
        ("Authentication-Results", "mx.acmebank.example; spf=pass smtp.mailfrom=bulkmail.example;\r\n"
                                   "\tdkim=none; dmarc=fail (p=reject) header.from=acmebank.example"),
        ("Received", "from smtp3.bulkmail.example (smtp3.bulkmail.example [198.51.100.66])\r\n"
                     "\tby mx.acmebank.example with ESMTP id 7e21; Sat, 17 Oct 2026 05:32:14 +0000"),
    ])

    # 3. Look-alike domain: 'acrnebank' (r+n looks like m). Its SPF and DKIM are genuinely valid
    #    because the attacker owns that domain; only the identity checks catch it.
    lookalike = build([
        ("From", '"AcmeBank Security <security@acmebank.example>" <security@acrnebank.example>'),
        ("To", "keerthy@student.example"),
        ("Subject", "Unusual sign-in detected: verify your account"),
        ("Date", "Sat, 17 Oct 2026 13:15:40 +0530"),
        ("Message-ID", "<k2l9x8@acrnebank.example>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ], "We noticed a sign-in from a new device. Verify your account within 24 hours:\n"
       "https://acrnebank.example/verify\n")
    lookalike = sign(lookalike, "acrnebank.example", "s1", fake_key)
    lookalike = prepend(lookalike, [
        ("Return-Path", "<security@acrnebank.example>"),
        ("Received", "from mx.acrnebank.example (mx.acrnebank.example [198.51.100.24])\r\n"
                     "\tby mx.student.example with ESMTPS id 1b77; Sat, 17 Oct 2026 07:45:43 +0000"),
    ])

    for name, data in [("legit_statement.eml", legit), ("ceo_fraud.eml", ceo), ("lookalike_domain.eml", lookalike)]:
        with open(os.path.join(HERE, name), "wb") as fh:
            fh.write(data)
    with open(os.path.join(HERE, "dns_fixture.json"), "w") as fh:
        json.dump(fixture, fh, indent=2)
    print("wrote 3 sample emails and dns_fixture.json")


if __name__ == "__main__":
    main()
