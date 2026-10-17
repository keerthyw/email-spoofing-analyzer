"""Run with:  python -m unittest discover tests"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from spoofcheck.analyzer import analyze  # noqa: E402
from spoofcheck.auth import FixtureResolver, check_spf  # noqa: E402
from spoofcheck.domains import lookalike_of, org_domain  # noqa: E402
from spoofcheck.parser import parse_email, parse_received  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def fixture(txt=None, a=None, mx=None):
    return FixtureResolver({"TXT": txt or {}, "A": a or {}, "MX": mx or {}})


class TestSPF(unittest.TestCase):
    def test_ip4_pass_and_fail(self):
        r = fixture({"x.example": ["v=spf1 ip4:192.0.2.0/24 -all"]})
        self.assertEqual(check_spf(r, "192.0.2.10", "x.example").result, "pass")
        self.assertEqual(check_spf(r, "198.51.100.1", "x.example").result, "fail")

    def test_softfail_and_neutral(self):
        r = fixture({"s.example": ["v=spf1 ip4:192.0.2.1 ~all"], "n.example": ["v=spf1 ip4:192.0.2.1"]})
        self.assertEqual(check_spf(r, "203.0.113.9", "s.example").result, "softfail")
        self.assertEqual(check_spf(r, "203.0.113.9", "n.example").result, "neutral")

    def test_include(self):
        r = fixture({"main.example": ["v=spf1 include:esp.example -all"],
                     "esp.example": ["v=spf1 ip4:203.0.113.0/24 -all"]})
        self.assertEqual(check_spf(r, "203.0.113.50", "main.example").result, "pass")
        # Failing inside an include means "no match", so the outer -all decides.
        self.assertEqual(check_spf(r, "192.0.2.1", "main.example").result, "fail")

    def test_a_and_mx(self):
        r = fixture({"d.example": ["v=spf1 a mx -all"]},
                    a={"d.example": ["192.0.2.5"], "mail.d.example": ["192.0.2.6"]},
                    mx={"d.example": ["mail.d.example"]})
        self.assertEqual(check_spf(r, "192.0.2.5", "d.example").result, "pass")
        self.assertEqual(check_spf(r, "192.0.2.6", "d.example").result, "pass")
        self.assertEqual(check_spf(r, "192.0.2.7", "d.example").result, "fail")

    def test_redirect(self):
        r = fixture({"r.example": ["v=spf1 redirect=base.example"], "base.example": ["v=spf1 ip4:192.0.2.0/24 -all"]})
        self.assertEqual(check_spf(r, "192.0.2.1", "r.example").result, "pass")

    def test_no_record_and_two_records(self):
        self.assertEqual(check_spf(fixture(), "192.0.2.1", "none.example").result, "none")
        r = fixture({"dup.example": ["v=spf1 -all", "v=spf1 +all"]})
        self.assertEqual(check_spf(r, "192.0.2.1", "dup.example").result, "permerror")

    def test_lookup_limit(self):
        # A chain of 11 includes exceeds the 10-lookup limit.
        txt = {f"d{i}.example": [f"v=spf1 include:d{i + 1}.example -all"] for i in range(11)}
        txt["d11.example"] = ["v=spf1 ip4:192.0.2.1 -all"]
        self.assertEqual(check_spf(fixture(txt), "192.0.2.1", "d0.example").result, "permerror")


class TestDomains(unittest.TestCase):
    def test_org_domain(self):
        self.assertEqual(org_domain("mail.google.com"), "google.com")
        self.assertEqual(org_domain("alerts.sbi.co.in"), "sbi.co.in")
        self.assertEqual(org_domain("example.com"), "example.com")

    def test_lookalikes(self):
        protected = ["paypal.com", "hdfcbank.com"]
        self.assertEqual(lookalike_of("paypa1.com", protected), "paypal.com")        # 1 for l
        self.assertEqual(lookalike_of("hdfcbankk.com", protected), "hdfcbank.com")   # typo
        self.assertEqual(lookalike_of("paypal-secure.net", protected), "paypal.com")  # brand embedded
        self.assertIsNone(lookalike_of("mail.paypal.com", protected))                # the real thing
        self.assertIsNone(lookalike_of("github.com", protected))


class TestParser(unittest.TestCase):
    def test_received_header(self):
        hop = parse_received("from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) "
                             "by mx.google.com with SMTPS id x5sor; Sat, 17 Oct 2026 04:30:01 -0700 (PDT)")
        self.assertEqual(hop.from_ip, "209.85.220.41")
        self.assertEqual(hop.by_host, "mx.google.com")
        self.assertEqual(hop.protocol, "SMTPS")
        self.assertIsNotNone(hop.timestamp)

    def test_gmail_style_headers(self):
        raw = (b"Received: by 2002:a05:6a10:1234 with SMTP id abc; Sat, 17 Oct 2026 04:30:02 -0700 (PDT)\r\n"
               b"Received: from mail.shop.example (mail.shop.example [192.0.2.44]) by mx.google.com with ESMTPS id q1; "
               b"Sat, 17 Oct 2026 04:30:01 -0700 (PDT)\r\n"
               b"Received-SPF: pass (google.com: domain of news@shop.example designates 192.0.2.44 as permitted sender) "
               b"client-ip=192.0.2.44;\r\n"
               b"Authentication-Results: mx.google.com; dkim=pass header.i=@shop.example; spf=pass; dmarc=pass\r\n"
               b"From: =?utf-8?q?Shop_=E2=9C=93?= <news@shop.example>\r\n"
               b"Subject: hi\r\n\r\nbody\r\n")
        e = parse_email(raw)
        self.assertEqual(e.sending_ip, "192.0.2.44")
        self.assertEqual(e.sending_ip_source, "Received-SPF header")
        self.assertEqual(e.receiver_auth["dmarc"], "pass")
        self.assertEqual(e.from_name, "Shop ✓")
        self.assertEqual(len(e.hops), 2)


class TestSamples(unittest.TestCase):
    """End-to-end: the three demo emails get the verdicts they were designed for."""

    def run_sample(self, name):
        with open(os.path.join(SAMPLES, name), "rb") as fh:
            return analyze(fh.read(), FixtureResolver.from_file(os.path.join(SAMPLES, "dns_fixture.json")),
                           name, ["acmebank.example"])

    def test_legit(self):
        r = self.run_sample("legit_statement.eml")
        self.assertEqual((r.spf.result, r.dkim[0].result, r.dmarc.result), ("pass", "pass", "pass"))
        self.assertEqual(r.verdict, "LOW")

    def test_ceo_fraud(self):
        r = self.run_sample("ceo_fraud.eml")
        self.assertEqual(r.dmarc.result, "fail")
        self.assertEqual(r.verdict, "HIGH")

    def test_lookalike_passes_auth_but_is_flagged(self):
        r = self.run_sample("lookalike_domain.eml")
        self.assertEqual(r.dmarc.result, "pass")
        self.assertIn("Look-alike sender domain", [f.title for f in r.findings])
        self.assertEqual(r.verdict, "HIGH")

    def test_tampered_body_breaks_dkim(self):
        with open(os.path.join(SAMPLES, "legit_statement.eml"), "rb") as fh:
            raw = fh.read().replace(b"October statement", b"November statement")
        r = analyze(raw, FixtureResolver.from_file(os.path.join(SAMPLES, "dns_fixture.json")), "t", [])
        self.assertEqual(r.dkim[0].result, "fail")


if __name__ == "__main__":
    unittest.main()
