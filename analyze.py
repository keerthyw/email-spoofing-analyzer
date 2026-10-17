#!/usr/bin/env python3
"""Analyse .eml files for spoofing.

Examples:
    python analyze.py suspicious.eml
    python analyze.py samples/*.eml --dns-fixture samples/dns_fixture.json --protect acmebank.example
    python analyze.py mail.eml --html report.html
    python analyze.py mail.eml --offline          # no DNS; use the receiver's Authentication-Results
"""

import argparse
import json
import os
import sys

from spoofcheck.analyzer import analyze
from spoofcheck.auth import DNSResolver, FixtureResolver
from spoofcheck.report import to_html, to_terminal


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Email header forensics and spoofing detection.")
    p.add_argument("files", nargs="+", help=".eml files to analyse")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--offline", action="store_true",
                     help="skip DNS; use the receiving server's Authentication-Results header")
    src.add_argument("--dns-fixture", metavar="JSON", help="answer DNS queries from a JSON file (for demos/tests)")
    p.add_argument("--ip", help="override the detected sending IP")
    p.add_argument("--protect", action="append", default=[], metavar="DOMAIN",
                   help="extra domain to protect from look-alikes (repeatable)")
    p.add_argument("--html", metavar="PATH", help="write an HTML report (a folder if several files are given)")
    p.add_argument("--json", action="store_true", help="print JSON instead of text")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = p.parse_args(argv)

    if args.offline:
        resolver = None
    elif args.dns_fixture:
        resolver = FixtureResolver.from_file(args.dns_fixture)
    else:
        try:
            resolver = DNSResolver()
        except ImportError:
            print("dnspython is not installed (pip install -r requirements.txt); falling back to --offline",
                  file=sys.stderr)
            resolver = None

    color = sys.stdout.isatty() and not args.no_color
    worst = 0
    reports = []
    for path in args.files:
        with open(path, "rb") as fh:
            report = analyze(fh.read(), resolver, os.path.basename(path), args.protect, args.ip)
        reports.append(report)
        worst = max(worst, {"LOW": 0, "MEDIUM": 1, "HIGH": 2}[report.verdict])

        if args.html:
            out = args.html
            if len(args.files) > 1:
                os.makedirs(out, exist_ok=True)
                out = os.path.join(out, os.path.splitext(os.path.basename(path))[0] + ".html")
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(to_html(report))

        if not args.json:
            print(to_terminal(report, color))
            print()

    if args.json:
        data = [r.to_dict() for r in reports]
        print(json.dumps(data[0] if len(data) == 1 else data, indent=2, default=str))

    return worst  # exit code 0/1/2 lets scripts react to the risk level


if __name__ == "__main__":
    sys.exit(main())
