"""Ties parsing, authentication checks and rules together into one report."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .auth import DKIMResult, DMARCResult, SPFResult, check_dkim, check_dmarc, check_spf
from .domains import DEFAULT_PROTECTED
from .parser import ParsedEmail, parse_email
from .rules import Finding, check_auth, check_identity, check_route, score


@dataclass
class Report:
    source: str
    email: ParsedEmail
    spf: SPFResult
    dkim: list[DKIMResult]
    dmarc: DMARCResult
    findings: list[Finding]
    score: int
    verdict: str          # LOW / MEDIUM / HIGH
    offline: bool

    def to_dict(self) -> dict:
        e = self.email
        return {
            "source": self.source,
            "verdict": self.verdict,
            "score": self.score,
            "message": {
                "subject": e.subject, "date": e.date.isoformat() if e.date else None,
                "from_name": e.from_name, "from": e.from_addr, "return_path": e.return_path,
                "reply_to": e.reply_to, "message_id": e.message_id,
                "sending_ip": e.sending_ip, "sending_ip_source": e.sending_ip_source,
            },
            "route": [{"from": h.from_host, "ip": h.from_ip, "by": h.by_host, "with": h.protocol,
                       "time": h.timestamp.isoformat() if h.timestamp else None,
                       "delay_seconds": h.delay_seconds} for h in e.hops],
            "authentication": {"spf": asdict(self.spf), "dkim": [asdict(d) for d in self.dkim],
                               "dmarc": asdict(self.dmarc), "receiver": e.receiver_auth},
            "findings": [asdict(f) for f in self.findings],
        }


def _from_receiver(e: ParsedEmail) -> tuple[SPFResult, list[DKIMResult], DMARCResult]:
    """Offline mode: trust the receiving server's Authentication-Results instead of DNS."""
    r = e.receiver_auth
    spf = SPFResult(r.get("spf", "none"), e.return_path_domain, e.sending_ip,
                    explanation="taken from the receiver's Authentication-Results (offline mode)")
    dkim = [DKIMResult(r.get("dkim", "none"), s["d"], s["s"], "receiver's verdict (offline mode)")
            for s in e.dkim_signatures] or [DKIMResult(r.get("dkim", "none"), "", "", "offline mode")]
    policy = r.get("dmarc_policy")
    dmarc = DMARCResult(r.get("dmarc", "none"), e.from_domain, policy=policy,
                        explanation="receiver's Authentication-Results (offline mode)"
                                    + (f", domain policy p={policy}" if policy else ""))
    return spf, dkim, dmarc


def analyze(raw: bytes, resolver=None, source: str = "", protected: list[str] | None = None,
            ip_override: str | None = None) -> Report:
    e = parse_email(raw)
    if ip_override:
        e.sending_ip, e.sending_ip_source = ip_override, "set on command line"
    protected = DEFAULT_PROTECTED + (protected or [])

    offline = resolver is None
    if offline:
        spf, dkim, dmarc = _from_receiver(e)
        auth_findings = []  # we can't verify anything ourselves
        if not e.receiver_auth:
            auth_findings.append(Finding("info", "No authentication data",
                                         "Offline mode and no Authentication-Results header: SPF/DKIM/DMARC unknown."))
        else:
            auth_findings = check_auth(spf, dkim, dmarc, {})
    else:
        spf = check_spf(resolver, e.sending_ip, e.return_path_domain or (e.helo or ""))
        dkim = check_dkim(resolver, raw, e.dkim_signatures)
        dmarc = check_dmarc(resolver, e.from_domain, spf, dkim)
        auth_findings = check_auth(spf, dkim, dmarc, e.receiver_auth)

    findings = auth_findings + check_identity(e, protected) + check_route(e)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: order[f.severity])
    total, verdict = score(findings)
    return Report(source, e, spf, dkim, dmarc, findings, total, verdict, offline)
