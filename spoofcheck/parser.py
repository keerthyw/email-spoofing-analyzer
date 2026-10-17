"""Parse a raw .eml file into the fields a forensic analyst cares about."""

from __future__ import annotations

import email
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

from .domains import org_domain

IP_IN_BRACKETS = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]")


@dataclass
class Hop:
    """One server-to-server step, taken from a Received: header."""

    from_host: str | None
    from_ip: str | None
    by_host: str | None
    protocol: str | None
    timestamp: datetime | None
    delay_seconds: float | None = None
    raw: str = ""


@dataclass
class ParsedEmail:
    raw: bytes
    subject: str
    date: datetime | None
    from_name: str
    from_addr: str
    from_domain: str
    return_path: str
    return_path_domain: str
    reply_to: list[str]
    message_id: str
    hops: list[Hop]                      # oldest first (chronological order)
    sending_ip: str | None
    sending_ip_source: str               # where sending_ip came from
    helo: str | None
    dkim_signatures: list[dict] = field(default_factory=list)
    receiver_auth: dict = field(default_factory=dict)   # Authentication-Results from the receiving server


def decode(value: str | None) -> str:
    """Decode RFC 2047 encoded words (=?utf-8?...?=) and unfold whitespace."""
    if not value:
        return ""
    try:
        value = str(make_header(decode_header(value)))
    except Exception:
        pass
    return re.sub(r"\s+", " ", value).strip()


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower().strip(" >.") if "@" in address else ""


INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10",
)]


def is_public_ip(ip: str) -> bool:
    """True for addresses reachable on the internet (i.e. not LAN, loopback or link-local).

    ipaddress.is_global is not used because it also rejects the documentation ranges
    (192.0.2.0/24 etc.) that the sample emails use.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr.version == net.version and addr in net for net in INTERNAL_NETS)


def parse_received(header: str) -> Hop:
    text = decode(header)
    body, _, date_part = text.rpartition(";")
    if not body:  # no ';' present
        body, date_part = text, ""

    # The "from" clause ends where the "by" clause starts.
    from_clause = re.split(r"\bby\s", body, maxsplit=1)[0]
    from_host = re.search(r"\bfrom\s+(\S+)", from_clause)
    ip_match = IP_IN_BRACKETS.search(from_clause)
    by_host = re.search(r"\bby\s+(\S+)", body)
    protocol = re.search(r"\bwith\s+(\S+)", body)

    timestamp = None
    if date_part.strip():
        try:
            timestamp = parsedate_to_datetime(date_part.strip())
        except (TypeError, ValueError):
            timestamp = None

    return Hop(
        from_host=from_host.group(1).strip("()") if from_host else None,
        from_ip=ip_match.group(1) if ip_match else None,
        by_host=by_host.group(1) if by_host else None,
        protocol=protocol.group(1) if protocol else None,
        timestamp=timestamp,
        raw=text,
    )


def parse_auth_results(values: list[str]) -> dict:
    """Read the receiving server's verdicts, e.g. 'spf=pass', 'dkim=fail', 'dmarc=pass'."""
    verdicts: dict[str, str] = {}
    for value in values:
        text = decode(value)
        for method in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{method}=(\w+)", text, re.IGNORECASE)
            if m and method not in verdicts:
                verdicts[method] = m.group(1).lower()
        policy = re.search(r"dmarc=\w+\s*\(p=(\w+)", text, re.IGNORECASE)
        if policy and "dmarc_policy" not in verdicts:
            verdicts["dmarc_policy"] = policy.group(1).lower()
        if verdicts and "server" not in verdicts:
            verdicts["server"] = text.split(";", 1)[0].strip()
    return verdicts


def parse_dkim_tags(header: str) -> dict:
    tags = {}
    for part in decode(header).split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip()] = re.sub(r"\s+", "", v)
    return {"d": tags.get("d", "").lower(), "s": tags.get("s", ""), "a": tags.get("a", "")}


def find_sending_ip(msg, hops_newest_first: list[Hop]) -> tuple[str | None, str, str | None]:
    """Work out which IP actually handed the message to the recipient's server.

    Received-SPF (written by the receiver) is the most trustworthy source. Otherwise we
    take the newest Received header that names a public IP: headers below it could have
    been written by the sender and so can be forged.
    """
    received_spf = decode(msg.get("Received-SPF"))
    m = re.search(r"client-ip=([0-9a-fA-F:.]+)", received_spf)
    helo = re.search(r"helo=([^\s;]+)", received_spf)
    if m:
        return m.group(1), "Received-SPF header", helo.group(1) if helo else None

    for hop in hops_newest_first:
        if hop.from_ip and is_public_ip(hop.from_ip):
            return hop.from_ip, "first public IP in Received chain", hop.from_host
    return None, "not found", None


def parse_email(raw: bytes) -> ParsedEmail:
    msg = email.message_from_bytes(raw, policy=policy.compat32)

    from_name, from_addr = parseaddr(decode(msg.get("From")))
    _, return_path = parseaddr(decode(msg.get("Return-Path")))
    reply_to = [addr for _, addr in getaddresses([decode(v) for v in msg.get_all("Reply-To", [])]) if addr]

    date = None
    try:
        date = parsedate_to_datetime(msg.get("Date")) if msg.get("Date") else None
    except (TypeError, ValueError):
        pass

    newest_first = [parse_received(h) for h in msg.get_all("Received", [])]
    sending_ip, ip_source, helo = find_sending_ip(msg, newest_first)

    hops = list(reversed(newest_first))
    for prev, cur in zip(hops, hops[1:]):
        if prev.timestamp and cur.timestamp:
            cur.delay_seconds = (cur.timestamp - prev.timestamp).total_seconds()

    return ParsedEmail(
        raw=raw,
        subject=decode(msg.get("Subject")),
        date=date,
        from_name=from_name,
        from_addr=from_addr.lower(),
        from_domain=domain_of(from_addr),
        return_path=return_path.lower(),
        return_path_domain=domain_of(return_path),
        reply_to=[r.lower() for r in reply_to],
        message_id=decode(msg.get("Message-ID")),
        hops=hops,
        sending_ip=sending_ip,
        sending_ip_source=ip_source,
        helo=helo,
        dkim_signatures=[parse_dkim_tags(h) for h in msg.get_all("DKIM-Signature", [])],
        receiver_auth=parse_auth_results(msg.get_all("Authentication-Results", [])),
    )


__all__ = ["Hop", "ParsedEmail", "parse_email", "parse_received", "domain_of", "org_domain", "is_public_ip"]
