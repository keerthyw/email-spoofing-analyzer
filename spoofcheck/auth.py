"""SPF, DKIM and DMARC checks, done independently of the receiving mail server.

SPF follows RFC 7208 for the mechanisms real records use (ip4, ip6, a, mx, include,
redirect, all) and enforces the 10-DNS-lookup limit. Macros, `ptr` and `exists` are
reported as unsupported rather than guessed at.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field

from .domains import org_domain

SPF_QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
MAX_SPF_LOOKUPS = 10


class TempDNSError(Exception):
    """DNS server failure or timeout: the answer is unknown, not negative."""


# --------------------------------------------------------------------------- resolvers

class DNSResolver:
    """Live DNS lookups through dnspython."""

    def __init__(self, timeout: float = 5.0):
        import dns.resolver  # imported here so offline/fixture modes don't need it

        self._dns = dns
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout

    def _query(self, name: str, rtype: str):
        try:
            return list(self._resolver.resolve(name, rtype))
        except (self._dns.resolver.NXDOMAIN, self._dns.resolver.NoAnswer):
            return []
        except Exception as exc:  # timeouts, SERVFAIL, no nameservers
            raise TempDNSError(f"{rtype} {name}: {exc.__class__.__name__}") from exc

    def txt(self, name: str) -> list[str]:
        return [b"".join(r.strings).decode("utf-8", "replace") for r in self._query(name, "TXT")]

    def a(self, name: str) -> list[str]:
        return [r.to_text() for r in self._query(name, "A")]

    def aaaa(self, name: str) -> list[str]:
        return [r.to_text() for r in self._query(name, "AAAA")]

    def mx(self, name: str) -> list[str]:
        return [r.exchange.to_text().rstrip(".") for r in self._query(name, "MX")]


class FixtureResolver:
    """Answers DNS queries from a JSON file, so samples and tests run without internet.

    Format: {"TXT": {"name": ["record", ...]}, "A": {...}, "AAAA": {...}, "MX": {...}}
    """

    def __init__(self, data: dict):
        self.data = {rtype: {k.lower().rstrip("."): v for k, v in records.items()}
                     for rtype, records in data.items()}

    @classmethod
    def from_file(cls, path: str) -> "FixtureResolver":
        with open(path, encoding="utf-8") as fh:
            return cls(json.load(fh))

    def _get(self, rtype: str, name: str) -> list:
        return list(self.data.get(rtype, {}).get(name.lower().rstrip("."), []))

    def txt(self, name): return self._get("TXT", name)
    def a(self, name): return self._get("A", name)
    def aaaa(self, name): return self._get("AAAA", name)
    def mx(self, name): return self._get("MX", name)


# --------------------------------------------------------------------------- SPF

@dataclass
class SPFResult:
    result: str                       # pass / fail / softfail / neutral / none / permerror / temperror
    domain: str
    ip: str | None
    record: str | None = None
    explanation: str = ""
    lookups: int = 0
    notes: list[str] = field(default_factory=list)


class _SPFState:
    def __init__(self):
        self.lookups = 0
        self.notes: list[str] = []

    def count(self):
        self.lookups += 1
        if self.lookups > MAX_SPF_LOOKUPS:
            raise _PermError(f"more than {MAX_SPF_LOOKUPS} DNS lookups")


class _PermError(Exception):
    pass


def _spf_record(resolver, domain: str) -> str | None:
    records = [t for t in resolver.txt(domain) if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]
    if len(records) > 1:
        raise _PermError(f"{domain} publishes {len(records)} SPF records (only one is allowed)")
    return records[0] if records else None


def _split_cidr(arg: str | None, default_domain: str) -> tuple[str, int | None, int | None]:
    """Parse 'domain/24//64' into (domain, ipv4 prefix, ipv6 prefix)."""
    arg = arg or ""
    v6 = None
    if "//" in arg:
        arg, v6s = arg.split("//", 1)
        v6 = int(v6s)
    v4 = None
    if "/" in arg:
        arg, v4s = arg.split("/", 1)
        v4 = int(v4s)
    return (arg or default_domain), v4, v6


def _ip_in(ip, addresses: list[str], v4: int | None, v6: int | None) -> bool:
    for addr in addresses:
        prefix = v4 if ":" not in addr else v6
        net = ipaddress.ip_network(f"{addr}/{prefix}" if prefix is not None else addr, strict=False)
        if ip.version == net.version and ip in net:
            return True
    return False


def _host_addresses(resolver, host: str, ip) -> list[str]:
    return resolver.a(host) if ip.version == 4 else resolver.aaaa(host)


def _evaluate(resolver, domain: str, ip, state: _SPFState, depth: int = 0) -> tuple[str, str | None, str]:
    """Returns (result, record, explanation)."""
    if depth > 10:
        raise _PermError("include/redirect nesting too deep")
    record = _spf_record(resolver, domain)
    if record is None:
        return "none", None, f"{domain} has no SPF record"

    redirect = None
    for term in record.split()[1:]:
        if "=" in term and term.split("=", 1)[0].lower() in ("redirect", "exp"):
            key, value = term.split("=", 1)
            if key.lower() == "redirect":
                redirect = value
            continue

        qualifier = "+"
        if term[0] in SPF_QUALIFIERS:
            qualifier, term = term[0], term[1:]
        mech, _, arg = term.partition(":")
        mech = mech.lower()
        if "/" in mech:  # e.g. "a/24" or "mx/24" without a domain
            mech, cidr = mech.split("/", 1)
            arg = "/" + cidr
        result = SPF_QUALIFIERS[qualifier]

        if arg and "%" in arg:
            state.notes.append(f"skipped '{term}': SPF macros are not supported")
            continue

        if mech == "all":
            return result, record, f"matched '{qualifier}all' in {domain}"

        if mech in ("ip4", "ip6"):
            net = ipaddress.ip_network(arg, strict=False)
            if ip.version == net.version and ip in net:
                return result, record, f"{ip} is inside {mech}:{arg} in {domain}"

        elif mech == "a":
            state.count()
            host, v4, v6 = _split_cidr(arg, domain)
            if _ip_in(ip, _host_addresses(resolver, host, ip), v4, v6):
                return result, record, f"{ip} matches the A/AAAA record of {host}"

        elif mech == "mx":
            state.count()
            host, v4, v6 = _split_cidr(arg, domain)
            for mx_host in resolver.mx(host)[:10]:
                if _ip_in(ip, _host_addresses(resolver, mx_host, ip), v4, v6):
                    return result, record, f"{ip} is the mail server {mx_host} of {host}"

        elif mech == "include":
            state.count()
            inner, _, inner_expl = _evaluate(resolver, arg, ip, state, depth + 1)
            if inner == "pass":
                return result, record, f"authorised through include:{arg} ({inner_expl})"
            if inner == "temperror":
                return "temperror", record, inner_expl
            if inner in ("none", "permerror"):
                raise _PermError(f"include:{arg} returned {inner}")

        elif mech in ("ptr", "exists"):
            state.count()
            state.notes.append(f"skipped '{mech}' mechanism (not supported by this tool)")

        else:
            raise _PermError(f"unknown mechanism '{mech}'")

    if redirect:
        state.count()
        res, _, expl = _evaluate(resolver, redirect, ip, state, depth + 1)
        return ("permerror" if res == "none" else res), record, f"via redirect={redirect}: {expl}"

    return "neutral", record, "no mechanism matched (default result is neutral)"


def check_spf(resolver, ip: str | None, domain: str) -> SPFResult:
    if not domain:
        return SPFResult("none", domain, ip, explanation="no envelope sender domain to check")
    if not ip:
        return SPFResult("none", domain, ip, explanation="could not determine the sending IP")
    state = _SPFState()
    try:
        result, record, expl = _evaluate(resolver, domain, ipaddress.ip_address(ip), state)
    except (_PermError, ValueError) as exc:  # ValueError: malformed IP/CIDR in the record
        return SPFResult("permerror", domain, ip, explanation=str(exc), lookups=state.lookups, notes=state.notes)
    except TempDNSError as exc:
        return SPFResult("temperror", domain, ip, explanation=str(exc), lookups=state.lookups, notes=state.notes)
    return SPFResult(result, domain, ip, record, expl, state.lookups, state.notes)


# --------------------------------------------------------------------------- DKIM

@dataclass
class DKIMResult:
    result: str                       # pass / fail / temperror / none
    domain: str
    selector: str
    reason: str = ""


def check_dkim(resolver, raw: bytes, signatures: list[dict]) -> list[DKIMResult]:
    if not signatures:
        return [DKIMResult("none", "", "", "message has no DKIM-Signature header")]
    try:
        import dkim
    except ImportError:
        return [DKIMResult("temperror", s["d"], s["s"], "dkimpy is not installed") for s in signatures]

    def dnsfunc(name, timeout=5):
        name = name.decode() if isinstance(name, bytes) else name
        records = resolver.txt(name)
        return records[0].encode() if records else None

    results = []
    verifier = dkim.DKIM(raw)
    for idx, sig in enumerate(signatures):
        try:
            ok = verifier.verify(idx=idx, dnsfunc=dnsfunc)
            reason = "signature verified" if ok else "signature does not match the message (altered in transit or forged)"
            results.append(DKIMResult("pass" if ok else "fail", sig["d"], sig["s"], reason))
        except TempDNSError as exc:
            results.append(DKIMResult("temperror", sig["d"], sig["s"], str(exc)))
        except Exception as exc:  # dkim.DKIMException and malformed signatures
            results.append(DKIMResult("fail", sig["d"], sig["s"], str(exc) or exc.__class__.__name__))
    return results


# --------------------------------------------------------------------------- DMARC

@dataclass
class DMARCResult:
    result: str                       # pass / fail / none / temperror
    domain: str
    record: str | None = None
    policy: str | None = None
    spf_aligned: bool = False
    dkim_aligned: bool = False
    explanation: str = ""


def _parse_tags(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def _aligned(a: str, b: str, mode: str) -> bool:
    if not a or not b:
        return False
    return a == b if mode == "s" else org_domain(a) == org_domain(b)


def check_dmarc(resolver, from_domain: str, spf: SPFResult, dkim_results: list[DKIMResult]) -> DMARCResult:
    if not from_domain:
        return DMARCResult("none", from_domain, explanation="no From domain")

    def lookup(name):
        recs = [t for t in resolver.txt(f"_dmarc.{name}") if t.lower().replace(" ", "").startswith("v=dmarc1")]
        return recs[0] if recs else None

    try:
        record, used_org = lookup(from_domain), False
        if record is None and org_domain(from_domain) != from_domain:
            record, used_org = lookup(org_domain(from_domain)), True
    except TempDNSError as exc:
        return DMARCResult("temperror", from_domain, explanation=str(exc))

    if record is None:
        return DMARCResult("none", from_domain,
                           explanation=f"{from_domain} publishes no DMARC policy, so receivers are not told to reject forgeries")

    tags = _parse_tags(record)
    policy = (tags.get("sp") if used_org and "sp" in tags else tags.get("p", "none")).lower()
    spf_ok = spf.result == "pass" and _aligned(spf.domain, from_domain, tags.get("aspf", "r").lower())
    dkim_ok = any(d.result == "pass" and _aligned(d.domain, from_domain, tags.get("adkim", "r").lower())
                  for d in dkim_results)

    if spf_ok or dkim_ok:
        how = " and ".join(x for x, ok in (("SPF", spf_ok), ("DKIM", dkim_ok)) if ok)
        return DMARCResult("pass", from_domain, record, policy, spf_ok, dkim_ok,
                           f"{how} passed and aligned with the From domain")
    return DMARCResult("fail", from_domain, record, policy, spf_ok, dkim_ok,
                       "neither SPF nor DKIM passed for a domain aligned with the From address "
                       f"(domain policy: p={policy})")


__all__ = ["DNSResolver", "FixtureResolver", "TempDNSError", "check_spf", "check_dkim", "check_dmarc",
           "SPFResult", "DKIMResult", "DMARCResult"]
