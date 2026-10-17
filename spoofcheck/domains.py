"""Domain helpers: organisational domain, edit distance and look-alike detection."""

from __future__ import annotations

# Common multi-part public suffixes. A full implementation would use the Public Suffix
# List; this short list covers the suffixes this tool is most likely to meet.
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "co.in", "org.in", "net.in", "ac.in", "edu.in", "gov.in", "nic.in", "res.in",
    "com.au", "net.au", "org.au", "edu.au",
    "co.jp", "co.nz", "com.br", "com.sg", "com.my", "co.za", "com.cn",
}

# Characters and sequences attackers swap in to make a domain look like another one.
HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s")]

# Brands commonly impersonated. Extend at runtime with --protect.
DEFAULT_PROTECTED = [
    "google.com", "gmail.com", "microsoft.com", "outlook.com", "apple.com", "amazon.com",
    "paypal.com", "netflix.com", "linkedin.com", "github.com", "facebook.com", "instagram.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "paytm.com", "flipkart.com",
    "irctc.co.in", "incometax.gov.in", "srmist.edu.in",
]

FREE_MAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com",
    "live.com", "icloud.com", "proton.me", "protonmail.com", "aol.com", "gmx.com", "zoho.com",
    "rediffmail.com", "yandex.com", "mail.com",
}


def org_domain(domain: str) -> str:
    """Return the registrable ('organisational') domain: mail.google.com -> google.com."""
    labels = domain.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def brand_label(domain: str) -> str:
    """The first label of the organisational domain: hdfcbank.com -> hdfcbank."""
    return org_domain(domain).split(".")[0]


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalise_homoglyphs(label: str) -> str:
    for fake, real in HOMOGLYPHS:
        label = label.replace(fake, real)
    return label


def lookalike_of(domain: str, protected: list[str]) -> str | None:
    """If `domain` imitates one of the protected domains (without being it), return that domain."""
    if not domain:
        return None
    org = org_domain(domain)
    label = brand_label(domain)
    for target in protected:
        t_org, t_label = org_domain(target), brand_label(target)
        if org == t_org:
            return None  # it *is* the real domain
        if len(t_label) < 4:
            # Very short brands (e.g. 'sbi') produce too many false positives on edit distance.
            if label == t_label:
                return target  # same brand name on a different suffix, e.g. sbi.com vs sbi.co.in
            continue
        if normalise_homoglyphs(label) == normalise_homoglyphs(t_label):
            return target
        if levenshtein(label, t_label) <= (1 if len(t_label) < 6 else 2):
            return target
        # Brand name embedded in a longer domain, e.g. paypal-security.com
        if t_label in label and label != t_label:
            return target
    return None


__all__ = ["org_domain", "brand_label", "levenshtein", "lookalike_of", "DEFAULT_PROTECTED", "FREE_MAIL"]
