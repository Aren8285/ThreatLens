"""IOC (Indicator of Compromise) extraction using regex + lightweight NLP heuristics.

Extracts:
  * URLs (http/https and bare-domain with path)
  * Domains (bare TLD-bearing hosts)
  * IPv4 addresses
  * Email addresses / senders
  * Crypto wallet addresses (BTC, ETH, LTC, XMR)

Every extracted indicator is ALSO returned defanged so it is never a live,
clickable string anywhere in reports, logs, or the UI.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Iterable

# --------------------------------------------------------------------------
# Regex corpus
# --------------------------------------------------------------------------
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

# URLs (with scheme) — group(0) is the full URL, stop at common delimiters.
_URL_SCHEME_RE = re.compile(
    r"""(?i)\b(?:https?|ftp|hXXps?|hxxps?)://"""
    r"""[^\s<>"'()\[\]{}]+""",
)

# Bare domains, e.g. secure-paypa1.com/login or mailchimp-spoof.xyz
_TLD = r"(?:com|net|org|io|co|xyz|top|ru|cn|info|biz|us|uk|ca|de|fr|nl|eu|me|app|link|site|online|club|shop|store|click|mom|bar|rest|cam|cfd|icu|live|pro|dev|zip|mk|su|tk|ml|ga|cf|gq|pw|aws)\b"
_BARE_DOMAIN_RE = re.compile(
    r"""(?i)\b"""
    r"""(?:[a-z0-9](?:[a-z0-9\-_]{0,61}[a-z0-9])?\.)+"""
    + _TLD +
    r"""(?:/[^\s<>"'()\[\]{}]*)?"""
)

_EMAIL_RE = re.compile(
    r"""(?i)\b[A-Z0-9._%+\-]+@(?:[A-Z0-9\-]+\.)+[A-Z]{2,}\b"""
)

# Crypto wallets
_BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{20,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_LTC_RE = re.compile(r"\b(?:ltc1[a-z0-9]{20,71}|[LM3][a-km-zA-HJ-NP-Z1-9]{26,34})\b")
_XMR_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

# Reserved words that appear in prose but are not useful IOCs on their own.
_IP_WHITELIST = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}

# Brand/legitimity heuristics for the "similar-to-brand" flag.
_KNOWN_BRANDS = {
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook",
    "google", "gmail", "amazon", "netflix", "chase", "wellsfargo",
    "hsbc", "dhl", "fedex", "ups", "usps", "linkedin", "facebook",
    "instagram", "whatsapp", "binance", "coinbase", "metamask",
    "steam", "roblox", "irs.gov", "hmrc",
}


@dataclass
class IOC:
    raw: str                  # the indicator exactly as it appears in source
    defanged: str             # defanged, safe-to-render version
    ioc_type: str             # url | domain | ipv4 | email | crypto_wallet
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------
# Defanging — string out of band, never render a live link
# --------------------------------------------------------------------------
def defang(value: str) -> str:
    v = value.replace("http", "hXXp").replace("HTTP", "HXXP")
    v = v.replace("://", "[://]").replace(".", "[.]")
    v = v.replace("@", "[@]") if "@" in value else v
    return v


def refang(value: str) -> str:
    """Inverse for internal API calls only (never exposed to the user)."""
    v = value.replace("[.]", ".").replace("[://]", "://")
    v = v.replace("hXXp://", "http://").replace("hXXps://", "https://")
    v = v.replace("HXXP://", "http://").replace("HXXPS://", "https://")
    return v.replace("[@]", "@")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _looks_like_ip_host(url: str) -> bool:
    host = re.sub(r"^[a-zA-Z]+://", "", url).split("/")[0]
    return bool(_IPV4_RE.fullmatch(host))


def _contains_brand(value_lower: str) -> str | None:
    for brand in _KNOWN_BRANDS:
        if brand in value_lower:
            return brand
    return None


def _dedupe(items: Iterable[IOC]) -> list[IOC]:
    seen: set[tuple[str, str]] = set()
    out: list[IOC] = []
    for ioc in items:
        key = (ioc.ioc_type, ioc.raw.lower())
        if key in seen:
            seen_key = ioc.raw.lower()
            _ = seen_key
            continue
        seen.add(key)
        out.append(ioc)
    return out


def extract_iocs(text: str) -> list[IOC]:
    if not text or not text.strip():
        return []
    findings: list[IOC] = []

    # ---- URLs with a scheme -------------------------------------------------
    for m in _URL_SCHEME_RE.finditer(text):
        raw = m.group(0).rstrip(".,;:!?)")
        low = raw.lower()
        notes: list[str] = []
        if "hxxp" in low or "hXXp" in raw:
            notes.append("Source text was already defanged")
        if _looks_like_ip_host(raw):
            notes.append("Bare IP host instead of a domain — common in mass phishing infra")
        brand = _contains_brand(low)
        if brand:
            notes.append(f"References known brand: {brand} (possible brand spoof)")
        if re.search(r"(login|signin|verify|secure|account|update|wallet|confirm|bill|invoice|unlock|webscr)", low):
            notes.append("Path suggests credential/payment landing page")
        if raw.count("/") - raw.count("://") >= 2 and low.count("-") >= 2:
            notes.append("Long multi-hyphen path/domain (obfuscation keep-alive common)")
        findings.append(IOC(raw=raw, defanged=defang(raw), ioc_type="url", notes=notes))

    # ---- Bare domains -------------------------------------------------------
    covered_up_to = [m.end() for m in _URL_SCHEME_RE.finditer(text)]
    for m in _BARE_DOMAIN_RE.finditer(text):
        # Skip anything inside a URL we already captured
        if any(start - 0 <= m.start() <= end for start, end in
               zip([m.start() - 0], covered_up_to)):
            pass
        raw = m.group(0)
        if _EMAIL_RE.search(raw):
            continue
        low = raw.lower()
        # Skip if this fragment is part of a full URL already captured
        if any(raw.lower() in full.raw.lower() for full in findings):
            continue
        notes: list[str] = []
        brand = _contains_brand(low)
        if brand:
            notes.append(f"Domain references known brand: {brand} (possible spoof)")
        if low.count("-") >= 2 and len(low) > 15:
            notes.append("Multi-hyphen domain (classic homograph/spoof pattern)")
        findings.append(IOC(raw=raw, defanged=defang(raw), ioc_type="domain", notes=notes))

    # ---- IPv4 ---------------------------------------------------------------
    urls_in_text = [m.group(0).lower() for m in _URL_SCHEME_RE.finditer(text)]
    for m in _IPV4_RE.finditer(text):
        raw = m.group(0)
        if raw in _IP_WHITELIST:
            continue
        # If a URL we already captured contains it, don't double-report
        if any(raw.lower() in u for u in urls_in_text):
            continue
        notes = []
        if raw.endswith(".0") or raw.endswith(".1"):
            notes.append("Possible internal CIDR reference")
        findings.append(IOC(raw=raw, defanged=defang(raw), ioc_type="ipv4", notes=notes))

    # ---- Emails -------------------------------------------------------------
    for m in _EMAIL_RE.finditer(text):
        raw = m.group(0)
        notes: list[str] = []
        brand = _contains_brand(raw.lower())
        if brand:
            notes.append(f"Sender/description references known brand: {brand}")
            display = raw.split("@")[0].lower()
            if any(fn in display for fn in
                   ("noreply", "no-reply", "support", "security", "billing", "admin")):
                notes.append("Generic sender/description name — check the true root cause")
        findings.append(IOC(raw=raw, defanged=defang(raw), ioc_type="email", notes=notes))

    # ---- Crypto wallets -----------------------------------------------------
    wallet_types = [
        ("bitcoin", _BTC_RE),
        ("ethereum", _ETH_RE),
        ("litecoin", _LTC_RE),
        ("monero", _XMR_RE),
    ]
    # ETH addresses get matched by hex pattern — don't also flag as BTC/LTC
    for chain, rx in wallet_types:
        for m in rx.finditer(text):
            raw = m.group(0)
            if chain != "ethereum" and _ETH_RE.fullmatch(raw):
                continue
            findings.append(IOC(
                raw=raw,
                defanged=defang(raw),
                ioc_type="crypto_wallet",
                notes=[f"Crypto chain: {chain}"],
            ))

    return _dedupe(findings)


def summary(iocs: list[IOC]) -> dict:
    counts: dict[str, int] = {}
    for ioc in iocs:
        counts[ioc.ioc_type] = counts.get(ioc.ioc_type, 0) + 1
    return {"total": len(iocs), "by_type": counts}
