"""OSINT enrichment module.

Queries VirusTotal (primary) and APIVoid (secondary, optional) for the
reputation / blacklist status of every extracted IOC.

Design notes
------------
* An asyncio-safe sliding-window rate limiter enforces VirusTotal public tier
  limits (default 4 lookups/min, overridden via VT_RATE_PER_MINUTE).
* To keep a single analysis under ~30s, OSINT_MAX_LOOKUPS_PER_REQUEST caps how
  many IOCs get queried in one run (highest-value ones first: URLs, then
  domains/IPs, then wallets).
* Un-configured keys degrade gracefully: results come back with status
  "not_configured" and the UI displays it, rather than crashing.
* IOC exclusion (skiplists) for obvious legit domains: github.com etc. — these
  appear in benign screenshots constantly (code, docs).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections import deque
from typing import Any

import httpx

import config

logger = logging.getLogger("osint")

VT_BASE = "https://www.virustotal.com/api/v3"
APIVOID_URL = "https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/"

# Domains that are almost always benign and shouldn't trigger reputation lookups
# when merely embedded in a benign screenshot (docs, code, newsletters).
_SAFE_DOMAINS = {
    "w3.org", "schema.org", "example.com", "localhost", "nist.gov",
    "mitre.org", "attack.mitre.org", "github.com", "gitlab.com",
    "stackexchange.com", "stackoverflow.com", "ubuntu.com", "debian.org",
    "apple.com", "microsoft.com", "google.com", "cloudflare.com",
    "wikipedia.org", "mozilla.org", "virustotal.com",
}

_SKIP_PATTERNS = ("example.org", "yourdomain.com", "domain.com", "sentry.io")


class _RateLimiter:
    """Sliding-window asyncio rate limiter (N events per window_seconds)."""

    def __init__(self, rate: int, window: float = 60.0):
        self.rate = rate
        self.window = window
        self._events: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> float:
        """Returns seconds to sleep before the quota frees up."""
        async with self._lock:
            now = time.monotonic()
            while self._events and now - self._events[0] > self.window:
                self._events.popleft()
        if len(self._events) >= self.rate:
            wait = self.window - (now - self._events[0])
            return max(0.05, min(wait, self.window))
        async with self._lock:
            now = time.monotonic()
            while self._events and now - self._events[0] > self.window:
                self._events.popleft()
            self._events.append(now)
        return 0.0


_limiter: _RateLimiter | None = None


def _get_limiter() -> _RateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = _RateLimiter(config.VT_RATE_PER_MINUTE)
    return _limiter


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _should_skip(ioc_type: str, raw: str) -> bool:
    low = raw.lower()
    if ioc_type == "crypto_wallet" or ioc_type == "email":
        return True  # VT has no direct endpoint; wallets handled by heuristics
    if ioc_type == "url":
        host = low.split("://", 1)[-1].split("/", 1)[0]
        extracted_domain = host.split("?")[0]
    else:
        extracted_domain = low
    if any(dlo in extracted_domain for dlo in _SKIP_PATTERNS):
        return True
    if any(dom in extracted_domain for dom in _SAFE_DOMAINS):
        return True
    return False


def _url_resource_id(url: str) -> str:
    # VT v3 URLs endpoint uses hex-encoded SHA-256 of the URL *without* scheme
    # dashboards canonicalise; API v3 accepts base64 too. We use SHA-256 hex.
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Providers
# --------------------------------------------------------------------------
async def _vt_lookup(client: httpx.AsyncClient, ioc_type: str, raw: str) -> dict[str, Any]:
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    base: str
    if ioc_type == "url":
        base = f"{VT_BASE}/urls/{_url_resource_id(raw)}"
    elif ioc_type == "domain":
        base = f"{VT_BASE}/domains/{raw}"
    else:  # ipv4
        base = f"{VT_BASE}/ip_addresses/{raw}"

    if ioc_type == "url":
        stats = await _vt_url_with_submit(client, raw)
    else:
        await asyncio.sleep(await _get_limiter().acquire())
        r = await client.get(base, headers=headers, timeout=config.OSINT_TIMEOUT_SECONDS)
        if r.status_code == 404:
            return {"provider": "virustotal", "ok": True, "present": False,
                    "note": "IOC has no prior analysis on record"}
        if r.status_code in (401, 429):
            return {"provider": "virustotal", "ok": False,
                    "error": f"VirusTotal returned {r.status_code} — "
                            + ("check VIRUSTOTAL_API_KEY" if r.status_code == 401
                               else "rate limit hit — reduce VT_RATE_PER_MINUTE")}
        r.raise_for_status()
        stats = r.json().get("data", {}).get("attributes", {})

    if stats is None:      # submitted for scan, no verdict in time budget
        return {"provider": "virustotal", "ok": True, "present": False,
                "note": "URL had no prior record — submitted for scanning; "
                        "check again after a few minutes"}

    return _vt_parse_attributes(stats)


def _vt_parse_attributes(attrs: dict[str, Any]) -> dict[str, Any]:
    stats = attrs.get("last_analysis_stats", {})
    MPI = stats.get("malicious", 0) or 0
    suspicious = stats.get("suspicious", 0) or 0
    harmless = stats.get("harmless", 0) or 0
    threat_labels: list[str] = []
    votes = attrs.get("reputation", 0)
    categories = attrs.get("categories", {})
    last_analysis = attrs.get("last_analysis_results", {}) or {}
    for engine, res in last_analysis.items():
        ver = res.get("result", "")
        if ver not in ("", "harmless", "undetected", "unrated"):
            threat_labels.append(f"{engine}: {ver}")

    out: dict[str, Any] = {
        "provider": "virustotal",
        "ok": True,
        "present": True,
        "detections": {"malicious": MPI, "suspicious": suspicious,
                       "harmless": harmless},
        "reputation": votes,
        "categories": categories,
        "engine_verdicts_sample": threat_labels[:8],
        "raw_stats": stats,
    }
    if MPI >= 3 or suspicious >= 3:
        out["verdict"] = "malicious" if MPI >= 3 else "suspicious"
    elif MPI + suspicious == 0:
        out["verdict"] = "clean"
    else:
        out["verdict"] = "mixed"
    return out


async def _vt_url_with_submit(client: httpx.AsyncClient, url: str) -> dict[str, Any] | None:
    """VT url record by sha256 id; on miss, try canonical variants then submit
    the URL for scanning and short-poll. Returns attribute dict, or None when
    nothing is available in the time budget."""
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}

    variants: list[str] = []
    base = url.split("#", 1)[0]
    variants.append(base)
    if "?" in base:                       # same path, no query string
        variants.append(base.split("?", 1)[0])
    if not base.endswith("/") and base.count("/") <= 3:
        variants.append(base + "/")
    # ordered unique
    seen: set[str] = set()
    variants = [v for v in variants if not (v in seen or seen.add(v))]

    for cand in variants:
        await asyncio.sleep(await _get_limiter().acquire())
        r = await client.get(
            f"{VT_BASE}/urls/{_url_resource_id(cand)}",
            headers=headers, timeout=config.OSINT_TIMEOUT_SECONDS,
        )
        if r.status_code == 200:
            return r.json().get("data", {}).get("attributes", {})
        if r.status_code not in (404, 400):
            return {"provider": "virustotal", "ok": False,
                    "error": f"VirusTotal returned {r.status_code} — "
                            + ("check VIRUSTOTAL_API_KEY" if r.status_code == 401
                               else "rate limit hit")}

    # ---- nothing on record: submit for scanning and short-poll -------------
    await asyncio.sleep(await _get_limiter().acquire())
    r = await client.post(
        f"{VT_BASE}/urls", headers=headers,
        data={"url": url}, timeout=config.OSINT_TIMEOUT_SECONDS,
    )
    if r.status_code != 200:
        return None
    analysis_id = r.json().get("data", {}).get("id")
    if not analysis_id:
        return None

    for _ in range(3):                     # ~3 polls × 4s ≈ 12s budget
        await asyncio.sleep(4)
        await asyncio.sleep(await _get_limiter().acquire())
        ar = await client.get(
            f"{VT_BASE}/analyses/{analysis_id}",
            headers=headers, timeout=config.OSINT_TIMEOUT_SECONDS,
        )
        if ar.status_code != 200:
            return None
        attrs = ar.json().get("data", {}).get("attributes", {})
        if attrs.get("status") == "completed" and attrs.get("last_analysis_stats"):
            stats = attrs["last_analysis_stats"]
            return {"last_analysis_stats": stats,
                    "last_analysis_results": attrs.get("last_analysis_results", {})}
    return None


async def _apivoid_lookup(client: httpx.AsyncClient, ioc_type: str, raw: str) -> dict[str, Any]:
    if not config.APIVOID_API_KEY or ioc_type != "url":
        return {}
    params = {"key": config.APIVOID_API_KEY, "url": raw, "safety": "1"}
    r = await client.get(APIVOID_URL, params=params, timeout=config.OSINT_TIMEOUT_SECONDS)
    r.raise_for_status()
    data = r.json()
    report = data.get("data", {}).get("report", {})
    if not report:
        return {"provider": "apivoid", "ok": False, "error": data.get("error", "unknown")[:200]}
    out: dict[str, Any] = {
        "provider": "apivoid",
        "ok": True,
        "risk_score": report.get("risk_score"),
        "blacklists": report.get("blacklists", {}),
        "domain_blacklist_engines": len((report.get("blacklists", {}) or {}).get("engines", []) if isinstance(report.get("blacklists", {}).get("engines"), list) else []),
    }
    if out["risk_score"] is not None:
        out["verdict"] = "malicious" if out["risk_score"] >= 50 else ("suspicious" if out["risk_score"] >= 25 else "clean")
    return out


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
async def enrich_iocs(iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Query OSINT sources for each candidate IOC and return annotated records.

    Each record is {raw, defanged, ioc_type, notes, lookups:[...], overall}.
    """
    out = [dict(i) for i in iocs]
    for rec in out:
        rec.setdefault("notes", [])
        rec["lookups"] = []
        rec["overall"] = "not_queryable"

    if not iocs:
        return out

    candidates = [
        rec for rec in out
        if rec["ioc_type"] in ("url", "domain", "ipv4")
        and not _should_skip(rec["ioc_type"], rec["raw"])
    ]
    candidates.sort(key=lambda r: {"url": 0, "domain": 1, "ipv4": 2}.get(r["ioc_type"], 9))
    candidates = candidates[: config.OSINT_MAX_LOOKUPS_PER_REQUEST]

    if not config.VIRUSTOTAL_API_KEY and not config.APIVOID_API_KEY:
        for rec in out:
            rec["overall"] = "not_configured"
            rec["notes"].append("No OSINT provider keys configured (VIRUSTOTAL_API_KEY / APIVOID_API_KEY missing)")
        return out

    provider_ok = False
    async with httpx.AsyncClient() as client:
        for rec in candidates:
            try:
                if config.VIRUSTOTAL_API_KEY:
                    rec["lookups"].append(await _vt_lookup(client, rec["ioc_type"], rec["raw"]))
                    provider_ok = True
                if config.APIVOID_API_KEY:
                    ap = await _apivoid_lookup(client, rec["ioc_type"], rec["raw"])
                    if ap:
                        rec["lookups"].append(ap)
                        provider_ok = True
            except Exception as exc:
                msg = f"OSINT lookup failed for {rec['raw'][:80]}: {exc}"
                logger.warning(msg)
                rec["lookups"].append({"provider": "error", "ok": False, "error": str(exc)[:240]})

        for rec in out:
            verdicts = [l.get("verdict") for l in rec["lookups"]
                        if l.get("ok") and l.get("present", True) and l.get("verdict")]
            if not verdicts:
                if "error" in [l.get("provider") for l in rec["lookups"]]:
                    rec["overall"] = "lookup_failed"
                else:
                    rec["overall"] = "not_queryable"
                continue
            if "malicious" in verdicts:
                rec["overall"] = "malicious"
            elif "suspicious" in verdicts:
                rec["overall"] = "suspicious"
            elif "mixed" in verdicts:
                rec["overall"] = "mixed"
            elif "clean" in verdicts:
                rec["overall"] = "clean"

    if not provider_ok and all(r["overall"] in ("not_queryable", "lookup_failed") for r in out):
        for rec in out:
            rec["notes"].append("OSINT providers could not be reached")
    return out


def osint_summary_for_llm(records: list[dict[str, Any]]) -> str:
    """Compact text summary of OSINT records to include in the LLM prompt."""
    lines: list[str] = []
    for rec in records:
        if rec["overall"] in ("not_queryable", "not_configured"):
            continue
        engine_bits: list[str] = []
        for l in rec["lookups"]:
            if l.get("provider") == "virustotal" and l.get("detections"):
                d = l["detections"]
                engine_bits.append(
                    f"VirusTotal {d.get('malicious',0)}/{d.get('malicious',0) + d.get('suspicious',0) + d.get('harmless',0) or 1} malicious engines;"
                    f" verdict={l.get('verdict')} categories={list((l.get('categories') or {}).keys())[:3]}"
                )
            elif l.get("provider") == "apivoid" and l.get("risk_score") is not None:
                engine_bits.append(f"APIVoid risk={l['risk_score']} verdict={l.get('verdict')}")
        if engine_bits:
            lines.append(f"• {rec.get('defanged') or rec.get('raw')} [{rec['ioc_type']}]: " + " | ".join(engine_bits))
    if not lines:
        return "NO OSINT data available (no IOC lookups succeeded or no keys configured)."
    return "\n".join(lines)


async def provider_status() -> dict[str, Any]:
    return {
        "virustotal_enabled": bool(config.VIRUSTOTAL_API_KEY),
        "apivoid_enabled": bool(config.APIVOID_API_KEY),
        "rate_limit_per_minute": config.VT_RATE_PER_MINUTE,
    }
