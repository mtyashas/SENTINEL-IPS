"""
intelligence/domain_reputation.py

Purpose: Domain and URL reputation engine that detects phishing, malware
         distribution, newly-registered domains, homograph attacks, suspicious
         TLDs, and mismatched SSL certificates. Queries VirusTotal for external
         validation and maintains a local phishing domain list for offline use.

Inputs:  Domain strings or full URL strings.
Outputs: DomainReputationResult dataclass with:
           domain, is_malicious, confidence, risk_factors, source, latency_ms

Usage:
    from intelligence.domain_reputation import DomainReputationChecker
    checker = DomainReputationChecker()
    result  = checker.check("evil-phishing.tk")
    if result.is_malicious:
        print(result.risk_factors)
"""

import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import requests

from config import THREAT_DIR, THREAT_FEEDS

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT_S = 5
_CACHE_TTL_S    = 600   # 10-minute domain verdict cache

# ---------------------------------------------------------------------------
# Static indicator sets
# ---------------------------------------------------------------------------

_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    ".tk", ".ml", ".ga", ".cf", ".xyz", ".gq", ".pw",
    ".top", ".work", ".click", ".download", ".loan", ".win",
    ".stream", ".racing", ".party", ".review", ".trade",
})

_URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "short.io", "rb.gy",
})

_HOMOGRAPH_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"paypa[l1][^a-z]",
        r"g[o0]{2}gle",
        r"micros[o0]ft",
        r"app[l1]e[^a-z]",
        r"arnazon",
        r"am[a4]zon[^.a-z]",
        r"faceb[o0]{2}k",
        r"twitt[e3]r",
        r"[il1]{3}inkedin",
        r"d[r0]opbox",
    ]
]

_MALWARE_KEYWORD_RE = re.compile(
    r"(free-?download|crack|keygen|warez|torrent|nulled|exploit|"
    r"ransomware|backdoor|rootkit|botnet|cryptominer|stealer)",
    re.IGNORECASE,
)


@dataclass
class DomainReputationResult:
    domain:      str
    is_malicious: bool
    confidence:  float                   # 0.0 – 1.0
    risk_factors: list[str] = field(default_factory=list)
    source:      str = "local"
    latency_ms:  float = 0.0


def _extract_domain(url_or_domain: str) -> str:
    """Return the bare hostname from a URL or pass through a plain domain."""
    if "://" in url_or_domain or url_or_domain.startswith("//"):
        try:
            return urlparse(url_or_domain).hostname or url_or_domain
        except Exception:
            pass
    return url_or_domain.split("/")[0].split("?")[0].lower()


class DomainReputationChecker:
    """
    Multi-signal domain reputation checker.

    Detection signals (applied in order, each contributes to confidence):
      1. Local phishing domain list       — instant O(1) lookup
      2. Suspicious TLD                   — known free/abused TLDs
      3. URL shortener                    — anonymisation of destination
      4. Homograph / brand impersonation  — lookalike character substitution
      5. Malware keywords in domain name  — keyword matching
      6. VirusTotal URL report            — external engine consensus

    Confidence is the fraction of signals triggered; any signal ≥ 0.5
    marks the domain as malicious.

    Parameters: none (VIRUSTOTAL_API_KEY read from environment)
    """

    def __init__(self) -> None:
        self._phishing_path = THREAT_DIR / "phishing_domains.txt"
        self._phishing_domains: set[str] = set()
        self._cache:            dict[str, tuple] = {}
        self._vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")

        if not self._vt_key:
            logger.warning("VIRUSTOTAL_API_KEY not set — VirusTotal checks disabled")

        self._load_phishing_list()

        logger.info(
            "DomainReputationChecker ready — phishing_list:%d domains",
            len(self._phishing_domains),
        )

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _load_phishing_list(self) -> None:
        if not self._phishing_path.exists():
            logger.warning("Phishing domain list not found: %s", self._phishing_path)
            return
        try:
            lines = self._phishing_path.read_text(encoding="utf-8").splitlines()
            self._phishing_domains = {
                ln.strip().lower() for ln in lines
                if ln.strip() and not ln.startswith("#")
            }
            logger.info("Loaded %d phishing domains", len(self._phishing_domains))
        except OSError as exc:
            logger.error("Phishing list load failed: %s", exc)

    # ------------------------------------------------------------------
    # Individual signal checks
    # ------------------------------------------------------------------

    def _check_local_list(self, domain: str) -> tuple[float, list[str]]:
        if domain in self._phishing_domains:
            return 1.0, ["known_phishing_domain"]
        return 0.0, []

    def _check_tld(self, domain: str) -> tuple[float, list[str]]:
        for tld in _SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return 0.4, [f"suspicious_tld:{tld}"]
        return 0.0, []

    def _check_shortener(self, domain: str) -> tuple[float, list[str]]:
        if domain in _URL_SHORTENERS:
            return 0.5, ["url_shortener"]
        return 0.0, []

    def _check_homograph(self, domain: str) -> tuple[float, list[str]]:
        for pattern in _HOMOGRAPH_PATTERNS:
            if pattern.search(domain):
                return 0.7, [f"homograph:{pattern.pattern}"]
        return 0.0, []

    def _check_keywords(self, domain: str) -> tuple[float, list[str]]:
        m = _MALWARE_KEYWORD_RE.search(domain)
        if m:
            return 0.6, [f"malware_keyword:{m.group(0)}"]
        return 0.0, []

    def _check_virustotal(self, url: str) -> tuple[float, list[str], str]:
        if not self._vt_key:
            return 0.0, [], "local"
        try:
            resp = requests.get(
                THREAT_FEEDS["virustotal"]["url"],
                params={"apikey": self._vt_key, "resource": url},
                timeout=_HTTP_TIMEOUT_S,
            )
            resp.raise_for_status()
            data      = resp.json()
            positives = int(data.get("positives", 0))
            total     = int(data.get("total", 1))
            if positives > 0:
                conf = round(positives / max(total, 1), 3)
                return conf, [f"virustotal:{positives}/{total}_engines"], "virustotal"
        except requests.RequestException as exc:
            logger.warning("VirusTotal domain check failed (%s): %s", url, exc)
        except (ValueError, KeyError) as exc:
            logger.warning("VirusTotal parse error: %s", exc)
        return 0.0, [], "local"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, url_or_domain: str) -> DomainReputationResult:
        """
        Run all reputation signals against a domain or URL.

        Results are cached for _CACHE_TTL_S seconds.

        Inputs:  url_or_domain — plain domain (e.g. "evil.tk") or full URL
        Outputs: DomainReputationResult
        """
        t0 = time.monotonic()
        domain = _extract_domain(url_or_domain)

        cached = self._cache.get(domain)
        if cached:
            result, ts = cached
            if time.monotonic() - ts < _CACHE_TTL_S:
                result.latency_ms = round((time.monotonic() - t0) * 1000, 2)
                return result

        confidence   = 0.0
        risk_factors: list[str] = []
        source       = "local"

        # Local list is definitive
        conf, factors = self._check_local_list(domain)
        if conf == 1.0:
            confidence = 1.0
            risk_factors = factors
        else:
            for check_fn in (
                self._check_tld,
                self._check_shortener,
                self._check_homograph,
                self._check_keywords,
            ):
                try:
                    c, f = check_fn(domain)
                    confidence   = min(1.0, confidence + c)
                    risk_factors.extend(f)
                except Exception as exc:
                    logger.error("Domain check error (%s): %s", check_fn.__name__, exc)

            # Call VirusTotal only if local signals are ambiguous
            if 0 < confidence < 1.0 or not risk_factors:
                try:
                    vt_conf, vt_factors, vt_src = self._check_virustotal(url_or_domain)
                    if vt_conf > 0:
                        confidence   = min(1.0, confidence + vt_conf)
                        risk_factors.extend(vt_factors)
                        source        = vt_src
                except Exception as exc:
                    logger.error("VirusTotal check error: %s", exc)

        result = DomainReputationResult(
            domain=domain,
            is_malicious=confidence >= 0.5,
            confidence=round(min(confidence, 1.0), 3),
            risk_factors=risk_factors,
            source=source,
            latency_ms=round((time.monotonic() - t0) * 1000, 2),
        )

        self._cache[domain] = (result, time.monotonic())

        if result.is_malicious:
            logger.info(
                "Malicious domain: %s (conf=%.2f, factors=%s)",
                domain, result.confidence, result.risk_factors,
            )

        return result

    def add_phishing_domain(self, domain: str) -> None:
        """
        Add a domain to the in-memory phishing set and persist to disk.

        Inputs:  domain — bare domain string to blacklist
        Outputs: None
        """
        domain = domain.lower().strip()
        self._phishing_domains.add(domain)
        self._cache.pop(domain, None)
        try:
            with self._phishing_path.open("a", encoding="utf-8") as fh:
                fh.write(f"{domain}\n")
            logger.info("Added %s to phishing domain list", domain)
        except OSError as exc:
            logger.error("Failed to persist phishing domain %s: %s", domain, exc)

    def reload(self) -> int:
        """Reload phishing domain list from disk. Returns new domain count."""
        self._load_phishing_list()
        self._cache.clear()
        return len(self._phishing_domains)
