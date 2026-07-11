"""
intelligence/ip_reputation.py

Purpose: Real-time IP reputation scoring that fuses local blacklist membership,
         Tor exit-node status, and AbuseIPDB confidence into a normalised
         0–100 risk score. Caches scores in memory with a configurable TTL
         so repeated lookups on the same IP cost nothing after the first call.

Inputs:  IP address string.
Outputs: IPReputationResult dataclass with:
           ip, score (0–100), risk_level, sources_hit, cached, latency_ms

Usage:
    from intelligence.ip_reputation import IPReputationScorer
    scorer = IPReputationScorer()
    result = scorer.score("192.168.1.1")
    print(result.risk_level, result.score)
"""

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests

from config import THREAT_DIR, THREAT_FEEDS

logger = logging.getLogger(__name__)

_CACHE_TTL_S     = 300     # cache individual scores for 5 minutes
_TOR_TTL_S       = 3600    # refresh Tor node list hourly
_HTTP_TIMEOUT_S  = 5
_ABUSE_THRESHOLD = 25      # AbuseIPDB score that triggers HIGH risk


@dataclass
class IPReputationResult:
    ip:          str
    score:       int              # 0 = clean, 100 = confirmed malicious
    risk_level:  str              # CLEAN / LOW / MEDIUM / HIGH / CRITICAL
    sources_hit: list[str] = field(default_factory=list)
    cached:      bool       = False
    latency_ms:  float      = 0.0


def _risk_level(score: int) -> str:
    if score == 0:
        return "CLEAN"
    if score < 25:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 75:
        return "HIGH"
    return "CRITICAL"


class IPReputationScorer:
    """
    Fused IP reputation scorer with in-memory TTL cache.

    Score composition (additive, capped at 100):
      • Local blacklist membership  → +100 (instant block)
      • Tor exit node               → +60
      • AbuseIPDB score ≥ threshold → raw AbuseIPDB value (0–100)

    Cache entries expire after _CACHE_TTL_S seconds so live traffic
    does not re-query the same IP on every packet.

    Parameters: none (API keys from ABUSEIPDB_API_KEY env var)
    """

    def __init__(self) -> None:
        self._blacklist_path = Path(THREAT_FEEDS["local_blacklist"]["path"])
        self._blacklist:     set[str]            = set()
        self._tor_nodes:     set[str]            = set()
        self._tor_loaded_at: float               = 0.0
        self._cache:         dict[str, tuple]    = {}   # ip → (score, sources, ts)
        self._abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")

        if not self._abuse_key:
            logger.warning("ABUSEIPDB_API_KEY not set — AbuseIPDB scoring disabled")

        self._load_blacklist()
        self._refresh_tor()

        logger.info(
            "IPReputationScorer ready — blacklist:%d, tor:%d",
            len(self._blacklist), len(self._tor_nodes),
        )

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _load_blacklist(self) -> None:
        if not self._blacklist_path.exists():
            logger.warning("Blacklist file missing: %s", self._blacklist_path)
            return
        try:
            lines = self._blacklist_path.read_text(encoding="utf-8").splitlines()
            self._blacklist = {
                ln.strip() for ln in lines
                if ln.strip() and not ln.startswith("#")
            }
        except OSError as exc:
            logger.error("Blacklist load failed: %s", exc)

    def _refresh_tor(self) -> None:
        now = time.monotonic()
        if now - self._tor_loaded_at < _TOR_TTL_S and self._tor_nodes:
            return
        try:
            resp = requests.get(
                THREAT_FEEDS["tor_exit_nodes"]["url"],
                timeout=_HTTP_TIMEOUT_S,
            )
            resp.raise_for_status()
            self._tor_nodes = {
                ln.split()[-1]
                for ln in resp.text.splitlines()
                if ln.startswith("ExitAddress")
            }
            self._tor_loaded_at = now
            logger.info("Tor nodes refreshed: %d", len(self._tor_nodes))
        except requests.RequestException as exc:
            logger.warning("Tor refresh failed: %s", exc)

    # ------------------------------------------------------------------
    # Per-source contribution
    # ------------------------------------------------------------------

    def _local_score(self, ip: str) -> tuple[int, Optional[str]]:
        if ip in self._blacklist:
            return 100, "local_blacklist"
        return 0, None

    def _tor_score(self, ip: str) -> tuple[int, Optional[str]]:
        self._refresh_tor()
        if ip in self._tor_nodes:
            return 60, "tor_exit_node"
        return 0, None

    def _abuse_score(self, ip: str) -> tuple[int, Optional[str]]:
        if not self._abuse_key:
            return 0, None
        try:
            resp = requests.get(
                THREAT_FEEDS["abuseipdb"]["url"],
                headers={"Key": self._abuse_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=_HTTP_TIMEOUT_S,
            )
            resp.raise_for_status()
            data  = resp.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            if score >= _ABUSE_THRESHOLD:
                return score, "abuseipdb"
        except requests.RequestException as exc:
            logger.warning("AbuseIPDB request failed (%s): %s", ip, exc)
        except (ValueError, KeyError) as exc:
            logger.warning("AbuseIPDB parse error: %s", exc)
        return 0, None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(self, ip: str) -> IPReputationResult:
        """
        Compute a fused reputation score for a single IP address.

        Results are cached for _CACHE_TTL_S seconds to avoid redundant
        API calls on repeated lookups of the same IP.

        Inputs:  ip — IPv4 or IPv6 string
        Outputs: IPReputationResult
        """
        t0 = time.monotonic()

        cached_entry = self._cache.get(ip)
        if cached_entry:
            cached_score, cached_sources, ts = cached_entry
            if time.monotonic() - ts < _CACHE_TTL_S:
                return IPReputationResult(
                    ip=ip,
                    score=cached_score,
                    risk_level=_risk_level(cached_score),
                    sources_hit=cached_sources,
                    cached=True,
                    latency_ms=round((time.monotonic() - t0) * 1000, 2),
                )

        combined = 0
        sources:  list[str] = []

        for score_fn in (self._local_score, self._tor_score, self._abuse_score):
            try:
                pts, src = score_fn(ip)
            except Exception as exc:
                logger.error("Score fn %s error: %s", score_fn.__name__, exc)
                pts, src = 0, None

            if pts > 0 and src:
                combined += pts
                sources.append(src)

            # local blacklist is definitive — skip remaining API calls
            if combined >= 100:
                combined = 100
                break

        combined = min(combined, 100)
        self._cache[ip] = (combined, sources, time.monotonic())

        latency = round((time.monotonic() - t0) * 1000, 2)
        logger.debug("IP %s score=%d risk=%s (%.1f ms)", ip, combined,
                     _risk_level(combined), latency)

        return IPReputationResult(
            ip=ip,
            score=combined,
            risk_level=_risk_level(combined),
            sources_hit=sources,
            cached=False,
            latency_ms=latency,
        )

    def bulk_score(self, ips: list[str]) -> list[IPReputationResult]:
        """
        Score multiple IPs sequentially, leveraging the cache for repeats.

        Inputs:  ips — list of IP address strings
        Outputs: list of IPReputationResult in the same order
        """
        return [self.score(ip) for ip in ips]

    def invalidate_cache(self, ip: Optional[str] = None) -> None:
        """
        Evict one or all cached scores.

        Inputs:  ip — specific IP to evict; None evicts entire cache
        Outputs: None
        """
        if ip is None:
            self._cache.clear()
            logger.info("IP reputation cache cleared")
        else:
            self._cache.pop(ip, None)
            logger.debug("Cache evicted for %s", ip)
