"""
intelligence/threat_feeds.py

Purpose: Unified threat feed aggregator that combines all intelligence sources
         into a single verdict. Checks in speed-optimal order:
         local blacklist (µs) → Tor exit nodes (fast) → AbuseIPDB (~100 ms)
         → VirusTotal (~200 ms). Short-circuits on first confirmed hit so
         live traffic classification stays under the 500 ms SLA.

Inputs:  IP address strings or URL strings.
Outputs: ThreatResult dataclass with:
           is_threat, confidence, source, detail, latency_ms

Usage:
    from intelligence.threat_feeds import ThreatFeedAggregator
    agg = ThreatFeedAggregator()
    result = agg.check_ip("1.2.3.4")
    if result.is_threat:
        print(result.source, result.confidence)
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

_TOR_CACHE_TTL_S  = 3600        # refresh Tor node list every hour
_HTTP_TIMEOUT_S   = 5           # per-request timeout
_ABUSE_THRESHOLD  = 25          # AbuseIPDB score ≥ this → threat confirmed


@dataclass
class ThreatResult:
    is_threat:   bool
    confidence:  float           # 0.0 – 1.0
    source:      Optional[str]   # which feed produced the verdict
    detail:      Optional[str]   # human-readable reason
    latency_ms:  float = 0.0
    raw:         dict  = field(default_factory=dict)


def _clean_result(latency_ms: float = 0.0) -> ThreatResult:
    return ThreatResult(
        is_threat=False,
        confidence=0.0,
        source=None,
        detail="No threat detected",
        latency_ms=latency_ms,
    )


class ThreatFeedAggregator:
    """
    Orchestrates multi-source threat intelligence lookups for a given IP or URL.

    Lookup order (fastest → slowest):
      1. Local IP blacklist  — file on disk, O(1) set lookup
      2. Tor exit nodes      — cached in memory, refreshed hourly
      3. AbuseIPDB           — REST API, requires ABUSEIPDB_API_KEY env var
      4. VirusTotal          — REST API, requires VIRUSTOTAL_API_KEY env var

    Any confirmed hit short-circuits the chain (no further API calls).
    API keys are read from environment variables at instantiation; if absent
    the corresponding source is skipped with a warning.

    Parameters: none
    """

    def __init__(self) -> None:
        self._blacklist_path = Path(
            THREAT_FEEDS["local_blacklist"]["path"]
        )
        self._blacklist:     set[str] = set()
        self._tor_nodes:     set[str] = set()
        self._tor_loaded_at: float    = 0.0

        self._abuse_key  = os.getenv("ABUSEIPDB_API_KEY", "")
        self._vt_key     = os.getenv("VIRUSTOTAL_API_KEY", "")

        if not self._abuse_key:
            logger.warning("ABUSEIPDB_API_KEY not set — AbuseIPDB checks disabled")
        if not self._vt_key:
            logger.warning("VIRUSTOTAL_API_KEY not set — VirusTotal checks disabled")

        self._load_local_blacklist()
        self._refresh_tor_nodes()

        logger.info(
            "ThreatFeedAggregator ready — blacklist:%d IPs, tor_nodes:%d",
            len(self._blacklist), len(self._tor_nodes),
        )

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _load_local_blacklist(self) -> None:
        if not self._blacklist_path.exists():
            logger.warning("Local blacklist not found: %s", self._blacklist_path)
            return
        try:
            lines = self._blacklist_path.read_text(encoding="utf-8").splitlines()
            self._blacklist = {
                ln.strip() for ln in lines
                if ln.strip() and not ln.startswith("#")
            }
            logger.info("Loaded %d IPs from local blacklist", len(self._blacklist))
        except OSError as exc:
            logger.error("Failed to load local blacklist: %s", exc)

    def _refresh_tor_nodes(self) -> None:
        now = time.monotonic()
        if now - self._tor_loaded_at < _TOR_CACHE_TTL_S and self._tor_nodes:
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
            logger.info("Tor exit node list refreshed: %d nodes", len(self._tor_nodes))
        except requests.RequestException as exc:
            logger.warning("Tor node refresh failed: %s", exc)

    # ------------------------------------------------------------------
    # Source-level checks
    # ------------------------------------------------------------------

    def _check_local(self, ip: str) -> Optional[ThreatResult]:
        if ip in self._blacklist:
            return ThreatResult(
                is_threat=True,
                confidence=1.0,
                source="local_blacklist",
                detail=f"{ip} is in local IP blacklist",
            )
        return None

    def _check_tor(self, ip: str) -> Optional[ThreatResult]:
        self._refresh_tor_nodes()
        if ip in self._tor_nodes:
            return ThreatResult(
                is_threat=True,
                confidence=0.95,
                source="tor_exit_nodes",
                detail=f"{ip} is a Tor exit node",
            )
        return None

    def _check_abuseipdb(self, ip: str) -> Optional[ThreatResult]:
        if not self._abuse_key:
            return None
        try:
            resp = requests.get(
                THREAT_FEEDS["abuseipdb"]["url"],
                headers={
                    "Key":    self._abuse_key,
                    "Accept": "application/json",
                },
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=_HTTP_TIMEOUT_S,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            if score >= _ABUSE_THRESHOLD:
                return ThreatResult(
                    is_threat=True,
                    confidence=round(score / 100.0, 3),
                    source="abuseipdb",
                    detail=f"AbuseIPDB score {score}/100",
                    raw=data,
                )
        except requests.RequestException as exc:
            logger.warning("AbuseIPDB request failed for %s: %s", ip, exc)
        except (ValueError, KeyError) as exc:
            logger.warning("AbuseIPDB response parse error: %s", exc)
        return None

    def _check_virustotal_url(self, url: str) -> Optional[ThreatResult]:
        if not self._vt_key:
            return None
        try:
            resp = requests.get(
                THREAT_FEEDS["virustotal"]["url"],
                params={"apikey": self._vt_key, "resource": url},
                timeout=_HTTP_TIMEOUT_S,
            )
            resp.raise_for_status()
            data       = resp.json()
            positives  = int(data.get("positives", 0))
            total      = int(data.get("total", 1))
            if positives > 0:
                confidence = round(positives / max(total, 1), 3)
                return ThreatResult(
                    is_threat=True,
                    confidence=confidence,
                    source="virustotal",
                    detail=f"VirusTotal: {positives}/{total} engines flagged",
                    raw=data,
                )
        except requests.RequestException as exc:
            logger.warning("VirusTotal request failed for %s: %s", url, exc)
        except (ValueError, KeyError) as exc:
            logger.warning("VirusTotal response parse error: %s", exc)
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_ip(self, ip: str) -> ThreatResult:
        """
        Run the full threat-intelligence chain for a single IP address.

        Short-circuits on first confirmed hit. Sources checked in order:
        local blacklist → Tor exit nodes → AbuseIPDB.

        Inputs:  ip — dotted-decimal IPv4 or IPv6 string
        Outputs: ThreatResult (is_threat=False if all sources pass clean)
        """
        t0 = time.monotonic()

        for check_fn in (self._check_local, self._check_tor, self._check_abuseipdb):
            try:
                result = check_fn(ip)
            except Exception as exc:
                logger.error("Threat check error (%s): %s", check_fn.__name__, exc)
                continue
            if result:
                result.latency_ms = round((time.monotonic() - t0) * 1000, 2)
                logger.info(
                    "Threat confirmed for %s via %s (conf=%.2f, %.1f ms)",
                    ip, result.source, result.confidence, result.latency_ms,
                )
                return result

        latency = round((time.monotonic() - t0) * 1000, 2)
        logger.debug("IP %s passed all checks (%.1f ms)", ip, latency)
        return _clean_result(latency_ms=latency)

    def check_url(self, url: str) -> ThreatResult:
        """
        Run threat-intelligence chain for a URL (VirusTotal).

        Inputs:  url — full URL string
        Outputs: ThreatResult
        """
        t0 = time.monotonic()
        try:
            result = self._check_virustotal_url(url)
        except Exception as exc:
            logger.error("VirusTotal check error: %s", exc)
            result = None

        latency = round((time.monotonic() - t0) * 1000, 2)
        if result:
            result.latency_ms = latency
            return result
        return _clean_result(latency_ms=latency)

    def reload_blacklist(self) -> int:
        """Reload the local blacklist from disk. Returns new IP count."""
        self._load_local_blacklist()
        return len(self._blacklist)

    def add_to_blacklist(self, ip: str) -> None:
        """
        Add an IP to the in-memory blacklist and persist it to disk.

        Inputs:  ip — IP address string to blacklist
        Outputs: None (writes to threat_intel/ip_blacklist.txt)
        """
        self._blacklist.add(ip)
        try:
            with self._blacklist_path.open("a", encoding="utf-8") as fh:
                fh.write(f"{ip}\n")
            logger.info("IP %s added to local blacklist", ip)
        except OSError as exc:
            logger.error("Failed to persist blacklist entry %s: %s", ip, exc)
