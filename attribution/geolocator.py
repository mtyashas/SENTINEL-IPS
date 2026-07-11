"""
attribution/geolocator.py

Purpose: Resolve attacker IP addresses to geographic and network metadata
         (country, city, lat/lon, ASN, ISP). Uses a local MaxMind GeoLite2
         database when available (zero latency, offline-capable); falls back
         to the ip-api.com REST service for environments without the DB file.
         Results are cached in memory to avoid redundant lookups on repeated
         hits from the same source.

Inputs:  IPv4 or IPv6 address string.
Outputs: GeoResult dataclass with:
           ip, country_code, country_name, city, latitude, longitude,
           asn, isp, is_vpn_or_proxy, source, latency_ms

Usage:
    from attribution.geolocator import Geolocator
    geo = Geolocator()
    result = geo.locate("8.8.8.8")
    print(result.country_code, result.city, result.latitude, result.longitude)
"""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests

from config import ROOT

logger = logging.getLogger(__name__)

_CACHE_TTL_S    = 1800           # 30-minute geo cache
_HTTP_TIMEOUT_S = 5
_IPAPI_URL      = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,as,isp,proxy,hosting"

# MaxMind DB paths to probe in order
_GEOIP_DB_CANDIDATES: list[Path] = [
    ROOT / "GeoLite2-City.mmdb",
    ROOT / "threat_intel" / "GeoLite2-City.mmdb",
    Path.home() / "GeoLite2-City.mmdb",
]


@dataclass
class GeoResult:
    ip:             str
    country_code:   str   = "XX"
    country_name:   str   = "Unknown"
    city:           str   = "Unknown"
    latitude:       float = 0.0
    longitude:      float = 0.0
    asn:            str   = ""
    isp:            str   = ""
    is_vpn_or_proxy: bool = False
    source:         str   = "unknown"
    latency_ms:     float = 0.0


def _unknown_result(ip: str, latency_ms: float = 0.0) -> GeoResult:
    return GeoResult(ip=ip, source="unavailable", latency_ms=latency_ms)


class Geolocator:
    """
    Two-tier IP geolocation engine with in-memory TTL cache.

    Tier 1 — MaxMind GeoLite2 local DB (sub-millisecond, offline).
    Tier 2 — ip-api.com REST API fallback (~150 ms, free, 45 req/min).

    If neither is available the result is a best-effort unknown record so
    callers never receive None or raise an exception.

    Parameters:
        db_path — explicit path to GeoLite2-City.mmdb; if None the module
                  searches the candidate list defined in _GEOIP_DB_CANDIDATES.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._reader   = None
        self._cache:   dict[str, tuple] = {}
        self._use_mmdb = False

        db = Path(db_path) if db_path else self._find_mmdb()
        if db and db.exists():
            self._use_mmdb = self._open_mmdb(db)
        else:
            logger.warning(
                "GeoLite2-City.mmdb not found — falling back to ip-api.com REST"
            )

        source = "MaxMind GeoLite2" if self._use_mmdb else "ip-api.com (fallback)"
        logger.info("Geolocator ready — source: %s", source)

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_mmdb() -> Optional[Path]:
        for candidate in _GEOIP_DB_CANDIDATES:
            if candidate.exists():
                return candidate
        return None

    def _open_mmdb(self, path: Path) -> bool:
        try:
            import geoip2.database  # type: ignore
            self._reader = geoip2.database.Reader(str(path))
            logger.info("MaxMind DB opened: %s", path)
            return True
        except ImportError:
            logger.warning("geoip2 package not installed — cannot use MaxMind DB")
        except Exception as exc:
            logger.warning("Failed to open MaxMind DB %s: %s", path, exc)
        return False

    # ------------------------------------------------------------------
    # Lookup backends
    # ------------------------------------------------------------------

    def _lookup_mmdb(self, ip: str) -> Optional[GeoResult]:
        if not self._reader:
            return None
        try:
            r = self._reader.city(ip)
            return GeoResult(
                ip=ip,
                country_code=r.country.iso_code or "XX",
                country_name=r.country.name or "Unknown",
                city=(r.city.name or "Unknown"),
                latitude=float(r.location.latitude or 0.0),
                longitude=float(r.location.longitude or 0.0),
                asn="",
                isp="",
                is_vpn_or_proxy=False,
                source="maxmind",
            )
        except Exception as exc:
            logger.debug("MaxMind lookup failed for %s: %s", ip, exc)
            return None

    def _lookup_ipapi(self, ip: str) -> Optional[GeoResult]:
        try:
            resp = requests.get(
                _IPAPI_URL.format(ip=ip),
                timeout=_HTTP_TIMEOUT_S,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") != "success":
                logger.debug("ip-api.com returned non-success for %s: %s", ip, data)
                return None
            return GeoResult(
                ip=ip,
                country_code=data.get("countryCode", "XX"),
                country_name=data.get("country", "Unknown"),
                city=data.get("city", "Unknown"),
                latitude=float(data.get("lat", 0.0)),
                longitude=float(data.get("lon", 0.0)),
                asn=data.get("as", ""),
                isp=data.get("isp", ""),
                is_vpn_or_proxy=bool(data.get("proxy") or data.get("hosting")),
                source="ip-api.com",
            )
        except requests.RequestException as exc:
            logger.warning("ip-api.com lookup failed for %s: %s", ip, exc)
        except (ValueError, KeyError) as exc:
            logger.warning("ip-api.com parse error: %s", exc)
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def locate(self, ip: str) -> GeoResult:
        """
        Resolve an IP address to geographic and network metadata.

        Checks in-memory cache first; on miss, tries MaxMind DB then
        ip-api.com. Never raises — returns an unknown-filled GeoResult
        on total failure.

        Inputs:  ip — IPv4 or IPv6 string
        Outputs: GeoResult dataclass
        """
        t0 = time.monotonic()

        cached = self._cache.get(ip)
        if cached:
            result, ts = cached
            if time.monotonic() - ts < _CACHE_TTL_S:
                result.latency_ms = round((time.monotonic() - t0) * 1000, 2)
                return result

        result: Optional[GeoResult] = None

        if self._use_mmdb:
            result = self._lookup_mmdb(ip)

        if result is None:
            result = self._lookup_ipapi(ip)

        if result is None:
            result = _unknown_result(ip)

        result.latency_ms = round((time.monotonic() - t0) * 1000, 2)
        self._cache[ip] = (result, time.monotonic())

        logger.debug(
            "Geo: %s → %s/%s (%.1f ms via %s)",
            ip, result.country_code, result.city,
            result.latency_ms, result.source,
        )
        return result

    def bulk_locate(self, ips: list[str]) -> list[GeoResult]:
        """
        Locate multiple IPs sequentially, leveraging the cache for repeats.

        Inputs:  ips — list of IP strings
        Outputs: list of GeoResult in the same order
        """
        return [self.locate(ip) for ip in ips]

    def invalidate_cache(self, ip: Optional[str] = None) -> None:
        """Evict one IP or the entire geo cache."""
        if ip is None:
            self._cache.clear()
            logger.info("Geo cache cleared")
        else:
            self._cache.pop(ip, None)

    def close(self) -> None:
        """Release the MaxMind DB file handle."""
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None
