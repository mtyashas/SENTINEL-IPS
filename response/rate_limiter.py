"""
response/rate_limiter.py

Purpose: Token-bucket rate limiter that throttles suspicious IPs before they
         trigger a full block. Each IP gets an independent bucket refilled at
         a configurable rate; requests that exhaust the bucket are rejected.
         Attack-type–specific limits from the RESPONSE_MATRIX are applied
         automatically so DDoS sources are throttled more aggressively than
         port scanners.

Inputs:  IP address string; optional attack context dict.
Outputs: RateLimitResult dataclass with allowed/denied verdict and metadata.

Usage:
    from response.rate_limiter import RateLimiter
    rl = RateLimiter()
    result = rl.check("1.2.3.4", attack_type="DDoS")
    if not result.allowed:
        drop_packet()
"""

import logging
import threading
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Per-attack-type rate limits  (requests per second allowed per IP)
# Tighter limits for volumetric attacks; looser for low-frequency probes.
# ---------------------------------------------------------------------------

_ATTACK_LIMITS: dict[str, float] = {
    "DDoS":         5.0,
    "DoS":          10.0,
    "BruteForce":   2.0,
    "PortScan":     20.0,
    "Bot":          5.0,
    "SQLInjection": 3.0,
    "XSS":          3.0,
    "Infiltration": 1.0,
    "Heartbleed":   1.0,
    "ZeroDay":      1.0,
    "APT":          1.0,
    "Phishing":     5.0,
    "default":      30.0,    # unknown or benign-looking traffic
}

# Bucket capacity = rate × burst_multiplier  (tokens)
_BURST_MULTIPLIER = 3.0


@dataclass
class RateLimitResult:
    ip:              str
    allowed:         bool
    tokens_remaining: float
    limit_rps:       float     # configured limit for this IP's attack context
    attack_type:     Optional[str]
    wait_s:          float     # seconds until next token available (0 if allowed)


class _TokenBucket:
    """Thread-safe token bucket for a single IP."""

    __slots__ = ("_rate", "_capacity", "_tokens", "_last_refill", "_lock")

    def __init__(self, rate_rps: float) -> None:
        self._rate      = rate_rps
        self._capacity  = rate_rps * _BURST_MULTIPLIER
        self._tokens    = self._capacity
        self._last_refill = time.monotonic()
        self._lock      = threading.Lock()

    def consume(self, tokens: float = 1.0) -> tuple[bool, float, float]:
        """
        Attempt to consume tokens from the bucket.
        Returns (allowed, tokens_remaining, wait_seconds).
        """
        with self._lock:
            now    = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                self._capacity,
                self._tokens + elapsed * self._rate,
            )
            self._last_refill = now

            if self._tokens >= tokens:
                self._tokens -= tokens
                return True, self._tokens, 0.0
            else:
                deficit  = tokens - self._tokens
                wait_s   = deficit / self._rate
                return False, self._tokens, wait_s

    def update_rate(self, new_rate_rps: float) -> None:
        with self._lock:
            self._rate     = new_rate_rps
            self._capacity = new_rate_rps * _BURST_MULTIPLIER


class RateLimiter:
    """
    Per-IP token-bucket rate limiter with attack-type–aware limits.

    Buckets are created on first sight of each IP and evicted after
    _IDLE_EVICT_S seconds without traffic to keep memory bounded.

    A background sweeper evicts idle buckets every 5 minutes.

    Parameters:
        default_rps    — fallback rate when attack_type is unknown (default 30)
        idle_evict_s   — seconds of inactivity before bucket is evicted (default 300)
    """

    _IDLE_EVICT_S = 300

    def __init__(
        self,
        default_rps:  float = _ATTACK_LIMITS["default"],
        idle_evict_s: int   = 300,
    ) -> None:
        self._default_rps  = default_rps
        self._idle_evict_s = idle_evict_s
        self._buckets:      dict[str, _TokenBucket] = {}
        self._last_seen:    dict[str, float]         = {}
        self._lock          = threading.Lock()

        self._start_sweep_thread()
        logger.info(
            "RateLimiter ready — default=%.1f rps, idle_evict=%ds",
            default_rps, idle_evict_s,
        )

    # ------------------------------------------------------------------
    # Background eviction
    # ------------------------------------------------------------------

    def _start_sweep_thread(self) -> None:
        t = threading.Thread(
            target=self._sweep_loop, daemon=True, name="rl-sweep"
        )
        t.start()

    def _sweep_loop(self) -> None:
        while True:
            time.sleep(300)
            self._evict_idle()

    def _evict_idle(self) -> None:
        now  = time.monotonic()
        with self._lock:
            stale = [
                ip for ip, ts in self._last_seen.items()
                if now - ts > self._idle_evict_s
            ]
            for ip in stale:
                self._buckets.pop(ip, None)
                self._last_seen.pop(ip, None)
        if stale:
            logger.debug("Rate-limiter evicted %d idle buckets", len(stale))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_limit(self, attack_type: Optional[str]) -> float:
        if attack_type and attack_type in _ATTACK_LIMITS:
            return _ATTACK_LIMITS[attack_type]
        return self._default_rps

    def _get_or_create_bucket(self, ip: str, rate_rps: float) -> _TokenBucket:
        with self._lock:
            if ip not in self._buckets:
                self._buckets[ip] = _TokenBucket(rate_rps)
            else:
                # Tighten the rate if a stricter attack context is now known
                existing = self._buckets[ip]
                if rate_rps < existing._rate:
                    existing.update_rate(rate_rps)
            self._last_seen[ip] = time.monotonic()
            return self._buckets[ip]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self,
        ip:          str,
        attack_type: Optional[str] = None,
        tokens:      float         = 1.0,
    ) -> RateLimitResult:
        """
        Check whether traffic from this IP is within the allowed rate.

        Consumes one token from the bucket. If the bucket is empty the
        request is denied and wait_s indicates when a token will be available.

        Inputs:
            ip          — source IP string
            attack_type — detected attack class (tightens the limit if known)
            tokens      — cost of this request in token units (default 1.0)
        Outputs: RateLimitResult
        """
        limit_rps = self._get_limit(attack_type)
        bucket    = self._get_or_create_bucket(ip, limit_rps)
        allowed, remaining, wait_s = bucket.consume(tokens)

        if not allowed:
            logger.debug(
                "Rate-limited %s (%s) — remaining=%.2f, wait=%.2fs",
                ip, attack_type or "unknown", remaining, wait_s,
            )

        return RateLimitResult(
            ip=ip,
            allowed=allowed,
            tokens_remaining=round(remaining, 3),
            limit_rps=limit_rps,
            attack_type=attack_type,
            wait_s=round(wait_s, 3),
        )

    def force_throttle(self, ip: str, rate_rps: float = 0.1) -> None:
        """
        Override the rate for an IP to near-zero, effectively blocking all
        traffic without a hard firewall rule. Useful for temporary soft-blocks
        where connection state should be preserved.

        Inputs:
            ip       — IP to throttle
            rate_rps — new tokens-per-second (default 0.1 = 1 req per 10 s)
        """
        with self._lock:
            if ip in self._buckets:
                self._buckets[ip].update_rate(rate_rps)
            else:
                self._buckets[ip] = _TokenBucket(rate_rps)
            self._last_seen[ip] = time.monotonic()
        logger.info("Force-throttled %s to %.2f rps", ip, rate_rps)

    def reset(self, ip: str) -> None:
        """Remove the rate-limit bucket for an IP (e.g. after block expires)."""
        with self._lock:
            self._buckets.pop(ip, None)
            self._last_seen.pop(ip, None)
        logger.debug("Rate-limit bucket reset for %s", ip)

    def status(self, ip: str) -> Optional[dict]:
        """
        Return current bucket state for an IP without consuming tokens.

        Outputs: dict with rate_rps, tokens, capacity; None if not tracked
        """
        with self._lock:
            bucket = self._buckets.get(ip)
            if not bucket:
                return None
            return {
                "ip":       ip,
                "rate_rps": bucket._rate,
                "capacity": bucket._capacity,
                "tokens":   round(bucket._tokens, 3),
            }

    def active_count(self) -> int:
        """Number of IPs currently tracked by the rate limiter."""
        with self._lock:
            return len(self._buckets)
