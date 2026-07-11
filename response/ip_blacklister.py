"""
response/ip_blacklister.py

Purpose: Enforce IP blocks at the OS firewall level and maintain the in-memory
         + on-disk blacklist used by the threat intelligence layer. Supports
         timed blocks (1 h, 24 h) and permanent blocks. Block application is
         platform-aware: Windows Firewall (netsh) on win32, iptables on Linux.
         In-memory enforcement is sub-microsecond; OS firewall calls complete
         in well under 100 ms.

Inputs:  IP address string, optional duration seconds (0 = permanent).
Outputs: BlacklistResult dataclass; side-effects on OS firewall and blacklist
         file at threat_intel/ip_blacklist.txt.

Usage:
    from response.ip_blacklister import IPBlacklister
    bl = IPBlacklister()
    result = bl.block("1.2.3.4", duration_s=3600, reason="BruteForce")
    print(result.success, result.method, result.latency_ms)
"""

import logging
import platform
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import THREAT_DIR

logger = logging.getLogger(__name__)

_BLACKLIST_PATH  = THREAT_DIR / "ip_blacklist.txt"
_OS              = platform.system()   # "Windows" | "Linux" | "Darwin"
_RULE_PREFIX     = "SENTINEL_BLOCK"    # prefix for named firewall rules


@dataclass
class BlacklistResult:
    ip:          str
    success:     bool
    method:      str       # "memory_only" | "netsh" | "iptables" | "noop"
    reason:      str
    expires_at:  Optional[datetime]
    latency_ms:  float


@dataclass
class _BlockEntry:
    ip:         str
    reason:     str
    blocked_at: datetime
    expires_at: Optional[datetime]   # None = permanent


class IPBlacklister:
    """
    Multi-tier IP blocking engine.

    Tier 1 — In-memory set  : checked on every flow, O(1), never expires early.
    Tier 2 — OS firewall    : drops packets before they reach userspace.
    Tier 3 — Disk blacklist : persisted across restarts.

    Expiry is enforced by a background daemon thread that runs every 60 s
    and removes timed-out entries from memory and the firewall.

    Parameters:
        enforce_os_firewall — if True (default), apply actual firewall rules.
                              Set False in unit tests or sandboxed environments.
    """

    def __init__(self, enforce_os_firewall: bool = True) -> None:
        self._entries:       dict[str, _BlockEntry] = {}
        self._lock           = threading.Lock()
        self._enforce_fw     = enforce_os_firewall
        self._os             = _OS

        self._load_persistent_blacklist()
        self._start_expiry_thread()

        logger.info(
            "IPBlacklister ready — OS=%s, fw_enforcement=%s, loaded=%d IPs",
            self._os, enforce_os_firewall, len(self._entries),
        )

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _load_persistent_blacklist(self) -> None:
        if not _BLACKLIST_PATH.exists():
            return
        try:
            lines = _BLACKLIST_PATH.read_text(encoding="utf-8").splitlines()
            for line in lines:
                ip = line.strip()
                if ip and not ip.startswith("#") and ip not in self._entries:
                    self._entries[ip] = _BlockEntry(
                        ip=ip,
                        reason="persistent_blacklist",
                        blocked_at=datetime.now(tz=timezone.utc),
                        expires_at=None,
                    )
            logger.info("Loaded %d IPs from persistent blacklist", len(self._entries))
        except OSError as exc:
            logger.error("Blacklist load failed: %s", exc)

    def _start_expiry_thread(self) -> None:
        t = threading.Thread(target=self._expiry_loop, daemon=True, name="bl-expiry")
        t.start()

    def _expiry_loop(self) -> None:
        while True:
            time.sleep(60)
            self._expire_timed_blocks()

    # ------------------------------------------------------------------
    # OS firewall helpers
    # ------------------------------------------------------------------

    def _apply_fw_block(self, ip: str) -> tuple[bool, str]:
        """Return (success, method_string)."""
        if not self._enforce_fw:
            return True, "noop"
        try:
            if self._os == "Windows":
                return self._netsh_block(ip)
            else:
                return self._iptables_block(ip)
        except Exception as exc:
            logger.error("Firewall block failed for %s: %s", ip, exc)
            return False, "error"

    def _netsh_block(self, ip: str) -> tuple[bool, str]:
        rule_name = f"{_RULE_PREFIX}_{ip.replace('.', '_').replace(':', '_')}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
            "enable=yes",
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            logger.info("netsh blocked %s (rule: %s)", ip, rule_name)
            return True, "netsh"
        logger.warning("netsh block failed for %s: %s", ip, result.stderr.strip())
        return False, "netsh_failed"

    def _iptables_block(self, ip: str) -> tuple[bool, str]:
        cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            logger.info("iptables blocked %s", ip)
            return True, "iptables"
        logger.warning("iptables block failed for %s: %s", ip, result.stderr.strip())
        return False, "iptables_failed"

    def _remove_fw_block(self, ip: str) -> None:
        if not self._enforce_fw:
            return
        try:
            if self._os == "Windows":
                rule_name = f"{_RULE_PREFIX}_{ip.replace('.', '_').replace(':', '_')}"
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule",
                     f"name={rule_name}"],
                    capture_output=True, timeout=5,
                )
            else:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=5,
                )
        except Exception as exc:
            logger.warning("Firewall rule removal failed for %s: %s", ip, exc)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist_ip(self, ip: str) -> None:
        try:
            with _BLACKLIST_PATH.open("a", encoding="utf-8") as fh:
                fh.write(f"{ip}\n")
        except OSError as exc:
            logger.error("Blacklist persist failed for %s: %s", ip, exc)

    def _rewrite_blacklist(self) -> None:
        """Rewrite the blacklist file from current in-memory permanent entries."""
        try:
            permanent = [
                e.ip for e in self._entries.values()
                if e.expires_at is None
            ]
            _BLACKLIST_PATH.write_text(
                "\n".join(permanent) + "\n", encoding="utf-8"
            )
        except OSError as exc:
            logger.error("Blacklist rewrite failed: %s", exc)

    # ------------------------------------------------------------------
    # Expiry
    # ------------------------------------------------------------------

    def _expire_timed_blocks(self) -> None:
        now = datetime.now(tz=timezone.utc)
        expired: list[str] = []

        with self._lock:
            for ip, entry in list(self._entries.items()):
                if entry.expires_at and entry.expires_at <= now:
                    expired.append(ip)
                    del self._entries[ip]

        for ip in expired:
            self._remove_fw_block(ip)
            logger.info("Block expired and removed for %s", ip)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def block(
        self,
        ip:         str,
        duration_s: int  = 0,
        reason:     str  = "unspecified",
    ) -> BlacklistResult:
        """
        Block an IP address at both the memory tier and OS firewall tier.

        Inputs:
            ip         — IPv4 or IPv6 string to block
            duration_s — seconds until automatic unblock; 0 = permanent
            reason     — human-readable reason logged and stored in profile
        Outputs: BlacklistResult with success flag, method, and latency
        """
        t0 = time.monotonic()

        expires_at = None
        if duration_s > 0:
            from datetime import timedelta
            expires_at = datetime.now(tz=timezone.utc) + timedelta(seconds=duration_s)

        with self._lock:
            if ip in self._entries:
                # Upgrade to permanent if already blocked temporarily
                existing = self._entries[ip]
                if existing.expires_at is not None and expires_at is None:
                    existing.expires_at = None
                    logger.info("Block for %s upgraded to permanent", ip)
                latency = round((time.monotonic() - t0) * 1000, 2)
                return BlacklistResult(
                    ip=ip, success=True, method="memory_already_blocked",
                    reason=reason, expires_at=existing.expires_at,
                    latency_ms=latency,
                )

            self._entries[ip] = _BlockEntry(
                ip=ip, reason=reason,
                blocked_at=datetime.now(tz=timezone.utc),
                expires_at=expires_at,
            )

        success, method = self._apply_fw_block(ip)

        if expires_at is None:
            self._persist_ip(ip)

        latency = round((time.monotonic() - t0) * 1000, 2)
        logger.info(
            "Blocked %s via %s reason=%s expires=%s (%.1f ms)",
            ip, method, reason,
            expires_at.isoformat() if expires_at else "permanent",
            latency,
        )
        return BlacklistResult(
            ip=ip, success=success, method=method,
            reason=reason, expires_at=expires_at,
            latency_ms=latency,
        )

    def unblock(self, ip: str) -> bool:
        """
        Immediately lift the block on an IP.

        Inputs:  ip — address to unblock
        Outputs: True if a block was found and removed, False if not blocked
        """
        with self._lock:
            if ip not in self._entries:
                return False
            del self._entries[ip]

        self._remove_fw_block(ip)
        self._rewrite_blacklist()
        logger.info("Unblocked %s", ip)
        return True

    def is_blocked(self, ip: str) -> bool:
        """O(1) membership check against the in-memory block set."""
        with self._lock:
            return ip in self._entries

    def blocked_count(self) -> int:
        with self._lock:
            return len(self._entries)

    def blocked_ips(self) -> list[str]:
        with self._lock:
            return list(self._entries.keys())

    def summary(self) -> dict:
        with self._lock:
            permanent = sum(1 for e in self._entries.values() if e.expires_at is None)
            timed     = len(self._entries) - permanent
        return {
            "total_blocked": len(self._entries),
            "permanent":     permanent,
            "timed":         timed,
            "os_firewall":   self._os if self._enforce_fw else "disabled",
        }
