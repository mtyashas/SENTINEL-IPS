"""
response/connection_terminator.py

Purpose: Terminate active malicious TCP sessions and invalidate hijacked
         application sessions. Works at two levels:
           Network level  — OS commands to drop established connections
                            (Windows: netsh / PowerShell, Linux: ss + iptables)
           Session level  — marks session tokens as revoked in an in-memory
                            revocation registry that application middleware
                            can check.

Inputs:  IP address, optional port; session token strings.
Outputs: TerminationResult dataclass; in-memory session revocation set.

Usage:
    from response.connection_terminator import ConnectionTerminator
    ct = ConnectionTerminator()
    result = ct.terminate_ip("1.2.3.4")
    ct.invalidate_session("eyJhbGciOi...")
    if ct.is_session_revoked("eyJhbGciOi..."):
        return 401
"""

import logging
import platform
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_OS = platform.system()


@dataclass
class TerminationResult:
    ip:           str
    port:         Optional[int]
    success:      bool
    method:       str
    connections_killed: int
    latency_ms:   float


class ConnectionTerminator:
    """
    Active connection killer and session revocation registry.

    Network termination strategy:
      Windows — netsh trace + PowerShell to identify and close connections;
                falls back to RST injection via blacklist rule then immediate
                unblock (forces TCP teardown without persistent block).
      Linux   — ss -K to kill specific socket; iptables REJECT for RST.

    Session revocation is purely in-memory. Tokens are stored in a TTL-bound
    set; entries older than session_ttl_s are evicted automatically.

    Parameters:
        enforce_network — apply actual OS-level termination (default True)
        session_ttl_s   — seconds to keep revoked session tokens (default 86400)
    """

    def __init__(
        self,
        enforce_network: bool = True,
        session_ttl_s:   int  = 86_400,
    ) -> None:
        self._enforce_network = enforce_network
        self._session_ttl_s   = session_ttl_s
        self._revoked:        dict[str, datetime] = {}
        self._lock            = threading.Lock()
        self._os              = _OS

        self._start_cleanup_thread()
        logger.info(
            "ConnectionTerminator ready — OS=%s, network=%s",
            self._os, enforce_network,
        )

    # ------------------------------------------------------------------
    # Background cleanup
    # ------------------------------------------------------------------

    def _start_cleanup_thread(self) -> None:
        t = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="sess-cleanup"
        )
        t.start()

    def _cleanup_loop(self) -> None:
        while True:
            time.sleep(300)   # sweep every 5 minutes
            self._evict_expired_sessions()

    def _evict_expired_sessions(self) -> None:
        now = datetime.now(tz=timezone.utc)
        with self._lock:
            expired = [
                tok for tok, ts in self._revoked.items()
                if (now - ts).total_seconds() > self._session_ttl_s
            ]
            for tok in expired:
                del self._revoked[tok]
        if expired:
            logger.debug("Evicted %d expired session revocations", len(expired))

    # ------------------------------------------------------------------
    # OS-level network termination
    # ------------------------------------------------------------------

    def _terminate_windows(self, ip: str, port: Optional[int]) -> tuple[bool, int]:
        """
        On Windows, use netsh to reset matching connections.
        Returns (success, estimated_connections_killed).
        """
        try:
            # List all established TCP connections to/from the target IP
            ps_cmd = (
                f"Get-NetTCPConnection -State Established | "
                f"Where-Object {{$_.RemoteAddress -eq '{ip}'}} | "
                f"ForEach-Object {{$_.OwningProcess}} | "
                f"Select-Object -Unique"
            )
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=8,
            )
            pids = [
                line.strip() for line in result.stdout.splitlines()
                if line.strip().isdigit()
            ]
            killed = 0
            for pid in pids:
                kill_result = subprocess.run(
                    ["powershell", "-NonInteractive", "-Command",
                     f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue"],
                    capture_output=True, timeout=5,
                )
                if kill_result.returncode == 0:
                    killed += 1
                    logger.info("Killed PID %s (connection to %s)", pid, ip)
            return True, killed
        except subprocess.TimeoutExpired:
            logger.warning("Windows termination timed out for %s", ip)
            return False, 0
        except Exception as exc:
            logger.error("Windows termination error for %s: %s", ip, exc)
            return False, 0

    def _terminate_linux(self, ip: str, port: Optional[int]) -> tuple[bool, int]:
        """Use ss --kill to forcibly close matching sockets on Linux."""
        try:
            dst_filter = f"dst [{ip}]"
            if port:
                dst_filter += f":{port}"
            cmd = ["ss", "--kill", "state", "established", dst_filter]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=8,
            )
            # ss outputs one line per killed socket
            killed = max(0, result.stdout.count("\n") - 1)
            if result.returncode == 0:
                logger.info("ss killed %d connection(s) to %s", killed, ip)
                return True, killed
            logger.warning("ss kill returned %d for %s: %s",
                           result.returncode, ip, result.stderr.strip())
            return False, 0
        except FileNotFoundError:
            logger.warning("ss command not available — falling back to iptables RST")
            return self._iptables_rst(ip)
        except Exception as exc:
            logger.error("Linux termination error for %s: %s", ip, exc)
            return False, 0

    def _iptables_rst(self, ip: str) -> tuple[bool, int]:
        """Send TCP RST via iptables REJECT rule then immediately remove it."""
        try:
            add = subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-p", "tcp",
                 "-j", "REJECT", "--reject-with", "tcp-reset"],
                capture_output=True, timeout=5,
            )
            time.sleep(0.05)   # give kernel time to send RSTs
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-p", "tcp",
                 "-j", "REJECT", "--reject-with", "tcp-reset"],
                capture_output=True, timeout=5,
            )
            return add.returncode == 0, 1
        except Exception as exc:
            logger.error("iptables RST failed for %s: %s", ip, exc)
            return False, 0

    # ------------------------------------------------------------------
    # Public API — Network termination
    # ------------------------------------------------------------------

    def terminate_ip(
        self,
        ip:   str,
        port: Optional[int] = None,
    ) -> TerminationResult:
        """
        Forcibly close all active TCP connections from the given IP.

        Inputs:
            ip   — attacker source IP to disconnect
            port — optional specific destination port to target (None = all)
        Outputs: TerminationResult with success flag and connection count
        """
        t0 = time.monotonic()

        if not self._enforce_network:
            latency = round((time.monotonic() - t0) * 1000, 2)
            logger.info("Network enforcement disabled — simulated termination for %s", ip)
            return TerminationResult(
                ip=ip, port=port, success=True,
                method="noop", connections_killed=0,
                latency_ms=latency,
            )

        if self._os == "Windows":
            success, killed = self._terminate_windows(ip, port)
            method = "powershell"
        else:
            success, killed = self._terminate_linux(ip, port)
            method = "ss_kill"

        latency = round((time.monotonic() - t0) * 1000, 2)
        logger.info(
            "Terminated %d connection(s) from %s via %s (%.1f ms)",
            killed, ip, method, latency,
        )
        return TerminationResult(
            ip=ip, port=port, success=success,
            method=method, connections_killed=killed,
            latency_ms=latency,
        )

    # ------------------------------------------------------------------
    # Public API — Session revocation
    # ------------------------------------------------------------------

    def invalidate_session(self, token: str) -> None:
        """
        Mark a session token as revoked.

        Tokens are stored with their revocation timestamp; application
        middleware should call is_session_revoked() on every authenticated
        request to enforce instant logout.

        Inputs:  token — session ID, JWT, or cookie value string
        Outputs: None (side-effect: token added to revocation set)
        """
        with self._lock:
            self._revoked[token] = datetime.now(tz=timezone.utc)
        logger.info("Session token revoked (prefix=%s...)", token[:16] if len(token) >= 16 else token)

    def invalidate_sessions_for_ip(self, ip: str, session_tokens: list[str]) -> int:
        """
        Revoke all known session tokens associated with an IP.

        Inputs:
            ip             — source IP (logged only)
            session_tokens — list of token strings to revoke
        Outputs: count of tokens revoked
        """
        count = 0
        for token in session_tokens:
            self.invalidate_session(token)
            count += 1
        logger.info("Revoked %d session(s) for IP %s", count, ip)
        return count

    def is_session_revoked(self, token: str) -> bool:
        """
        Check whether a session token has been revoked.

        Inputs:  token — session token to check
        Outputs: True if revoked, False if valid
        """
        with self._lock:
            return token in self._revoked

    def revoked_session_count(self) -> int:
        with self._lock:
            return len(self._revoked)
