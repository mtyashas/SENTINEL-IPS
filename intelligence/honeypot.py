"""
intelligence/honeypot.py

Purpose: Honeypot deception layer that listens on decoy service ports (fake SSH,
         FTP, admin panel, database, API). Any connection to a honeypot port is
         100% confirmed malicious — zero false positives by design.

         On detection the receiver:
           1. Logs full connection details with timestamp
           2. Writes a PCAP-formatted record to pcap/
           3. Immediately blocks the source IP (via callback)
           4. Adds IP to the local threat-intel blacklist
           5. Builds an attacker profile entry
           6. Fires a CRITICAL alert

Inputs:  Incoming connection metadata (ip, port, timestamp, payload).
Outputs: HoneypotEvent dataclass with full forensic detail; alert dispatched
         via registered callback.

Usage:
    from intelligence.honeypot import HoneypotMonitor, HoneypotEvent
    monitor = HoneypotMonitor(on_hit=my_alert_callback)
    monitor.start()          # starts async listener threads
    monitor.simulate_hit("192.168.1.99", 2222)   # for testing
"""

import ipaddress
import json
import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from config import HONEYPOT_SERVICES, PCAP_DIR, THREAT_DIR

logger = logging.getLogger(__name__)

_BANNER_TIMEOUT_S  = 2      # wait for client banner before closing
_LISTEN_BACKLOG    = 5
_MAX_RECV_BYTES    = 4096


# ---------------------------------------------------------------------------
# PCAP writing helpers  (minimal global + per-packet headers)
# ---------------------------------------------------------------------------

def _pcap_global_header() -> bytes:
    """Global header for a PCAP file (little-endian, Ethernet link layer)."""
    return struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,   # magic number
        2, 4,         # major/minor version
        0,            # thiszone (UTC)
        0,            # sigfigs
        65535,        # snaplen
        1,            # network — LINKTYPE_ETHERNET
    )


def _fake_ethernet_ip_tcp(src_ip: str, dst_port: int, payload: bytes) -> bytes:
    """
    Build a minimal fake Ethernet+IP+TCP frame carrying the payload.
    Used only for PCAP forensic logging — not sent over the wire.
    """
    # Ethernet header: src mac, dst mac, ethertype IPv4
    eth = b"\x00" * 6 + b"\xff" * 6 + b"\x08\x00"

    # IP header (no options)
    try:
        src_packed = socket.inet_aton(src_ip)
    except OSError:
        src_packed = b"\x00" * 4
    dst_packed = b"\x7f\x00\x00\x01"   # loopback as honeypot dst

    ip_len = 20 + 20 + len(payload)   # IP + TCP + payload
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,      # version+IHL
        0,         # DSCP+ECN
        ip_len,
        0,         # ID
        0x40 << 8, # flags (DF)
        64,        # TTL
        6,         # proto TCP
        0,         # checksum (zero for logging)
        src_packed,
        dst_packed,
    )

    # TCP header (minimal, SYN flag set)
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        0,           # src port (unknown)
        dst_port,
        0,           # seq
        0,           # ack
        0x50,        # data offset (5*4=20 bytes)
        0x02,        # flags: SYN
        65535,       # window
        0,           # checksum (zero for logging)
        0,           # urgent
    )

    return eth + ip_hdr + tcp_hdr + payload


def _pcap_record(raw_frame: bytes) -> bytes:
    """Wrap a raw frame in a PCAP packet record header."""
    ts = time.time()
    ts_sec  = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    length  = len(raw_frame)
    return struct.pack("<IIII", ts_sec, ts_usec, length, length) + raw_frame


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class HoneypotEvent:
    timestamp:       datetime
    src_ip:          str
    dst_port:        int
    service_name:    str
    payload:         bytes
    attacker_profile: dict = field(default_factory=dict)
    pcap_path:       Optional[Path] = None
    blocked:         bool = False


# ---------------------------------------------------------------------------
# Listener thread
# ---------------------------------------------------------------------------

class _HoneypotListener(threading.Thread):
    """
    Single-port TCP honeypot listener.

    Accepts one connection at a time, grabs the banner/payload, then
    fires the parent monitor's hit handler before closing the socket.
    """

    def __init__(
        self,
        service: dict,
        on_hit: Callable[["HoneypotEvent"], None],
    ) -> None:
        super().__init__(daemon=True, name=f"honeypot-{service['name']}")
        self._service = service
        self._on_hit  = on_hit
        self._stop_evt = threading.Event()

    def stop(self) -> None:
        self._stop_evt.set()

    def run(self) -> None:
        port = self._service["port"]
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(_LISTEN_BACKLOG)
            srv.settimeout(1.0)
            logger.info("Honeypot %s listening on port %d", self._service["name"], port)
        except OSError as exc:
            logger.error(
                "Honeypot %s failed to bind port %d: %s",
                self._service["name"], port, exc,
            )
            return

        while not self._stop_evt.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if not self._stop_evt.is_set():
                    logger.error("Accept error on port %d: %s", port, exc)
                break

            try:
                conn.settimeout(_BANNER_TIMEOUT_S)
                try:
                    payload = conn.recv(_MAX_RECV_BYTES)
                except socket.timeout:
                    payload = b""
                finally:
                    conn.close()

                src_ip = addr[0]
                event  = HoneypotEvent(
                    timestamp=datetime.now(tz=timezone.utc),
                    src_ip=src_ip,
                    dst_port=port,
                    service_name=self._service["name"],
                    payload=payload,
                )
                self._on_hit(event)

            except Exception as exc:
                logger.error("Honeypot connection handler error: %s", exc)

        srv.close()
        logger.info("Honeypot %s stopped", self._service["name"])


# ---------------------------------------------------------------------------
# Main monitor
# ---------------------------------------------------------------------------

class HoneypotMonitor:
    """
    Coordinates all honeypot listener threads and post-hit response actions.

    Every hit triggers (in order):
      1. Attacker profiling
      2. PCAP write to pcap/honeypot_<ip>_<ts>.pcap
      3. Local blacklist update (threat_intel/ip_blacklist.txt)
      4. User-supplied on_hit callback (for alert dispatch / IP blocking)

    Zero false positives: no legitimate traffic ever reaches honeypot ports.

    Parameters:
        on_hit  — callable receiving HoneypotEvent; use for alerting/blocking
        services — list of service dicts (defaults to config.HONEYPOT_SERVICES)
    """

    def __init__(
        self,
        on_hit:   Optional[Callable[[HoneypotEvent], None]] = None,
        services: Optional[list[dict]] = None,
    ) -> None:
        self._services  = services or HONEYPOT_SERVICES
        self._on_hit    = on_hit
        self._listeners: list[_HoneypotListener] = []
        self._events:    list[HoneypotEvent]      = []
        self._lock       = threading.Lock()
        self._blacklist_path = THREAT_DIR / "ip_blacklist.txt"

        logger.info(
            "HoneypotMonitor initialised with %d services",
            len(self._services),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Spawn listener threads for all configured honeypot services."""
        for svc in self._services:
            listener = _HoneypotListener(svc, self._handle_hit)
            listener.start()
            self._listeners.append(listener)
        logger.info("All honeypot listeners started")

    def stop(self) -> None:
        """Signal all listener threads to stop and wait for them to exit."""
        for listener in self._listeners:
            listener.stop()
        for listener in self._listeners:
            listener.join(timeout=3)
        self._listeners.clear()
        logger.info("All honeypot listeners stopped")

    # ------------------------------------------------------------------
    # Hit handling
    # ------------------------------------------------------------------

    def _handle_hit(self, event: HoneypotEvent) -> None:
        """Orchestrate all post-detection actions for a confirmed hit."""
        logger.critical(
            "HONEYPOT HIT — src=%s port=%d service=%s",
            event.src_ip, event.dst_port, event.service_name,
        )

        event.attacker_profile = self._build_profile(event)
        event.pcap_path        = self._write_pcap(event)
        self._update_blacklist(event.src_ip)

        with self._lock:
            self._events.append(event)

        if self._on_hit:
            try:
                self._on_hit(event)
            except Exception as exc:
                logger.error("on_hit callback raised: %s", exc)

    def _build_profile(self, event: HoneypotEvent) -> dict:
        """Construct an initial attacker profile from connection metadata."""
        profile = {
            "first_seen":   event.timestamp.isoformat(),
            "src_ip":       event.src_ip,
            "targeted_port": event.dst_port,
            "service":      event.service_name,
            "payload_hex":  event.payload.hex() if event.payload else "",
            "payload_ascii": event.payload.decode("latin-1", errors="replace"),
            "hit_count":    1,
        }

        # Validate IP and attempt basic classification
        try:
            addr = ipaddress.ip_address(event.src_ip)
            profile["ip_version"] = addr.version
            profile["is_private"] = addr.is_private
            profile["is_loopback"] = addr.is_loopback
        except ValueError:
            profile["ip_version"] = "unknown"

        # Count previous hits from same IP
        with self._lock:
            prior = sum(
                1 for e in self._events
                if e.src_ip == event.src_ip
            )
        if prior > 0:
            profile["hit_count"] = prior + 1
            profile["repeat_attacker"] = True
        else:
            profile["repeat_attacker"] = False

        return profile

    def _write_pcap(self, event: HoneypotEvent) -> Optional[Path]:
        """Write a minimal PCAP file capturing the honeypot connection."""
        ts_str = event.timestamp.strftime("%Y%m%d_%H%M%S")
        safe_ip = event.src_ip.replace(":", "_")
        path    = PCAP_DIR / f"honeypot_{safe_ip}_{ts_str}.pcap"
        try:
            frame  = _fake_ethernet_ip_tcp(
                event.src_ip, event.dst_port, event.payload
            )
            record = _pcap_record(frame)
            with path.open("wb") as fh:
                fh.write(_pcap_global_header())
                fh.write(record)
            logger.info("Honeypot PCAP written: %s", path)
            return path
        except OSError as exc:
            logger.error("Failed to write honeypot PCAP: %s", exc)
            return None

    def _update_blacklist(self, ip: str) -> None:
        """Append the attacker IP to the local threat-intel blacklist."""
        try:
            with self._blacklist_path.open("a", encoding="utf-8") as fh:
                fh.write(f"{ip}\n")
            logger.info("Blacklisted attacker IP: %s", ip)
        except OSError as exc:
            logger.error("Failed to update blacklist with %s: %s", ip, exc)

    # ------------------------------------------------------------------
    # Testing / inspection
    # ------------------------------------------------------------------

    def simulate_hit(self, src_ip: str, dst_port: int, payload: bytes = b"") -> HoneypotEvent:
        """
        Inject a synthetic honeypot hit without opening a real socket.

        Used for integration testing and pipeline validation.

        Inputs:  src_ip   — attacker source IP to simulate
                 dst_port — honeypot port targeted
                 payload  — optional raw payload bytes
        Outputs: HoneypotEvent that was processed
        """
        service_name = next(
            (s["name"] for s in self._services if s["port"] == dst_port),
            "unknown",
        )
        event = HoneypotEvent(
            timestamp=datetime.now(tz=timezone.utc),
            src_ip=src_ip,
            dst_port=dst_port,
            service_name=service_name,
            payload=payload,
        )
        self._handle_hit(event)
        return event

    @property
    def events(self) -> list[HoneypotEvent]:
        """All captured honeypot events (thread-safe snapshot)."""
        with self._lock:
            return list(self._events)

    def event_summary(self) -> dict:
        """Return aggregate statistics across all captured events."""
        with self._lock:
            events = list(self._events)
        if not events:
            return {"total_hits": 0, "unique_attackers": 0, "services_hit": []}
        unique_ips = {e.src_ip for e in events}
        services   = list({e.service_name for e in events})
        return {
            "total_hits":       len(events),
            "unique_attackers": len(unique_ips),
            "services_hit":     services,
            "top_attacker_ip":  max(
                unique_ips,
                key=lambda ip: sum(1 for e in events if e.src_ip == ip),
            ) if unique_ips else None,
        }
