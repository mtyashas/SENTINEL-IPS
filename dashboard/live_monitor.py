"""
dashboard/live_monitor.py

Purpose: Real-time flow throughput and alert stream data structures for the
         SENTINEL IPS v2.0 Streamlit dashboard. Maintains an in-memory ring
         buffer of recent detection events, per-second throughput samples, and
         per-attack-type counters so the dashboard can render live gauges and
         scrolling alert tables without touching disk on every refresh.

Inputs:  Detection event dicts pushed via push_event(); throughput samples
         pushed via record_throughput().
Outputs: Snapshot dicts consumed by dashboard/app.py widgets.

Usage:
    from dashboard.live_monitor import LiveMonitor
    monitor = LiveMonitor()
    monitor.push_event({"attack_type": "DDoS", "src_ip": "1.2.3.4",
                        "confidence": 0.97, "severity": "HIGH"})
    snapshot = monitor.snapshot()
"""

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

logger = logging.getLogger(__name__)

# Ring buffer capacities
_MAX_EVENTS     = 500     # keep last N detection events
_MAX_THROUGHPUT = 120     # keep last N throughput samples (2 min @ 1 Hz)

# Severity display colours (CSS hex — consumed by Streamlit markdown)
SEVERITY_COLOURS: dict[str, str] = {
    "CRITICAL": "#E53935",
    "HIGH":     "#FB8C00",
    "MEDIUM":   "#FDD835",
    "LOW":      "#43A047",
    "INFO":     "#29B6F6",
}


@dataclass
class ThroughputSample:
    timestamp: float   # time.monotonic()
    fps:       float   # flows per second at that moment


@dataclass
class DetectionEvent:
    timestamp:   float
    attack_type: str
    src_ip:      str
    dst_ip:      str
    confidence:  float
    severity:    str
    mitre_tactic: str
    risk_score:  float
    action:      str
    extra:       dict = field(default_factory=dict)

    @property
    def age_s(self) -> float:
        return round(time.monotonic() - self.timestamp, 1)

    def to_row(self) -> dict:
        return {
            "time":        time.strftime("%H:%M:%S", time.localtime(time.time() - self.age_s)),
            "attack":      self.attack_type,
            "src_ip":      self.src_ip,
            "confidence":  f"{self.confidence * 100:.1f}%",
            "severity":    self.severity,
            "tactic":      self.mitre_tactic,
            "risk":        f"{self.risk_score:.1f}",
            "action":      self.action,
            # attribution.threat_profiler.ThreatActorProfiler already
            # classifies every attacker (APT/Organised/ScriptKiddie/
            # Insider) and sentinel.py already pushes both fields into
            # every event -- they landed in `extra` via push_event()'s
            # generic passthrough but were never surfaced here, so the
            # dashboard never showed them despite the data existing.
            "actor_class":    self.extra.get("actor_class", "Unknown"),
            "sophistication": self.extra.get("sophistication", 0),
        }


class LiveMonitor:
    """
    Thread-safe in-memory monitor for real-time SENTINEL dashboard data.

    push_event(event_dict)       -- ingest a new detection event
    record_throughput(fps)       -- record one throughput sample
    snapshot()                   -- return a consistent dashboard snapshot
    attack_type_counts()         -- dict of attack_type -> count (last window)
    clear()                      -- reset all buffers

    All public methods are thread-safe via a single Lock.
    """

    def __init__(self) -> None:
        self._lock        = Lock()
        self._events:     deque[DetectionEvent] = deque(maxlen=_MAX_EVENTS)
        self._throughput: deque[ThroughputSample] = deque(maxlen=_MAX_THROUGHPUT)
        self._total_flows       = 0
        self._total_attacks     = 0
        self._session_start     = time.monotonic()
        logger.info("LiveMonitor initialised (event_cap=%d, tput_cap=%d)",
                    _MAX_EVENTS, _MAX_THROUGHPUT)

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def push_event(self, event: dict) -> None:
        """
        Ingest a detection event dict from the detection engine.

        Recognised keys: attack_type, src_ip, dst_ip, confidence,
        severity, mitre_tactic, risk_score, action.  All optional
        with safe defaults.
        """
        det = DetectionEvent(
            timestamp=time.monotonic(),
            attack_type=str(event.get("attack_type", "Unknown")),
            src_ip=str(event.get("src_ip", "0.0.0.0")),
            dst_ip=str(event.get("dst_ip", "0.0.0.0")),
            confidence=float(event.get("confidence", 0.0)),
            severity=str(event.get("severity", "INFO")),
            mitre_tactic=str(event.get("mitre_tactic", "Unknown")),
            risk_score=float(event.get("risk_score", 0.0)),
            action=str(event.get("action", "log")),
            extra={k: v for k, v in event.items()
                   if k not in ("attack_type", "src_ip", "dst_ip", "confidence",
                                "severity", "mitre_tactic", "risk_score", "action")},
        )
        with self._lock:
            self._events.append(det)
            self._total_attacks += 1

    def record_throughput(self, fps: float) -> None:
        """Record a flows-per-second sample from the ingestion layer."""
        sample = ThroughputSample(timestamp=time.monotonic(), fps=fps)
        with self._lock:
            self._throughput.append(sample)
            self._total_flows += int(fps)

    def increment_flows(self, n: int = 1) -> None:
        """Increment total flow counter without recording a throughput sample."""
        with self._lock:
            self._total_flows += n

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def snapshot(self) -> dict:
        """
        Return a consistent snapshot of current monitor state for the dashboard.

        Fields:
            events_list       -- list of row dicts (newest first)
            throughput_fps    -- list of fps values (chronological)
            current_fps       -- most recent fps sample
            total_flows       -- cumulative flows processed
            total_attacks     -- cumulative attack detections
            attack_counts     -- dict[attack_type, count]
            severity_counts   -- dict[severity, count]
            uptime_s          -- seconds since monitor start
        """
        with self._lock:
            events_snap = list(self._events)
            tput_snap   = list(self._throughput)
            total_f     = self._total_flows
            total_a     = self._total_attacks
            uptime      = round(time.monotonic() - self._session_start, 1)

        events_snap.reverse()          # newest first for the table

        attack_counts:   dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        for ev in events_snap:
            attack_counts[ev.attack_type]   = attack_counts.get(ev.attack_type, 0)   + 1
            severity_counts[ev.severity]    = severity_counts.get(ev.severity, 0)    + 1

        current_fps = tput_snap[-1].fps if tput_snap else 0.0

        return {
            "events_list":     [e.to_row() for e in events_snap],
            "throughput_fps":  [s.fps for s in tput_snap],
            "current_fps":     current_fps,
            "total_flows":     total_f,
            "total_attacks":   total_a,
            "attack_counts":   attack_counts,
            "severity_counts": severity_counts,
            "uptime_s":        uptime,
        }

    def attack_type_counts(self, last_n: int = _MAX_EVENTS) -> dict[str, int]:
        """Return attack_type -> count for the last `last_n` events."""
        with self._lock:
            events = list(self._events)[-last_n:]
        counts: dict[str, int] = {}
        for ev in events:
            counts[ev.attack_type] = counts.get(ev.attack_type, 0) + 1
        return counts

    def recent_events(self, n: int = 20) -> list[dict]:
        """Return the most recent n events as row dicts (newest first)."""
        with self._lock:
            events = list(self._events)
        events.reverse()
        return [e.to_row() for e in events[:n]]

    def clear(self) -> None:
        """Reset all buffers. Useful for testing."""
        with self._lock:
            self._events.clear()
            self._throughput.clear()
            self._total_flows   = 0
            self._total_attacks = 0
            self._session_start = time.monotonic()
        logger.info("LiveMonitor cleared")
