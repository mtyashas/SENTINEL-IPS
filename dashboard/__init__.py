"""dashboard — SENTINEL IPS v2.0 real-time SOC dashboard."""

from dashboard.live_monitor import LiveMonitor, DetectionEvent, ThroughputSample, SEVERITY_COLOURS
from dashboard.attack_map import AttackMap, GeoHit

__all__ = [
    "LiveMonitor",
    "DetectionEvent",
    "ThroughputSample",
    "SEVERITY_COLOURS",
    "AttackMap",
    "GeoHit",
]
