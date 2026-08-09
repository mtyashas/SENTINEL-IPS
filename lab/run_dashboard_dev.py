"""
lab/run_dashboard_dev.py

Purpose: Manual QA harness for dashboard/server.py and dashboard/web --
         NOT part of the sentinel.py product surface. sentinel.py live is
         live-only (no synthetic data), per
         docs/superpowers/specs/2026-08-09-live-dashboard-design.md.
         This script starts the embedded dashboard server against a
         LiveMonitor/AttackMap fed a rotating stream of synthetic
         detection events, so the frontend can be developed and eyeballed
         in a browser without needing a real packet capture running.

Usage:
    python lab/run_dashboard_dev.py
    # then open http://localhost:5000
"""
import random
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from dashboard.attack_map import AttackMap
from dashboard.live_monitor import LiveMonitor
from dashboard.server import start_dashboard_server

_SAMPLE_ATTACKS = [
    ("DDoS", "HIGH", "Impact", "203.0.113.10", "United States", "USA", 37.09, -95.71),
    ("PortScan", "LOW", "Discovery", "198.51.100.5", "Russia", "RUS", 61.52, 105.31),
    ("BruteForce", "MEDIUM", "Initial Access", "192.0.2.88", "China", "CHN", 35.86, 104.19),
    ("Bot", "HIGH", "Persistence", "185.220.101.5", "Germany", "DEU", 51.16, 10.45),
    ("SQLInjection", "MEDIUM", "Execution", "203.0.113.77", "Brazil", "BRA", -14.23, -51.92),
    ("Infiltration", "CRITICAL", "Lateral Movement", "198.51.100.42", "North Korea", "PRK", 40.33, 127.51),
]


def main() -> None:
    monitor = LiveMonitor()
    amap = AttackMap()
    start_dashboard_server(monitor, amap)
    print("Dev dashboard running at http://localhost:5000 -- Ctrl+C to stop")

    rng = random.Random()
    try:
        while True:
            atk, sev, tactic, ip, country, code, lat, lon = rng.choice(_SAMPLE_ATTACKS)
            event = {
                "attack_type": atk, "severity": sev, "mitre_tactic": tactic,
                "src_ip": ip, "confidence": round(rng.uniform(0.65, 0.99), 3),
                "risk_score": round(rng.uniform(30, 98), 1), "action": "ip_block",
                "lat": lat + rng.uniform(-2, 2), "lon": lon + rng.uniform(-2, 2),
                "country": country, "country_code": code, "city": "Unknown",
            }
            monitor.push_event(event)
            amap.ingest(event)
            monitor.record_throughput(rng.uniform(800_000, 1_700_000))
            time.sleep(3)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
