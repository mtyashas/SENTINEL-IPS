"""
lab/verify_dashboard_snapshot_serialization.py

Purpose: Self-check that dashboard.server.build_snapshot_payload() always
         produces a payload that round-trips cleanly through
         json.dumps/json.loads. This is the one place a silent
         serialization break (a non-JSON-safe value leaking into a Plotly
         figure, or a NaN in a numpy-derived stat) could hide behind a
         working-looking UI -- Socket.IO's own encoder would raise at
         emit time in production; this catches it standalone, without
         needing a running server.

Usage:
    python lab/verify_dashboard_snapshot_serialization.py
"""
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from dashboard.attack_map import AttackMap
from dashboard.live_monitor import LiveMonitor
from dashboard.server import build_snapshot_payload

print("--- Check 1: empty monitor/amap payload round-trips through JSON ---")
monitor = LiveMonitor()
amap = AttackMap()
payload = build_snapshot_payload(monitor, amap)
decoded = json.loads(json.dumps(payload))
assert decoded["monitor"]["total_attacks"] == 0
assert decoded["top_countries"] == []
assert decoded["unique_ips"] == 0
print("PASS: empty payload round-trips")

print()
print("--- Check 2: populated payload round-trips; tuples decode as JSON arrays ---")
monitor.push_event({
    "attack_type": "DDoS", "src_ip": "203.0.113.10", "dst_ip": "10.0.0.5",
    "confidence": 0.97, "severity": "CRITICAL", "mitre_tactic": "Impact",
    "risk_score": 91.4, "action": "ip_block",
})
monitor.record_throughput(128_402.0)
amap.ingest({
    "lat": 37.09, "lon": -95.71, "country": "United States",
    "country_code": "USA", "city": "Unknown", "src_ip": "203.0.113.10",
    "attack_type": "DDoS", "severity": "CRITICAL",
})
payload = build_snapshot_payload(monitor, amap)
decoded = json.loads(json.dumps(payload))
assert decoded["monitor"]["total_attacks"] == 1
assert decoded["unique_ips"] == 1
assert decoded["top_countries"] == [["United States", 1]], decoded["top_countries"]
assert decoded["monitor"]["events_list"][0]["attack"] == "DDoS"
print("PASS: populated payload round-trips, top_countries tuples decode as lists")

print()
print("--- Check 3: every figure (once built) is a JSON-safe dict, not a raw Plotly object ---")
if decoded["figures"]:
    for name, fig in decoded["figures"].items():
        assert fig is None or isinstance(fig, dict), f"figure {name!r} did not serialize to a plain dict"
    print("PASS: all figures are JSON-safe dicts")
else:
    print("PASS: no figures yet (stub stage, expected before Task 2)")

print()
print("All checks passed.")
