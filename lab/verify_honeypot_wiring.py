"""
lab/verify_honeypot_wiring.py

Purpose: Self-check for wiring HoneypotMonitor into the live pipeline
         (2026-07-31). intelligence/honeypot.py was fully implemented
         (fake SSH/FTP/admin/DB/API listeners, PCAP capture, auto-blacklist,
         attacker profiling) but never instantiated or started anywhere in
         sentinel.py -- grepping the file, the only reference was a
         module-name string in the health-check list. Confirms, without
         opening a real socket (HoneypotMonitor.simulate_hit() is built for
         exactly this): a decoy-service hit reaches
         SentinelIPS._run_honeypot_response(), gets a real IPBlacklister
         block, CRITICAL severity, and shows up on the dashboard feed.

Usage:
    python lab/verify_honeypot_wiring.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from intelligence.honeypot import HoneypotMonitor
from sentinel import SentinelIPS

ATTACKER_IP = "203.0.113.66"   # TEST-NET-3, safe to use as a fake attacker

print("--- Building a SentinelIPS instance and wiring a HoneypotMonitor ---")
ips = SentinelIPS()  # no model_path needed -- honeypot path never touches layer1
honeypot = HoneypotMonitor(on_hit=ips._run_honeypot_response)

print(f"--- Simulating a hit on fake_ssh from {ATTACKER_IP} ---")
honeypot.simulate_hit(ATTACKER_IP, 2222, payload=b"SSH-2.0-libssh\r\n")

print()
print("--- Check 1: IP genuinely blocked via IPBlacklister ---")
assert ips._blacklist.is_blocked(ATTACKER_IP), (
    f"FAIL: {ATTACKER_IP} was not blocked after a honeypot hit"
)
print(f"PASS: {ATTACKER_IP} is blocked ({ips._blacklist.summary()})")

print()
print("--- Check 2: event pushed to the dashboard feed as CRITICAL ---")
events = ips.monitor.snapshot()["events_list"]
matches = [e for e in events if e.get("src_ip") == ATTACKER_IP
           and e.get("attack") == "Honeypot"]
assert matches, "FAIL: no Honeypot event found in the dashboard feed"
assert matches[-1]["severity"] == "CRITICAL", (
    f"FAIL: expected CRITICAL severity, got {matches[-1]['severity']!r}"
)
print(f"PASS: Honeypot event present, severity={matches[-1]['severity']}")

print()
print("--- Check 3: HoneypotMonitor's own record also shows the hit ---")
assert honeypot.event_summary()["total_hits"] == 1
print("PASS: HoneypotMonitor recorded the hit independently")

print()
print("All checks passed.")
