"""
lab/verify_beacon_detection.py

Purpose: Self-check for Bot/C2 beacon detection (2026-07-31, backlog item
         found 2026-07-30: a simulated C2 beacon -- 30x curl at a 10s
         interval -- produced zero detections at any confidence, because a
         single isolated GET has no burst/shape signal distinguishing it
         from ordinary browsing. Fixed with cross-flow connection-timing
         tracking in core/flow_collector.py (FlowCollector.beacon_score())
         and a new rule-based pipeline stage (sentinel.py._run_beacon()),
         rather than a full model retrain -- adding a genuinely new
         stateful feature to the trained ML models would need recomputing
         it across the entire CIC-2017 training set, a much bigger lift
         than this architectural gap needs to justify tonight.

         Confirms: (1) regular-interval connections score as a beacon,
         (2) irregular-interval connections (ordinary browsing) don't,
         (3) _run_beacon() correctly promotes a beacon-flagged flow to
         Bot/pred_binary=1, (4) a chunk with no beacon_detected column
         (simulate mode) is an untouched no-op.

Usage:
    python lab/verify_beacon_detection.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd
from scapy.layers.inet import IP, TCP

from core.flow_collector import FlowCollector
from sentinel import SentinelIPS

SRC, DST = "192.168.56.10", "192.168.56.1"


def make_connection(collector: FlowCollector, sport: int, ts: float) -> None:
    """One minimal 2-packet 'connection' (SYN + RST) at a given src port
    and timestamp -- enough for FlowCollector to register a new flow."""
    syn = IP(src=SRC, dst=DST) / TCP(sport=sport, dport=80, flags="S", seq=1000)
    syn.time = ts
    collector.ingest_packet(syn)
    rst = IP(src=DST, dst=SRC) / TCP(sport=80, dport=sport, flags="R", seq=5000, ack=1001)
    rst.time = ts + 0.01
    collector.ingest_packet(rst)


print("--- Check 1: regular-interval connections (beacon) score as a beacon ---")
collector = FlowCollector()
base = 1_000_000.0
for i in range(10):
    make_connection(collector, sport=40000 + i, ts=base + i * 10.0)   # exactly every 10s
score = collector.beacon_score(SRC, DST)
print(f"Regular: {score}")
assert score["is_beacon"], f"FAIL: regular 10s-interval connections not flagged as beacon: {score}"
print("PASS: regular-interval connections correctly flagged as a beacon")

print()
print("--- Check 2: irregular-interval connections (ordinary browsing) do NOT score as a beacon ---")
collector2 = FlowCollector()
irregular_offsets = [0, 3, 25, 27, 60, 61, 140, 200, 205, 500]   # human-like, bursty
for i, off in enumerate(irregular_offsets):
    make_connection(collector2, sport=50000 + i, ts=base + off)
score2 = collector2.beacon_score(SRC, DST)
print(f"Irregular: {score2}")
assert not score2["is_beacon"], f"FAIL: irregular connections incorrectly flagged as beacon: {score2}"
print("PASS: irregular-interval connections correctly NOT flagged")

print()
print("--- Check 3: _run_beacon() promotes a beacon-flagged flow to Bot ---")
ips = SentinelIPS()  # no model_path needed -- _run_beacon never touches layer1
chunk = pd.DataFrame({
    "beacon_detected": [True, False],
    "src_ip":          [SRC, SRC],
    "destination_port": [80, 80],
})
result = ips._run_beacon(chunk)
assert result.iloc[0]["sig_attack_type"] == "Bot"
assert result.iloc[0]["pred_binary"] == 1
assert result.iloc[0]["confidence"] >= 0.75
assert pd.isna(result.iloc[1]["sig_attack_type"]), "non-beacon row should be untouched"
print(f"PASS: beacon row -> sig_attack_type=Bot, confidence={result.iloc[0]['confidence']:.2f}; "
      f"non-beacon row untouched")

print()
print("--- Check 4: chunk with no beacon_detected column (simulate mode) is a no-op ---")
plain_chunk = pd.DataFrame({"src_ip": [SRC]})
result = ips._run_beacon(plain_chunk)
assert "sig_attack_type" not in result.columns
assert result.equals(plain_chunk)
print("PASS: simulate-mode chunk (no beacon_detected column) passed through untouched")

print()
print("All checks passed.")
