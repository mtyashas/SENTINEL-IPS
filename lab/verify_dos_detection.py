"""
lab/verify_dos_detection.py

Purpose: Self-check for rule-based DoS/DDoS detection (2026-08-23,
         mirroring lab/verify_beacon_detection.py's exact structure).
         core.flow_collector.FlowCollector.connection_rate() reads the
         same cross-flow _conn_history beacon_score() uses, interpreted
         as raw rate instead of regularity -- confirmed live 2026-08-20/21:
         an hping3 SYN flood was reliably caught by the binary model but
         the multiclass model couldn't name it, falling back to the
         generic ATTACK label with no MITRE mapping (severity capped at
         MEDIUM, since attack-type-keyed lookups have nothing to match).
         Fixed with a rule-based override
         (sentinel.py._run_dos()/_add_dos_column()), the same pattern
         already used for Bot/beacon detection, rather than a multiclass
         retrain -- see
         docs/superpowers/specs/2026-08-23-dos-ddos-multiclass-retrain-design.md's
         Revision History for why.

         Confirms: (1) fast, regular connections (flood-shaped) score as
         a flood, (2) slow/occasional connections (ordinary traffic)
         don't, (3) too little history (below _DOS_MIN_CONNECTIONS)
         returns rate_per_sec=None rather than a misleading 0.0.

Usage:
    python lab/verify_dos_detection.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scapy.layers.inet import IP, TCP

from core.flow_collector import FlowCollector

SRC, DST = "192.168.56.10", "192.168.56.1"


def make_connection(collector: FlowCollector, sport: int, ts: float) -> None:
    """One minimal 2-packet 'connection' (SYN + RST) at a given src port
    and timestamp -- enough for FlowCollector to register a new flow."""
    syn = IP(src=SRC, dst=DST) / TCP(sport=sport, dport=80, flags="S", seq=1000)
    syn.time = ts
    collector.ingest_packet(syn)
    rst = IP(src=DST, dst=SRC) / TCP(sport=80, dport=sport, flags="R", seq=5000, ack=1001)
    rst.time = ts + 0.001
    collector.ingest_packet(rst)


print("--- Check 1: fast, regular connections (flood-shaped) score as a flood ---")
collector = FlowCollector()
base = 1_000_000.0
for i in range(10):
    make_connection(collector, sport=40000 + i, ts=base + i * 0.01)   # 100 conns/sec
score = collector.connection_rate(SRC, DST)
print(f"Flood-shaped: {score}")
assert score["is_flood"], f"FAIL: fast repeated connections not flagged as a flood: {score}"
assert score["rate_per_sec"] > 50.0, f"FAIL: expected rate well above threshold: {score}"
print("PASS: fast, regular connections correctly flagged as a flood")

print()
print("--- Check 2: slow/occasional connections (ordinary traffic) do NOT score as a flood ---")
collector2 = FlowCollector()
offsets = [0, 12, 30, 65, 140]   # a handful of requests over ~2.5 minutes
for i, off in enumerate(offsets):
    make_connection(collector2, sport=50000 + i, ts=base + off)
score2 = collector2.connection_rate(SRC, DST)
print(f"Ordinary: {score2}")
assert not score2["is_flood"], f"FAIL: ordinary-paced connections incorrectly flagged as a flood: {score2}"
print("PASS: ordinary-paced connections correctly NOT flagged")

print()
print("--- Check 3: too little history returns rate_per_sec=None, not a misleading 0.0 ---")
collector3 = FlowCollector()
make_connection(collector3, sport=60000, ts=base)   # only 1 connection
score3 = collector3.connection_rate(SRC, DST)
print(f"Insufficient history: {score3}")
assert score3["conn_count"] == 1
assert not score3["is_flood"]
assert score3["rate_per_sec"] is None, f"FAIL: expected None with insufficient history: {score3}"
print("PASS: insufficient history correctly returns rate_per_sec=None")

import pandas as pd

from sentinel import SentinelIPS

print()
print("--- Check 4: _run_dos() promotes a flood-flagged flow to DoS ---")
ips = SentinelIPS()  # no model_path needed -- _run_dos never touches layer1
chunk = pd.DataFrame({
    "dos_flagged":     [True, False],
    "src_ip":          [SRC, SRC],
    "destination_port": [80, 80],
})
result = ips._run_dos(chunk)
assert result.iloc[0]["sig_attack_type"] == "DoS"
assert result.iloc[0]["pred_binary"] == 1
assert result.iloc[0]["confidence"] >= 0.75
assert pd.isna(result.iloc[1]["sig_attack_type"]), "non-flagged row should be untouched"
print(f"PASS: flood-flagged row -> sig_attack_type=DoS, confidence={result.iloc[0]['confidence']:.2f}; "
      f"non-flagged row untouched")

print()
print("--- Check 5: chunk with no dos_flagged column (simulate mode) is a no-op ---")
plain_chunk = pd.DataFrame({"src_ip": [SRC]})
result = ips._run_dos(plain_chunk)
assert "sig_attack_type" not in result.columns
assert result.equals(plain_chunk)
print("PASS: simulate-mode chunk (no dos_flagged column) passed through untouched")

print()
print("All checks passed.")
