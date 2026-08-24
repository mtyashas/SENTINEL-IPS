"""
lab/verify_exfil_detection.py

Purpose: Self-check for rule-based Exfiltration detection (2026-08-24).
         Unlike DoS/Beacon, this needs no cross-flow state -- a single
         flow's own byte-count features (total_length_of_fwd_packets /
         total_length_of_bwd_packets, already computed by FlowCollector
         for every flow, live or simulated) are sufficient signal on
         their own. Confirms: (1) a flow whose combined transferred bytes
         cross _EXFIL_BYTES_THRESHOLD gets flagged, (2) an ordinary small
         flow doesn't, (3) a flow that already has a more specific
         signature match (e.g. SQLInjection) keeps that label instead of
         being overridden -- Exfiltration is the lowest-confidence
         rule-based override (0.60) and must never steal a more specific
         detection's label.

Usage:
    python lab/verify_exfil_detection.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd

from sentinel import SentinelIPS

ips = SentinelIPS()  # no model_path needed -- _run_exfil never touches layer1

print("--- Check 1: a flow whose combined bytes cross the threshold is flagged Exfiltration ---")
chunk = pd.DataFrame({
    "total_length_of_fwd_packets": [100.0, 6_000_000.0],
    "total_length_of_bwd_packets": [200.0, 500_000.0],
})
result = ips._run_exfil(chunk)
assert pd.isna(result.iloc[0]["sig_attack_type"]), f"FAIL: small flow should be untouched: {result.iloc[0]}"
assert result.iloc[1]["sig_attack_type"] == "Exfiltration", f"FAIL: large flow not flagged: {result.iloc[1]}"
assert result.iloc[1]["pred_binary"] == 1
assert result.iloc[1]["confidence"] >= 0.60
print(f"PASS: large-transfer row -> sig_attack_type=Exfiltration, confidence={result.iloc[1]['confidence']:.2f}; "
      f"small row untouched")

print()
print("--- Check 2: a flow with an existing, more specific signature match keeps that label ---")
chunk2 = pd.DataFrame({
    "total_length_of_fwd_packets": [8_000_000.0],
    "total_length_of_bwd_packets": [0.0],
    "sig_attack_type":             ["SQLInjection"],
})
result2 = ips._run_exfil(chunk2)
assert result2.iloc[0]["sig_attack_type"] == "SQLInjection", \
    f"FAIL: Exfiltration must not override an existing, more specific label: {result2.iloc[0]}"
print("PASS: existing SQLInjection label preserved, not overridden by the lower-confidence Exfiltration check")

print()
print("--- Check 3: chunk with neither byte-count column (unexpected schema) is a no-op ---")
chunk3 = pd.DataFrame({"src_ip": ["1.2.3.4"]})
result3 = ips._run_exfil(chunk3)
assert "sig_attack_type" not in result3.columns
assert result3.equals(chunk3)
print("PASS: chunk without byte-count columns passed through untouched")

print()
print("All checks passed.")
