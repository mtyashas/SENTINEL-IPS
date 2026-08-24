"""
lab/verify_self_traffic_exclusion.py

Purpose: Self-check for the self-originated-traffic exclusion added to
         SentinelIPS.process_chunk() (2026-08-24). Confirmed live: this
         machine's own outbound traffic (geolocator's ip-api.com calls,
         ordinary browser HTTPS bursts) was getting misclassified as
         Phishing/PortScan/DoS across three separate detection paths at
         once, because the live capture filter has no subnet restriction
         and sniffs this machine's own packets along with real inbound
         traffic. Fixed with one guard at the top of process_chunk() that
         drops any row where src_ip matches this machine's own resolved
         IP, before any detection layer runs -- fixes all three paths at
         the shared root instead of patching each one separately.

         Confirms: (1) a chunk containing only self-originated rows comes
         back empty with no attack columns added, (2) a mixed chunk keeps
         only the non-self rows and still detects a real attack among
         them, (3) the filter is a no-op when src_ip isn't present
         (simulate mode).

Usage:
    python lab/verify_self_traffic_exclusion.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd

from sentinel import SentinelIPS

ips = SentinelIPS()  # no model_path needed -- own-IP resolution doesn't touch layer1
assert ips._own_ip, "own IP failed to resolve -- can't run this check"
print(f"Resolved own IP: {ips._own_ip}")

print()
print("--- Check 1: chunk of only self-originated rows comes back empty ---")
self_only = pd.DataFrame({
    "src_ip":          [ips._own_ip, ips._own_ip],
    "dos_flagged":     [True, True],
    "destination_port": [443, 443],
})
result = ips.process_chunk(self_only)
assert result.empty, f"FAIL: self-originated rows should all be dropped: {result}"
print("PASS: self-originated-only chunk correctly comes back empty")

print()
print("--- Check 2: mixed chunk keeps only the non-self row, still detects it ---")
mixed = pd.DataFrame({
    "src_ip":          [ips._own_ip, "192.168.0.150"],
    "dos_flagged":     [True, True],
    "destination_port": [443, 80],
})
result = ips.process_chunk(mixed)
assert len(result) == 1, f"FAIL: expected exactly 1 surviving row: {result}"
assert result.iloc[0]["src_ip"] == "192.168.0.150"
assert result.iloc[0]["sig_attack_type"] == "DoS"
print("PASS: self row dropped, real attacker row survived and was still detected as DoS")

print()
print("--- Check 3: chunk with no src_ip column (simulate mode) is unaffected ---")
no_src_ip = pd.DataFrame({"destination_port": [80]})
result = ips.process_chunk(no_src_ip)
assert len(result) == 1, "FAIL: simulate-mode chunk without src_ip should pass through untouched"
print("PASS: simulate-mode chunk (no src_ip column) unaffected by the filter")

print()
print("All checks passed.")
