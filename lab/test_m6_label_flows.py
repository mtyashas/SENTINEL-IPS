"""
lab/test_m6_label_flows.py

Purpose: Unit test for m6_multiclass_retrain_multihost.label_flows() --
         the one genuinely pure, testable piece of the retraining script
         (everything else needs real PCAP/model/dataset files). Verifies
         multi-IP attacker/benign handling, collision-window exclusion,
         and unknown-IP exclusion, all in one small synthetic DataFrame.

Usage:
    python lab/test_m6_label_flows.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd

from config import ATTACK_CLASSES
from lab.m6_multiclass_retrain_multihost import label_flows

flows = pd.DataFrame([
    # attacker1, scan-shape (2 total pkts, no PSH) -> PortScan
    {"src_ip": "10.0.0.10", "total_fwd_packets": 1, "total_backward_packets": 1, "psh_flag_count": 0},
    # attacker2, scan-shape -> PortScan
    {"src_ip": "10.0.0.11", "total_fwd_packets": 2, "total_backward_packets": 0, "psh_flag_count": 0},
    # attacker1, real HTTP exchange (has PSH data) -> WebAttack
    {"src_ip": "10.0.0.10", "total_fwd_packets": 5, "total_backward_packets": 4, "psh_flag_count": 2},
    # benign -> BENIGN
    {"src_ip": "10.0.0.20", "total_fwd_packets": 4, "total_backward_packets": 3, "psh_flag_count": 1},
    # excluded (collision window) -> dropped entirely, even though it's also listed as an attacker IP
    {"src_ip": "10.0.0.99", "total_fwd_packets": 1, "total_backward_packets": 1, "psh_flag_count": 0},
    # unknown IP (neither attacker/benign/excluded) -> dropped entirely
    {"src_ip": "10.0.0.200", "total_fwd_packets": 3, "total_backward_packets": 2, "psh_flag_count": 0},
])

result = label_flows(
    flows,
    attacker_ips=["10.0.0.10", "10.0.0.11", "10.0.0.99"],
    benign_ips=["10.0.0.20"],
    exclude_ips=["10.0.0.99"],
)

print("--- Check 1: excluded and unknown IPs are dropped ---")
assert len(result) == 4, f"expected 4 rows, got {len(result)}"
assert "10.0.0.99" not in result["src_ip"].values
assert "10.0.0.200" not in result["src_ip"].values
print("PASS")

print()
print("--- Check 2: labels are correct per attacker/benign + flow shape ---")
portscan_idx = ATTACK_CLASSES.index("PortScan")
webattack_idx = ATTACK_CLASSES.index("WebAttack")
benign_idx = ATTACK_CLASSES.index("BENIGN")

truth_by_ip_and_psh = {
    (row["src_ip"], row["psh_flag_count"]): row["__truth__"]
    for _, row in result.iterrows()
}
assert truth_by_ip_and_psh[("10.0.0.10", 0)] == portscan_idx, "scan-shape attacker traffic should be PortScan"
assert truth_by_ip_and_psh[("10.0.0.11", 0)] == portscan_idx, "scan-shape attacker traffic should be PortScan"
assert truth_by_ip_and_psh[("10.0.0.10", 2)] == webattack_idx, "non-scan-shape attacker traffic should be WebAttack"
assert truth_by_ip_and_psh[("10.0.0.20", 1)] == benign_idx, "benign IP traffic should be BENIGN"
print("PASS")

print()
print("All checks passed.")
