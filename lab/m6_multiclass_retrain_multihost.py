"""
lab/m6_multiclass_retrain_multihost.py

Purpose: Adaptive-retraining pass for the multiclass model, adapting
         lab/m5_multiclass_retrain.py's single-attacker-VM pattern to the
         real multi-host live captures from 2026-08-20/21 (two physical
         Kali VMs across two test runs -- see
         docs/superpowers/specs/2026-08-22-multiclass-portscan-retrain-design.md
         for the full design and known limitations).

         Ground truth: src_ip identifies attacker vs benign, but not
         *which* attack type -- distinguished by flow shape instead,
         reusing m5's exact heuristic (dataset-agnostic, unchanged):
           - src_ip in benign_ips                                  -> BENIGN
           - src_ip in attacker_ips, <=3 packets, no PSH data       -> PortScan
             (nmap -sS's own shape regardless of port state)
           - src_ip in attacker_ips, otherwise                      -> WebAttack
             (CIC-IDS-2017 collapses SQLi/XSS/CommandInject into one
             WebAttack class -- moot anyway since Layer 2 signatures
             already label these correctly and take priority over
             whatever the multiclass model predicts)
           - src_ip in exclude_ips, or in neither list               -> dropped

         Scope is PortScan only. DoS/DDoS is explicitly out of scope --
         a single hping3 flood packet is indistinguishable from one
         failed connection attempt without a cross-flow rate feature
         that doesn't exist yet (separate follow-up).

Inputs:  pcap/sentinel_20260820_124005_6571ee5e.pcap (Run 1);
         pcap/sentinel_20260820_192521_bc0ea8f1.pcap (Run 2);
         models/benchmarkids_multiclass.pkl; datasets/CIC-IDS-2017/**/*.csv
         (sampled).
Outputs: Retrained multiclass model in models/ if macro recall improves
         (old model backed up, matching AdaptiveTrainer's existing
         behavior); before/after accuracy on the combined captures
         printed to stdout.

Usage:
    python lab/m6_multiclass_retrain_multihost.py
    python lab/m6_multiclass_retrain_multihost.py --sample-frac 0.05
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import numpy as np
import pandas as pd

from config import ATTACK_CLASSES

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("m6_multiclass_retrain_multihost")

_BENIGN_IDX    = ATTACK_CLASSES.index("BENIGN")
_PORTSCAN_IDX  = ATTACK_CLASSES.index("PortScan")
_WEBATTACK_IDX = ATTACK_CLASSES.index("WebAttack")


def label_flows(
    flows: pd.DataFrame,
    attacker_ips: list[str],
    benign_ips: list[str],
    exclude_ips: Optional[list[str]] = None,
) -> pd.DataFrame:
    """Ground truth by src_ip + flow shape (see module docstring). Flows
    from `exclude_ips` (e.g. an IP-collision window) are dropped even if
    also listed in attacker_ips/benign_ips; any IP in neither list is
    dropped too -- only known-clean sources get labeled."""
    exclude_ips = exclude_ips or []
    known_ips = [ip for ip in (attacker_ips + benign_ips) if ip not in exclude_ips]
    labelled = flows[flows["src_ip"].isin(known_ips)].copy()

    total_pkts     = labelled["total_fwd_packets"] + labelled["total_backward_packets"]
    is_scan_shape  = (total_pkts <= 3) & (labelled["psh_flag_count"] == 0)
    is_attacker    = labelled["src_ip"].isin(attacker_ips)

    truth = np.full(len(labelled), _BENIGN_IDX, dtype=int)
    truth[is_attacker & is_scan_shape]  = _PORTSCAN_IDX
    truth[is_attacker & ~is_scan_shape] = _WEBATTACK_IDX
    labelled["__truth__"] = truth
    return labelled
