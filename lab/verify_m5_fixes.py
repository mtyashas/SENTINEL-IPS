"""
lab/verify_m5_fixes.py

Purpose: Self-check for the two M5 gaps fixed 2026-07-28 (see
         docs/SESSION_LEDGER.md, 2026-07-27 entry "Next steps"):

         1. RESPONSE_MATRIX's per-attack ip_block_* actions (e.g. BruteForce
            -> ip_block_1h) were computed in sentinel.py's _run_response()
            but only used for a cosmetic log string -- the actual block
            decision checked severity alone, so MEDIUM/LOW-severity attacks
            with an explicit block action (BruteForce, PortScan) never
            actually got blacklisted despite the documented design saying
            they should.
         2. AnomalyDetector fit on whatever was in the first single chunk
            to cross 100 rows, regardless of attack/benign mix -- a
            flood/scan produces large chunks fast, risking a baseline fit
            on attack-heavy data that then flags genuine benign traffic as
            anomalous by comparison.

Usage:
    python lab/verify_m5_fixes.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import numpy as np
import pandas as pd

from sentinel import SentinelIPS
from config import MODEL_DIR


def check_response_matrix_block():
    print("--- Check 1: RESPONSE_MATRIX ip_block_* honoured for MEDIUM severity ---")
    ips = SentinelIPS(model_path=str(MODEL_DIR / "benchmarkids_binary.pkl"))

    ip = "203.0.113.55"
    assert not ips._blacklist.is_blocked(ip), "test IP should start unblocked"

    event = {
        "src_ip": ip, "dst_ip": "192.168.56.1", "src_port": 4444, "dst_port": 80,
        "attack_type": "BruteForce", "confidence": 0.85, "severity": "MEDIUM",
        "anomaly_score": 0.0, "timestamp": 0.0, "flow_bytes": 0.0,
    }
    ips._run_response(event)

    assert ips._blacklist.is_blocked(ip), (
        "BruteForce (MEDIUM severity) has ip_block_1h in RESPONSE_MATRIX and "
        "should now be blocked even though severity alone wouldn't trigger it"
    )
    print(f"OK: {ip} blocked via BruteForce's ip_block_1h action, "
          f"event['action']={event['action']!r}")


def check_anomaly_baseline_benign_only():
    print("\n--- Check 2: anomaly baseline fits only on accumulated benign rows ---")
    ips = SentinelIPS(model_path=None)  # skip ML load, only Layer 3 under test
    assert not ips._anomaly_fitted

    n_feat = 20
    cols = [f"f{i}" for i in range(n_feat)]

    def make_chunk(n_attack: int, n_benign: int) -> pd.DataFrame:
        rng = np.random.default_rng(42)
        attack = pd.DataFrame(rng.normal(50, 5, size=(n_attack, n_feat)), columns=cols)
        attack["pred_binary"] = 1
        benign = pd.DataFrame(rng.normal(0, 1, size=(n_benign, n_feat)), columns=cols)
        benign["pred_binary"] = 0
        return pd.concat([attack, benign], ignore_index=True)

    # Chunk 1: 200 attack rows + 5 benign -- large enough to have tripped the
    # old ">=100 rows in this chunk" check using attack-contaminated data.
    chunk1 = make_chunk(n_attack=200, n_benign=5)
    ips._run_anomaly(chunk1)
    assert not ips._anomaly_fitted, (
        "must not fit yet -- only 5 benign rows accumulated, even though "
        "the raw chunk itself has 205 rows"
    )
    assert sum(len(b) for b in ips._anomaly_baseline_buffer) == 5

    # Chunk 2: adds 96 more benign rows -- 5 + 96 = 101, crosses the threshold.
    chunk2 = make_chunk(n_attack=200, n_benign=96)
    ips._run_anomaly(chunk2)
    assert ips._anomaly_fitted, "should fit once accumulated benign rows >= 100"
    assert ips._anomaly_baseline_buffer == [], "buffer should be cleared after fitting"
    print("OK: baseline only fit once 101 benign-labelled rows had accumulated "
          "across two chunks, ignoring 400 attack-labelled rows seen in between")


if __name__ == "__main__":
    check_response_matrix_block()
    check_anomaly_baseline_benign_only()
    print("\nAll M5 fix checks passed.")
