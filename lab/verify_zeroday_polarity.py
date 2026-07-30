"""
lab/verify_zeroday_polarity.py

Purpose: Self-check for the anomaly-score polarity bug found 2026-07-30 while
         building zero-day attack test traffic. sentinel.py's _build_event()
         only promoted a flow to "ZeroDay" when anomaly_score >= 0.2, but
         IsolationForest.decision_function (which populates anomaly_score)
         returns *more negative* for more anomalous flows -- so that check
         had the polarity backwards and could never fire for a genuinely
         anomalous flow. The same backwards check gated
         adaptive/zero_day_miner.py's candidate filter. Both fixed: sentinel.py
         now keys off anomaly_detected (Layer 3's own thresholded verdict);
         zero_day_miner.py's filter direction flipped to <= -_MIN_ANOMALY_SCORE.

Usage:
    python lab/verify_zeroday_polarity.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import numpy as np
import pandas as pd

from sentinel import SentinelIPS
from adaptive.zero_day_miner import ZeroDayMiner


def check_build_event_zeroday_label():
    print("--- Check 1: _build_event labels an IsolationForest-flagged flow as ZeroDay ---")
    ips = SentinelIPS()  # no model_path needed -- _build_event never touches layer1

    anomalous_row = pd.Series({
        "attack_class": "BENIGN", "anomaly_detected": True, "anomaly_score": -0.35,
        "src_ip": "192.168.56.10", "dst_ip": "192.168.56.1",
        "src_port": 47523, "destination_port": 47523, "confidence": 0.5,
    })
    event = ips._build_event(anomalous_row)
    assert event["attack_type"] == "ZeroDay", f"expected ZeroDay, got {event['attack_type']}"
    assert event["severity"] == "CRITICAL", f"expected CRITICAL, got {event['severity']}"
    print("OK: anomaly_detected=True -> ZeroDay / CRITICAL")

    print("\n--- Check 2: a normal-looking flow is NOT mislabelled ZeroDay ---")
    normal_row = pd.Series({
        "attack_class": "BENIGN", "anomaly_detected": False, "anomaly_score": 0.31,
        "src_ip": "192.168.56.20", "dst_ip": "192.168.56.1",
        "src_port": 51000, "destination_port": 80, "confidence": 0.5,
    })
    event = ips._build_event(normal_row)
    assert event["attack_type"] == "Unknown", f"expected Unknown, got {event['attack_type']}"
    print("OK: anomaly_detected=False (positive/normal-range anomaly_score) -> Unknown, not ZeroDay")


def check_miner_mines_the_anomalous_cluster():
    print("\n--- Check 3: ZeroDayMiner clusters the negative-score group, not the positive one ---")
    rng = np.random.RandomState(0)
    anomalous = pd.DataFrame({
        "anomaly_score": -0.5 + rng.normal(0, 0.01, 6),
        "feat_a":        100.0 + rng.normal(0, 0.01, 6),
        "feat_b":        200.0 + rng.normal(0, 0.01, 6),
    })
    normal = pd.DataFrame({
        "anomaly_score": 0.4 + rng.normal(0, 0.01, 6),
        "feat_a":        1.0 + rng.normal(0, 0.01, 6),
        "feat_b":        2.0 + rng.normal(0, 0.01, 6),
    })
    df = pd.concat([anomalous, normal], ignore_index=True)

    # eps widened from the class default (0.5) -- StandardScaler fit on just
    # these 6 candidate rows alone rescales their tiny noise to ~unit
    # variance, so the default eps is too tight for a sample this small.
    # Unrelated to the polarity fix under test; only the *filter direction*
    # (which rows become candidates) is what this check cares about.
    miner = ZeroDayMiner(eps=3.0, min_samples=5)
    miner._persist_patterns = lambda patterns: None  # skip writing test data to threat_intel/
    patterns = miner.mine(df)

    assert len(patterns) == 1, f"expected exactly 1 cluster (the anomalous one), got {len(patterns)}"
    assert patterns[0].anomaly_score_mean < -0.1, (
        f"mined cluster should be the negative/anomalous one, got {patterns[0].anomaly_score_mean}"
    )
    print(f"OK: mined cluster anomaly_score_mean={patterns[0].anomaly_score_mean:.3f} "
          f"-- correctly picked the anomalous cluster, not the normal one")


if __name__ == "__main__":
    check_build_event_zeroday_label()
    check_miner_mines_the_anomalous_cluster()
    print("\nAll zero-day polarity checks passed.")
