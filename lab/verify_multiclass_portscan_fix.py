"""
lab/verify_multiclass_portscan_fix.py

Purpose: Self-check for the multiclass PortScan retrain (2026-07-31, run
         via lab/m5_multiclass_retrain.py). Confirmed live over three
         separate test sessions: nmap -sS always got detected as an attack
         (binary model correct) but the multiclass model's top class always
         resolved to BENIGN, so detection/layer1_ml.py's contradiction
         guard fell back to the generic "ATTACK" label instead of
         "PortScan" -- which meant severity never escalated past MEDIUM
         and auto-blacklisting (which requires HIGH/CRITICAL) never fired
         for this attack type. The retrain's own held-out CIC-2017 gate
         rejected the candidate (recall dipped 97.51% -> 94.97%), but real
         capture accuracy went 35.48% -> 97.49% with the old model never
         once predicting PortScan and the new one nearly matching ground
         truth exactly (4205 predicted vs 4204 actual) -- manually
         promoted, same call made for the binary model in M4. This script
         confirms the promoted model is genuinely in place and correct,
         independent of trusting the retrain script's own printed numbers.

Usage:
    python lab/verify_multiclass_portscan_fix.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from collections import Counter

from config import ATTACK_CLASSES
from detection.layer1_ml import MLDetectionLayer
from lab.m5_multiclass_retrain import (
    BINARY_MODEL, DEFAULT_PCAP, FEAT_COLS, reprocess_pcap,
)

_PORTSCAN_IDX = ATTACK_CLASSES.index("PortScan")
_MIN_ACCURACY = 0.90

print("--- Loading production model and the real 2026-07-29 capture ---")
flows  = reprocess_pcap(str(DEFAULT_PCAP))
layer1 = MLDetectionLayer(model_path=str(BINARY_MODEL), feat_cols_path=str(FEAT_COLS))
assert layer1._mc_model is not None, "FAIL: no multiclass model loaded"

X = layer1._align_features(flows)
pred  = layer1._mc_model.predict(X)
truth = flows["__truth__"].values
accuracy = (pred == truth).sum() / len(truth)

print()
print("--- Check 1: overall accuracy on the real capture ---")
print(f"Accuracy: {accuracy:.4f} (predictions: {dict(Counter(int(p) for p in pred))})")
assert accuracy >= _MIN_ACCURACY, (
    f"FAIL: accuracy {accuracy:.4f} below {_MIN_ACCURACY} — old model behavior may still be in place"
)
print(f"PASS: accuracy {accuracy:.4f} >= {_MIN_ACCURACY}")

print()
print("--- Check 2: PortScan flows are actually predicted PortScan ---")
portscan_mask = truth == _PORTSCAN_IDX
portscan_recall = (pred[portscan_mask] == _PORTSCAN_IDX).sum() / portscan_mask.sum()
print(f"PortScan recall: {portscan_recall:.4f} ({portscan_mask.sum()} true PortScan flows)")
assert portscan_recall >= _MIN_ACCURACY, (
    f"FAIL: PortScan recall {portscan_recall:.4f} too low — this is the exact bug being fixed"
)
print(f"PASS: PortScan recall {portscan_recall:.4f} >= {_MIN_ACCURACY}")

print()
print("All checks passed.")
