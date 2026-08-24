# Multiclass PortScan Retraining Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adapt the existing `lab/m5_multiclass_retrain.py` pattern into a new `lab/m6_multiclass_retrain_multihost.py` that retrains the multiclass model on real PortScan traffic from last night's two live multi-host captures, closing the measured ~90-97% generic-`ATTACK`-fallback gap for scan-shaped traffic.

**Architecture:** Reprocess both PCAPs through the existing `FlowCollector`, label flows by `src_ip` + flow-shape (scan-shape: ≤3 packets, no PSH data → PortScan; other attacker traffic → WebAttack; else BENIGN), find where the current production multiclass model disagrees via `MistakeCollector`, retrain through the existing `AdaptiveTrainer` (already multiclass-capable) combined with a CIC-IDS-2017 sample, and only keep the new model if it's measurably better on a held-out test set.

**Tech Stack:** Python, scapy (`rdpcap`), pandas, existing `core.flow_collector.FlowCollector`, `detection.layer1_ml.MLDetectionLayer`, `adaptive.mistake_collector.MistakeCollector`, `adaptive.adaptive_trainer.AdaptiveTrainer`, `core.features`, `core.preprocessing`, `sklearn.model_selection.train_test_split`.

**Spec:** `docs/superpowers/specs/2026-08-22-multiclass-portscan-retrain-design.md`

## Global Constraints

- New file only: `lab/m6_multiclass_retrain_multihost.py`. Do not modify `lab/m5_multiclass_retrain.py`, `sentinel.py`, `detection/layer1_ml.py`, `adaptive/adaptive_trainer.py`, or `adaptive/mistake_collector.py` — all reused exactly as they exist today.
- Scope is PortScan only. DoS/DDoS labeling is explicitly out of scope (needs a cross-flow rate feature that doesn't exist yet — separate follow-up).
- IP table (confirmed by direct packet inspection, verbatim from the spec):
  - Run 1 (`pcap/sentinel_20260820_124005_6571ee5e.pcap`): attacker `192.168.0.100`, benign `192.168.0.104`.
  - Run 2 (`pcap/sentinel_20260820_192521_bc0ea8f1.pcap`): attackers `192.168.0.150`, `192.168.0.151`; benign `192.168.0.104`, `192.168.0.108`; exclude `192.168.0.100` (DHCP collision window, ambiguous source).
- `label_flows()`'s scan-shape heuristic is dataset-agnostic and must be reused unchanged: `(total_fwd_packets + total_backward_packets) <= 3` and `psh_flag_count == 0`.
- No pytest suite exists for `lab/` scripts in this project — the established convention (matching `lab/m5_multiclass_retrain.py`, `lab/verify_*.py`) is direct execution with printed before/after results as the verification. Task 1's pure-function unit test is an exception since `label_flows()` is genuinely pure and testable without real data files; Task 2's integration work follows the project's existing run-directly convention.

---

## File Structure

```
lab/
└── m6_multiclass_retrain_multihost.py   NEW — everything for this effort

models/
├── train_cache_multiclass_multihost.parquet     NEW (script output, cache)
└── mistakes_buffer_multiclass_multihost.parquet NEW (script output, cache)
```

---

### Task 1: Multi-IP flow labeling with collision exclusion

**Files:**
- Create: `lab/m6_multiclass_retrain_multihost.py` (module docstring, imports, constants, `label_flows()` only at this stage)
- Test: `lab/test_m6_label_flows.py`

**Interfaces:**
- Produces: `label_flows(flows: pd.DataFrame, attacker_ips: list[str], benign_ips: list[str], exclude_ips: Optional[list[str]] = None) -> pd.DataFrame` — returns a copy of `flows` restricted to rows whose `src_ip` is in `attacker_ips` or `benign_ips` (and not in `exclude_ips`), with a new `__truth__` column (int, an index into `config.ATTACK_CLASSES`).

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python lab/test_m6_label_flows.py`
Expected: `ModuleNotFoundError` or `ImportError` — `lab/m6_multiclass_retrain_multihost.py` doesn't exist yet.

- [ ] **Step 3: Write the module with label_flows()**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python lab/test_m6_label_flows.py`
Expected: both `PASS` lines, then `All checks passed.`

- [ ] **Step 5: Commit**

```bash
git add lab/m6_multiclass_retrain_multihost.py lab/test_m6_label_flows.py
git commit -m "feat: add multi-IP flow labeling for multi-host PortScan retrain"
```

---

### Task 2: PCAP reprocessing, mistake-finding, and retrain orchestration

**Files:**
- Modify: `lab/m6_multiclass_retrain_multihost.py` (add everything after `label_flows()`)

**Interfaces:**
- Consumes: `label_flows(flows, attacker_ips, benign_ips, exclude_ips=None) -> pd.DataFrame` (Task 1). `MLDetectionLayer(model_path: str, feat_cols_path: str)` with `._align_features(df) -> pd.DataFrame` and `._mc_model.predict(X)`. `MistakeCollector(buffer_path=None)` with `.add(features: pd.Series, predicted: int, corrected: int, mistake_type: str) -> MistakeRecord`. `AdaptiveTrainer(collector, train_cache_path=None, mode="binary", production_model_name=None)` with `.cache_training_data(X, y)` and `.retrain(X_test=None, y_test=None) -> RetrainResult` (fields: `.improved`, `.old_recall`, `.new_recall`, `.old_f1`, `.new_f1`, `.notes`). `NetworkFeatureEngineer(keep_raw=True).transform(df)`. `get_feature_matrix(df, label_col=...) -> tuple[pd.DataFrame, pd.Series]`. `load_full_dataset(pattern, sample_frac=...) -> pd.DataFrame`. `FlowCollector()` with `.ingest_packet(pkt)` and `.flush_all() -> pd.DataFrame`.
- Produces: a runnable `main()` — the deliverable is the script's own printed output, not a function other code calls.

- [ ] **Step 1: Add the reprocessing, mistake-finding, and evaluation functions**

Append to `lab/m6_multiclass_retrain_multihost.py`, after `label_flows()`:

```python
from scapy.utils import rdpcap
from sklearn.model_selection import train_test_split

from adaptive.adaptive_trainer import AdaptiveTrainer
from adaptive.mistake_collector import MistakeCollector
from config import DATA_2017, MODEL_DIR, MULTICLASS_LABEL_COL
from core.features import NetworkFeatureEngineer, get_feature_matrix
from core.flow_collector import FlowCollector
from core.preprocessing import load_full_dataset
from detection.layer1_ml import MLDetectionLayer

RUN1_PCAP = _ROOT / "pcap" / "sentinel_20260820_124005_6571ee5e.pcap"
RUN2_PCAP = _ROOT / "pcap" / "sentinel_20260820_192521_bc0ea8f1.pcap"

RUN1_ATTACKER_IPS: list[str] = ["192.168.0.100"]
RUN1_BENIGN_IPS:   list[str] = ["192.168.0.104"]

RUN2_ATTACKER_IPS: list[str] = ["192.168.0.150", "192.168.0.151"]
RUN2_BENIGN_IPS:   list[str] = ["192.168.0.104", "192.168.0.108"]
RUN2_EXCLUDE_IPS:  list[str] = ["192.168.0.100"]  # DHCP collision window, ambiguous source

BINARY_MODEL     = MODEL_DIR / "benchmarkids_binary.pkl"
FEAT_COLS        = MODEL_DIR / "benchmarkids_binary_feature_cols.pkl"
TRAIN_CACHE      = MODEL_DIR / "train_cache_multiclass_multihost.parquet"
MISTAKE_BUFFER   = MODEL_DIR / "mistakes_buffer_multiclass_multihost.parquet"


def reprocess_pcap(
    pcap_path: str,
    attacker_ips: list[str],
    benign_ips: list[str],
    exclude_ips: Optional[list[str]] = None,
) -> pd.DataFrame:
    logger.info("Reprocessing %s", pcap_path)
    collector = FlowCollector()
    for pkt in rdpcap(pcap_path):
        collector.ingest_packet(pkt)
    flows = label_flows(collector.flush_all(), attacker_ips, benign_ips, exclude_ips)
    counts = flows["__truth__"].value_counts()
    logger.info("Labelled %d flows from %s: %s", len(flows), pcap_path,
                {ATTACK_CLASSES[k]: v for k, v in counts.items()})
    return flows


def find_mistakes(flows: pd.DataFrame, collector: MistakeCollector, layer1: MLDetectionLayer):
    """Run the current production multiclass model directly (bypassing the
    binary gate, unlike live inference) so mistakes reflect what the
    multiclass model itself gets wrong, not what the binary layer missed."""
    X = layer1._align_features(flows)
    pred_raw = layer1._mc_model.predict(X)
    truth = flows["__truth__"].values

    n_mistakes = 0
    for i in range(len(X)):
        if int(pred_raw[i]) != int(truth[i]):
            collector.add(X.iloc[i], predicted=int(pred_raw[i]), corrected=int(truth[i]),
                          mistake_type="MISCLASS")
            n_mistakes += 1

    accuracy = (pred_raw == truth).sum() / len(truth)
    logger.info("Production multiclass model on combined captures: %.4f accuracy, %d/%d mistakes",
                accuracy, n_mistakes, len(truth))
    return n_mistakes, accuracy, X


def eval_on_captures(flows: pd.DataFrame, layer1: MLDetectionLayer) -> float:
    X = layer1._align_features(flows)
    pred = layer1._mc_model.predict(X)
    truth = flows["__truth__"].values
    return (pred == truth).sum() / len(truth)
```

- [ ] **Step 2: Add main() and the CLI entry point**

Append to `lab/m6_multiclass_retrain_multihost.py`:

```python
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-frac", type=float, default=0.02,
                         help="Fraction of CIC-IDS-2017 loaded for the cache/validation set")
    args = parser.parse_args()

    flows_run1 = reprocess_pcap(str(RUN1_PCAP), RUN1_ATTACKER_IPS, RUN1_BENIGN_IPS)
    flows_run2 = reprocess_pcap(str(RUN2_PCAP), RUN2_ATTACKER_IPS, RUN2_BENIGN_IPS, RUN2_EXCLUDE_IPS)
    flows = pd.concat([flows_run1, flows_run2], ignore_index=True)

    counts = flows["__truth__"].value_counts()
    logger.info("Combined labelled flows: %d total: %s", len(flows),
                {ATTACK_CLASSES[k]: v for k, v in counts.items()})
    assert len(counts) > 1, "Need multiple classes present to compute meaningful mistakes"

    layer1 = MLDetectionLayer(model_path=str(BINARY_MODEL), feat_cols_path=str(FEAT_COLS))
    if layer1._mc_model is None:
        logger.error("No multiclass model loaded — nothing to retrain")
        return

    mistake_collector = MistakeCollector(buffer_path=MISTAKE_BUFFER)
    n_mistakes, acc_before, X_capture = find_mistakes(flows, mistake_collector, layer1)
    if n_mistakes == 0:
        logger.info("No mistakes found — production model already correct on these captures.")
        return

    trainer = AdaptiveTrainer(
        mistake_collector,
        train_cache_path=TRAIN_CACHE,
        mode="multiclass",
        production_model_name="benchmarkids_multiclass.pkl",
    )

    logger.info("Loading CIC-IDS-2017 sample (frac=%.3f) for cache + held-out validation", args.sample_frac)
    df17 = load_full_dataset(str(DATA_2017 / "**" / "*.csv"), sample_frac=args.sample_frac)
    df17 = NetworkFeatureEngineer(keep_raw=True).transform(df17)
    X17, y17 = get_feature_matrix(df17, label_col=MULTICLASS_LABEL_COL)
    X17_tr, X17_te, y17_tr, y17_te = train_test_split(
        X17, y17, test_size=0.2, random_state=42, stratify=y17,
    )

    y_capture = pd.Series(flows["__truth__"].values, index=X_capture.index, name=MULTICLASS_LABEL_COL)
    X_cache = pd.concat([X17_tr, X_capture], ignore_index=True)
    y_cache = pd.concat([y17_tr, y_capture], ignore_index=True)
    trainer.cache_training_data(X_cache, y_cache)

    result = trainer.retrain(X17_te, y17_te)
    logger.info(
        "Retrain result: improved=%s old_recall(macro)=%.4f new_recall(macro)=%.4f "
        "old_f1=%.4f new_f1=%.4f",
        result.improved, result.old_recall, result.new_recall, result.old_f1, result.new_f1,
    )
    logger.info(result.notes)

    layer1_after = MLDetectionLayer(model_path=str(BINARY_MODEL), feat_cols_path=str(FEAT_COLS))
    acc_after = eval_on_captures(flows, layer1_after)
    logger.info(
        "Combined-capture accuracy: before=%.4f after=%.4f (%d flows)",
        acc_before, acc_after, len(flows),
    )
    verdict = "PASS" if acc_after > acc_before else "NO IMPROVEMENT"
    logger.info("Multiclass adaptive-retrain check (multi-host): %s", verdict)


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Run the script for real**

Run: `python lab/m6_multiclass_retrain_multihost.py`
Expected: log lines for both PCAPs being reprocessed and labeled, a combined flow-count summary, the production model's accuracy/mistake-count on the combined captures, the CIC-2017 cache/validation split loading, the retrain result (`improved=True/False`, recall/F1 before and after), and a final `PASS` or `NO IMPROVEMENT` verdict. No unhandled exceptions.

- [ ] **Step 4: Confirm the fallback rate actually dropped**

Re-check the combined-capture accuracy printed in Step 3's output (the `Combined-capture accuracy: before=X after=Y` line). Confirm `Y > X`, matching the spec's success criteria (a measurable drop in the fraction of attacker-sourced scan-shaped flows still falling back to the wrong class).

- [ ] **Step 5: Commit**

```bash
git add lab/m6_multiclass_retrain_multihost.py
git commit -m "feat: retrain multiclass model on real multi-host PortScan captures"
```

Note: `models/train_cache_multiclass_multihost.parquet` and `models/mistakes_buffer_multiclass_multihost.parquet` are script-generated cache files, not source — check `.gitignore` covers `models/*.parquet` before staging; if not already covered, add it rather than committing generated cache data.
