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
