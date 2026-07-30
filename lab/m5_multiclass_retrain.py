"""
lab/m5_multiclass_retrain.py

Purpose: Adaptive-retraining pass for the multiclass model, mirroring
         lab/m4_adaptive_retrain.py's approach for the binary model
         (docs/SESSION_LEDGER.md, 2026-07-27 next-steps: "same domain-shift
         pattern as M4's binary model, apparently never addressed for
         multiclass"). Without a real attack-type label, severity never
         escalates past MEDIUM (SEVERITY_LEVELS matches on exact attack-type
         name) and threat_intel/ip_blacklist.txt auto-blacklisting never
         fires for anything the multiclass model can't name -- confirmed
         live 2026-07-29/30: nmap -sS -p1-1000 was correctly detected as an
         attack every time but never labelled PortScan, always the generic
         ATTACK fallback (detection/layer1_ml.py:232-238).

         Ground truth: src_ip identifies attacker vs benign as in M4, but
         not *which* attack type -- distinguished by flow shape instead
         (revised 2026-07-31, see below), using only already-computed flow
         features (no payload inspection):
           - src_ip == BENIGN_IP                                  -> BENIGN
           - src_ip == ATTACKER_IP, <=3 packets, no PSH data       -> PortScan
             (nmap -sS's own shape regardless of port state: SYN only
             if filtered, SYN+RST if closed, SYN+SYN-ACK+RST if open --
             never more than 3 packets, never a payload)
           - src_ip == ATTACKER_IP, otherwise (real HTTP request/
             response exchanged, PSH data present)                -> WebAttack
             (the CommandInject/PathTraversal/SQLInjection curls in this
             capture -- WebAttack is the only class available for any of
             these three: core/preprocessing.py collapses "Web Attack -
             Brute Force/XSS/Sql Injection" into one WebAttack label in the
             original CIC-2017 data, there's no separate class to target.
             This doesn't matter operationally: Layer 2 signatures already
             label these correctly and reliably by payload match,
             independent of and prioritised over whatever the multiclass
             model predicts -- see sentinel.py _build_event()'s sig_type
             check-first branch. This pass only needs to fix cases the
             multiclass model is the *only* signal for, which is PortScan.)

         An M4-style capture is used here rather than M5's original mixed
         hping3-flood/hydra/curl one specifically because it contains no
         DoS-shaped flood traffic -- the earlier version of this script
         (2026-07-27) had to *exclude* short/no-payload flows entirely
         because bare-SYN hping3 flood fragments and gen_benign_traffic.sh's
         deliberate closed-port :8081 probes are genuinely indistinguishable
         at the single-flow-feature level (no cross-flow rate signal exists
         in this schema -- still an open, separate gap). This capture's only
         short/no-payload attacker traffic is the nmap scan itself, so no
         such ambiguity applies here and nothing needs to be excluded.

Inputs:  pcap/<2026-07-29 four-attack capture>.pcap;
         models/benchmarkids_multiclass.pkl; datasets/CIC-IDS-2017/**/*.csv
         (sampled).
Outputs: Retrained multiclass model in models/ if macro recall improves
         (old model backed up to .bak); before/after accuracy on the
         capture printed to stdout.

Usage:
    python lab/m5_multiclass_retrain.py
    python lab/m5_multiclass_retrain.py --pcap pcap/other_capture.pcap --sample-frac 0.02
"""

import argparse
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scapy.utils import rdpcap
from sklearn.model_selection import train_test_split

from adaptive.adaptive_trainer import AdaptiveTrainer
from adaptive.mistake_collector import MistakeCollector
from config import ATTACK_CLASSES, DATA_2017, MODEL_DIR, MULTICLASS_LABEL_COL
from core.features import NetworkFeatureEngineer, get_feature_matrix
from core.flow_collector import FlowCollector
from core.preprocessing import load_full_dataset
from detection.layer1_ml import MLDetectionLayer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("m5_multiclass_retrain")

ATTACKER_IP  = "192.168.56.10"
BENIGN_IP    = "192.168.56.20"
DEFAULT_PCAP = _ROOT / "pcap" / "sentinel_20260729_184145_7f742e9a.pcap"
BINARY_MODEL     = MODEL_DIR / "benchmarkids_binary.pkl"
MULTICLASS_MODEL = MODEL_DIR / "benchmarkids_multiclass.pkl"
FEAT_COLS        = MODEL_DIR / "benchmarkids_binary_feature_cols.pkl"
TRAIN_CACHE      = MODEL_DIR / "train_cache_multiclass.parquet"
MISTAKE_BUFFER   = MODEL_DIR / "mistakes_buffer_multiclass.parquet"

_BENIGN_IDX    = ATTACK_CLASSES.index("BENIGN")
_PORTSCAN_IDX  = ATTACK_CLASSES.index("PortScan")
_WEBATTACK_IDX = ATTACK_CLASSES.index("WebAttack")


def label_flows(flows: pd.DataFrame) -> pd.DataFrame:
    """Ground truth by src_ip + flow shape (see module docstring). No
    exclusion needed for this capture -- see docstring for why."""
    labelled = flows[flows["src_ip"].isin([ATTACKER_IP, BENIGN_IP])].copy()

    total_pkts   = labelled["total_fwd_packets"] + labelled["total_backward_packets"]
    is_scan_shape = (total_pkts <= 3) & (labelled["psh_flag_count"] == 0)
    is_attacker   = labelled["src_ip"] == ATTACKER_IP

    truth = np.full(len(labelled), _BENIGN_IDX, dtype=int)
    truth[is_attacker & is_scan_shape]  = _PORTSCAN_IDX
    truth[is_attacker & ~is_scan_shape] = _WEBATTACK_IDX
    labelled["__truth__"] = truth
    return labelled


def reprocess_pcap(pcap_path: str) -> pd.DataFrame:
    logger.info("Reprocessing %s", pcap_path)
    collector = FlowCollector()
    for pkt in rdpcap(pcap_path):
        collector.ingest_packet(pkt)
    flows = label_flows(collector.flush_all())
    counts = flows["__truth__"].value_counts()
    logger.info("Labelled %d flows: %s", len(flows),
                {ATTACK_CLASSES[k]: v for k, v in counts.items()})
    assert len(counts) > 1, "Need multiple classes present to compute meaningful mistakes"
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
    logger.info("Production multiclass model on capture: %.4f accuracy, %d/%d mistakes",
                accuracy, n_mistakes, len(truth))
    return n_mistakes, accuracy, X


def eval_on_capture(flows: pd.DataFrame, layer1: MLDetectionLayer) -> float:
    X = layer1._align_features(flows)
    pred = layer1._mc_model.predict(X)
    truth = flows["__truth__"].values
    return (pred == truth).sum() / len(truth)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", default=str(DEFAULT_PCAP))
    parser.add_argument("--sample-frac", type=float, default=0.02,
                         help="Fraction of CIC-IDS-2017 loaded for the cache/validation set")
    args = parser.parse_args()

    flows = reprocess_pcap(args.pcap)

    layer1 = MLDetectionLayer(model_path=str(BINARY_MODEL), feat_cols_path=str(FEAT_COLS))
    if layer1._mc_model is None:
        logger.error("No multiclass model loaded — nothing to retrain")
        return

    mistake_collector = MistakeCollector(buffer_path=MISTAKE_BUFFER)
    n_mistakes, acc_before, X_capture = find_mistakes(flows, mistake_collector, layer1)
    if n_mistakes == 0:
        logger.info("No mistakes found — production model already correct on this capture.")
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

    # Reload whichever model is now production (old if rejected, new if accepted)
    layer1_after = MLDetectionLayer(model_path=str(BINARY_MODEL), feat_cols_path=str(FEAT_COLS))
    acc_after = eval_on_capture(flows, layer1_after)
    logger.info(
        "Capture accuracy: before=%.4f after=%.4f (%d flows)",
        acc_before, acc_after, len(flows),
    )
    verdict = "PASS" if acc_after > acc_before else "NO IMPROVEMENT"
    logger.info("Multiclass adaptive-retrain check: %s", verdict)


if __name__ == "__main__":
    main()
