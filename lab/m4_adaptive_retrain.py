"""
lab/m4_adaptive_retrain.py

Purpose: Offline adaptive-retraining pass over the M4 domain-shift finding
         (docs/SESSION_LEDGER.md, 2026-07-25). Reprocesses the M4 pcap into
         flows via FlowCollector, labels ground truth from src_ip
         (192.168.56.10 = attacker/PortScan, 192.168.56.20 = benign), diffs
         those labels against the CURRENT production model's real
         predictions to find its actual mistakes, feeds them to
         MistakeCollector, caches a held-out CIC-IDS-2017 sample PLUS every
         M4 flow (not just the mistakes) so the retrain is validated against
         benchmark recall and can't whack-a-mole one lab flow-shape into
         wrongness while fixing another, and runs one
         AdaptiveTrainer.retrain() cycle.

         Feeding only mistakes (rows the pre-retrain model got wrong) into
         the retrainer means any lab flow-shape the pre-retrain model
         happened to get right by coincidence has zero representation in
         training — so a retrain that fixes one mistaken shape can freely
         flip a different, previously-correct shape to wrong, since nothing
         constrains it not to. Mixing in the full ground-truth-labelled M4
         capture at baseline weight (alongside the heavily-weighted mistake
         rows) gives every observed lab pattern some presence in training.

Inputs:  pcap/<M4 capture>.pcap; models/benchmarkids_binary.pkl;
         datasets/CIC-IDS-2017/**/*.csv (sampled).
Outputs: Retrained model in models/ if recall improves (old model backed up
         to .bak automatically by AdaptiveTrainer); before/after accuracy
         on the M4 capture printed to stdout.

Usage:
    python lab/m4_adaptive_retrain.py
    python lab/m4_adaptive_retrain.py --pcap pcap/other_capture.pcap --sample-frac 0.02
"""

import argparse
import logging
import sys
from pathlib import Path

import pandas as pd

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scapy.utils import rdpcap
from sklearn.model_selection import train_test_split

from adaptive.adaptive_trainer import AdaptiveTrainer
from adaptive.mistake_collector import MistakeCollector
from config import BINARY_LABEL_COL, DATA_2017, MODEL_DIR
from core.features import NetworkFeatureEngineer, get_feature_matrix
from core.flow_collector import FlowCollector
from core.preprocessing import load_full_dataset
from detection.layer1_ml import MLDetectionLayer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("m4_adaptive_retrain")

ATTACKER_IP  = "192.168.56.10"
BENIGN_IP    = "192.168.56.20"
DEFAULT_PCAP = _ROOT / "pcap" / "sentinel_20260725_201455_916db410.pcap"
BINARY_MODEL = MODEL_DIR / "benchmarkids_binary.pkl"
FEAT_COLS    = MODEL_DIR / "benchmarkids_binary_feature_cols.pkl"


def label_flows(flows):
    """Ground truth from known lab VM IPs; drops host-originated noise (ARP/mDNS)."""
    labelled = flows[flows["src_ip"].isin([ATTACKER_IP, BENIGN_IP])].copy()
    labelled["__truth__"] = (labelled["src_ip"] == ATTACKER_IP).astype(int)
    return labelled


def reprocess_pcap(pcap_path: str):
    logger.info("Reprocessing %s", pcap_path)
    collector = FlowCollector()
    for pkt in rdpcap(pcap_path):
        collector.ingest_packet(pkt)
    flows = label_flows(collector.flush_all())
    n_attack = int(flows["__truth__"].sum())
    n_benign = len(flows) - n_attack
    logger.info("Labelled %d flows (%d attack / %d benign)", len(flows), n_attack, n_benign)
    assert n_attack > 0 and n_benign > 0, "Need both classes present to compute meaningful mistakes"
    return flows


def find_mistakes(flows, collector: MistakeCollector) -> tuple:
    """Run the current production model, diff vs ground truth, buffer real mistakes."""
    layer1 = MLDetectionLayer(model_path=str(BINARY_MODEL), feat_cols_path=str(FEAT_COLS))
    result = layer1.predict_chunk(flows)
    X = layer1._align_features(flows)

    pred  = result["pred_binary"].values
    conf  = result["confidence"].values
    truth = flows["__truth__"].values

    n_mistakes = 0
    for i in range(len(X)):
        if pred[i] != truth[i]:
            collector.add(X.iloc[i], predicted=int(pred[i]), corrected=int(truth[i]),
                          confidence=float(conf[i]))
            n_mistakes += 1

    accuracy = (pred == truth).sum() / len(truth)
    logger.info("Production model on M4 capture: %.4f accuracy, %d/%d mistakes",
                accuracy, n_mistakes, len(truth))
    return n_mistakes, accuracy, X


def eval_on_m4(flows) -> float:
    """Reload whatever model is currently in production and score it on the M4 capture."""
    layer1 = MLDetectionLayer(model_path=str(BINARY_MODEL), feat_cols_path=str(FEAT_COLS))
    result = layer1.predict_chunk(flows)
    pred = result["pred_binary"].values
    truth = flows["__truth__"].values
    return (pred == truth).sum() / len(truth)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", default=str(DEFAULT_PCAP))
    parser.add_argument("--sample-frac", type=float, default=0.02,
                         help="Fraction of CIC-IDS-2017 loaded for the cache/validation set")
    args = parser.parse_args()

    flows = reprocess_pcap(args.pcap)

    mistake_collector = MistakeCollector()
    n_mistakes, acc_before, X_m4 = find_mistakes(flows, mistake_collector)
    if n_mistakes == 0:
        logger.info("No mistakes found — production model already correct on this capture. Nothing to retrain.")
        return

    trainer = AdaptiveTrainer(mistake_collector)

    logger.info("Loading CIC-IDS-2017 sample (frac=%.3f) for cache + held-out validation", args.sample_frac)
    df17 = load_full_dataset(str(DATA_2017 / "**" / "*.csv"), sample_frac=args.sample_frac)
    df17 = NetworkFeatureEngineer(keep_raw=True).transform(df17)
    X17, y17 = get_feature_matrix(df17, label_col=BINARY_LABEL_COL)
    X17_tr, X17_te, y17_tr, y17_te = train_test_split(
        X17, y17, test_size=0.2, random_state=42, stratify=y17,
    )

    # Mix in every M4 flow (not just the mistakes) at baseline weight, so
    # flow-shapes the pre-retrain model already got right stay represented
    # and can't get silently flipped while the retrain fixes its mistakes.
    y_m4 = pd.Series(flows["__truth__"].values, index=X_m4.index, name=BINARY_LABEL_COL)
    X_cache = pd.concat([X17_tr, X_m4], ignore_index=True)
    y_cache = pd.concat([y17_tr, y_m4], ignore_index=True)
    trainer.cache_training_data(X_cache, y_cache)

    result = trainer.retrain(X17_te, y17_te)
    logger.info(
        "Retrain result: improved=%s old_recall=%.4f new_recall=%.4f old_f1=%.4f new_f1=%.4f",
        result.improved, result.old_recall, result.new_recall, result.old_f1, result.new_f1,
    )
    logger.info(result.notes)

    acc_after = eval_on_m4(flows)
    logger.info(
        "M4 capture accuracy: before=%.4f after=%.4f (%d flows)",
        acc_before, acc_after, len(flows),
    )
    verdict = "PASS" if acc_after > acc_before else "NO IMPROVEMENT"
    logger.info("M4 adaptive-retrain check: %s", verdict)


if __name__ == "__main__":
    main()
