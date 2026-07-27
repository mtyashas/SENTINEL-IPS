"""
lab/m5_multiclass_retrain.py

Purpose: Adaptive-retraining pass for the multiclass model, mirroring
         lab/m4_adaptive_retrain.py's approach for the binary model
         (docs/SESSION_LEDGER.md, 2026-07-27 next-steps: "same domain-shift
         pattern as M4's binary model, apparently never addressed for
         multiclass"). Without a real attack-type label, severity never
         escalates past MEDIUM (SEVERITY_LEVELS matches on exact attack-type
         name) and threat_intel/ip_blacklist.txt auto-blacklisting never
         fires — this is a dead code path until attack_class resolves to
         real names on live traffic.

         Ground truth here is inferred from the M5 lab capture rather than
         known per-flow: src_ip alone identifies attacker vs benign (as in
         M4), but not *which* attack type. Distinguished by flow shape
         instead, using only already-computed flow features (no payload
         inspection):
           - src_ip == BENIGN_IP                                 -> BENIGN
           - src_ip == ATTACKER_IP, <=2 packets, no PSH data      -> EXCLUDED
             (hping3 --flood -S produces bare-SYN, no-payload flows --
             the *identical* per-flow shape as gen_benign_traffic.sh's
             deliberate closed-port probes to :8081. Genuinely
             indistinguishable at the single-flow feature level with no
             cross-flow rate signal in this schema; an earlier version of
             this script force-labelled these DoS and it taught the model
             to also flag ~28% of real benign traffic as DoS. Excluding
             them is honest about the limitation instead of shipping a
             confident false positive. DoS/DDoS detection for this exact
             attack style remains an open gap -- would need a rate/volume
             feature FlowCollector doesn't currently compute.)
           - src_ip == ATTACKER_IP, otherwise (real HTTP request/
             response exchanged)                                 -> BruteForce
             (hydra's many login POSTs dominate this bucket by volume;
             the one SQLi-shaped curl request gets folded in too --
             a known, deliberate simplification, not a labeling bug:
             BruteForce and the true WebAttack class are adjacent-severity
             MEDIUM anyway, so this doesn't affect the severity-escalation
             goal this pass targets.)

Inputs:  pcap/<M5 capture>.pcap; models/benchmarkids_multiclass.pkl;
         datasets/CIC-IDS-2017/**/*.csv (sampled).
Outputs: Retrained multiclass model in models/ if macro recall improves
         (old model backed up to .bak); before/after accuracy on the M5
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
DEFAULT_PCAP = _ROOT / "pcap" / "sentinel_20260727_130028_613ecac5.pcap"
BINARY_MODEL     = MODEL_DIR / "benchmarkids_binary.pkl"
MULTICLASS_MODEL = MODEL_DIR / "benchmarkids_multiclass.pkl"
FEAT_COLS        = MODEL_DIR / "benchmarkids_binary_feature_cols.pkl"
TRAIN_CACHE      = MODEL_DIR / "train_cache_multiclass.parquet"
MISTAKE_BUFFER   = MODEL_DIR / "mistakes_buffer_multiclass.parquet"

_BENIGN_IDX = ATTACK_CLASSES.index("BENIGN")
_BF_IDX     = ATTACK_CLASSES.index("BruteForce")


def label_flows(flows: pd.DataFrame) -> pd.DataFrame:
    """Ground truth by src_ip + flow shape (see module docstring).

    Bare "<=2 packets, no payload" flows are EXCLUDED entirely rather than
    labelled DoS: gen_benign_traffic.sh's deliberate closed-port probes
    (curl --max-time 1 to :8081) produce the identical per-flow shape as a
    bare-SYN hping3 flood fragment -- genuinely indistinguishable at the
    single-flow feature level (no cross-flow rate signal exists in this
    schema). Training the model to call that shape DoS just teaches it to
    also flag the benign probes; better to admit the ambiguity than ship a
    confident false positive on real benign traffic.
    """
    labelled = flows[flows["src_ip"].isin([ATTACKER_IP, BENIGN_IP])].copy()

    total_pkts = labelled["total_fwd_packets"] + labelled["total_backward_packets"]
    is_ambiguous_shape = (total_pkts <= 2) & (labelled["psh_flag_count"] == 0)
    labelled = labelled[~is_ambiguous_shape].copy()

    truth = np.full(len(labelled), _BF_IDX, dtype=int)
    truth[labelled["src_ip"] == BENIGN_IP] = _BENIGN_IDX
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
    logger.info("Production multiclass model on M5 capture: %.4f accuracy, %d/%d mistakes",
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
    n_mistakes, acc_before, X_m5 = find_mistakes(flows, mistake_collector, layer1)
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

    y_m5 = pd.Series(flows["__truth__"].values, index=X_m5.index, name=MULTICLASS_LABEL_COL)
    X_cache = pd.concat([X17_tr, X_m5], ignore_index=True)
    y_cache = pd.concat([y17_tr, y_m5], ignore_index=True)
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
        "M5 capture accuracy: before=%.4f after=%.4f (%d flows)",
        acc_before, acc_after, len(flows),
    )
    verdict = "PASS" if acc_after > acc_before else "NO IMPROVEMENT"
    logger.info("M5 multiclass adaptive-retrain check: %s", verdict)


if __name__ == "__main__":
    main()
