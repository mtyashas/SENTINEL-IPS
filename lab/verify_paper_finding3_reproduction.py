"""
lab/verify_paper_finding3_reproduction.py

Purpose: Fresh, independently-reproduced verification of the paper's
         Finding 3 numbers (docs/RESEARCH_PAPER_RESULTS_M1-M4.md Table in
         §4.1b: 17,612-flow independent re-verification capture, before/after
         the second adaptive retrain). Replays the actual saved pcap through
         the exact live-inference path (FlowCollector -> MLDetectionLayer),
         same approach the project already used for M4, rather than trusting
         the documented numbers without re-running them for the paper.

Inputs:  pcap/sentinel_20260726_201541_fad8ceaa.pcap (identified as the
         44,823-packet / 17,612-flow re-verification capture referenced in
         project memory and docs/RESEARCH_PAPER_RESULTS_M1-M4.md);
         model files read ONLY from lab/paper_repro/models/ (isolated copies
         of benchmarkids_adaptive_20260726_180648_v1.pkl /
         benchmarkids_adaptive_20260726_203058_v1.pkl / the shared
         feature-columns file) -- never the live models/ directory, so this
         script cannot touch production regardless of what MLDetectionLayer
         or its dependencies do internally.
Outputs: Printed accuracy/precision/recall/F1/ROC-AUC/confusion-matrix for
         both models, for direct comparison against the documented
         95.16% -> 99.74% Table.

Usage:
    python lab/verify_paper_finding3_reproduction.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scapy.utils import rdpcap
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)

from core.flow_collector import FlowCollector
from detection.layer1_ml import MLDetectionLayer

PCAP        = _ROOT / "pcap" / "sentinel_20260726_201541_fad8ceaa.pcap"
ATTACKER_IP = "192.168.56.10"
BENIGN_IP   = "192.168.56.20"
REPRO_DIR   = _ROOT / "lab" / "paper_repro" / "models"
FEAT_COLS   = REPRO_DIR / "feature_cols.pkl"
BEFORE      = REPRO_DIR / "finding3_before.pkl"
AFTER       = REPRO_DIR / "finding3_after.pkl"

DOCUMENTED = {
    "before": dict(accuracy=0.9516, precision=0.9538, recall=0.9922, f1=0.9726,
                    roc_auc=0.8987, tp=15128, tn=1632, fp=733, fn=119),
    "after":  dict(accuracy=0.9974, precision=1.0000, recall=0.9970, f1=0.9985,
                    roc_auc=0.9998, tp=15201, tn=2365, fp=0,   fn=46),
}


def label_flows(flows):
    labelled = flows[flows["src_ip"].isin([ATTACKER_IP, BENIGN_IP])].copy()
    labelled["__truth__"] = (labelled["src_ip"] == ATTACKER_IP).astype(int)
    return labelled


def evaluate(model_path: Path, flows, truth) -> dict:
    layer1 = MLDetectionLayer(model_path=str(model_path), feat_cols_path=str(FEAT_COLS))
    result = layer1.predict_chunk(flows)
    pred = result["pred_binary"].values
    proba = result["confidence"].values
    tn, fp, fn, tp = confusion_matrix(truth, pred, labels=[0, 1]).ravel()
    return dict(
        accuracy=accuracy_score(truth, pred),
        precision=precision_score(truth, pred, zero_division=0),
        recall=recall_score(truth, pred, zero_division=0),
        f1=f1_score(truth, pred, zero_division=0),
        roc_auc=roc_auc_score(truth, proba) if len(set(truth)) > 1 else float("nan"),
        tp=int(tp), tn=int(tn), fp=int(fp), fn=int(fn),
    )


def report(label: str, fresh: dict, documented: dict) -> None:
    print(f"\n--- {label} ---")
    print(f"{'metric':<10} {'fresh':>10} {'documented':>12} {'delta':>8}")
    for k in ("accuracy", "precision", "recall", "f1", "roc_auc"):
        d = fresh[k] - documented[k]
        print(f"{k:<10} {fresh[k]:>10.4f} {documented[k]:>12.4f} {d:>+8.4f}")
    print(f"confusion  fresh: TP={fresh['tp']} TN={fresh['tn']} FP={fresh['fp']} FN={fresh['fn']}")
    print(f"confusion  doc:   TP={documented['tp']} TN={documented['tn']} "
          f"FP={documented['fp']} FN={documented['fn']}")


def main() -> None:
    if not PCAP.exists():
        print(f"FAIL: pcap not found: {PCAP}")
        sys.exit(1)

    print(f"Reprocessing {PCAP.name} ...")
    collector = FlowCollector()
    for pkt in rdpcap(str(PCAP)):
        collector.ingest_packet(pkt)
    flows = label_flows(collector.flush_all())
    n_attack = int(flows["__truth__"].sum())
    n_benign = len(flows) - n_attack
    print(f"Labelled {len(flows)} flows ({n_attack} attack / {n_benign} benign) "
          f"-- documented: 17,612 flows (15,247 attack / 2,365 benign)")

    truth = flows["__truth__"].values

    fresh_before = evaluate(BEFORE, flows, truth)
    report("BEFORE 2nd retrain", fresh_before, DOCUMENTED["before"])

    fresh_after = evaluate(AFTER, flows, truth)
    report("AFTER 2nd retrain", fresh_after, DOCUMENTED["after"])

    print("\nDone. Compare deltas above -- small (<1pp) drift is expected noise; "
          "large drift means the identified pcap/model pairing may not be exactly "
          "the one that produced the documented numbers, and should be flagged, "
          "not silently accepted.")


if __name__ == "__main__":
    main()
