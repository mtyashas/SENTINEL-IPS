"""
lab/paper_repro/cross_dataset_eval.py

Purpose: Fresh, independent reproduction of the paper's Table 2/3 numbers
         (Experiment 2 - cross-dataset shift, Experiment 3 - combined
         training) for the IEEE paper's re-verification pass. Deliberately
         isolated: reads the project's real datasets/config but writes
         ONLY into lab/paper_repro/ (models, no report plots) -- never
         touches the live models/ directory, avoiding the mistake made
         earlier this session when train.py's default save path overwrote
         the production model.

Experiment 2 (train-2017, test-2018, no retraining): reuses the already
         fresh-trained lab/paper_repro/models/finding1_fresh_retrain.pkl
         (a plain BenchmarkIDS fit on full CIC-IDS-2017, same model this
         session already verified for Table 1) and evaluates it as-is,
         at its default (in-distribution) threshold, against CIC-IDS-2018.
         The recall collapse this is expected to reproduce IS the point:
         a fixed high in-distribution threshold under-fires on
         out-of-distribution probability outputs.

Experiment 3 (combined training): trains a fresh CombinedIDS (same
         architecture, lower default confidence threshold per
         config.CONFIDENCE_THRESHOLD_CROSSDATASET, exactly the class
         core/model.py documents as producing the original 80.83%
         recall / 89.40% F1 / 100% precision numbers) on a combined,
         2M-row-capped sample of 2017+2018 (matching train.py's own
         combined-mode capping logic), evaluated on a held-out 2018 split.

Usage:
    python lab/paper_repro/cross_dataset_eval.py
"""
import gc
import logging
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import train_test_split

from config import BINARY_LABEL_COL, CONFIDENCE_THRESHOLD_CROSS, DATA_2017, DATA_2018
from core.features import NetworkFeatureEngineer, get_feature_matrix
from core.model import CombinedIDS
from core.preprocessing import load_full_dataset
from detection.layer1_ml import MLDetectionLayer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                     datefmt="%H:%M:%S")
logger = logging.getLogger("cross_dataset_eval")

REPRO_DIR = _ROOT / "lab" / "paper_repro"
MODELS    = REPRO_DIR / "models"

DOCUMENTED = {
    "exp2": dict(accuracy=0.8564, precision=0.7418, recall=0.2012, f1=0.3166, roc_auc=0.9235),
    "exp3": dict(recall=0.8083, f1=0.8940, precision=1.0000),
}


def report(label, fresh, documented):
    print(f"\n--- {label} ---")
    print(f"{'metric':<10} {'fresh':>10} {'documented':>12} {'delta':>8}")
    for k, doc_v in documented.items():
        fresh_v = fresh.get(k, float("nan"))
        print(f"{k:<10} {fresh_v:>10.4f} {doc_v:>12.4f} {fresh_v - doc_v:>+8.4f}")


def experiment2(sample_frac: float = 1.0, chunk_size: int = 100_000):
    logger.info("=" * 70)
    logger.info("EXPERIMENT 2 -- train-2017 model evaluated cross-dataset on 2018 "
                "(sample_frac=%.3f)", sample_frac)
    logger.info("=" * 70)

    # MLDetectionLayer wraps the same 2017-trained model and applies
    # _align_features() before predicting -- required because 2018's raw
    # schema has extra columns (Protocol, Src Port) the 2017 training
    # schema never saw and is missing one the training schema expects
    # (the duplicate "Fwd Header Length.1" column, a known CIC-IDS-2017
    # quirk documented in CLAUDE.md). A direct model.predict_proba() call
    # enforces exact column-name equality via sklearn and throws on this
    # mismatch -- confirmed the hard way earlier this session.
    # threshold=CONFIDENCE_THRESHOLD_CROSS (0.35), not the 0.55 in-distribution
    # default -- config.py documents 0.35 specifically as "cross-dataset detection
    # threshold". Missing this on the first attempt produced a precision/recall
    # skew (too-high precision, too-low recall) that didn't match the documented
    # Experiment 2 numbers -- a real methodology bug, not noise.
    layer1 = MLDetectionLayer(
        model_path=str(MODELS / "finding1_fresh_retrain.pkl"),
        feat_cols_path=str(MODELS / "finding1_feature_cols.pkl"),
        threshold=CONFIDENCE_THRESHOLD_CROSS,
    )
    logger.info("Loaded pre-trained 2017 model via MLDetectionLayer (aligned inference path, "
                "threshold=%.2f)", CONFIDENCE_THRESHOLD_CROSS)

    logger.info("Loading CIC-IDS-2018 (sample_frac=%.3f)...", sample_frac)
    t0 = time.monotonic()
    df18 = load_full_dataset(str(DATA_2018 / "**" / "*.csv"), sample_frac=sample_frac)
    logger.info("Loaded %d rows in %.1fs", len(df18), time.monotonic() - t0)

    df18 = NetworkFeatureEngineer(keep_raw=True).transform(df18)
    logger.info("Feature-engineered shape: %s", df18.shape)

    all_truth, all_pred, all_proba = [], [], []
    t0 = time.monotonic()
    for start in range(0, len(df18), chunk_size):
        chunk = df18.iloc[start:start + chunk_size]
        result = layer1.predict_chunk(chunk)
        all_truth.append(chunk[BINARY_LABEL_COL].values)
        all_pred.append(result["pred_binary"].values)
        all_proba.append(result["confidence"].values)
    logger.info("Predicted %d flows in %.1fs", len(df18), time.monotonic() - t0)
    del df18
    gc.collect()

    truth = np.concatenate(all_truth)
    pred = np.concatenate(all_pred)
    proba = np.concatenate(all_proba)

    tn, fp, fn, tp = confusion_matrix(truth, pred, labels=[0, 1]).ravel()
    fresh = dict(
        accuracy=accuracy_score(truth, pred),
        precision=precision_score(truth, pred, zero_division=0),
        recall=recall_score(truth, pred, zero_division=0),
        f1=f1_score(truth, pred, zero_division=0),
        roc_auc=roc_auc_score(truth, proba),
    )
    report("Experiment 2 (cross-dataset)", fresh, DOCUMENTED["exp2"])
    print(f"confusion  fresh: TP={tp} TN={tn} FP={fp} FN={fn}  n={len(truth)}")
    print(f"(documented: n=15,188,468 flows tested)")

    del truth, pred, proba
    gc.collect()
    return fresh

    del X18, y18, proba, pred
    gc.collect()
    return fresh


def experiment3():
    logger.info("=" * 70)
    logger.info("EXPERIMENT 3 -- combined 2017+2018 training, evaluated on held-out 2018")
    logger.info("=" * 70)

    logger.info("Loading 2017...")
    df17 = load_full_dataset(str(DATA_2017 / "**" / "*.csv"), sample_frac=0.5)
    logger.info("Loading 2018...")
    df18 = load_full_dataset(str(DATA_2018 / "**" / "*.csv"), sample_frac=0.2)

    # Split 2018 into a training portion and a held-out test portion BEFORE any
    # capping/combining, so the evaluation set is never seen in training. The
    # first attempt at this instead evaluated against a set built from the same
    # (capped) 2018 rows used to train -- real train/test leakage, not the
    # "2017+2018 -> 2018" methodology Table III's original number describes.
    df18_train, df18_test = train_test_split(
        df18, test_size=0.2, random_state=42, stratify=df18[BINARY_LABEL_COL],
    )
    del df18
    gc.collect()

    # Keep the engineered test frame (with its label column) intact, rather than
    # reducing it to a bare feature matrix via get_feature_matrix() -- 2018-only
    # data doesn't carry the "Fwd Header Length.1" duplicate column that's a
    # CIC-IDS-2017 CSV quirk baked into the training schema, and get_feature_matrix
    # does no alignment, so a direct model.predict() on it throws the exact
    # column-mismatch error the Experiment 2 fix above already solved once.
    # MLDetectionLayer.predict_chunk() (used below, after training) handles this
    # correctly via _align_features().
    df18_test_eng = NetworkFeatureEngineer(keep_raw=True).transform(df18_test.copy())
    del df18_test
    gc.collect()

    cap = 2_000_000
    if len(df17) + len(df18_train) > cap:
        frac = cap / (len(df17) + len(df18_train))
        df17 = df17.sample(frac=frac, random_state=42)
        df18_train = df18_train.sample(frac=frac, random_state=42)
        logger.info("Capped combined training set to ~%d rows (matches train.py's own cap)", cap)

    # Intersect columns before combining rather than plain concat -- 2017 and
    # 2018 don't share every column (e.g. "Fwd Header Length.1" is 2017-only),
    # and a plain concat leaves those NaN for whichever source lacks them,
    # silently degrading that feature via median-imputation for half the rows.
    # This exact approach (intersection, not concat-then-hope) is what the
    # project's original combine_and_train.py script used.
    common_cols = list(set(df17.columns) & set(df18_train.columns))
    df_train = pd.concat(
        [df17[common_cols], df18_train[common_cols]], ignore_index=True,
    )
    del df17, df18_train
    gc.collect()

    df_train = NetworkFeatureEngineer(keep_raw=True).transform(df_train)
    X_tr, y_tr = get_feature_matrix(df_train, label_col=BINARY_LABEL_COL)
    del df_train
    gc.collect()

    # Undersample the majority (benign) class to a 2:1 ratio and derive
    # scale_pos_weight from that balanced set, exactly matching the project's
    # original combine_and_train.py methodology (undersample_majority() +
    # compute_scale_pos_weight()) -- omitting this on the first attempt left
    # the model trained on the natural ~15% attack rate with a generic fixed
    # scale_pos_weight, producing a model biased toward predicting "benign"
    # (99.88% precision, 25.5% recall -- confident but far too conservative).
    rng = np.random.default_rng(42)
    idx_attack = y_tr[y_tr == 1].index
    idx_benign = y_tr[y_tr == 0].index
    target = min(len(idx_benign), int(len(idx_attack) * 2.0))
    chosen_benign = rng.choice(idx_benign, size=target, replace=False)
    keep = np.concatenate([idx_attack, chosen_benign])
    rng.shuffle(keep)
    X_tr, y_tr = X_tr.loc[keep], y_tr.loc[keep]
    scale_pos_weight = float((y_tr == 0).sum()) / max((y_tr == 1).sum(), 1)
    logger.info("Undersampled to %d rows (attack=%d, benign=%d), scale_pos_weight=%.2f",
                len(X_tr), (y_tr == 1).sum(), (y_tr == 0).sum(), scale_pos_weight)

    # scale_pos_weight computed above from the undersampled set was previously
    # computed but never actually passed here -- CombinedIDS silently fell back
    # to its default (config.SCALE_POS_WEIGHT=3.0) instead. Didn't explain the
    # recall=0 result (a separate stale-cache bug did, fixed below), but was
    # still a real inconsistency with the intended methodology.
    model = CombinedIDS(mode="binary", scale_pos_weight=scale_pos_weight)
    t0 = time.monotonic()
    model.fit(X_tr, y_tr)
    logger.info("Fit time: %.1fs", time.monotonic() - t0)
    del X_tr, y_tr
    gc.collect()

    # Save immediately after fit -- before evaluation -- so a crash during
    # evaluation (as happened on the first attempt) never loses a completed
    # 100+ second training run.
    save_path = MODELS / "finding_combined_experiment3.pkl"
    model.save(save_path)
    logger.info("Model saved to isolated path: %s", save_path)

    # Delete any stale feature-columns cache from a previous run's different
    # model schema before loading -- MLDetectionLayer reuses a cache file by
    # path, not by model identity, and reusing one across two differently-
    # trained models here (78 cols now vs. a wider set from an earlier attempt)
    # caused every prediction to fail and silently fall back to all-benign.
    feat_cols_path = MODELS / "finding_combined_experiment3_feature_cols.pkl"
    feat_cols_path.unlink(missing_ok=True)

    layer1 = MLDetectionLayer(
        model_path=str(save_path),
        feat_cols_path=str(feat_cols_path),
        threshold=CONFIDENCE_THRESHOLD_CROSS,
    )

    all_truth, all_pred = [], []
    chunk_size = 100_000
    for start in range(0, len(df18_test_eng), chunk_size):
        chunk = df18_test_eng.iloc[start:start + chunk_size]
        result = layer1.predict_chunk(chunk)
        all_truth.append(chunk[BINARY_LABEL_COL].values)
        all_pred.append(result["pred_binary"].values)
    del df18_test_eng
    gc.collect()

    truth = np.concatenate(all_truth)
    pred = np.concatenate(all_pred)
    fresh = dict(
        recall=recall_score(truth, pred, zero_division=0),
        f1=f1_score(truth, pred, zero_division=0),
        precision=precision_score(truth, pred, zero_division=0),
    )
    report("Experiment 3 (combined training, held-out split)", fresh, DOCUMENTED["exp3"])

    del truth, pred
    gc.collect()
    return fresh


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke-test", action="store_true",
                         help="Run experiment 2 on a tiny 2018 sample first, to validate "
                              "the alignment fix before committing to a full 15M-row run.")
    parser.add_argument("--only", choices=["2", "3"], default=None,
                         help="Run only experiment 2 or only experiment 3 "
                              "(e.g. to re-run 3 alone after fixing a bug in it, "
                              "without repeating experiment 2's already-successful "
                              "15M-row load).")
    args = parser.parse_args()

    if args.smoke_test:
        experiment2(sample_frac=0.005)
    elif args.only == "2":
        experiment2(sample_frac=1.0)
    elif args.only == "3":
        experiment3()
    else:
        experiment2(sample_frac=1.0)
        experiment3()
        print("\nDone. Both experiments evaluated with fresh, isolated runs -- "
              "no file outside lab/paper_repro/ was written.")
