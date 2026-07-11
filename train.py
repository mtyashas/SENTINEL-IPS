"""
train.py

Purpose: End-to-end training pipeline for SENTINEL IPS v2.0.
         Loads CIC-IDS-2017 / CIC-IDS-2018 data, engineers features,
         trains BenchmarkIDS (binary + multiclass), LightweightIDS, and
         optionally CombinedIDS; evaluates against CLAUDE.md benchmark
         targets; generates SHAP explanations and saves all artefacts.

Usage:
    python train.py --dataset 2017 --sample-frac 0.10
    python train.py --dataset combined --sample-frac 0.05 --skip-shap
    python train.py --dataset 2017 --sample-frac 1.0 --mode all

Arguments:
    --dataset      2017 | 2018 | combined  (default: 2017)
    --sample-frac  float 0 < f <= 1.0      (default: 0.10)
    --mode         binary | multiclass | lightweight | all  (default: all)
    --skip-shap    skip SHAP explanation step (saves ~10 minutes)
    --no-report    skip evaluation report plots
"""

import argparse
import gc
import logging
import sys
import time
from pathlib import Path

# Ensure project root is on sys.path
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config import (
    BINARY_LABEL_COL,
    DATA_2017,
    DATA_2018,
    ENGINEERED_FEATURES,
    MODEL_DIR,
    MULTICLASS_LABEL_COL,
    REPORT_DIR,
    SHAP_DIR,
)
from core.features import NetworkFeatureEngineer, get_feature_matrix
from core.model import BenchmarkIDS, CombinedIDS, LightweightIDS, evaluate_model
from core.preprocessing import load_full_dataset
from evaluation.metrics import IDSEvaluator
from evaluation.reporter import EvaluationReporter

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(_ROOT / "logs" / "train.log", mode="a", encoding="utf-8"),
    ],
)
logger = logging.getLogger("sentinel.train")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _banner(text: str) -> None:
    bar = "=" * 70
    logger.info(bar)
    logger.info("  %s", text)
    logger.info(bar)


def _train_test_split(X, y, test_frac: float = 0.2, random_state: int = 42):
    """Stratified train/test split without sklearn dependency on large frames."""
    from sklearn.model_selection import train_test_split
    return train_test_split(X, y, test_size=test_frac,
                             stratify=y, random_state=random_state)


def _load_data(dataset: str, sample_frac: float):
    """Load and engineer features for the requested dataset."""
    _banner(f"LOADING DATA — dataset={dataset}, sample_frac={sample_frac}")

    if dataset == "2017":
        pattern = str(DATA_2017 / "**" / "*.csv")
        df = load_full_dataset(pattern, sample_frac=sample_frac)
        experiment_binary = "2017_binary"
        experiment_mc     = "multiclass"

    elif dataset == "2018":
        pattern = str(DATA_2018 / "**" / "*.csv")
        df = load_full_dataset(pattern, sample_frac=sample_frac)
        experiment_binary = "cross_dataset"
        experiment_mc     = "multiclass"

    else:  # combined
        logger.info("Loading 2017 data...")
        df_17 = load_full_dataset(str(DATA_2017 / "**" / "*.csv"),
                                   sample_frac=sample_frac)
        logger.info("Loading 2018 data...")
        df_18 = load_full_dataset(str(DATA_2018 / "**" / "*.csv"),
                                   sample_frac=sample_frac)
        # Cap combined dataset to avoid memory error
        cap = 2_000_000
        if len(df_17) + len(df_18) > cap:
            frac = cap / (len(df_17) + len(df_18))
            df_17 = df_17.sample(frac=frac, random_state=42)
            df_18 = df_18.sample(frac=frac, random_state=42)
            logger.info("Capped combined dataset to ~%d rows", cap)
        import pandas as pd
        df = pd.concat([df_17, df_18], ignore_index=True)
        del df_17, df_18
        gc.collect()
        experiment_binary = "combined_training"
        experiment_mc     = "multiclass"

    logger.info("Raw dataset shape: %s", df.shape)

    # Feature engineering
    engineer = NetworkFeatureEngineer(keep_raw=True)
    df = engineer.transform(df)
    logger.info("Feature-engineered shape: %s", df.shape)

    return df, experiment_binary, experiment_mc


# ---------------------------------------------------------------------------
# Training functions
# ---------------------------------------------------------------------------

def train_benchmark_binary(df, experiment: str, reporter: EvaluationReporter,
                            skip_shap: bool):
    """Train BenchmarkIDS binary classifier."""
    _banner("TRAINING — BenchmarkIDS (binary)")

    X, y = get_feature_matrix(df, label_col=BINARY_LABEL_COL)
    X_tr, X_te, y_tr, y_te = _train_test_split(X, y)
    logger.info("Train: %d rows | Test: %d rows | Features: %d",
                len(X_tr), len(X_te), X_tr.shape[1])

    model = BenchmarkIDS(mode="binary")
    t0    = time.monotonic()
    model.fit(X_tr, y_tr)
    logger.info("Fit time: %.1fs", time.monotonic() - t0)

    # Core evaluation
    metrics = evaluate_model(model, X_te, y_te)
    logger.info(
        "BenchmarkIDS binary: acc=%.4f  prec=%.4f  rec=%.4f  f1=%.4f  auc=%.4f",
        metrics["accuracy"], metrics["precision"], metrics["recall"],
        metrics["f1"], metrics["roc_auc"],
    )

    # Full IDSEvaluator suite
    evaluator = IDSEvaluator()
    result    = evaluator.evaluate(model, X_te, y_te, experiment=experiment)
    br        = evaluator.validate_benchmark(result, experiment)
    logger.info(br.summary)

    # Reports
    import numpy as np
    y_pred = model.predict(X_te)
    reporter.full_phase_report(
        result, benchmark=br,
        y_true=(y_te.values if hasattr(y_te, "values") else y_te),
        y_pred=y_pred,
    )

    # SHAP
    if not skip_shap:
        _run_shap(model, X_te, "BenchmarkIDS-binary")

    # Save
    path = model.save()
    logger.info("Model saved: %s", path)

    del X_tr, y_tr
    gc.collect()
    return model, result, br


def train_benchmark_multiclass(df, reporter: EvaluationReporter, skip_shap: bool):
    """Train BenchmarkIDS multiclass classifier."""
    _banner("TRAINING — BenchmarkIDS (multiclass)")

    X, y = get_feature_matrix(df, label_col=MULTICLASS_LABEL_COL)
    n_classes = y.nunique()
    logger.info("Classes: %d | Train+test rows: %d", n_classes, len(X))

    if n_classes < 2:
        logger.warning("Only %d class(es) found — skipping multiclass training", n_classes)
        return None, None

    X_tr, X_te, y_tr, y_te = _train_test_split(X, y)

    model = BenchmarkIDS(mode="multiclass")
    t0    = time.monotonic()
    model.fit(X_tr, y_tr)
    logger.info("Fit time: %.1fs", time.monotonic() - t0)

    metrics = evaluate_model(model, X_te, y_te)
    logger.info("BenchmarkIDS multiclass: acc=%.4f  f1_macro=%.4f",
                metrics["accuracy"], metrics["f1_macro"])

    evaluator = IDSEvaluator()
    mc_result = evaluator.evaluate_multiclass(
        model, X_te, y_te, experiment="multiclass")
    br = evaluator.validate_benchmark(mc_result, "multiclass")
    logger.info(br.summary)

    reporter.save_report(mc_result, benchmark=br)
    from config import ATTACK_CLASSES
    reporter.plot_per_class(mc_result.per_class, class_names=ATTACK_CLASSES)

    if not skip_shap:
        _run_shap(model, X_te, "BenchmarkIDS-multiclass")

    path = model.save()
    logger.info("Model saved: %s", path)

    del X_tr, y_tr
    gc.collect()
    return model, mc_result


def train_lightweight(df, reporter: EvaluationReporter):
    """Train LightweightIDS on the 10 ENGINEERED_FEATURES."""
    _banner("TRAINING — LightweightIDS (10-feature)")

    # Keep only engineered features + labels
    avail = [f for f in ENGINEERED_FEATURES if f in df.columns]
    if len(avail) < 5:
        logger.warning("Only %d ENGINEERED_FEATURES present — skipping", len(avail))
        return None

    X, y = get_feature_matrix(df, label_col=BINARY_LABEL_COL)
    X = X[[c for c in avail if c in X.columns]]
    X_tr, X_te, y_tr, y_te = _train_test_split(X, y)

    model = LightweightIDS()
    t0    = time.monotonic()
    model.fit(X_tr, y_tr)
    logger.info("Fit time: %.1fs", time.monotonic() - t0)

    metrics  = evaluate_model(model, X_te, y_te)
    tput_fps = model.benchmark_throughput(X_te)
    logger.info(
        "LightweightIDS: acc=%.4f  f1=%.4f  auc=%.4f  throughput=%.0f fps",
        metrics["accuracy"], metrics["f1"], metrics["roc_auc"], tput_fps,
    )

    evaluator = IDSEvaluator()
    result    = evaluator.evaluate(model, X_te, y_te, experiment="lightweight")
    result.throughput_fps = tput_fps
    br = evaluator.validate_benchmark(result, "lightweight")
    logger.info(br.summary)

    reporter.save_report(result, benchmark=br)

    path = MODEL_DIR / "lightweightids_binary.pkl"
    import joblib
    joblib.dump(model, path)
    logger.info("Model saved: %s", path)

    del X_tr, y_tr
    gc.collect()
    return model


def _run_shap(model, X_test, label: str) -> None:
    """Generate SHAP summary plot for a fitted model."""
    try:
        import pandas as pd
        from explainability.shap_explainer import SHAPExplainer

        X_sample = X_test.sample(
            n=min(500, len(X_test)), random_state=42
        ) if len(X_test) > 500 else X_test.copy()

        if not isinstance(X_sample, pd.DataFrame):
            return

        explainer = SHAPExplainer(model)
        result    = explainer.explain(X_sample)
        if result is not None:
            path = explainer.plot_summary(result, title=f"SHAP — {label}")
            logger.info("SHAP plot: %s", path)
            ranked = explainer.global_importance(result)
            logger.info("Top 5 features (%s): %s",
                        label, ranked[:5])
    except Exception as exc:
        logger.warning("SHAP failed for %s: %s", label, exc)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL IPS v2.0 — Training Pipeline",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--dataset",     choices=["2017", "2018", "combined"],
                        default="2017",
                        help="Dataset to train on")
    parser.add_argument("--sample-frac", type=float, default=0.10,
                        metavar="F",
                        help="Fraction of each CSV to sample (0 < F <= 1.0)")
    parser.add_argument("--mode",        choices=["binary", "multiclass",
                                                   "lightweight", "all"],
                        default="all",
                        help="Which model(s) to train")
    parser.add_argument("--skip-shap",   action="store_true",
                        help="Skip SHAP explanation step")
    parser.add_argument("--no-report",   action="store_true",
                        help="Skip evaluation report generation")
    args = parser.parse_args()

    if not (0 < args.sample_frac <= 1.0):
        parser.error("--sample-frac must be in (0, 1]")

    _banner("SENTINEL IPS v2.0 — TRAINING PIPELINE")
    logger.info("Dataset=%s  sample_frac=%.3f  mode=%s  skip_shap=%s",
                args.dataset, args.sample_frac, args.mode, args.skip_shap)

    t_start  = time.monotonic()
    reporter = EvaluationReporter() if not args.no_report else None

    # Ensure dirs exist
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    SHAP_DIR.mkdir(parents=True,  exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    try:
        df, exp_binary, exp_mc = _load_data(args.dataset, args.sample_frac)
    except FileNotFoundError as exc:
        logger.error("Data not found: %s", exc)
        logger.error(
            "Place CIC-IDS-2017 CSVs under datasets/CIC-IDS-2017/ "
            "and CIC-IDS-2018 under datasets/CIC-IDS-2018/"
        )
        sys.exit(1)

    train_binary     = args.mode in ("binary",     "all")
    train_mc         = args.mode in ("multiclass", "all")
    train_lite       = args.mode in ("lightweight","all")

    binary_model = None
    if train_binary:
        binary_model, _, _ = train_benchmark_binary(
            df, exp_binary, reporter or EvaluationReporter(),
            skip_shap=args.skip_shap,
        )

    if train_mc:
        train_benchmark_multiclass(
            df, reporter or EvaluationReporter(),
            skip_shap=args.skip_shap,
        )

    if train_lite:
        train_lightweight(df, reporter or EvaluationReporter())

    elapsed = time.monotonic() - t_start
    _banner(f"TRAINING COMPLETE in {elapsed:.1f}s")
    logger.info("Models in  : %s", MODEL_DIR)
    logger.info("Reports in : %s", REPORT_DIR)
    logger.info("SHAP plots : %s", SHAP_DIR)
    logger.info("To launch the dashboard: streamlit run dashboard/app.py")


if __name__ == "__main__":
    main()
