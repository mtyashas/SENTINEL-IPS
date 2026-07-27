"""
core/model.py

Purpose: Three XGBoost-based intrusion detection classifiers with sklearn Pipeline
         API, model persistence, throughput benchmarking, and unified evaluation.

         BenchmarkIDS   — Full-feature binary/multiclass IDS. ANOVA k=30 selection
                          across all preprocessed columns. Targets 99.69% accuracy,
                          99.10% F1, 99.99% AUC on CIC-IDS-2017.

         LightweightIDS — 10 ENGINEERED_FEATURES IDS optimised for real-time
                          throughput. Targets >= 1.6M flows/second in batch mode.

         CombinedIDS    — BenchmarkIDS variant trained on 2017+2018 combined data.
                          Uses CONFIDENCE_THRESHOLD_CROSS (0.35) to recover recall
                          lost to domain shift. Targets 80.83% recall / 89.40% F1.

Inputs:  pd.DataFrame from core/preprocessing → core/features pipeline.
Outputs: Fitted sklearn-compatible models, metrics dicts, joblib .pkl files.

Usage:
    from core.model import BenchmarkIDS, LightweightIDS, CombinedIDS, evaluate_model
    model = BenchmarkIDS(mode='binary')
    model.fit(X_train, y_train)
    metrics = evaluate_model(model, X_test, y_test)
    model.save()
"""

import gc
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

from config import (
    CONFIDENCE_THRESHOLD,
    CONFIDENCE_THRESHOLD_CROSS,
    ENGINEERED_FEATURES,
    K_BEST_FEATURES,
    MODEL_DIR,
    SCALE_POS_WEIGHT,
    XGB_PARAMS,
)
from core.features import ANOVAFeatureSelector

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal pipeline factory
# ---------------------------------------------------------------------------

def _build_pipeline(
    mode: str,
    k_features: int,
    scale_pos_weight: float,
    include_selector: bool = True,
    n_estimators_override: Optional[int] = None,
) -> Pipeline:
    """
    Construct the mandated SENTINEL pipeline with pandas output preservation.

    set_output(transform='pandas') is applied to SimpleImputer and StandardScaler
    so that the ANOVAFeatureSelector always receives a named DataFrame — the
    critical requirement for SHAP to show real feature names (not f0/f13).
    """
    imputer = SimpleImputer(strategy="median").set_output(transform="pandas")
    scaler  = StandardScaler().set_output(transform="pandas")

    xgb_kw = dict(XGB_PARAMS)
    if n_estimators_override is not None:
        xgb_kw["n_estimators"] = n_estimators_override

    if mode == "binary":
        xgb_kw.update({
            "objective":         "binary:logistic",
            "eval_metric":       "logloss",
            "scale_pos_weight":  scale_pos_weight,
        })
    else:
        xgb_kw.pop("scale_pos_weight", None)
        xgb_kw.update({
            "objective":   "multi:softproba",
            "eval_metric": "mlogloss",
        })

    steps: List[tuple] = [("imputer", imputer), ("scaler", scaler)]
    if include_selector:
        steps.append(("selector", ANOVAFeatureSelector(k=k_features)))
    steps.append(("clf", XGBClassifier(**xgb_kw)))

    return Pipeline(steps)


# ---------------------------------------------------------------------------
# BenchmarkIDS
# ---------------------------------------------------------------------------

class BenchmarkIDS(BaseEstimator, ClassifierMixin):
    """
    Full-feature XGBoost IDS using the complete mandated Pipeline structure.

    Applies ANOVA f_classif selection (k=K_BEST_FEATURES) over all available
    numeric columns. Supports binary and multi-class classification. Implements
    the exact Pipeline structure from CLAUDE.md:
        imputer(median) → scaler → ANOVAFeatureSelector(k=30) → XGBClassifier

    Feature names are preserved end-to-end by using set_output('pandas') on
    imputer and scaler — mandatory for downstream SHAP explainability.

    LabelEncoder is applied for multiclass mode to guarantee contiguous class
    labels [0, 1, 2, ...], resolving the XGBoost class-gap error.

    Parameters:
        mode              — 'binary' (default) or 'multiclass'
        k_features        — ANOVA top-k features (default: K_BEST_FEATURES)
        scale_pos_weight  — XGBoost class balance weight, binary mode only
        confidence_threshold — probability cutoff for predict() (binary mode)

    Inputs:  X: pd.DataFrame of numeric features, y: pd.Series of labels.
    Outputs: Fitted model; predict() → class array; predict_proba() → float array.

    Usage:
        model = BenchmarkIDS(mode='binary')
        model.fit(X_train, y_train)
        metrics = evaluate_model(model, X_test, y_test)
        model.save()
    """

    def __init__(
        self,
        mode: str = "binary",
        k_features: int = K_BEST_FEATURES,
        scale_pos_weight: float = SCALE_POS_WEIGHT,
        confidence_threshold: float = CONFIDENCE_THRESHOLD,
    ) -> None:
        self.mode = mode
        self.k_features = k_features
        self.scale_pos_weight = scale_pos_weight
        self.confidence_threshold = confidence_threshold

    # ------------------------------------------------------------------

    def fit(
        self,
        X: pd.DataFrame,
        y: pd.Series,
        sample_weight: Optional[np.ndarray] = None,
    ) -> "BenchmarkIDS":
        if not isinstance(X, pd.DataFrame):
            raise TypeError(
                "BenchmarkIDS.fit() requires a pd.DataFrame — "
                "passing a numpy array destroys feature names and breaks SHAP."
            )

        self._pipeline = _build_pipeline(
            mode=self.mode,
            k_features=self.k_features,
            scale_pos_weight=self.scale_pos_weight,
            include_selector=True,
        )

        if self.mode == "multiclass":
            self._label_encoder = LabelEncoder()
            y_fit = pd.Series(
                self._label_encoder.fit_transform(y.astype(int)),
                index=y.index,
            )
            self.classes_ = self._label_encoder.classes_
        else:
            y_fit = y
            self._label_encoder = None
            self.classes_ = np.array([0, 1])

        logger.info(
            "Fitting %s [%s] on %d samples × %d features",
            self.__class__.__name__, self.mode, X.shape[0], X.shape[1],
        )
        if sample_weight is not None:
            self._pipeline.fit(X, y_fit, clf__sample_weight=sample_weight)
        else:
            self._pipeline.fit(X, y_fit)
        self.n_features_in_ = X.shape[1]
        logger.info("%s fit complete", self.__class__.__name__)
        return self

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        return self._pipeline.predict_proba(X)

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        if self.mode == "binary":
            return (self.predict_proba(X)[:, 1] >= self.confidence_threshold).astype(int)
        raw = np.argmax(self.predict_proba(X), axis=1)
        if self._label_encoder is not None:
            return self._label_encoder.inverse_transform(raw)
        return raw

    def get_selected_features(self) -> List[str]:
        """Return ANOVA-selected feature names (available after fit)."""
        if not hasattr(self, "_pipeline"):
            raise RuntimeError("Call fit() before get_selected_features()")
        return self._pipeline.named_steps["selector"].selected_features_

    # ------------------------------------------------------------------

    def save(self, path: Optional[Path] = None) -> Path:
        fname = f"{self.__class__.__name__.lower()}_{self.mode}.pkl"
        save_path = Path(path) if path else MODEL_DIR / fname
        try:
            joblib.dump(self, save_path)
            logger.info("Saved → %s", save_path)
            return save_path
        except Exception as exc:
            logger.error("Save failed: %s", exc)
            raise

    @classmethod
    def load(cls, path: "Path | str") -> "BenchmarkIDS":
        try:
            model = joblib.load(path)
            logger.info("Loaded ← %s", path)
            return model
        except Exception as exc:
            logger.error("Load failed from %s: %s", path, exc)
            raise


# ---------------------------------------------------------------------------
# LightweightIDS
# ---------------------------------------------------------------------------

class LightweightIDS(BaseEstimator, ClassifierMixin):
    """
    10-feature XGBoost IDS optimised for real-time throughput.

    Uses only ENGINEERED_FEATURES from config.py — no ANOVA selection step
    since the feature set is pre-specified. The smaller feature vector combined
    with XGBoost's vectorised C++ prediction backend achieves >= 1.6M flows/sec
    in batch mode while maintaining 99.47% accuracy.

    Parameters:
        scale_pos_weight     — XGBoost class balance weight
        confidence_threshold — probability cutoff for predict()

    Usage:
        lite = LightweightIDS()
        lite.fit(X_train, y_train)
        fps = lite.benchmark_throughput(X_test)
        print(f'{fps:,.0f} flows/sec')
    """

    def __init__(
        self,
        scale_pos_weight: float = SCALE_POS_WEIGHT,
        confidence_threshold: float = CONFIDENCE_THRESHOLD,
    ) -> None:
        self.scale_pos_weight = scale_pos_weight
        self.confidence_threshold = confidence_threshold

    # ------------------------------------------------------------------

    def _resolve_cols(self, X: pd.DataFrame) -> List[str]:
        return [f for f in ENGINEERED_FEATURES if f in X.columns]

    def fit(self, X: pd.DataFrame, y: pd.Series) -> "LightweightIDS":
        self._feature_cols = self._resolve_cols(X)
        if not self._feature_cols:
            raise ValueError(
                "None of ENGINEERED_FEATURES present in X. "
                f"Available cols (first 10): {X.columns.tolist()[:10]}"
            )

        self._pipeline = _build_pipeline(
            mode="binary",
            k_features=len(self._feature_cols),
            scale_pos_weight=self.scale_pos_weight,
            include_selector=False,   # features already selected
        )

        logger.info(
            "Fitting LightweightIDS on %d samples, %d features: %s",
            X.shape[0], len(self._feature_cols), self._feature_cols,
        )
        self._pipeline.fit(X[self._feature_cols], y)
        logger.info("LightweightIDS fit complete")
        return self

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        cols = [f for f in self._feature_cols if f in X.columns]
        return self._pipeline.predict_proba(X[cols])

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= self.confidence_threshold).astype(int)

    def benchmark_throughput(
        self,
        X: pd.DataFrame,
        target_rows: int = 500_000,
        n_runs: int = 5,
    ) -> float:
        """
        Measure batch prediction throughput in flows per second.

        Pads X to target_rows via repetition for a statistically stable batch,
        then averages n_runs timed trials after one warm-up pass.

        Returns:
            float — mean flows per second across n_runs trials
        """
        cols = [f for f in self._feature_cols if f in X.columns]
        X_sub = X[cols]

        if len(X_sub) < target_rows:
            reps = -(-target_rows // len(X_sub))
            X_bench = pd.concat([X_sub] * reps, ignore_index=True).iloc[:target_rows]
        else:
            X_bench = X_sub.iloc[:target_rows].copy()

        # Warm-up: fill JIT caches
        self._pipeline.predict(X_bench.iloc[:min(1000, len(X_bench))])

        timings = []
        for _ in range(n_runs):
            t0 = time.perf_counter()
            self._pipeline.predict(X_bench)
            timings.append(time.perf_counter() - t0)

        fps = len(X_bench) / float(np.mean(timings))
        logger.info(
            "LightweightIDS throughput: %.0f flows/sec (batch=%d, runs=%d)",
            fps, len(X_bench), n_runs,
        )
        return fps

    # ------------------------------------------------------------------

    def save(self, path: Optional[Path] = None) -> Path:
        save_path = Path(path) if path else MODEL_DIR / "lightweightids_binary.pkl"
        try:
            joblib.dump(self, save_path)
            logger.info("Saved → %s", save_path)
            return save_path
        except Exception as exc:
            logger.error("Save failed: %s", exc)
            raise

    @classmethod
    def load(cls, path: "Path | str") -> "LightweightIDS":
        return joblib.load(path)


# ---------------------------------------------------------------------------
# CombinedIDS
# ---------------------------------------------------------------------------

class CombinedIDS(BenchmarkIDS):
    """
    XGBoost IDS for cross-dataset generalisation (2017 + 2018 combined training).

    Identical to BenchmarkIDS in architecture. The key difference is the default
    confidence_threshold of 0.35 (CONFIDENCE_THRESHOLD_CROSS) — lower than the
    0.55 in-distribution threshold — which recovers recall lost to domain shift
    when the model encounters 2018-style traffic patterns.

    From Experiment 3 (combined training on 2017 + 2018):
        Recall     : 80.83%
        F1-Score   : 89.40%
        Precision  : 100.00%

    Intended to be trained via train.py on the union of CIC-IDS-2017 and
    CIC-IDS-2018 datasets. Use load_full_dataset() on both DATA_2017 and
    DATA_2018 glob patterns, concat, then call combined.fit(X, y).

    Usage:
        combo = CombinedIDS(mode='binary')
        combo.fit(X_combined, y_combined)
        combo.save()
    """

    def __init__(
        self,
        mode: str = "binary",
        k_features: int = K_BEST_FEATURES,
        scale_pos_weight: float = SCALE_POS_WEIGHT,
        confidence_threshold: float = CONFIDENCE_THRESHOLD_CROSS,
    ) -> None:
        super().__init__(
            mode=mode,
            k_features=k_features,
            scale_pos_weight=scale_pos_weight,
            confidence_threshold=confidence_threshold,
        )

    def save(self, path: Optional[Path] = None) -> Path:
        fname = f"combinedids_{self.mode}.pkl"
        save_path = Path(path) if path else MODEL_DIR / fname
        try:
            joblib.dump(self, save_path)
            logger.info("Saved → %s", save_path)
            return save_path
        except Exception as exc:
            logger.error("Save failed: %s", exc)
            raise


# ---------------------------------------------------------------------------
# evaluate_model
# ---------------------------------------------------------------------------

def evaluate_model(
    model: "BenchmarkIDS | LightweightIDS",
    X_test: pd.DataFrame,
    y_test: pd.Series,
    threshold: Optional[float] = None,
) -> Dict[str, float]:
    """
    Compute classification metrics for any fitted SENTINEL IDS model.

    For binary classifiers returns accuracy, precision, recall, F1, ROC-AUC,
    FP rate, FN rate, and raw TP/TN/FP/FN counts. For multi-class models
    returns accuracy and macro-averaged F1.

    Inputs:
        model     — fitted BenchmarkIDS, LightweightIDS, or CombinedIDS
        X_test    — feature DataFrame (same schema as training X)
        y_test    — ground-truth label Series
        threshold — override the model's confidence_threshold for this call
    Outputs:
        dict with float values. Binary keys: accuracy, precision, recall, f1,
        roc_auc, fp_rate, fn_rate, tp, tn, fp, fn.
        Multiclass keys: accuracy, f1_macro.

    Usage:
        metrics = evaluate_model(model, X_test, y_test)
        print(f"Acc={metrics['accuracy']:.4f}  F1={metrics['f1']:.4f}  AUC={metrics['roc_auc']:.4f}")
    """
    try:
        proba = model.predict_proba(X_test)
    except Exception as exc:
        logger.error("predict_proba failed during evaluation: %s", exc)
        raise

    is_binary = proba.shape[1] == 2

    if is_binary:
        t = threshold if threshold is not None else getattr(model, "confidence_threshold", 0.5)
        y_pred  = (proba[:, 1] >= t).astype(int)
        y_score = proba[:, 1]

        acc  = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec  = float(recall_score(y_test, y_pred, zero_division=0))
        f1   = float(f1_score(y_test, y_pred, zero_division=0))

        try:
            auc = float(roc_auc_score(y_test, y_score))
        except ValueError:
            auc = float("nan")

        cm = confusion_matrix(y_test, y_pred)
        if cm.size == 4:
            tn, fp, fn, tp = cm.ravel()
        else:
            tn = fp = fn = tp = 0

        fp_rate = float(fp) / (float(fp + tn) + 1e-9)
        fn_rate = float(fn) / (float(fn + tp) + 1e-9)

        metrics: Dict[str, float] = {
            "accuracy":  acc,   "precision": prec,
            "recall":    rec,   "f1":        f1,
            "roc_auc":   auc,
            "fp_rate":   fp_rate, "fn_rate": fn_rate,
            "tp": float(tp), "tn": float(tn),
            "fp": float(fp), "fn": float(fn),
        }
    else:
        y_pred = np.argmax(proba, axis=1)
        acc  = float(accuracy_score(y_test, y_pred))
        f1mc = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
        metrics = {"accuracy": acc, "f1_macro": f1mc}

    logger.info(
        "evaluate_model: Acc=%.4f  F1=%.4f  AUC=%s",
        metrics.get("accuracy", 0.0),
        metrics.get("f1", metrics.get("f1_macro", 0.0)),
        f"{metrics['roc_auc']:.4f}" if "roc_auc" in metrics else "n/a",
    )
    gc.collect()
    return metrics
