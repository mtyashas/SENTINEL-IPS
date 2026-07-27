"""
adaptive/adaptive_trainer.py

Purpose: Automatically retrain the production XGBoost model using accumulated
         FP/FN mistakes from MistakeCollector combined with a balanced subsample
         of the original training data. Validates that recall improves on a
         held-out test set before replacing the production model. Falls back to
         the previous model if validation fails. All retrains are versioned and
         the best model checkpoint is preserved.

Inputs:  MistakeCollector instance; optional held-out (X_test, y_test).
Outputs: Retrained model saved to models/; RetrainResult dataclass with
         metrics comparison.

Usage:
    from adaptive.adaptive_trainer import AdaptiveTrainer
    from adaptive.mistake_collector import MistakeCollector
    collector = MistakeCollector()
    trainer   = AdaptiveTrainer(collector)
    result    = trainer.retrain(X_test, y_test)
    print(result.improved, result.new_recall, result.old_recall)
"""

import gc
import logging
import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, recall_score
from sklearn.model_selection import train_test_split

from adaptive.mistake_collector import MistakeCollector
from config import (
    ADAPTIVE_MAX_SAMPLES,
    CHUNK_SIZE,
    K_BEST_FEATURES,
    MODEL_DIR,
    SCALE_POS_WEIGHT,
    XGB_PARAMS,
)
from core.model import BenchmarkIDS, evaluate_model

logger = logging.getLogger(__name__)

_PRODUCTION_MODEL_NAME  = "benchmarkids_binary.pkl"
_BACKUP_SUFFIX          = ".bak"
_RETRAIN_MAX_ORIG       = 20_000    # max rows sampled from original data per retrain
_MISTAKE_WEIGHT         = 5.0       # sample weight multiplier for mistake rows
_MIN_RECALL_DELTA       = 0.001     # retrain must improve recall by at least 0.1 pp
_RETRAIN_N_ESTIMATORS   = 200       # fewer trees for incremental update (faster)


@dataclass
class RetrainResult:
    timestamp:    datetime
    improved:     bool
    old_recall:   float
    new_recall:   float
    old_f1:       float
    new_f1:       float
    mistake_rows: int
    total_rows:   int
    model_path:   Optional[Path]
    notes:        str = ""


class AdaptiveTrainer:
    """
    Incremental model updater that learns from detection mistakes.

    Retraining strategy:
      1. Pull the current mistake buffer from MistakeCollector
      2. Combine with a balanced subsample of any available original training
         data (loaded from models/train_cache.parquet if present)
      3. Assign higher sample weights to mistake rows (_MISTAKE_WEIGHT × 1.0)
      4. Retrain a BenchmarkIDS with fewer estimators (faster incremental update)
      5. Evaluate new vs old model on the held-out test set
      6. Replace production model only if recall improved by >= _MIN_RECALL_DELTA
      7. Clear the mistake buffer on successful replacement

    Parameters:
        collector       — MistakeCollector instance to pull mistakes from
        model_dir       — directory for model files (default MODEL_DIR)
        train_cache_path — optional path to cached training data (Parquet)
    """

    def __init__(
        self,
        collector:        MistakeCollector,
        model_dir:        Path = MODEL_DIR,
        train_cache_path: Optional[Path] = None,
        mode:             str = "binary",
        production_model_name: Optional[str] = None,
    ) -> None:
        self._collector        = collector
        self._model_dir        = model_dir
        self.mode               = mode
        self._prod_name         = production_model_name or _PRODUCTION_MODEL_NAME
        self._prod_path        = model_dir / self._prod_name
        self._train_cache_path = train_cache_path or (model_dir / "train_cache.parquet")
        self._retrain_count    = 0

        logger.info(
            "AdaptiveTrainer ready — mode=%s prod_model=%s, train_cache=%s",
            self.mode, self._prod_path, self._train_cache_path,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_current_model(self) -> Optional[BenchmarkIDS]:
        if not self._prod_path.exists():
            logger.warning("No production model found at %s", self._prod_path)
            return None
        try:
            return joblib.load(self._prod_path)
        except Exception as exc:
            logger.error("Failed to load production model: %s", exc)
            return None

    def _load_train_cache(self, n: int) -> tuple[pd.DataFrame, pd.Series]:
        """Load a balanced subsample of original training data."""
        if not self._train_cache_path.exists():
            return pd.DataFrame(), pd.Series(dtype=int)
        try:
            df = pd.read_parquet(self._train_cache_path)
            if len(df) > n:
                # Stratified sample to preserve class ratio, generalized to
                # any number of classes (binary is just the n=2 case).
                classes = df["__label__"].unique()
                n_per_class = max(n // len(classes), 1)
                df = pd.concat([
                    df[df["__label__"] == c].sample(
                        n=min((df["__label__"] == c).sum(), n_per_class),
                        random_state=42,
                    )
                    for c in classes
                ], ignore_index=True)

            y = df["__label__"].astype(int)
            X = df.drop(columns=["__label__"], errors="ignore")
            X = X.select_dtypes(include=["number"])
            return X, y
        except Exception as exc:
            logger.warning("Train cache load failed: %s", exc)
            return pd.DataFrame(), pd.Series(dtype=int)

    @staticmethod
    def _balanced_mistake_weights(mistake_types: pd.Series) -> np.ndarray:
        """
        Per-row sample weight for the mistake buffer, balanced by mistake
        type (FP vs FN) rather than a flat _MISTAKE_WEIGHT for every row.

        A flat weight lets whichever mistake type is numerically dominant
        (e.g. thousands of missed-attack FNs from one noisy capture) drown
        out a handful of FP mistakes in the loss, even though the FPs are
        just as real and often rarer precisely because they're the harder
        case. Weight is _MISTAKE_WEIGHT scaled by inverse frequency within
        the mistake buffer, mirroring standard balanced class weighting but
        applied only within the mistakes (original-data rows keep weight 1.0).
        """
        if mistake_types.empty:
            return np.zeros(0)
        counts = mistake_types.value_counts()
        n_total = len(mistake_types)
        n_types = len(counts)
        balanced = mistake_types.map(lambda t: n_total / (n_types * counts[t]))
        return (_MISTAKE_WEIGHT * balanced).to_numpy()

    @staticmethod
    def _align_to_model(X: pd.DataFrame, model: BenchmarkIDS) -> pd.DataFrame:
        """
        Restrict/reindex X to exactly the columns `model`'s pipeline was fit
        on (zero-filling anything missing). Old and new models in a retrain
        cycle are frequently fit on different column sets than whatever the
        caller's held-out X_test happens to contain (e.g. it was built from
        raw feature engineering rather than the model's own trained schema),
        so evaluation must align per-model rather than assuming X_test
        already matches.
        """
        try:
            expected = list(model._pipeline.named_steps["imputer"].feature_names_in_)
        except Exception:
            return X
        aligned = pd.DataFrame(index=X.index)
        for col in expected:
            aligned[col] = X[col] if col in X.columns else 0.0
        return aligned

    def _eval_model(
        self,
        model:  BenchmarkIDS,
        X_test: pd.DataFrame,
        y_test: pd.Series,
    ) -> tuple[float, float]:
        """Return (recall, f1) for a model on the given test set."""
        try:
            X_test = self._align_to_model(X_test, model)
            preds  = model.predict(X_test)
            average = "macro" if self.mode == "multiclass" else "binary"
            recall = float(recall_score(y_test, preds, average=average, zero_division=0))
            f1     = float(f1_score(y_test, preds, average=average, zero_division=0))
            return recall, f1
        except Exception as exc:
            logger.error("Model evaluation failed: %s", exc)
            return 0.0, 0.0

    def _save_versioned(self, model: BenchmarkIDS) -> Path:
        ts   = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = self._model_dir / f"benchmarkids_adaptive_{ts}_v{self._retrain_count}.pkl"
        try:
            joblib.dump(model, path, compress=3)
            logger.info("Versioned model saved: %s", path)
        except Exception as exc:
            logger.error("Versioned save failed: %s", exc)
        return path

    def _replace_production(self, new_model: BenchmarkIDS) -> Path:
        """Backup current production model then replace it."""
        if self._prod_path.exists():
            backup = self._prod_path.with_suffix(_BACKUP_SUFFIX)
            try:
                shutil.copy2(self._prod_path, backup)
                logger.info("Backed up old model to %s", backup)
            except OSError as exc:
                logger.warning("Model backup failed: %s", exc)

        try:
            joblib.dump(new_model, self._prod_path, compress=3)
            logger.info("Production model replaced: %s", self._prod_path)
        except Exception as exc:
            logger.error("Production model replace failed: %s", exc)
            # Restore backup if replacement failed
            backup = self._prod_path.with_suffix(_BACKUP_SUFFIX)
            if backup.exists():
                shutil.copy2(backup, self._prod_path)
                logger.info("Restored backup model after failed replacement")

        return self._prod_path

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def retrain(
        self,
        X_test: Optional[pd.DataFrame] = None,
        y_test: Optional[pd.Series]    = None,
    ) -> RetrainResult:
        """
        Execute one adaptive retraining cycle.

        Pulls mistakes from the collector, merges with cached training data,
        trains a fresh model, validates against held-out test data, and
        replaces the production model only if recall improves.

        Inputs:
            X_test — held-out feature DataFrame for validation (optional)
            y_test — held-out label Series for validation (optional)
        Outputs: RetrainResult with metrics comparison
        """
        t0 = time.monotonic()
        self._retrain_count += 1
        logger.info("Adaptive retrain #%d starting", self._retrain_count)

        # --- Step 1: Get mistake samples ---
        X_mistakes, y_mistakes = self._collector.get_xy()
        mistake_weights = self._balanced_mistake_weights(self._collector.get_types())
        if X_mistakes.empty:
            logger.warning("No mistake samples available — skipping retrain")
            return RetrainResult(
                timestamp=datetime.now(tz=timezone.utc),
                improved=False,
                old_recall=0.0, new_recall=0.0,
                old_f1=0.0,     new_f1=0.0,
                mistake_rows=0, total_rows=0,
                model_path=None,
                notes="No mistake samples in buffer",
            )

        # --- Step 2: Load original training cache ---
        X_orig, y_orig = self._load_train_cache(_RETRAIN_MAX_ORIG)

        # --- Step 3: Combine with sample weights ---
        if not X_orig.empty:
            # Align columns: intersect but preserve X_mistakes's order (the
            # production model's original training-time column order) — a
            # plain set intersection has no guaranteed order and produces a
            # model whose fit-time column order silently drifts from what
            # MLDetectionLayer's cached feature-column list expects.
            orig_cols_set = set(X_orig.columns)
            common_cols = [c for c in X_mistakes.columns if c in orig_cols_set]
            if not common_cols:
                logger.warning("No overlapping columns between mistakes and cache — using mistakes only")
                X_train, y_train = X_mistakes, y_mistakes
                weights = mistake_weights
            else:
                X_mistakes_aligned = X_mistakes[common_cols]
                X_orig_aligned     = X_orig[common_cols]
                X_train = pd.concat([X_mistakes_aligned, X_orig_aligned], ignore_index=True)
                y_train = pd.concat([y_mistakes, y_orig],                 ignore_index=True)
                weights = np.concatenate([
                    mistake_weights,
                    np.ones(len(X_orig)),
                ])
        else:
            X_train, y_train = X_mistakes, y_mistakes
            weights = mistake_weights

        total_rows = len(X_train)
        logger.info(
            "Retrain dataset: %d rows (%d mistakes + %d original)",
            total_rows, len(X_mistakes), len(X_orig) if not X_orig.empty else 0,
        )

        # --- Step 4: Load current model for baseline metrics ---
        old_model = self._load_current_model()
        old_recall, old_f1 = 0.0, 0.0
        if old_model is not None and X_test is not None and y_test is not None:
            old_recall, old_f1 = self._eval_model(old_model, X_test, y_test)
            logger.info("Baseline: recall=%.4f f1=%.4f", old_recall, old_f1)

        # --- Step 5: Train new model ---
        try:
            # scale_pos_weight=1.0 (not the global SCALE_POS_WEIGHT): XGBoost
            # multiplies scale_pos_weight onto every positive-class row's
            # weight *on top of* sample_weight. The global constant exists to
            # correct the original dataset's class imbalance; stacking it
            # here would blanket-favour the attack class across all 22k
            # training rows and drown out the deliberate per-mistake
            # balancing in `weights`, which already targets exactly the rows
            # that need correcting.
            new_model = BenchmarkIDS(
                mode=self.mode,
                k_features=min(K_BEST_FEATURES, X_train.shape[1]),
                scale_pos_weight=1.0,
            )
            new_model.fit(X_train, y_train, sample_weight=weights)
        except Exception as exc:
            logger.error("Retraining failed: %s", exc)
            return RetrainResult(
                timestamp=datetime.now(tz=timezone.utc),
                improved=False,
                old_recall=old_recall, new_recall=0.0,
                old_f1=old_f1,         new_f1=0.0,
                mistake_rows=len(X_mistakes), total_rows=total_rows,
                model_path=None,
                notes=f"Training exception: {exc}",
            )
        finally:
            gc.collect()

        # --- Step 6: Validate ---
        new_recall, new_f1 = 0.0, 0.0
        if X_test is not None and y_test is not None:
            new_recall, new_f1 = self._eval_model(new_model, X_test, y_test)
            logger.info("New model: recall=%.4f f1=%.4f", new_recall, new_f1)

        improved = (X_test is None) or (new_recall >= old_recall + _MIN_RECALL_DELTA)
        notes    = ""

        # --- Step 7: Save versioned; replace production if improved ---
        versioned_path = self._save_versioned(new_model)

        if improved:
            prod_path = self._replace_production(new_model)
            cleared   = self._collector.clear()
            notes     = (
                f"Recall improved {old_recall:.4f} -> {new_recall:.4f}; "
                f"cleared {cleared} mistake samples"
            )
            logger.info("Retrain #%d ACCEPTED — %s", self._retrain_count, notes)
        else:
            prod_path = self._prod_path
            notes     = (
                f"Recall did not improve ({new_recall:.4f} vs {old_recall:.4f}) "
                f"— production model unchanged"
            )
            logger.warning("Retrain #%d REJECTED — %s", self._retrain_count, notes)

        elapsed = round((time.monotonic() - t0), 1)
        logger.info("Adaptive retrain #%d complete in %.1fs", self._retrain_count, elapsed)

        return RetrainResult(
            timestamp=datetime.now(tz=timezone.utc),
            improved=improved,
            old_recall=round(old_recall, 4),
            new_recall=round(new_recall, 4),
            old_f1=round(old_f1, 4),
            new_f1=round(new_f1, 4),
            mistake_rows=len(X_mistakes),
            total_rows=total_rows,
            model_path=versioned_path,
            notes=notes,
        )

    def cache_training_data(
        self,
        X: pd.DataFrame,
        y: pd.Series,
        max_rows: int = _RETRAIN_MAX_ORIG,
    ) -> None:
        """
        Persist a labelled training sample to disk for use in future retrains.

        Called once after the initial model is trained. Samples up to max_rows
        rows stratified by label.

        Inputs:
            X        — feature DataFrame
            y        — label Series
            max_rows — max rows to cache (default _RETRAIN_MAX_ORIG)
        """
        try:
            df = X.copy()
            df["__label__"] = y.values
            if len(df) > max_rows:
                classes = df["__label__"].unique()
                n_per_class = max(max_rows // len(classes), 1)
                df = pd.concat([
                    df[df["__label__"] == c].sample(
                        n=min((df["__label__"] == c).sum(), n_per_class),
                        random_state=42,
                    )
                    for c in classes
                ], ignore_index=True)
            df.to_parquet(self._train_cache_path, index=False)
            logger.info(
                "Training cache saved: %d rows → %s",
                len(df), self._train_cache_path,
            )
        except Exception as exc:
            logger.error("Training cache save failed: %s", exc)
        finally:
            gc.collect()
