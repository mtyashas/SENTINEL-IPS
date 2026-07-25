"""
detection/layer1_ml.py

Purpose: Load trained XGBoost IDS models and run streaming inference over
         live or file-based network flow data.
Inputs:  Serialised BenchmarkIDS .pkl files, raw CSV chunks (2017 or 2018 schema).
Outputs: DataFrames augmented with pred_binary, confidence, attack_class columns.

Usage:
    from detection.layer1_ml import MLDetectionLayer
    from config import MODEL_DIR
    layer1 = MLDetectionLayer(
        model_path=str(MODEL_DIR / 'benchmarkids_binary.pkl'),
        feat_cols_path=str(MODEL_DIR / 'benchmarkids_feature_cols.pkl'),
    )
    for result_df in layer1.predict_stream(str(DATA_2017 / '**' / '*.csv')):
        process(result_df)
"""

import logging
from collections import defaultdict
from pathlib import Path
from typing import Dict, Generator, List, Optional

import joblib
import numpy as np
import pandas as pd

from config import (
    ATTACK_CLASSES,
    BINARY_LABEL_COL,
    COL_REMAP_2018,
    CONFIDENCE_THRESHOLD,
    MODEL_DIR,
    MULTICLASS_LABEL_COL,
)
from core.model import BenchmarkIDS
from core.preprocessing import _find_csv_files, stream_csv_chunks

logger = logging.getLogger(__name__)


class MLDetectionLayer:
    """
    Layer 1 of the SENTINEL detection engine — XGBoost ML inference.

    Loads a trained BenchmarkIDS binary pipeline and (optionally) a multiclass
    pipeline for attack-type labelling. Aligns incoming DataFrames to the
    training schema, fills missing features with 0.0, clips Inf/NaN, then
    runs both pipelines to produce per-flow predictions.

    Parameters:
        model_path      — path to trained benchmarkids_binary.pkl
        feat_cols_path  — path to cached feature-column list (.pkl); created
                          automatically on first run from the loaded pipeline
        threshold       — confidence threshold for binary classification
                          (default: CONFIDENCE_THRESHOLD = 0.55)

    Usage:
        layer1 = MLDetectionLayer(
            model_path=str(MODEL_DIR / 'benchmarkids_binary.pkl'),
            feat_cols_path=str(MODEL_DIR / 'benchmarkids_feature_cols.pkl'),
        )
        result = layer1.predict_chunk(raw_df)
        print(layer1.get_stats())
    """

    def __init__(
        self,
        model_path: str,
        feat_cols_path: str,
        threshold: float = CONFIDENCE_THRESHOLD,
    ) -> None:
        self.model_path     = model_path
        self.feat_cols_path = feat_cols_path
        self.threshold      = threshold

        self._model: Optional[BenchmarkIDS]    = None
        self._mc_model: Optional[BenchmarkIDS] = None
        self._all_feature_cols: List[str]      = []   # all 79 training features
        self._selected_cols: List[str]         = []   # 30 ANOVA-selected features
        self._stats: Dict[str, int]            = defaultdict(int)

        self.load_model()

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------

    def load_model(self) -> None:
        """
        Load binary and optional multiclass models from disk.

        Derives the full feature list from the fitted pipeline's imputer step
        (feature_names_in_) and caches it to feat_cols_path for fast reload.
        """
        try:
            self._model = BenchmarkIDS.load(self.model_path)
            logger.info("Binary model loaded from %s", Path(self.model_path).name)
        except Exception as exc:
            logger.error("Failed to load binary model: %s", exc)
            raise

        feat_path = Path(self.feat_cols_path)
        if feat_path.exists():
            try:
                cached = joblib.load(feat_path)
                if isinstance(cached, dict):
                    self._all_feature_cols = cached.get("all_features", [])
                    self._selected_cols    = cached.get("selected_features", [])
                else:
                    self._all_feature_cols = list(cached)
                    self._selected_cols    = self._model.get_selected_features()
                logger.info("Feature columns loaded from cache (%d cols)", len(self._all_feature_cols))
            except Exception as exc:
                logger.warning("Cache read failed, deriving from model: %s", exc)
                self._derive_and_cache_features(feat_path)
        else:
            self._derive_and_cache_features(feat_path)

        # Load multiclass model (optional — for attack-type labelling)
        mc_path = Path(self.model_path).parent / "benchmarkids_multiclass.pkl"
        if mc_path.exists():
            try:
                self._mc_model = BenchmarkIDS.load(str(mc_path))
                logger.info("Multiclass model loaded")
            except Exception as exc:
                logger.warning("Multiclass model unavailable: %s", exc)
                self._mc_model = None
        else:
            self._mc_model = None
            logger.info("No multiclass model found at %s — attack_class will be ATTACK/BENIGN", mc_path.name)

    def _derive_and_cache_features(self, feat_path: Path) -> None:
        """Extract feature names from the fitted pipeline and cache them."""
        try:
            imputer = self._model._pipeline.named_steps["imputer"]
            self._all_feature_cols = list(imputer.feature_names_in_)
        except AttributeError:
            self._all_feature_cols = self._model.get_selected_features()
            logger.warning("imputer.feature_names_in_ unavailable; using selected features only")

        self._selected_cols = self._model.get_selected_features()
        logger.info("Derived %d feature columns from pipeline", len(self._all_feature_cols))

        try:
            cached = {"all_features": self._all_feature_cols, "selected_features": self._selected_cols}
            joblib.dump(cached, feat_path)
            logger.info("Feature column cache saved to %s", feat_path.name)
        except Exception as exc:
            logger.warning("Could not save feature cache: %s", exc)

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def _align_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Align incoming DataFrame to the training schema.

        Applies COL_REMAP_2018 for 2018-format data, fills missing training
        columns with 0.0, strips Inf/NaN, and returns a numeric DataFrame
        with exactly self._all_feature_cols columns.
        """
        df = df.copy()
        df.columns = [c.strip() for c in df.columns]

        # Detect and remap 2018 column names
        if "Dst Port" in df.columns:
            rename = {k: v for k, v in COL_REMAP_2018.items() if k in df.columns}
            df = df.rename(columns=rename)

        # Build the exact feature matrix the pipeline expects
        feature_cols = self._all_feature_cols if self._all_feature_cols else self._selected_cols
        X = pd.DataFrame(index=df.index)
        for col in feature_cols:
            if col in df.columns:
                X[col] = pd.to_numeric(df[col], errors="coerce")
            else:
                X[col] = 0.0

        X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        return X

    def predict_chunk(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Run binary and multiclass inference on a single DataFrame chunk.

        Aligns columns to the training schema, then produces three new columns:
            pred_binary  — 0 (benign) or 1 (attack) based on confidence threshold
            confidence   — model probability score for the attack class (float 0-1)
            attack_class — ATTACK_CLASSES name for attacks; 'BENIGN' otherwise

        Inputs:  Raw or preprocessed pd.DataFrame (any 2017/2018 schema)
        Outputs: Input DataFrame with pred_binary, confidence, attack_class appended
        """
        if df.empty:
            return df

        result = df.copy()

        try:
            X = self._align_features(df)
        except Exception as exc:
            logger.error("Feature alignment failed: %s", exc)
            result["pred_binary"]  = 0
            result["confidence"]   = 0.0
            result["attack_class"] = "BENIGN"
            return result

        # Binary prediction
        try:
            proba       = self._model.predict_proba(X)[:, 1]
            pred_binary = (proba >= self.threshold).astype(np.int8)
        except Exception as exc:
            logger.error("Binary prediction failed: %s", exc)
            proba       = np.zeros(len(X))
            pred_binary = np.zeros(len(X), dtype=np.int8)

        result["pred_binary"] = pred_binary
        result["confidence"]  = proba

        # Attack-class labelling from multiclass model
        if self._mc_model is not None:
            try:
                mc_preds = self._mc_model.predict(X)
                attack_classes = []
                for binary, mc in zip(pred_binary, mc_preds):
                    if binary == 0:
                        attack_classes.append("BENIGN")
                    else:
                        idx = int(mc) if int(mc) < len(ATTACK_CLASSES) else 0
                        # Binary already flagged this row as an attack; if the
                        # multiclass model's top class disagrees and says
                        # BENIGN (idx 0), trust the binary decision and fall
                        # back to a generic label rather than emitting the
                        # self-contradictory "flagged attack, class=BENIGN".
                        attack_classes.append(ATTACK_CLASSES[idx] if idx != 0 else "ATTACK")
                result["attack_class"] = attack_classes
            except Exception as exc:
                logger.warning("Multiclass prediction failed: %s", exc)
                result["attack_class"] = ["ATTACK" if p else "BENIGN" for p in pred_binary]
        else:
            result["attack_class"] = ["ATTACK" if p else "BENIGN" for p in pred_binary]

        # Update running statistics
        self._stats["total_flows"]      += len(result)
        self._stats["attacks_detected"] += int(pred_binary.sum())
        self._stats["benign_flows"]     += int((pred_binary == 0).sum())

        return result

    def predict_stream(
        self,
        glob_pattern: str,
        sample_frac: float = 1.0,
    ) -> Generator[pd.DataFrame, None, None]:
        """
        Generator yielding predicted DataFrames for all CSV files matching glob_pattern.

        Inputs:
            glob_pattern — e.g. str(DATA_2017 / '**' / '*.csv')
            sample_frac  — fraction of each chunk to process (default: 1.0)
        Outputs:
            Generator of DataFrames with pred_binary, confidence, attack_class columns.

        Usage:
            for df in layer1.predict_stream(str(DATA_2017 / '**' / '*.csv')):
                handle_detections(df[df.pred_binary == 1])
        """
        files = _find_csv_files(glob_pattern)
        if not files:
            logger.warning("No CSV files found for pattern: %s", glob_pattern)
            return

        logger.info("predict_stream: processing %d file(s)", len(files))
        for fpath in files:
            for chunk in stream_csv_chunks(fpath, sample_frac=sample_frac):
                try:
                    yield self.predict_chunk(chunk)
                except Exception as exc:
                    logger.error("predict_stream error on %s: %s", fpath.name, exc)
                    continue

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, int]:
        """
        Return cumulative detection statistics since instantiation.

        Returns:
            dict with keys: total_flows, attacks_detected, benign_flows
        """
        stats = dict(self._stats)
        total = stats.get("total_flows", 0)
        attacks = stats.get("attacks_detected", 0)
        stats["attack_rate_pct"] = round(100 * attacks / total, 2) if total > 0 else 0.0
        return stats
