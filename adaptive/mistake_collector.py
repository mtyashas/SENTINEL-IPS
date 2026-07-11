"""
adaptive/mistake_collector.py

Purpose: Collect false-positive (FP) and false-negative (FN) samples from
         live detections to feed the adaptive retraining pipeline. Each
         mistake is stored with its full feature vector, the model's
         predicted label, and the corrected ground-truth label so the
         retrainer can learn from the error.

         Buffer is capped at ADAPTIVE_MAX_SAMPLES to prevent unbounded
         memory growth. When the count crosses ADAPTIVE_MISTAKE_THRESHOLD
         the collector fires an optional callback so the AdaptiveTrainer
         can schedule a retrain automatically.

Inputs:  pd.Series of flow features; predicted label; corrected label.
Outputs: MistakeRecord dataclass; Parquet snapshot on disk at
         models/mistakes_buffer.parquet.

Usage:
    from adaptive.mistake_collector import MistakeCollector
    collector = MistakeCollector(on_threshold=lambda: trainer.schedule_retrain())
    collector.add(features_series, predicted=1, corrected=0, mistake_type="FP")
    df = collector.get_dataframe()
"""

import gc
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import pandas as pd

from config import (
    ADAPTIVE_MAX_SAMPLES,
    ADAPTIVE_MISTAKE_THRESHOLD,
    MODEL_DIR,
)

logger = logging.getLogger(__name__)

_BUFFER_PATH = MODEL_DIR / "mistakes_buffer.parquet"
_LABEL_COL   = "__corrected_label__"
_TYPE_COL    = "__mistake_type__"     # "FP" or "FN"
_TS_COL      = "__timestamp__"


@dataclass
class MistakeRecord:
    features:       dict           # feature_name → value
    predicted:      int            # model's wrong prediction
    corrected:      int            # ground truth label
    mistake_type:   str            # "FP" or "FN"
    timestamp:      datetime
    confidence:     float          # model confidence at time of error


class MistakeCollector:
    """
    Thread-safe ring buffer for FP/FN collection.

    When the buffer reaches ADAPTIVE_MISTAKE_THRESHOLD a user-supplied
    callback is fired (if provided). When the buffer reaches
    ADAPTIVE_MAX_SAMPLES the oldest entries are evicted (FIFO) to keep
    memory bounded.

    Parameters:
        on_threshold — callable fired when mistake count hits the threshold;
                       receives the current collector instance as argument.
        buffer_path  — override path for the Parquet snapshot file.
    """

    def __init__(
        self,
        on_threshold: Optional[Callable[["MistakeCollector"], None]] = None,
        buffer_path:  Optional[Path] = None,
    ) -> None:
        self._rows:          list[dict]   = []
        self._lock           = threading.Lock()
        self._on_threshold   = on_threshold
        self._buffer_path    = buffer_path or _BUFFER_PATH
        self._threshold_fired = False

        self._load_from_disk()
        logger.info(
            "MistakeCollector ready — loaded %d existing mistakes (threshold=%d, max=%d)",
            len(self._rows), ADAPTIVE_MISTAKE_THRESHOLD, ADAPTIVE_MAX_SAMPLES,
        )

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _load_from_disk(self) -> None:
        if not self._buffer_path.exists():
            return
        try:
            df = pd.read_parquet(self._buffer_path)
            self._rows = df.to_dict(orient="records")
            logger.info("Loaded %d mistake records from %s", len(self._rows), self._buffer_path)
        except Exception as exc:
            logger.warning("Could not load mistake buffer from disk: %s", exc)

    def _flush_to_disk(self) -> None:
        if not self._rows:
            return
        try:
            df = pd.DataFrame(self._rows)
            df.to_parquet(self._buffer_path, index=False)
            logger.debug("Flushed %d records to %s", len(self._rows), self._buffer_path)
        except Exception as exc:
            logger.error("Mistake buffer flush failed: %s", exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(
        self,
        features:     pd.Series,
        predicted:    int,
        corrected:    int,
        confidence:   float = 0.0,
        mistake_type: Optional[str] = None,
    ) -> MistakeRecord:
        """
        Add one FP or FN sample to the buffer.

        Automatically infers mistake_type from predicted vs corrected if not
        supplied: predicted=1/corrected=0 → FP, predicted=0/corrected=1 → FN.

        Inputs:
            features     — pd.Series of numeric flow features (index = feature names)
            predicted    — model output label (0 or 1)
            corrected    — ground truth label (0 or 1)
            confidence   — model confidence score at time of error
            mistake_type — "FP" or "FN"; inferred if None
        Outputs: MistakeRecord
        """
        if mistake_type is None:
            mistake_type = "FP" if (predicted == 1 and corrected == 0) else "FN"

        record = MistakeRecord(
            features=features.to_dict(),
            predicted=predicted,
            corrected=corrected,
            mistake_type=mistake_type,
            timestamp=datetime.now(tz=timezone.utc),
            confidence=confidence,
        )

        row = dict(features.to_dict())
        row[_LABEL_COL]  = corrected
        row[_TYPE_COL]   = mistake_type
        row[_TS_COL]     = record.timestamp.isoformat()

        threshold_hit = False
        with self._lock:
            self._rows.append(row)

            # Evict oldest entries if over the hard cap
            if len(self._rows) > ADAPTIVE_MAX_SAMPLES:
                overflow = len(self._rows) - ADAPTIVE_MAX_SAMPLES
                self._rows = self._rows[overflow:]
                logger.debug("Evicted %d oldest mistake records", overflow)

            count = len(self._rows)
            if count >= ADAPTIVE_MISTAKE_THRESHOLD and not self._threshold_fired:
                self._threshold_fired = True
                threshold_hit = True

        logger.debug(
            "Mistake recorded: type=%s predicted=%d corrected=%d conf=%.3f",
            mistake_type, predicted, corrected, confidence,
        )

        if threshold_hit:
            logger.info(
                "Mistake threshold reached (%d) — triggering adaptive retrain",
                ADAPTIVE_MISTAKE_THRESHOLD,
            )
            if self._on_threshold:
                try:
                    self._on_threshold(self)
                except Exception as exc:
                    logger.error("on_threshold callback raised: %s", exc)

        return record

    def get_dataframe(self) -> pd.DataFrame:
        """
        Return a copy of the mistake buffer as a DataFrame.

        The corrected label is in the column defined by _LABEL_COL
        (__corrected_label__). Feature columns are everything else except
        _TYPE_COL and _TS_COL.

        Outputs: pd.DataFrame; empty DataFrame if buffer is empty
        """
        with self._lock:
            if not self._rows:
                return pd.DataFrame()
            return pd.DataFrame(self._rows).copy()

    def get_xy(self) -> tuple[pd.DataFrame, pd.Series]:
        """
        Return (X, y) split ready for model training.

        X contains only numeric feature columns; y contains corrected labels.

        Outputs: (X: pd.DataFrame, y: pd.Series)
        """
        df = self.get_dataframe()
        if df.empty:
            return pd.DataFrame(), pd.Series(dtype=int)

        meta_cols = [_LABEL_COL, _TYPE_COL, _TS_COL]
        y = df[_LABEL_COL].astype(int)
        X = df.drop(columns=[c for c in meta_cols if c in df.columns], errors="ignore")
        X = X.select_dtypes(include=["number"])
        return X, y

    def count(self) -> int:
        with self._lock:
            return len(self._rows)

    def fp_count(self) -> int:
        with self._lock:
            return sum(1 for r in self._rows if r.get(_TYPE_COL) == "FP")

    def fn_count(self) -> int:
        with self._lock:
            return sum(1 for r in self._rows if r.get(_TYPE_COL) == "FN")

    def clear(self) -> int:
        """
        Clear the buffer after a successful retrain. Returns the count cleared.
        Also resets the threshold-fired flag so the next batch can trigger again.
        """
        with self._lock:
            cleared = len(self._rows)
            self._rows.clear()
            self._threshold_fired = False

        try:
            if self._buffer_path.exists():
                self._buffer_path.unlink()
        except OSError as exc:
            logger.warning("Could not delete buffer file: %s", exc)

        logger.info("Mistake buffer cleared (%d records removed)", cleared)
        return cleared

    def save(self) -> None:
        """Persist the current buffer to disk."""
        with self._lock:
            self._flush_to_disk()

    def summary(self) -> dict:
        with self._lock:
            total = len(self._rows)
            fp    = sum(1 for r in self._rows if r.get(_TYPE_COL) == "FP")
            fn    = total - fp
        return {
            "total":             total,
            "fp_count":          fp,
            "fn_count":          fn,
            "threshold":         ADAPTIVE_MISTAKE_THRESHOLD,
            "max_samples":       ADAPTIVE_MAX_SAMPLES,
            "threshold_reached": total >= ADAPTIVE_MISTAKE_THRESHOLD,
        }
