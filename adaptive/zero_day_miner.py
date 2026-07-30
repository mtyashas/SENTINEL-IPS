"""
adaptive/zero_day_miner.py

Purpose: Mine novel attack patterns from flows that the ML model flagged as
         anomalous (high IsolationForest anomaly score) but that do not match
         any known signature. Clusters these unknowns using DBSCAN to isolate
         distinct attack families, extracts a feature-centroid signature for
         each cluster, and emits ZeroDayPattern records that the threat
         intelligence layer can convert to new detection rules.

Inputs:  pd.DataFrame of high-anomaly flows with feature columns +
         'anomaly_score' column from Layer 3.
Outputs: list[ZeroDayPattern]; persisted cluster signatures to
         threat_intel/zero_day_patterns.jsonl.

Usage:
    from adaptive.zero_day_miner import ZeroDayMiner
    miner    = ZeroDayMiner()
    patterns = miner.mine(anomaly_df)
    for p in patterns:
        print(p.cluster_id, p.size, p.top_features)
"""

import gc
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

from config import ENGINEERED_FEATURES, THREAT_DIR

logger = logging.getLogger(__name__)

_PATTERNS_PATH      = THREAT_DIR / "zero_day_patterns.jsonl"
_MIN_ANOMALY_SCORE  = 0.1       # IsolationForest score below -this → candidate
_DBSCAN_EPS         = 0.5       # neighbourhood radius in scaled feature space
_DBSCAN_MIN_SAMPLES = 5         # minimum flows to form a cluster
_MAX_CANDIDATES     = 10_000    # cap on flows sent to DBSCAN (memory safety)
_TOP_FEATURES_N     = 10        # features reported per cluster


@dataclass
class ZeroDayPattern:
    cluster_id:     str
    discovered_at:  datetime
    size:           int                     # number of flows in cluster
    top_features:   list[tuple[str, float]] # (feature_name, centroid_value) top N
    anomaly_score_mean: float
    anomaly_score_max:  float
    feature_signature:  dict                # full centroid dict
    ioc_hint:           str = ""            # human-readable summary for threat intel


class ZeroDayMiner:
    """
    Unsupervised zero-day cluster miner using DBSCAN.

    Workflow:
      1. Filter incoming flows to those with anomaly_score <= -_MIN_ANOMALY_SCORE
         (IsolationForest decision_function: more negative = more anomalous)
      2. Select numeric feature columns; drop constant columns
      3. Scale features to zero mean / unit variance
      4. Run DBSCAN to identify dense clusters of similar unknown flows
      5. For each cluster extract centroid, top differentiating features,
         and a plain-language IOC hint
      6. Persist new patterns to threat_intel/zero_day_patterns.jsonl

    Noise points (DBSCAN label = -1) are ignored — they are isolated anomalies
    that lack the cluster coherence needed to extract a reliable signature.

    Parameters:
        eps         — DBSCAN neighbourhood radius (default 0.5)
        min_samples — min flows per cluster (default 5)
    """

    def __init__(
        self,
        eps:         float = _DBSCAN_EPS,
        min_samples: int   = _DBSCAN_MIN_SAMPLES,
    ) -> None:
        self._eps         = eps
        self._min_samples = min_samples
        self._patterns:   list[ZeroDayPattern] = []
        self._run_count   = 0
        logger.info(
            "ZeroDayMiner ready — eps=%.2f, min_samples=%d",
            eps, min_samples,
        )

    # ------------------------------------------------------------------
    # Feature preparation
    # ------------------------------------------------------------------

    @staticmethod
    def _prepare_features(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
        """
        Select and clean numeric features from the anomaly DataFrame.

        Returns (scaled_df, feature_names).
        """
        # Exclude metadata/label columns
        exclude = {
            "anomaly_score", "label", "label_class",
            "pred_binary", "confidence", "attack_class",
        }
        feature_cols = [
            c for c in df.select_dtypes(include=["number"]).columns
            if c not in exclude
        ]
        if not feature_cols:
            return pd.DataFrame(), []

        X = df[feature_cols].copy()

        # Replace Inf / -Inf
        X.replace([np.inf, -np.inf], np.nan, inplace=True)

        # Drop columns with > 50% NaN
        thresh = len(X) * 0.5
        X.dropna(axis=1, thresh=int(thresh), inplace=True)
        X.fillna(X.median(), inplace=True)

        # Drop constant columns (zero variance)
        variances = X.var()
        X = X.loc[:, variances > 0]
        feature_cols = list(X.columns)

        if X.empty or not feature_cols:
            return pd.DataFrame(), []

        scaler = StandardScaler()
        X_scaled = pd.DataFrame(
            scaler.fit_transform(X),
            columns=feature_cols,
            index=X.index,
        )
        return X_scaled, feature_cols

    # ------------------------------------------------------------------
    # Pattern extraction
    # ------------------------------------------------------------------

    def _extract_pattern(
        self,
        cluster_id: str,
        mask:       pd.Series,
        df_orig:    pd.DataFrame,
        feature_cols: list[str],
    ) -> ZeroDayPattern:
        """Build a ZeroDayPattern from a cluster mask over the original DataFrame."""
        cluster_df = df_orig.loc[mask, feature_cols].copy()
        cluster_df.fillna(cluster_df.median(), inplace=True)

        centroid = cluster_df.mean()
        std      = cluster_df.std().fillna(0)

        # Top features: highest absolute centroid values after scaling
        top_n = centroid.abs().nlargest(_TOP_FEATURES_N)
        top_features = [(col, round(float(centroid[col]), 4)) for col in top_n.index]

        anomaly_scores = df_orig.loc[mask, "anomaly_score"] \
            if "anomaly_score" in df_orig.columns else pd.Series([0.0])

        ioc_hint = self._generate_ioc_hint(cluster_id, centroid, top_features)

        return ZeroDayPattern(
            cluster_id=cluster_id,
            discovered_at=datetime.now(tz=timezone.utc),
            size=int(mask.sum()),
            top_features=top_features,
            anomaly_score_mean=round(float(anomaly_scores.mean()), 4),
            anomaly_score_max=round(float(anomaly_scores.max()), 4),
            feature_signature={col: round(float(centroid[col]), 4) for col in feature_cols},
            ioc_hint=ioc_hint,
        )

    @staticmethod
    def _generate_ioc_hint(
        cluster_id:   str,
        centroid:     pd.Series,
        top_features: list[tuple[str, float]],
    ) -> str:
        """Generate a plain-language description of the cluster signature."""
        lines = [f"ZeroDay cluster {cluster_id}:"]

        # Heuristic descriptions based on feature names
        hints: list[str] = []
        feat_dict = dict(top_features)

        if feat_dict.get("bwd_packet_length_std", 0) > 1.0:
            hints.append("high backward packet-length variance (possible exfiltration or C2)")
        if feat_dict.get("psh_flag_count", 0) > 1.0:
            hints.append("elevated PSH flags (data-push heavy session)")
        if feat_dict.get("syn_flag_count", 0) > 1.0:
            hints.append("high SYN count (possible SYN flood or port sweep)")
        if feat_dict.get("flow_duration", 0) < -0.5:
            hints.append("very short flow duration (fast-scan pattern)")
        if feat_dict.get("total_fwd_packets", 0) > 1.5:
            hints.append("high forward packet count (possible data-push attack)")
        if feat_dict.get("destination_port", 0) > 1.0:
            hints.append("anomalous destination port distribution")

        if hints:
            lines.extend(hints)
        else:
            top_str = ", ".join(f"{k}={v:.2f}" for k, v in top_features[:3])
            lines.append(f"signature: {top_str}")

        return "; ".join(lines)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def mine(self, df: pd.DataFrame) -> list[ZeroDayPattern]:
        """
        Run a full zero-day mining pass on a DataFrame of anomalous flows.

        Only flows with anomaly_score <= -_MIN_ANOMALY_SCORE are processed.
        Results are accumulated in self.patterns and persisted to disk.

        Inputs:
            df — pd.DataFrame with numeric feature columns and 'anomaly_score'
        Outputs: list[ZeroDayPattern] discovered in this run (empty if none found)
        """
        t0 = time.monotonic()
        self._run_count += 1
        logger.info("ZeroDayMiner run #%d — input rows: %d", self._run_count, len(df))

        if df.empty:
            return []

        # Filter to high-anomaly candidates
        if "anomaly_score" in df.columns:
            candidates = df[df["anomaly_score"] <= -_MIN_ANOMALY_SCORE].copy()
        else:
            candidates = df.copy()

        if candidates.empty:
            logger.info("No anomaly candidates above threshold — nothing to mine")
            return []

        # Cap for memory safety
        if len(candidates) > _MAX_CANDIDATES:
            candidates = candidates.sample(n=_MAX_CANDIDATES, random_state=42)
            logger.debug("Sampled %d anomaly candidates for DBSCAN", _MAX_CANDIDATES)

        # Prepare features
        X_scaled, feature_cols = self._prepare_features(candidates)
        if X_scaled.empty:
            logger.warning("No usable features after preparation — skipping mine")
            return []

        # DBSCAN clustering
        try:
            db = DBSCAN(eps=self._eps, min_samples=self._min_samples, n_jobs=-1)
            labels = db.fit_predict(X_scaled.values)
        except Exception as exc:
            logger.error("DBSCAN failed: %s", exc)
            return []
        finally:
            gc.collect()

        unique_labels = set(labels)
        cluster_labels = [l for l in unique_labels if l != -1]
        noise_count    = int((labels == -1).sum())

        logger.info(
            "DBSCAN found %d cluster(s), %d noise points",
            len(cluster_labels), noise_count,
        )

        # Build patterns for each cluster
        new_patterns: list[ZeroDayPattern] = []
        candidates_reset = candidates.reset_index(drop=True)

        for label in sorted(cluster_labels):
            mask   = pd.Series(labels == label, index=candidates_reset.index)
            cid    = f"ZD-{self._run_count:03d}-{label:03d}"
            try:
                pattern = self._extract_pattern(cid, mask, candidates_reset, feature_cols)
                new_patterns.append(pattern)
                logger.info(
                    "Pattern %s: %d flows, anomaly_score_mean=%.3f, top=%s",
                    cid, pattern.size, pattern.anomaly_score_mean,
                    pattern.top_features[:2],
                )
            except Exception as exc:
                logger.error("Pattern extraction failed for cluster %s: %s", label, exc)

        self._patterns.extend(new_patterns)
        self._persist_patterns(new_patterns)

        elapsed = round((time.monotonic() - t0) * 1000, 1)
        logger.info(
            "ZeroDayMiner run #%d complete — %d new pattern(s) in %.1f ms",
            self._run_count, len(new_patterns), elapsed,
        )
        return new_patterns

    def _persist_patterns(self, patterns: list[ZeroDayPattern]) -> None:
        try:
            with _PATTERNS_PATH.open("a", encoding="utf-8") as fh:
                for p in patterns:
                    d = asdict(p)
                    d["discovered_at"] = p.discovered_at.isoformat()
                    d["top_features"]  = [list(t) for t in p.top_features]
                    fh.write(json.dumps(d) + "\n")
        except OSError as exc:
            logger.error("Pattern persist failed: %s", exc)

    @property
    def patterns(self) -> list[ZeroDayPattern]:
        """All patterns discovered across all mining runs."""
        return list(self._patterns)

    def summary(self) -> dict:
        return {
            "total_patterns": len(self._patterns),
            "mining_runs":    self._run_count,
            "patterns_path":  str(_PATTERNS_PATH),
        }
