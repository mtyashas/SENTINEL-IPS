"""
core/features.py

Purpose: Feature engineering and ANOVA-based feature selection for SENTINEL IPS.
         Computes the 10 lightweight engineered features and wraps SelectKBest
         in an sklearn-compatible API that preserves DataFrame column names for
         downstream SHAP explainability.
Inputs:  Preprocessed pd.DataFrame (output of core/preprocessing.py).
Outputs: Transformed DataFrame with engineered features; fitted selector with
         named feature list; (X, y) tuple for model training.

Usage:
    from core.features import NetworkFeatureEngineer, ANOVAFeatureSelector, get_feature_matrix
    eng = NetworkFeatureEngineer(keep_raw=True)
    df_eng = eng.transform(df)
    X, y = get_feature_matrix(df_eng)
    sel = ANOVAFeatureSelector(k=30)
    sel.fit(X, y)
    X_selected = sel.transform(X)
"""

import logging
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.exceptions import NotFittedError
from sklearn.feature_selection import SelectKBest, f_classif

from config import (
    BINARY_LABEL_COL,
    ENGINEERED_FEATURES,
    K_BEST_FEATURES,
    MULTICLASS_LABEL_COL,
)

logger = logging.getLogger(__name__)

# Columns whose sum forms the numerator/denominator of bytes_per_pkt
_FWD_BYTES_COL  = "total_length_of_fwd_packets"
_BWD_BYTES_COL  = "total_length_of_bwd_packets"
_FWD_PKTS_COL   = "total_fwd_packets"
_BWD_PKTS_COL   = "total_backward_packets"

# Columns to always exclude from the feature matrix (non-numeric / label)
_META_COLS = {BINARY_LABEL_COL, MULTICLASS_LABEL_COL, "label_raw"}


# ---------------------------------------------------------------------------
# NetworkFeatureEngineer
# ---------------------------------------------------------------------------

class NetworkFeatureEngineer(BaseEstimator, TransformerMixin):
    """
    Computes the 10 ENGINEERED_FEATURES defined in config.py.

    The only truly computed feature is ``bytes_per_pkt``; the remaining nine
    already exist in the preprocessed DataFrame under their standard names.
    The transform step adds ``bytes_per_pkt`` and optionally restricts the
    output to just the engineered feature set.

    Parameters:
        keep_raw — if True (default), return all original columns plus
                   ``bytes_per_pkt``; if False, return only ENGINEERED_FEATURES.

    Inputs:  Preprocessed pd.DataFrame (output of load_full_dataset).
    Outputs: pd.DataFrame with ``bytes_per_pkt`` added (and optionally trimmed
             to ENGINEERED_FEATURES only).

    Usage:
        eng = NetworkFeatureEngineer(keep_raw=True)
        df_eng = eng.transform(df)
    """

    def __init__(self, keep_raw: bool = True) -> None:
        self.keep_raw = keep_raw

    def fit(self, X: pd.DataFrame, y=None) -> "NetworkFeatureEngineer":
        return self

    def transform(self, X: pd.DataFrame, y=None) -> pd.DataFrame:
        X = X.copy()

        try:
            fwd_bytes = X[_FWD_BYTES_COL] if _FWD_BYTES_COL in X.columns else 0
            bwd_bytes = X[_BWD_BYTES_COL] if _BWD_BYTES_COL in X.columns else 0
            fwd_pkts  = X[_FWD_PKTS_COL]  if _FWD_PKTS_COL  in X.columns else 1
            bwd_pkts  = X[_BWD_PKTS_COL]  if _BWD_PKTS_COL  in X.columns else 1
            total_bytes = pd.to_numeric(fwd_bytes, errors="coerce").fillna(0) + \
                          pd.to_numeric(bwd_bytes, errors="coerce").fillna(0)
            total_pkts  = pd.to_numeric(fwd_pkts,  errors="coerce").fillna(1) + \
                          pd.to_numeric(bwd_pkts,   errors="coerce").fillna(1)
            X["bytes_per_pkt"] = total_bytes / (total_pkts + 1e-9)
        except Exception as exc:
            logger.error("bytes_per_pkt computation failed: %s", exc)
            X["bytes_per_pkt"] = np.nan

        if self.keep_raw:
            return X

        available = [f for f in ENGINEERED_FEATURES if f in X.columns]
        if not available:
            logger.warning("None of ENGINEERED_FEATURES found in DataFrame — returning full frame")
            return X
        return X[available]


# ---------------------------------------------------------------------------
# ANOVAFeatureSelector
# ---------------------------------------------------------------------------

class ANOVAFeatureSelector(BaseEstimator, TransformerMixin):
    """
    ANOVA F-test feature selector wrapping sklearn's SelectKBest(f_classif).

    CRITICAL: Always call fit() with a pd.DataFrame — never a numpy array.
    Fitting on a DataFrame preserves feature names so that downstream SHAP
    explanations display real column names (e.g. ``bwd_packet_length_std``)
    rather than anonymous indices (``f0``, ``f13``).

    Parameters:
        k — number of top features to select (default K_BEST_FEATURES from config).

    Attributes after fit():
        selected_features_ — ordered list of selected feature name strings.
        feature_scores_    — dict mapping each selected feature to its F-score.

    Inputs:  X: pd.DataFrame of numeric features, y: pd.Series of labels.
    Outputs: transform() returns a pd.DataFrame with only selected columns.

    Usage:
        sel = ANOVAFeatureSelector(k=30)
        sel.fit(X_df, y)
        X_reduced = sel.transform(X_df)
        print(sel.selected_features_)
    """

    def __init__(self, k: int = K_BEST_FEATURES) -> None:
        self.k = k

    def fit(self, X: pd.DataFrame, y: pd.Series) -> "ANOVAFeatureSelector":
        if not isinstance(X, pd.DataFrame):
            raise TypeError(
                "ANOVAFeatureSelector requires a pd.DataFrame — passing a numpy "
                "array destroys feature names and breaks SHAP explainability."
            )

        # Replace Inf/NaN with safe values before F-statistic computation
        X_fit = X.replace([np.inf, -np.inf], np.nan)
        col_medians = X_fit.median()
        X_fit = X_fit.fillna(col_medians).fillna(0)

        y_fit = pd.to_numeric(y, errors="coerce").fillna(0)

        effective_k = min(self.k, X_fit.shape[1])
        self._selector = SelectKBest(f_classif, k=effective_k)
        self._selector.fit(X_fit, y_fit)

        mask = self._selector.get_support()
        self.selected_features_: List[str] = X.columns[mask].tolist()

        all_scores = self._selector.scores_
        if all_scores is not None:
            self.feature_scores_: dict = {
                name: float(score)
                for name, score in zip(X.columns, all_scores)
                if name in self.selected_features_
            }
        else:
            self.feature_scores_ = {}

        logger.info(
            "ANOVAFeatureSelector fitted: %d → %d features selected",
            X.shape[1], len(self.selected_features_),
        )
        return self

    def transform(self, X: pd.DataFrame, y=None) -> pd.DataFrame:
        if not hasattr(self, "selected_features_"):
            raise NotFittedError(
                "This ANOVAFeatureSelector instance is not fitted yet. "
                "Call fit() before transform()."
            )
        present = [f for f in self.selected_features_ if f in X.columns]
        missing = set(self.selected_features_) - set(present)
        if missing:
            logger.warning("Features missing from transform input: %s", missing)
        return X[present]


# ---------------------------------------------------------------------------
# get_feature_matrix
# ---------------------------------------------------------------------------

def get_feature_matrix(
    df: pd.DataFrame,
    label_col: str = BINARY_LABEL_COL,
    extra_drop: Optional[List[str]] = None,
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Extract a numeric feature matrix X and label vector y from a preprocessed DataFrame.

    Drops all label/metadata columns and non-numeric columns, returning a
    pd.DataFrame for X (so feature names are available for SHAP and the
    ANOVAFeatureSelector) and a pd.Series for y.

    Inputs:
        df         — preprocessed DataFrame (output of load_full_dataset or
                     NetworkFeatureEngineer.transform)
        label_col  — column to use as y target (default: BINARY_LABEL_COL)
        extra_drop — additional column names to exclude from X
    Outputs:
        (X, y) where X is pd.DataFrame of numeric features and y is pd.Series.

    Usage:
        X, y = get_feature_matrix(df, label_col=BINARY_LABEL_COL)
    """
    if label_col not in df.columns:
        raise KeyError(
            f"Label column '{label_col}' not found. "
            f"Available columns: {df.columns.tolist()[:10]}..."
        )

    always_drop = _META_COLS.copy()
    if extra_drop:
        always_drop.update(extra_drop)

    y = df[label_col].copy()

    drop_cols = [c for c in always_drop if c in df.columns]
    X = df.drop(columns=drop_cols)
    X = X.select_dtypes(include=[np.number])

    # Align on shared index (guards against filtering in _encode_labels)
    common_idx = X.index.intersection(y.index)
    X = X.loc[common_idx]
    y = y.loc[common_idx]

    logger.debug("get_feature_matrix → X%s, y%s", X.shape, y.shape)
    return X, y
