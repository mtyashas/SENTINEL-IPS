"""
explainability/shap_explainer.py

Purpose: Generate SHAP (SHapley Additive exPlanations) feature-importance values
         for trained SENTINEL IDS models. Uses TreeExplainer for XGBoost models
         (exact, fast) with KernelExplainer as a fallback for other estimators.

         CRITICAL INVARIANT: feature names must be preserved end-to-end.
         X must always be a pd.DataFrame when passed to the explainer so that
         SHAP plots show real column names (bwd_packet_length_std, etc.) rather
         than positional aliases (f0, f13). This is enforced by extracting the
         selected feature list from the ANOVAFeatureSelector pipeline step and
         constructing named DataFrames before every SHAP call.

Inputs:  Fitted BenchmarkIDS / LightweightIDS model; pd.DataFrame of samples.
Outputs: SHAPResult dataclass with shap_values array and feature_names list;
         PNG plots saved to shap_plots/.

Usage:
    from explainability.shap_explainer import SHAPExplainer
    explainer = SHAPExplainer(model)
    result    = explainer.explain(X_sample)
    explainer.plot_summary(result, title="Binary IDS — SHAP Summary")
"""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

from config import (
    SHAP_BACKGROUND_SAMPLES,
    SHAP_DIR,
    SHAP_EXPLAIN_SAMPLES,
)

logger = logging.getLogger(__name__)


@dataclass
class SHAPResult:
    shap_values:   np.ndarray        # shape (n_samples, n_features)
    feature_names: list[str]
    base_value:    float             # expected model output
    X_explained:   pd.DataFrame      # the rows that were explained
    latency_ms:    float = 0.0
    explainer_type: str = "unknown"


class SHAPExplainer:
    """
    SHAP explanation engine for SENTINEL IDS models.

    Wraps shap.TreeExplainer (XGBoost) or shap.KernelExplainer (fallback).
    Preserves feature names by always operating on named DataFrames so plots
    display bwd_packet_length_std instead of f0.

    Parameters:
        model       — fitted BenchmarkIDS, LightweightIDS, or CombinedIDS
        background  — background dataset for KernelExplainer (ignored by Tree)
        shap_dir    — output directory for plots (default config.SHAP_DIR)
    """

    def __init__(
        self,
        model,
        background:  Optional[pd.DataFrame] = None,
        shap_dir:    Optional[Path] = None,
    ) -> None:
        self._model    = model
        self._shap_dir = shap_dir or SHAP_DIR
        self._explainer = None
        self._feature_names: list[str] = []
        self._explainer_type = "none"

        self._build_explainer(model, background)

    # ------------------------------------------------------------------
    # Explainer construction
    # ------------------------------------------------------------------

    def _get_pipeline(self, model):
        """Extract the sklearn Pipeline from a SENTINEL model wrapper."""
        if hasattr(model, "_pipeline"):
            return model._pipeline
        if hasattr(model, "pipeline_"):
            return model.pipeline_
        return None

    def _get_feature_names(self, model) -> list[str]:
        """
        Get the exact feature names the model was trained on.

        For BenchmarkIDS: names come from ANOVAFeatureSelector.selected_features_.
        For LightweightIDS: names are the fixed ENGINEERED_FEATURES list.
        Falls back to pipeline feature_names_in_ if available.
        """
        # BenchmarkIDS / CombinedIDS — ANOVA-selected names
        try:
            return list(model.get_selected_features())
        except (AttributeError, RuntimeError):
            pass

        # LightweightIDS — fixed feature set
        from config import ENGINEERED_FEATURES
        pipeline = self._get_pipeline(model)
        if pipeline is not None:
            try:
                clf = pipeline.named_steps.get("clf")
                if clf is not None and hasattr(clf, "feature_names_in_"):
                    return list(clf.feature_names_in_)
            except Exception:
                pass

        return list(ENGINEERED_FEATURES)

    def _get_xgb_classifier(self, model):
        """Extract the XGBClassifier from inside the Pipeline."""
        pipeline = self._get_pipeline(model)
        if pipeline is not None:
            return pipeline.named_steps.get("clf")
        # If model is itself an XGBClassifier
        try:
            from xgboost import XGBClassifier
            if isinstance(model, XGBClassifier):
                return model
        except ImportError:
            pass
        return None

    def _transform_to_selected(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        Run X through the pipeline up to (but not including) the classifier
        and return a named DataFrame with only the selected features.
        """
        pipeline = self._get_pipeline(self._model)

        # Fast path: X already has the right feature columns
        if all(c in X.columns for c in self._feature_names):
            return X[self._feature_names].copy()

        # No usable pipeline — return as-is
        if pipeline is None or not hasattr(pipeline, "steps"):
            return X.copy()

        # Apply imputer → scaler → selector in order
        out = X.copy()
        for name, step in pipeline.steps[:-1]:   # exclude clf
            try:
                transformed = step.transform(out)
                # Preserve DataFrame structure
                if isinstance(transformed, pd.DataFrame):
                    out = transformed
                elif hasattr(transformed, "shape"):
                    cols = getattr(step, "get_feature_names_out", lambda: None)()
                    if cols is not None:
                        out = pd.DataFrame(transformed, columns=cols, index=out.index)
                    elif transformed.shape[1] == len(self._feature_names):
                        out = pd.DataFrame(transformed, columns=self._feature_names, index=out.index)
                    else:
                        out = pd.DataFrame(transformed, index=out.index)
            except Exception as exc:
                logger.debug("Pipeline step %s transform failed: %s", name, exc)
                break

        # Ensure column names are correct
        if isinstance(out, pd.DataFrame) and list(out.columns) != self._feature_names:
            if out.shape[1] == len(self._feature_names):
                out.columns = self._feature_names

        return out

    def _build_explainer(self, model, background: Optional[pd.DataFrame]) -> None:
        try:
            import shap
        except ImportError:
            logger.error("shap package not installed — install with: pip install shap")
            return

        self._feature_names = self._get_feature_names(model)
        logger.info("SHAPExplainer: %d features identified", len(self._feature_names))

        xgb_clf = self._get_xgb_classifier(model)

        if xgb_clf is not None:
            try:
                self._explainer = shap.TreeExplainer(xgb_clf)
                self._explainer_type = "TreeExplainer"
                logger.info("SHAPExplainer using TreeExplainer (XGBoost)")
                return
            except Exception as exc:
                logger.warning("TreeExplainer failed: %s — falling back to KernelExplainer", exc)

        # KernelExplainer fallback
        if background is None:
            logger.warning(
                "No background dataset supplied for KernelExplainer — "
                "SHAP values may be less accurate"
            )
            return

        try:
            bg = background.sample(
                n=min(SHAP_BACKGROUND_SAMPLES, len(background)),
                random_state=42,
            )
            bg_transformed = self._transform_to_selected(bg)

            def _predict_fn(X_arr: np.ndarray) -> np.ndarray:
                X_df = pd.DataFrame(X_arr, columns=self._feature_names)
                return model.predict_proba(X_df)[:, 1]

            self._explainer = shap.KernelExplainer(_predict_fn, bg_transformed.values)
            self._explainer_type = "KernelExplainer"
            logger.info("SHAPExplainer using KernelExplainer (fallback)")
        except Exception as exc:
            logger.error("KernelExplainer initialisation failed: %s", exc)

    # ------------------------------------------------------------------
    # Explanation
    # ------------------------------------------------------------------

    def explain(
        self,
        X:        pd.DataFrame,
        n_samples: Optional[int] = None,
    ) -> Optional[SHAPResult]:
        """
        Compute SHAP values for rows of X.

        Feature names are preserved by operating on named DataFrames throughout —
        this guarantees plots show bwd_packet_length_std instead of f0.

        Inputs:
            X         — pd.DataFrame of flow features (any number of rows)
            n_samples — max rows to explain; defaults to SHAP_EXPLAIN_SAMPLES
        Outputs: SHAPResult or None if explainer not available
        """
        if self._explainer is None:
            logger.error("Explainer not initialised — cannot explain")
            return None

        if not isinstance(X, pd.DataFrame):
            raise TypeError("SHAPExplainer.explain() requires pd.DataFrame — numpy destroys feature names")

        t0 = time.monotonic()
        n  = n_samples or SHAP_EXPLAIN_SAMPLES
        sample = X.sample(n=min(n, len(X)), random_state=42) if len(X) > n else X.copy()

        try:
            import shap

            X_transformed = self._transform_to_selected(sample)

            # Ensure correct column ordering
            if list(X_transformed.columns) != self._feature_names and \
               len(X_transformed.columns) == len(self._feature_names):
                X_transformed.columns = self._feature_names

            if self._explainer_type == "TreeExplainer":
                raw = self._explainer.shap_values(X_transformed.values)
                # Binary classification returns list [neg_class, pos_class] or single array
                if isinstance(raw, list):
                    shap_vals = raw[1] if len(raw) == 2 else raw[0]
                else:
                    shap_vals = raw
                base_value = float(
                    self._explainer.expected_value[1]
                    if isinstance(self._explainer.expected_value, (list, np.ndarray))
                    else self._explainer.expected_value
                )
            else:
                shap_vals  = self._explainer.shap_values(X_transformed.values)
                base_value = float(self._explainer.expected_value)

            latency = round((time.monotonic() - t0) * 1000, 1)
            logger.info(
                "SHAP values computed: %d samples × %d features (%.1f ms, %s)",
                shap_vals.shape[0], shap_vals.shape[1], latency, self._explainer_type,
            )

            return SHAPResult(
                shap_values=shap_vals,
                feature_names=list(X_transformed.columns),
                base_value=base_value,
                X_explained=X_transformed,
                latency_ms=latency,
                explainer_type=self._explainer_type,
            )

        except Exception as exc:
            logger.error("SHAP explain failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Plotting
    # ------------------------------------------------------------------

    def plot_summary(
        self,
        result:  SHAPResult,
        title:   str = "SHAP Feature Importance",
        plot_type: str = "bar",        # "bar" | "beeswarm" | "both"
        save:    bool = True,
    ) -> Optional[Path]:
        """
        Generate and optionally save a SHAP summary plot.

        plot_type:
          "bar"      — mean |SHAP| bar chart (fast, one figure)
          "beeswarm" — violin/dot scatter showing value distribution
          "both"     — saves bar chart; returns bar chart path

        Inputs:  result — SHAPResult from explain()
        Outputs: Path to saved PNG, or None if matplotlib unavailable
        """
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import shap
        except ImportError as exc:
            logger.warning("Plot dependencies missing: %s", exc)
            return None

        plots: list[Path] = []

        def _save_fig(suffix: str) -> Path:
            ts   = time.strftime("%Y%m%d_%H%M%S")
            path = self._shap_dir / f"shap_{suffix}_{ts}.png"
            plt.tight_layout()
            plt.savefig(path, dpi=150, bbox_inches="tight")
            plt.close()
            logger.info("SHAP plot saved: %s", path)
            return path

        if plot_type in ("bar", "both"):
            plt.figure(figsize=(10, 7))
            mean_abs = np.abs(result.shap_values).mean(axis=0)
            idx      = np.argsort(mean_abs)[::-1][:20]
            plt.barh(
                [result.feature_names[i] for i in idx[::-1]],
                mean_abs[idx[::-1]],
                color="#2196F3",
            )
            plt.xlabel("Mean |SHAP value|")
            plt.title(title)
            path = _save_fig("bar")
            plots.append(path)

        if plot_type in ("beeswarm", "both"):
            plt.figure(figsize=(10, 8))
            shap.summary_plot(
                result.shap_values,
                result.X_explained,
                feature_names=result.feature_names,
                show=False,
                max_display=20,
            )
            plt.title(title + " (beeswarm)")
            path = _save_fig("beeswarm")
            plots.append(path)

        return plots[0] if plots else None

    def plot_waterfall(
        self,
        result:      SHAPResult,
        sample_idx:  int = 0,
    ) -> Optional[Path]:
        """
        Generate a waterfall plot explaining a single prediction.

        Inputs:  result — SHAPResult; sample_idx — row index to explain
        Outputs: Path to saved PNG
        """
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import shap
        except ImportError:
            return None

        try:
            row_shap = result.shap_values[sample_idx]
            row_data = result.X_explained.iloc[sample_idx]

            # Build bar chart sorted by absolute contribution
            idx  = np.argsort(np.abs(row_shap))[::-1][:15]
            vals = row_shap[idx]
            names = [
                f"{result.feature_names[i]}={row_data.iloc[i]:.2f}"
                for i in idx
            ]

            colours = ["#E53935" if v > 0 else "#1E88E5" for v in vals]
            plt.figure(figsize=(10, 7))
            plt.barh(names[::-1], vals[::-1], color=colours[::-1])
            plt.axvline(0, color="black", linewidth=0.8)
            plt.xlabel("SHAP value (contribution to attack probability)")
            plt.title(f"SHAP Waterfall — sample {sample_idx} (base={result.base_value:.3f})")
            plt.tight_layout()

            ts   = time.strftime("%Y%m%d_%H%M%S")
            path = self._shap_dir / f"shap_waterfall_{sample_idx}_{ts}.png"
            plt.savefig(path, dpi=150, bbox_inches="tight")
            plt.close()
            logger.info("Waterfall plot saved: %s", path)
            return path
        except Exception as exc:
            logger.error("Waterfall plot failed: %s", exc)
            return None

    def global_importance(self, result: SHAPResult) -> list[tuple[str, float]]:
        """
        Return global feature importance as sorted (feature_name, mean_abs_shap) tuples.

        Inputs:  result — SHAPResult
        Outputs: list sorted by importance descending
        """
        mean_abs = np.abs(result.shap_values).mean(axis=0)
        total    = mean_abs.sum() or 1.0
        ranked   = sorted(
            zip(result.feature_names, (mean_abs / total * 100).tolist()),
            key=lambda x: x[1],
            reverse=True,
        )
        return [(name, round(pct, 2)) for name, pct in ranked]
