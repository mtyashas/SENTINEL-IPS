"""
evaluation/metrics.py

Purpose: Comprehensive metrics computation for SENTINEL IDS models. Extends
         core.model.evaluate_model with per-class breakdowns, calibration
         analysis, benchmark validation against the proven targets from
         CLAUDE.md, and throughput measurement. All results are returned as
         typed dataclasses so the reporter can consume them without
         re-parsing dicts.

Inputs:  Fitted model; X_test pd.DataFrame; y_test pd.Series; optional
         y_proba overrides for pre-computed probability arrays.
Outputs: EvaluationResult dataclass with all metric fields; BenchmarkReport
         comparing actual vs target performance.

Usage:
    from evaluation.metrics import IDSEvaluator
    evaluator = IDSEvaluator()
    result    = evaluator.evaluate(model, X_test, y_test, experiment="2017_binary")
    print(result.accuracy, result.f1, result.roc_auc)
    bm = evaluator.validate_benchmark(result, "2017_binary")
    print(bm.passed, bm.summary)
"""

import gc
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.calibration import calibration_curve
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Benchmark targets from CLAUDE.md
# ---------------------------------------------------------------------------

BENCHMARK_TARGETS: dict[str, dict[str, float]] = {
    "2017_binary": {
        "accuracy":  0.9969,
        "precision": 0.9853,
        "recall":    0.9968,
        "f1":        0.9910,
        "roc_auc":   0.9999,
        "fp_rate":   0.0031,
        "fn_rate":   0.0032,
    },
    "cross_dataset": {
        "accuracy":  0.8564,
        "precision": 0.7418,
        "recall":    0.2012,
        "f1":        0.3166,
        "roc_auc":   0.9235,
    },
    "combined_training": {
        "recall":    0.8083,
        "f1":        0.8940,
        "precision": 1.0000,
    },
    "lightweight": {
        "accuracy":  0.9947,
        "f1":        0.9846,
        "roc_auc":   0.9995,
    },
    "multiclass": {
        "f1_macro":  0.8831,
    },
}

# Per-metric tolerance (absolute difference allowed before flagging a miss)
_TOLERANCE: dict[str, float] = {
    "accuracy":  0.005,
    "precision": 0.010,
    "recall":    0.015,
    "f1":        0.010,
    "roc_auc":   0.005,
    "fp_rate":   0.005,
    "fn_rate":   0.005,
    "f1_macro":  0.020,
}


@dataclass
class PerClassMetrics:
    label:     int
    precision: float
    recall:    float
    f1:        float
    support:   int


@dataclass
class EvaluationResult:
    experiment:    str
    n_samples:     int
    # Binary metrics
    accuracy:      float = 0.0
    precision:     float = 0.0
    recall:        float = 0.0
    f1:            float = 0.0
    roc_auc:       float = 0.0
    avg_precision: float = 0.0   # area under PR curve
    brier_score:   float = 0.0
    fp_rate:       float = 0.0
    fn_rate:       float = 0.0
    tp:            int   = 0
    tn:            int   = 0
    fp:            int   = 0
    fn:            int   = 0
    # Multiclass
    f1_macro:      float = 0.0
    f1_weighted:   float = 0.0
    per_class:     list[PerClassMetrics] = field(default_factory=list)
    # Curve data (for plotting)
    fpr_curve:     list[float] = field(default_factory=list)
    tpr_curve:     list[float] = field(default_factory=list)
    thresholds_roc: list[float] = field(default_factory=list)
    precision_curve: list[float] = field(default_factory=list)
    recall_curve:    list[float] = field(default_factory=list)
    # Calibration
    fraction_pos:  list[float] = field(default_factory=list)
    mean_pred:     list[float] = field(default_factory=list)
    # Throughput
    throughput_fps: float = 0.0
    eval_latency_s: float = 0.0


@dataclass
class BenchmarkReport:
    experiment:   str
    passed:       bool
    checks:       list[dict]   # {metric, target, actual, delta, passed}
    summary:      str


class IDSEvaluator:
    """
    Full evaluation suite for SENTINEL IDS models.

    evaluate()          — compute all metrics for one experiment
    evaluate_multiclass() — per-class breakdown for multi-label models
    validate_benchmark()  — compare result against CLAUDE.md targets
    measure_throughput()  — flows-per-second timing

    Parameters: none
    """

    def __init__(self) -> None:
        logger.info("IDSEvaluator ready — %d benchmark targets loaded",
                    len(BENCHMARK_TARGETS))

    # ------------------------------------------------------------------
    # Binary evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        model,
        X_test:     pd.DataFrame,
        y_test:     pd.Series,
        experiment: str = "custom",
        threshold:  Optional[float] = None,
    ) -> EvaluationResult:
        """
        Compute the full binary classification metric suite.

        Inputs:
            model      — fitted BenchmarkIDS / LightweightIDS / CombinedIDS
            X_test     — feature DataFrame
            y_test     — binary label Series (0/1)
            experiment — label for this run ("2017_binary", "cross_dataset", etc.)
            threshold  — override model confidence threshold
        Outputs: EvaluationResult
        """
        t0 = time.monotonic()

        try:
            y_proba = model.predict_proba(X_test)[:, 1]
        except Exception as exc:
            logger.error("predict_proba failed: %s", exc)
            raise

        t_used  = threshold or getattr(model, "confidence_threshold", 0.5)
        y_pred  = (y_proba >= t_used).astype(int)
        y_true  = (y_test.values if hasattr(y_test, "values") else y_test).astype(int)

        # Core metrics
        acc  = float(accuracy_score(y_true, y_pred))
        prec = float(precision_score(y_true, y_pred, zero_division=0))
        rec  = float(recall_score(y_true, y_pred, zero_division=0))
        f1   = float(f1_score(y_true, y_pred, zero_division=0))

        try:
            auc = float(roc_auc_score(y_true, y_proba))
        except ValueError:
            auc = float("nan")

        try:
            ap = float(average_precision_score(y_true, y_proba))
        except ValueError:
            ap = 0.0

        try:
            brier = float(brier_score_loss(y_true, y_proba))
        except Exception:
            brier = 0.0

        cm      = confusion_matrix(y_true, y_pred)
        tn, fp_, fn_, tp_ = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        fp_rate = float(fp_ / max(tn + fp_, 1))
        fn_rate = float(fn_ / max(tp_ + fn_, 1))

        # Curve data
        try:
            fpr, tpr, thr_roc = roc_curve(y_true, y_proba)
            fpr_l, tpr_l, thr_l = fpr.tolist(), tpr.tolist(), thr_roc.tolist()
        except Exception:
            fpr_l, tpr_l, thr_l = [], [], []

        try:
            prec_c, rec_c, _ = precision_recall_curve(y_true, y_proba)
            prec_cl, rec_cl  = prec_c.tolist(), rec_c.tolist()
        except Exception:
            prec_cl, rec_cl = [], []

        # Calibration
        try:
            frac_pos, mean_pred = calibration_curve(y_true, y_proba, n_bins=10)
            frac_l, mean_l = frac_pos.tolist(), mean_pred.tolist()
        except Exception:
            frac_l, mean_l = [], []

        elapsed = round(time.monotonic() - t0, 3)

        result = EvaluationResult(
            experiment=experiment,
            n_samples=len(y_true),
            accuracy=round(acc,  4),
            precision=round(prec, 4),
            recall=round(rec,  4),
            f1=round(f1,   4),
            roc_auc=round(auc,  4),
            avg_precision=round(ap, 4),
            brier_score=round(brier, 4),
            fp_rate=round(fp_rate, 4),
            fn_rate=round(fn_rate, 4),
            tp=int(tp_), tn=int(tn), fp=int(fp_), fn=int(fn_),
            fpr_curve=fpr_l,
            tpr_curve=tpr_l,
            thresholds_roc=thr_l,
            precision_curve=prec_cl,
            recall_curve=rec_cl,
            fraction_pos=frac_l,
            mean_pred=mean_l,
            eval_latency_s=elapsed,
        )

        logger.info(
            "[%s] acc=%.4f prec=%.4f rec=%.4f f1=%.4f auc=%.4f (%.2fs)",
            experiment, acc, prec, rec, f1, auc, elapsed,
        )
        return result

    # ------------------------------------------------------------------
    # Multiclass evaluation
    # ------------------------------------------------------------------

    def evaluate_multiclass(
        self,
        model,
        X_test:     pd.DataFrame,
        y_test:     pd.Series,
        experiment: str = "multiclass",
        class_names: Optional[list[str]] = None,
    ) -> EvaluationResult:
        """
        Per-class metrics for multi-label IDS classification.

        Inputs:
            model       — fitted BenchmarkIDS(mode='multiclass') or CombinedIDS
            X_test      — feature DataFrame
            y_test      — integer label Series
            class_names — optional list of class name strings
        Outputs: EvaluationResult with per_class list populated
        """
        t0 = time.monotonic()

        try:
            y_pred = model.predict(X_test)
        except Exception as exc:
            logger.error("predict failed: %s", exc)
            raise

        y_true = (y_test.values if hasattr(y_test, "values") else y_test).astype(int)

        acc          = float(accuracy_score(y_true, y_pred))
        f1_macro     = float(f1_score(y_true, y_pred, average="macro",    zero_division=0))
        f1_weighted  = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

        # Per-class breakdown
        labels = sorted(np.unique(np.concatenate([y_true, y_pred])))
        prec_arr = precision_score(y_true, y_pred, labels=labels, average=None, zero_division=0)
        rec_arr  = recall_score   (y_true, y_pred, labels=labels, average=None, zero_division=0)
        f1_arr   = f1_score       (y_true, y_pred, labels=labels, average=None, zero_division=0)
        support  = np.bincount(y_true, minlength=max(labels) + 1)

        per_class: list[PerClassMetrics] = []
        for i, label in enumerate(labels):
            name = class_names[label] if class_names and label < len(class_names) else str(label)
            per_class.append(PerClassMetrics(
                label=int(label),
                precision=round(float(prec_arr[i]), 4),
                recall=round(float(rec_arr[i]), 4),
                f1=round(float(f1_arr[i]), 4),
                support=int(support[label]) if label < len(support) else 0,
            ))

        elapsed = round(time.monotonic() - t0, 3)

        result = EvaluationResult(
            experiment=experiment,
            n_samples=len(y_true),
            accuracy=round(acc, 4),
            f1_macro=round(f1_macro, 4),
            f1_weighted=round(f1_weighted, 4),
            per_class=per_class,
            eval_latency_s=elapsed,
        )

        logger.info(
            "[%s] acc=%.4f f1_macro=%.4f f1_weighted=%.4f (%.2fs)",
            experiment, acc, f1_macro, f1_weighted, elapsed,
        )
        return result

    # ------------------------------------------------------------------
    # Throughput
    # ------------------------------------------------------------------

    def measure_throughput(
        self,
        model,
        X_bench: pd.DataFrame,
        n_runs:  int = 5,
    ) -> float:
        """
        Measure model prediction throughput in flows per second.

        Inputs:
            model   — fitted IDS model
            X_bench — feature DataFrame (ideally >= 100K rows for accuracy)
            n_runs  — number of timed runs to average
        Outputs: mean flows per second
        """
        # Warm-up
        try:
            model.predict_proba(X_bench.iloc[:min(1000, len(X_bench))])
        except Exception:
            pass

        timings: list[float] = []
        for _ in range(n_runs):
            t0 = time.perf_counter()
            try:
                model.predict_proba(X_bench)
            except Exception as exc:
                logger.error("Throughput run failed: %s", exc)
                return 0.0
            timings.append(time.perf_counter() - t0)

        fps = len(X_bench) / float(np.mean(timings))
        logger.info("Throughput: %.0f flows/sec (n=%d, rows=%d)", fps, n_runs, len(X_bench))
        return round(fps, 0)

    # ------------------------------------------------------------------
    # Benchmark validation
    # ------------------------------------------------------------------

    def validate_benchmark(
        self,
        result:     EvaluationResult,
        experiment: Optional[str] = None,
    ) -> BenchmarkReport:
        """
        Compare an EvaluationResult against the proven benchmark targets.

        Inputs:
            result     — EvaluationResult from evaluate() or evaluate_multiclass()
            experiment — key into BENCHMARK_TARGETS; defaults to result.experiment
        Outputs: BenchmarkReport with per-metric pass/fail and overall verdict
        """
        exp     = experiment or result.experiment
        targets = BENCHMARK_TARGETS.get(exp)

        if targets is None:
            return BenchmarkReport(
                experiment=exp,
                passed=True,
                checks=[],
                summary=f"No benchmark targets defined for experiment '{exp}' — skipped.",
            )

        checks: list[dict] = []
        all_passed = True

        metric_map = {
            "accuracy":  result.accuracy,
            "precision": result.precision,
            "recall":    result.recall,
            "f1":        result.f1,
            "roc_auc":   result.roc_auc,
            "fp_rate":   result.fp_rate,
            "fn_rate":   result.fn_rate,
            "f1_macro":  result.f1_macro,
        }

        for metric, target in targets.items():
            actual    = metric_map.get(metric, 0.0)
            tol       = _TOLERANCE.get(metric, 0.01)
            delta     = actual - target
            # fp_rate and fn_rate: lower is better → pass if actual <= target + tol
            if metric in ("fp_rate", "fn_rate"):
                passed = actual <= target + tol
            else:
                passed = actual >= target - tol

            if not passed:
                all_passed = False

            checks.append({
                "metric":  metric,
                "target":  round(target, 4),
                "actual":  round(actual, 4),
                "delta":   round(delta,  4),
                "passed":  passed,
            })

        passing_count = sum(1 for c in checks if c["passed"])
        summary_lines = [
            f"Benchmark validation for '{exp}': "
            f"{passing_count}/{len(checks)} checks passed "
            f"({'PASS' if all_passed else 'FAIL'})",
        ]
        for c in checks:
            icon = "OK" if c["passed"] else "FAIL"
            summary_lines.append(
                f"  [{icon}] {c['metric']:<15} target={c['target']:.4f}  "
                f"actual={c['actual']:.4f}  delta={c['delta']:+.4f}"
            )

        summary = "\n".join(summary_lines)
        logger.info(summary)

        return BenchmarkReport(
            experiment=exp,
            passed=all_passed,
            checks=checks,
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Convenience: full report dict
    # ------------------------------------------------------------------

    def full_report_dict(self, result: EvaluationResult) -> dict:
        """Serialise an EvaluationResult to a plain dict for JSON output."""
        return {
            "experiment":     result.experiment,
            "n_samples":      result.n_samples,
            "accuracy":       result.accuracy,
            "precision":      result.precision,
            "recall":         result.recall,
            "f1":             result.f1,
            "roc_auc":        result.roc_auc,
            "avg_precision":  result.avg_precision,
            "brier_score":    result.brier_score,
            "fp_rate":        result.fp_rate,
            "fn_rate":        result.fn_rate,
            "tp":             result.tp,
            "tn":             result.tn,
            "fp":             result.fp,
            "fn":             result.fn,
            "f1_macro":       result.f1_macro,
            "f1_weighted":    result.f1_weighted,
            "throughput_fps": result.throughput_fps,
            "eval_latency_s": result.eval_latency_s,
            "per_class": [
                {"label": pc.label, "precision": pc.precision,
                 "recall": pc.recall, "f1": pc.f1, "support": pc.support}
                for pc in result.per_class
            ],
        }
