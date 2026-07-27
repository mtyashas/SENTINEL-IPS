"""
evaluation/reporter.py

Purpose: Generate publication-quality evaluation reports for SENTINEL IDS models.
         Renders ROC curves, precision-recall curves, confusion matrix heatmaps,
         and benchmark comparison tables, then serialises full results to JSON and
         human-readable text in the reports/ directory.

Inputs:  EvaluationResult / list[PerClassMetrics] from IDSEvaluator; optional
         BenchmarkReport from validate_benchmark().
Outputs: PNG plots + JSON + .txt files written to reports/

Usage:
    from evaluation.reporter import EvaluationReporter
    reporter = EvaluationReporter()
    reporter.plot_roc(result, title="Binary IDS -- ROC Curve")
    reporter.plot_confusion_matrix(result)
    reporter.plot_pr_curve(result)
    reporter.save_report(result, benchmark_report=br)
"""

import json
import logging
import time
from pathlib import Path
from typing import Optional

import numpy as np

from config import REPORT_DIR
from evaluation.metrics import BenchmarkReport, EvaluationResult, PerClassMetrics

logger = logging.getLogger(__name__)

# Column widths for text benchmark table
_COL_W = {"metric": 22, "achieved": 14, "target": 14, "pass": 8}


class EvaluationReporter:
    """
    Report and visualisation engine for SENTINEL IDS evaluation results.

    Methods:
        plot_roc              -- ROC curve PNG
        plot_pr_curve         -- Precision-Recall curve PNG
        plot_confusion_matrix -- Confusion matrix heatmap PNG
        plot_benchmark_table  -- Bar chart comparing achieved vs target metrics
        plot_per_class        -- Per-class precision/recall/F1 bar chart
        save_report           -- JSON + plain-text report saved to reports/
        full_phase_report     -- convenience: all plots + report in one call

    Parameters:
        reports_dir -- output directory (default config.REPORT_DIR)
    """

    def __init__(self, reports_dir: Optional[Path] = None) -> None:
        self._reports_dir = reports_dir or REPORT_DIR
        self._reports_dir.mkdir(parents=True, exist_ok=True)
        logger.info("EvaluationReporter ready -> %s", self._reports_dir)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ts(self) -> str:
        return time.strftime("%Y%m%d_%H%M%S")

    def _save_fig(self, plt, name: str) -> Path:
        path = self._reports_dir / f"{name}_{self._ts()}.png"
        plt.tight_layout()
        plt.savefig(path, dpi=150, bbox_inches="tight")
        plt.close()
        logger.info("Plot saved: %s", path)
        return path

    def _matplotlib(self):
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            return plt
        except ImportError:
            logger.warning("matplotlib not installed -- plots skipped")
            return None

    # ------------------------------------------------------------------
    # ROC Curve
    # ------------------------------------------------------------------

    def plot_roc(
        self,
        result: EvaluationResult,
        title:  str = "ROC Curve",
        zoom:   bool = False,
    ) -> Optional[Path]:
        """
        Plot ROC curve with AUC annotation.

        Inputs:
            result -- EvaluationResult with fpr_curve/tpr_curve populated
            zoom   -- if True, fit axis limits to where the curve actually
                      varies (with padding) instead of the fixed full [0,1]
                      range. A near-perfect classifier's curve hugs the
                      top-left corner in the full view; zoom makes its shape
                      visible. Default False preserves prior plot output.
        Outputs: Path to saved PNG, or None
        """
        plt = self._matplotlib()
        if plt is None:
            return None

        if not result.fpr_curve:
            logger.warning("No ROC curve data in result -- skipping plot")
            return None

        fpr = np.array(result.fpr_curve)
        tpr = np.array(result.tpr_curve)

        fig, ax = plt.subplots(figsize=(8, 7))
        ax.plot(fpr, tpr, color="#2196F3", lw=2,
                label=f"ROC (AUC = {result.roc_auc:.4f})")
        ax.plot([0, 1], [0, 1], color="#BDBDBD", lw=1.2, linestyle="--",
                label="Random classifier")
        ax.fill_between(fpr, tpr, alpha=0.12, color="#2196F3")
        ax.set_xlabel("False Positive Rate", fontsize=12)
        ax.set_ylabel("True Positive Rate", fontsize=12)
        ax.set_title(f"{title}\n{result.experiment}", fontsize=13)
        ax.legend(loc="lower right", fontsize=11)
        ax.grid(alpha=0.3)
        if zoom:
            # roc_curve() sweeps every threshold down to the lowest score, so
            # fpr spans close to the full [0,1] range even for a near-perfect
            # classifier -- just at unrealistic operating points. Zoom to the
            # "elbow" instead: the region up to where tpr first approaches
            # its maximum, which is where the curve's shape actually lives.
            # A good classifier's ROC curve rises near-vertically at fpr=0
            # (tpr climbing from 0 to its operating value while fpr stays 0)
            # before flattening out -- that vertical run is real signal, not
            # noise to crop, so only the x-axis (fpr) is zoomed. Full [0,1]
            # unzoomed makes the whole curve invisible against the corner
            # for a near-perfect classifier; zooming fpr to the "elbow"
            # where tpr first approaches its max reveals its actual shape.
            tpr_max = float(tpr.max())
            elbow = np.argmax(tpr >= tpr_max - 0.01)
            x_hi = min(max(float(fpr[elbow]) * 4.0, 0.03), 1.0)
            ax.set_xlim([0.0, x_hi])
            ax.set_ylim([0.0, 1.01])
        else:
            ax.set_xlim([0.0, 1.0])
            ax.set_ylim([0.0, 1.01])

        return self._save_fig(plt, f"roc_{result.experiment}")

    # ------------------------------------------------------------------
    # Precision-Recall Curve
    # ------------------------------------------------------------------

    def plot_pr_curve(
        self,
        result: EvaluationResult,
        title:  str = "Precision-Recall Curve",
        zoom:   bool = False,
    ) -> Optional[Path]:
        """
        Plot Precision-Recall curve.

        Inputs:
            result -- EvaluationResult with precision_curve/recall_curve populated
            zoom   -- if True, fit the y-axis to where precision actually
                      varies (with padding) instead of the fixed [0,1.05]
                      range. A high-AP curve's real variation (e.g. 0.94-1.0)
                      is otherwise squeezed into a thin band at the top.
                      Default False preserves prior plot output.
        Outputs: Path to saved PNG, or None
        """
        plt = self._matplotlib()
        if plt is None:
            return None

        if not result.precision_curve:
            logger.warning("No PR curve data in result -- skipping plot")
            return None

        precision = np.array(result.precision_curve)
        recall    = np.array(result.recall_curve)

        fig, ax = plt.subplots(figsize=(8, 7))
        ax.plot(recall, precision, color="#E53935", lw=2,
                label=f"PR curve (AP = {result.avg_precision:.4f})")
        ax.fill_between(recall, precision, alpha=0.12, color="#E53935")
        ax.axhline(y=result.precision, color="#FF9800", lw=1.2,
                   linestyle="--", label=f"Operating point (P={result.precision:.3f})")
        ax.set_xlabel("Recall", fontsize=12)
        ax.set_ylabel("Precision", fontsize=12)
        ax.set_title(f"{title}\n{result.experiment}", fontsize=13)
        ax.legend(loc="upper right", fontsize=11)
        ax.grid(alpha=0.3)
        ax.set_xlim([0.0, 1.0])
        if zoom:
            span = float(precision.max() - precision.min())
            pad  = max(span * 0.15, 0.01)
            ax.set_ylim([max(float(precision.min()) - pad, 0.0), min(float(precision.max()) + pad, 1.01)])
        else:
            ax.set_ylim([0.0, 1.05])

        return self._save_fig(plt, f"pr_curve_{result.experiment}")

    # ------------------------------------------------------------------
    # Confusion Matrix
    # ------------------------------------------------------------------

    def plot_confusion_matrix(
        self,
        y_true:      np.ndarray,
        y_pred:      np.ndarray,
        result:      Optional[EvaluationResult] = None,
        class_names: Optional[list[str]] = None,
        title:       str = "Confusion Matrix",
    ) -> Optional[Path]:
        """
        Plot normalised confusion matrix heatmap from raw label arrays.

        Inputs:
            y_true      -- true integer labels
            y_pred      -- predicted integer labels
            result      -- used only for the experiment tag in the title
            class_names -- optional list of class name strings
        Outputs: Path to saved PNG, or None
        """
        plt = self._matplotlib()
        if plt is None:
            return None

        try:
            from sklearn.metrics import confusion_matrix as sk_cm
        except ImportError:
            return None

        cm_arr  = sk_cm(y_true, y_pred)
        row_sums = cm_arr.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1
        cm_norm = cm_arr / row_sums

        n = cm_arr.shape[0]
        labels = class_names or [str(i) for i in range(n)]
        exp_tag = result.experiment if result is not None else "eval"

        fig, ax = plt.subplots(figsize=(max(6, n * 1.4), max(5, n * 1.2)))
        im = ax.imshow(cm_norm, interpolation="nearest",
                       cmap="Blues", vmin=0, vmax=1)
        plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

        ax.set_xticks(range(n))
        ax.set_yticks(range(n))
        ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=9)
        ax.set_yticklabels(labels, fontsize=9)
        ax.set_xlabel("Predicted label", fontsize=11)
        ax.set_ylabel("True label", fontsize=11)
        ax.set_title(f"{title}\n{exp_tag}", fontsize=12)

        thresh = 0.5
        for i in range(n):
            for j in range(n):
                colour = "white" if cm_norm[i, j] > thresh else "black"
                ax.text(j, i,
                        f"{cm_arr[i, j]}\n({cm_norm[i, j]:.2f})",
                        ha="center", va="center",
                        fontsize=max(7, 10 - n), color=colour)

        return self._save_fig(plt, f"confusion_matrix_{exp_tag}")

    # ------------------------------------------------------------------
    # Benchmark comparison chart
    # ------------------------------------------------------------------

    def plot_benchmark_table(
        self,
        benchmark: BenchmarkReport,
        title:     str = "Benchmark Comparison",
    ) -> Optional[Path]:
        """
        Horizontal bar chart: achieved vs target for each metric.

        Inputs:  benchmark -- BenchmarkReport from IDSEvaluator.validate_benchmark()
        Outputs: Path to saved PNG, or None
        """
        plt = self._matplotlib()
        if plt is None:
            return None

        if not benchmark.checks:
            logger.warning("Empty benchmark report -- skipping plot")
            return None

        metrics  = [c["metric"]  for c in benchmark.checks]
        achieved = [c["actual"]  * 100 for c in benchmark.checks]
        targets  = [c["target"]  * 100 for c in benchmark.checks]
        passed   = [c["passed"]         for c in benchmark.checks]

        n      = len(metrics)
        y      = np.arange(n)
        height = 0.38
        colours = ["#4CAF50" if p else "#E53935" for p in passed]

        fig, ax = plt.subplots(figsize=(11, max(5, n * 0.65)))
        bars_a = ax.barh(y + height / 2, achieved, height,
                         color=colours, label="Achieved", alpha=0.9)
        bars_t = ax.barh(y - height / 2, targets,  height,
                         color="#90A4AE", label="Target", alpha=0.7)

        for bar, val in zip(bars_a, achieved):
            ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                    f"{val:.2f}%", va="center", fontsize=8)
        for bar, val in zip(bars_t, targets):
            ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                    f"{val:.2f}%", va="center", fontsize=8, color="#546E7A")

        passing_count = sum(1 for p in passed if p)
        ax.set_yticks(y)
        ax.set_yticklabels(metrics, fontsize=10)
        ax.set_xlabel("Score (%)", fontsize=11)
        ax.set_title(
            f"{title} -- {benchmark.experiment}\n"
            f"{passing_count}/{n} targets met  "
            f"({'PASS' if benchmark.passed else 'FAIL'})",
            fontsize=12,
        )
        ax.legend(loc="lower right", fontsize=10)
        ax.grid(axis="x", alpha=0.3)
        ax.set_xlim(0, 115)

        return self._save_fig(plt, f"benchmark_{benchmark.experiment}")

    # ------------------------------------------------------------------
    # Per-class bar chart (multi-class)
    # ------------------------------------------------------------------

    def plot_per_class(
        self,
        per_class:   list[PerClassMetrics],
        class_names: Optional[list[str]] = None,
        title:       str = "Per-Class Metrics",
    ) -> Optional[Path]:
        """
        Grouped bar chart of precision / recall / F1 per attack class.

        Inputs:
            per_class   -- list of PerClassMetrics from evaluate_multiclass()
            class_names -- optional human-readable labels (indexed by label int)
        Outputs: Path to saved PNG, or None
        """
        plt = self._matplotlib()
        if plt is None or not per_class:
            return None

        def _name(pc: PerClassMetrics) -> str:
            if class_names and pc.label < len(class_names):
                return class_names[pc.label]
            return str(pc.label)

        labels     = [_name(m) for m in per_class]
        precisions = [m.precision for m in per_class]
        recalls    = [m.recall    for m in per_class]
        f1s        = [m.f1        for m in per_class]

        n = len(labels)
        x = np.arange(n)
        w = 0.26

        fig, ax = plt.subplots(figsize=(max(10, n * 1.5), 6))
        ax.bar(x - w, precisions, w, label="Precision", color="#1E88E5")
        ax.bar(x,     recalls,    w, label="Recall",    color="#43A047")
        ax.bar(x + w, f1s,        w, label="F1-Score",  color="#FB8C00")

        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=9)
        ax.set_ylabel("Score", fontsize=11)
        ax.set_ylim(0, 1.08)
        ax.set_title(title, fontsize=13)
        ax.legend(fontsize=10)
        ax.grid(axis="y", alpha=0.3)

        return self._save_fig(plt, "per_class_metrics")

    # ------------------------------------------------------------------
    # JSON + text report
    # ------------------------------------------------------------------

    def save_report(
        self,
        result:    EvaluationResult,
        benchmark: Optional[BenchmarkReport] = None,
    ) -> tuple[Path, Path]:
        """
        Serialise evaluation results to JSON and plain-text files.

        Inputs:
            result    -- EvaluationResult
            benchmark -- optional BenchmarkReport for pass/fail table
        Outputs: (json_path, txt_path) tuple
        """
        ts  = self._ts()
        tag = result.experiment

        json_path = self._reports_dir / f"report_{tag}_{ts}.json"
        txt_path  = self._reports_dir / f"report_{tag}_{ts}.txt"

        payload: dict = {
            "experiment":  result.experiment,
            "n_samples":   result.n_samples,
            "timestamp":   ts,
            "metrics": {
                "accuracy":      result.accuracy,
                "precision":     result.precision,
                "recall":        result.recall,
                "f1":            result.f1,
                "roc_auc":       result.roc_auc,
                "avg_precision": result.avg_precision,
                "brier_score":   result.brier_score,
                "fp_rate":       result.fp_rate,
                "fn_rate":       result.fn_rate,
                "tp":            result.tp,
                "tn":            result.tn,
                "fp":            result.fp,
                "fn":            result.fn,
                "f1_macro":      result.f1_macro,
                "f1_weighted":   result.f1_weighted,
            },
            "throughput_fps": result.throughput_fps,
            "eval_latency_s": result.eval_latency_s,
        }
        if benchmark is not None:
            payload["benchmark"] = {
                "overall_pass": benchmark.passed,
                "checks":       benchmark.checks,
                "summary":      benchmark.summary,
            }

        json_path.write_text(json.dumps(payload, indent=2))
        logger.info("JSON report saved: %s", json_path)

        lines = self._format_text_report(result, benchmark)
        txt_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Text report saved: %s", txt_path)

        return json_path, txt_path

    def _format_text_report(
        self,
        result:    EvaluationResult,
        benchmark: Optional[BenchmarkReport],
    ) -> list[str]:
        sep = "=" * 70

        lines = [
            sep,
            "SENTINEL IPS v2.0 -- EVALUATION REPORT",
            sep,
            f"Experiment : {result.experiment}",
            f"Samples    : {result.n_samples:,}",
            f"Timestamp  : {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "PERFORMANCE METRICS",
            "-" * 40,
            f"  Accuracy       : {result.accuracy * 100:6.2f}%",
            f"  Precision      : {result.precision * 100:6.2f}%",
            f"  Recall         : {result.recall * 100:6.2f}%",
            f"  F1-Score       : {result.f1 * 100:6.2f}%",
            f"  ROC-AUC        : {result.roc_auc * 100:6.2f}%",
            f"  Avg Precision  : {result.avg_precision * 100:6.2f}%",
            f"  Brier Score    : {result.brier_score:.4f}",
            f"  FP Rate        : {result.fp_rate * 100:6.2f}%",
            f"  FN Rate        : {result.fn_rate * 100:6.2f}%",
            "",
            "CONFUSION MATRIX (binary)",
            "-" * 40,
            f"  TP : {result.tp:>10,}",
            f"  TN : {result.tn:>10,}",
            f"  FP : {result.fp:>10,}",
            f"  FN : {result.fn:>10,}",
        ]

        if result.f1_macro > 0:
            lines += [
                "",
                "MULTI-CLASS METRICS",
                "-" * 40,
                f"  F1 Macro    : {result.f1_macro * 100:6.2f}%",
                f"  F1 Weighted : {result.f1_weighted * 100:6.2f}%",
            ]

        if result.throughput_fps > 0:
            lines += [
                "",
                "THROUGHPUT",
                "-" * 40,
                f"  Flows/second : {result.throughput_fps:>12,.0f}",
            ]

        if benchmark is not None:
            cw = _COL_W
            hdr = (
                f"  {'Metric':<{cw['metric']}}"
                f"{'Achieved':>{cw['achieved']}}"
                f"{'Target':>{cw['target']}}"
                f"{'Pass?':>{cw['pass']}}"
            )
            lines += [
                "",
                "BENCHMARK VALIDATION",
                "-" * 40,
                hdr,
                "  " + "-" * (cw["metric"] + cw["achieved"] + cw["target"] + cw["pass"]),
            ]
            for c in benchmark.checks:
                tick = "PASS" if c["passed"] else "FAIL"
                lines.append(
                    f"  {c['metric']:<{cw['metric']}}"
                    f"{c['actual'] * 100:>{cw['achieved']}.2f}"
                    f"{c['target'] * 100:>{cw['target']}.2f}"
                    f"{tick:>{cw['pass']}}"
                )
            verdict = "OVERALL: PASS" if benchmark.passed else "OVERALL: FAIL"
            passing = sum(1 for c in benchmark.checks if c["passed"])
            lines += [
                "",
                f"  {verdict} ({passing}/{len(benchmark.checks)} targets met)",
            ]

        lines += ["", sep]
        return lines

    # ------------------------------------------------------------------
    # Convenience: full phase report
    # ------------------------------------------------------------------

    def full_phase_report(
        self,
        result:      EvaluationResult,
        benchmark:   Optional[BenchmarkReport] = None,
        y_true:      Optional[np.ndarray] = None,
        y_pred:      Optional[np.ndarray] = None,
        class_names: Optional[list[str]] = None,
    ) -> dict[str, Optional[Path]]:
        """
        Generate all plots + text/JSON reports in one call.

        Pass y_true + y_pred to also render the confusion matrix.
        Returns a dict of {artifact_name: Path_or_None}.
        """
        outputs: dict[str, Optional[Path]] = {}

        outputs["roc"]      = self.plot_roc(result)
        outputs["pr_curve"] = self.plot_pr_curve(result)

        if y_true is not None and y_pred is not None:
            outputs["cm"] = self.plot_confusion_matrix(
                y_true, y_pred, result=result, class_names=class_names)
        else:
            outputs["cm"] = None

        if benchmark is not None:
            outputs["benchmark_chart"] = self.plot_benchmark_table(benchmark)

        if result.per_class:
            outputs["per_class"] = self.plot_per_class(
                result.per_class, class_names=class_names)

        json_path, txt_path = self.save_report(result, benchmark)
        outputs["json_report"] = json_path
        outputs["txt_report"]  = txt_path

        saved = sum(1 for p in outputs.values() if p is not None)
        logger.info(
            "full_phase_report complete: %d/%d artifacts saved to %s",
            saved, len(outputs), self._reports_dir,
        )
        return outputs
