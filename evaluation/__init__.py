"""evaluation — SENTINEL IPS v2.0 model evaluation and reporting."""

from evaluation.metrics import (
    IDSEvaluator,
    EvaluationResult,
    PerClassMetrics,
    BenchmarkReport,
    BENCHMARK_TARGETS,
)
from evaluation.reporter import EvaluationReporter

__all__ = [
    "IDSEvaluator",
    "EvaluationResult",
    "PerClassMetrics",
    "BenchmarkReport",
    "BENCHMARK_TARGETS",
    "EvaluationReporter",
]
