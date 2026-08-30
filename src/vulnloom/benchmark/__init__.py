"""Deterministic, offline benchmark contracts and regression gates."""

from .evaluator import BenchmarkRejected, evaluate_metrics, evaluate_regressions
from .models import (
    BenchmarkArtifact,
    BenchmarkBaseline,
    BenchmarkCase,
    BenchmarkGateStatus,
    BenchmarkMetrics,
    BenchmarkObservation,
    BenchmarkObservationSet,
    BenchmarkOutcome,
    BenchmarkPlan,
    BenchmarkRegressionPolicy,
    BenchmarkResult,
    BenchmarkSource,
    BenchmarkSuite,
    GroundTruthFinding,
    RegressionViolation,
)
from .service import BenchmarkService
from .store import (
    BenchmarkArtifactStore,
    BenchmarkIdempotencyConflict,
    BenchmarkRecoveryRequired,
    BenchmarkStore,
)

__all__ = [
    "BenchmarkArtifact",
    "BenchmarkArtifactStore",
    "BenchmarkBaseline",
    "BenchmarkCase",
    "BenchmarkGateStatus",
    "BenchmarkIdempotencyConflict",
    "BenchmarkMetrics",
    "BenchmarkObservation",
    "BenchmarkObservationSet",
    "BenchmarkOutcome",
    "BenchmarkPlan",
    "BenchmarkRecoveryRequired",
    "BenchmarkRegressionPolicy",
    "BenchmarkRejected",
    "BenchmarkResult",
    "BenchmarkService",
    "BenchmarkSource",
    "BenchmarkStore",
    "BenchmarkSuite",
    "GroundTruthFinding",
    "RegressionViolation",
    "evaluate_metrics",
    "evaluate_regressions",
]
