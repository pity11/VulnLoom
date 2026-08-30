"""Run the sealed M6.3 cross-analyzer regression gate entirely offline."""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vulnloom.benchmark import (
    AnalyzerEvaluationArtifactStore,
    AnalyzerEvaluationBaseline,
    AnalyzerEvaluationLimits,
    AnalyzerEvaluationPlan,
    AnalyzerEvaluationPolicy,
    AnalyzerEvaluationService,
    AnalyzerEvaluationStore,
    AnalyzerObservationSet,
    AnalyzerTruthAlignment,
    BenchmarkGateStatus,
    BenchmarkSuite,
)


def main() -> int:
    fixture_root = Path(__file__).resolve().parents[1] / "benchmarks" / "m6_3"
    suite = BenchmarkSuite.model_validate_json(
        (fixture_root / "suite.json").read_text(encoding="utf-8")
    )
    observation_sets = tuple(
        AnalyzerObservationSet.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted(fixture_root.glob("observation-*.json"))
    )
    alignment = AnalyzerTruthAlignment.model_validate_json(
        (fixture_root / "alignment.json").read_text(encoding="utf-8")
    )
    baseline = AnalyzerEvaluationBaseline.model_validate_json(
        (fixture_root / "baseline.json").read_text(encoding="utf-8")
    )
    policy = AnalyzerEvaluationPolicy.model_validate_json(
        (fixture_root / "policy.json").read_text(encoding="utf-8")
    )
    now = datetime.now(UTC)
    plan = AnalyzerEvaluationPlan.create(
        suite=suite,
        alignment=alignment,
        policy=policy,
        limits=AnalyzerEvaluationLimits(),
        baseline=baseline,
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key=f"ci:m6.3:{suite.suite_id}:{alignment.alignment_id}",
    )
    with tempfile.TemporaryDirectory(prefix="vulnloom-m6.3-") as temporary:
        root = Path(temporary)
        with AnalyzerEvaluationStore(root / "evaluation.db") as store:
            outcome = AnalyzerEvaluationService(
                store=store,
                artifact_store=AnalyzerEvaluationArtifactStore(root / "results"),
            ).evaluate(suite, observation_sets, alignment, plan, now=now)
    if outcome.result.gate_status is BenchmarkGateStatus.FAILED:
        for violation in outcome.result.violations:
            print(
                f"{violation.code}: {violation.metric}="
                f"{violation.actual:g} limit={violation.limit:g}"
            )
        return 1
    print(
        f"M6.3 offline gate passed: recall={outcome.result.metrics.truth_recall:.3f} "
        f"precision={outcome.result.metrics.observation_precision:.3f} "
        f"analyzers={outcome.result.metrics.analyzer_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
