"""Run the sealed M6.1 microbenchmark entirely offline for CI."""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vulnloom.benchmark import (
    BenchmarkArtifactStore,
    BenchmarkBaseline,
    BenchmarkGateStatus,
    BenchmarkObservationSet,
    BenchmarkPlan,
    BenchmarkRegressionPolicy,
    BenchmarkService,
    BenchmarkStore,
    BenchmarkSuite,
)


def main() -> int:
    fixture_root = Path(__file__).resolve().parents[1] / "benchmarks" / "m6_1"
    suite = BenchmarkSuite.model_validate_json(
        (fixture_root / "suite.json").read_text(encoding="utf-8")
    )
    observations = BenchmarkObservationSet.model_validate_json(
        (fixture_root / "observations.json").read_text(encoding="utf-8")
    )
    baseline = BenchmarkBaseline.model_validate_json(
        (fixture_root / "baseline.json").read_text(encoding="utf-8")
    )
    policy = BenchmarkRegressionPolicy.model_validate_json(
        (fixture_root / "policy.json").read_text(encoding="utf-8")
    )
    now = datetime.now(UTC)
    plan = BenchmarkPlan.create(
        suite=suite,
        observations=observations,
        policy=policy,
        baseline=baseline,
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key=f"ci:m6.1:{suite.suite_id}:{observations.observation_set_id}",
    )
    with tempfile.TemporaryDirectory(prefix="vulnloom-m6.1-") as temporary:
        root = Path(temporary)
        with BenchmarkStore(root / "benchmark.db") as store:
            outcome = BenchmarkService(
                store=store,
                artifact_store=BenchmarkArtifactStore(root / "results"),
            ).evaluate(suite, observations, plan, now=now)
    if outcome.result.gate_status is BenchmarkGateStatus.FAILED:
        for violation in outcome.result.violations:
            print(
                f"{violation.code}: {violation.metric}="
                f"{violation.actual:g} limit={violation.limit:g}"
            )
        return 1
    print(
        f"M6.1 offline gate passed: recall={outcome.result.metrics.candidate_recall:.3f} "
        f"precision={outcome.result.metrics.finding_precision:.3f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
