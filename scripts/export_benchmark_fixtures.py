"""Generate the sealed M6.1 local ground-truth microbenchmark."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from vulnloom.benchmark import (
    BenchmarkBaseline,
    BenchmarkCase,
    BenchmarkObservation,
    BenchmarkObservationSet,
    BenchmarkRegressionPolicy,
    BenchmarkSuite,
    GroundTruthFinding,
    evaluate_metrics,
)
from vulnloom.domain.models import CandidateState, CriticVerdict, ValidationResult


def build_fixture():
    suite = BenchmarkSuite.create(
        name="vulnloom-m6.1-smoke",
        version="1",
        cases=(
            BenchmarkCase(
                case_id="3" * 64,
                target_version="a" * 40,
                ground_truth=(
                    GroundTruthFinding(
                        truth_id="1" * 64,
                        cwe="CWE-639",
                        duplicate_family="2" * 64,
                    ),
                ),
            ),
            BenchmarkCase(
                case_id="4" * 64,
                target_version="b" * 40,
                ground_truth=(),
            ),
        ),
    )
    observations = BenchmarkObservationSet.create(
        suite_id=suite.suite_id,
        observations=(
            BenchmarkObservation(
                case_id="3" * 64,
                target_version="a" * 40,
                candidate_id=UUID("00000000-0000-5000-8000-000000000001"),
                candidate_state=CandidateState.PROMOTED,
                duplicate_fingerprint="5" * 64,
                matched_truth_id="1" * 64,
                validation_result=ValidationResult.REPRODUCED,
                critic_verdict=CriticVerdict.ACCEPTED,
                finding_id=UUID("00000000-0000-5000-8000-000000000002"),
                evidence_required=4,
                evidence_present=4,
                elapsed_ms=100,
                cost_microunits=200,
            ),
        ),
    )
    metrics = evaluate_metrics(suite, observations)
    baseline = BenchmarkBaseline.create(suite=suite, metrics=metrics)
    policy = BenchmarkRegressionPolicy(
        max_total_elapsed_ms=100,
        max_cost_per_finding_microunits=200,
    )
    return suite, observations, baseline, policy


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "benchmarks" / "m6_1"
    root.mkdir(parents=True, exist_ok=True)
    values = zip(
        ("suite.json", "observations.json", "baseline.json", "policy.json"),
        build_fixture(),
        strict=True,
    )
    for name, value in values:
        (root / name).write_text(value.model_dump_json(indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
