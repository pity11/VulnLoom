"""Run the M9.3 joined static and completed-workflow quality gate offline."""

from pathlib import Path

from vulnloom.benchmark.local_source import (
    LocalSourceObservationSet,
    LocalSourceQualityPolicy,
    LocalSourceSuite,
    evaluate_local_source_quality,
)
from vulnloom.benchmark.models import BenchmarkBaseline, BenchmarkGateStatus


def main() -> int:
    root = Path(__file__).resolve().parents[1] / "benchmarks"
    local = root / "m9_3"
    suite = LocalSourceSuite.model_validate_json((local / "suite.json").read_text())
    observations = LocalSourceObservationSet.model_validate_json(
        (local / "observations.json").read_text()
    )
    policy = LocalSourceQualityPolicy.model_validate_json((local / "policy.json").read_text())
    baseline = BenchmarkBaseline.model_validate_json((root / "m6_1" / "baseline.json").read_text())
    result = evaluate_local_source_quality(suite, observations, baseline, policy)
    if result.gate_status is BenchmarkGateStatus.FAILED:
        for violation in result.violations:
            print(violation)
        return 1
    print(
        "M9.3 local-source quality gate passed: "
        f"cases={result.metrics.case_count} recall={result.metrics.candidate_recall:.3f} "
        f"candidate_precision={result.metrics.candidate_precision:.3f} "
        f"finding_precision={result.metrics.finding_precision:.3f} "
        f"evidence={result.metrics.evidence_completeness:.3f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
