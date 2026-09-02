"""Run the M9.4 sealed local-source robustness gate offline."""

from pathlib import Path

from vulnloom.benchmark.local_source import LocalSourceObservationSet, LocalSourceSuite
from vulnloom.benchmark.local_source_robustness import (
    LocalSourceRobustnessProfile,
    evaluate_local_source_robustness,
)
from vulnloom.benchmark.models import BenchmarkBaseline, BenchmarkGateStatus


def main() -> int:
    root = Path(__file__).resolve().parents[1] / "benchmarks"
    local = root / "m9_4"
    suite = LocalSourceSuite.model_validate_json((local / "suite.json").read_text())
    observations = LocalSourceObservationSet.model_validate_json(
        (local / "observations.json").read_text()
    )
    profile = LocalSourceRobustnessProfile.model_validate_json((local / "profile.json").read_text())
    baseline = BenchmarkBaseline.model_validate_json((root / "m6_1" / "baseline.json").read_text())
    base, result = evaluate_local_source_robustness(suite, observations, baseline, profile)
    if result.gate_status is BenchmarkGateStatus.FAILED:
        for violation in (*base.violations, *result.violations):
            print(violation)
        return 1
    print(
        "M9.4 local-source robustness gate passed: "
        f"positive={result.metrics.positive_case_count} "
        f"negative={result.metrics.negative_case_count} "
        f"frameworks={result.metrics.framework_count} "
        f"cross_file={result.metrics.cross_file_case_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
