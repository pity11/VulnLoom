"""Run a small offline ablation study over the sealed M9.4/M9.5 quality inputs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from vulnloom.benchmark import (
    BenchmarkBaseline,
    LocalSourceCaseObservation,
    LocalSourceObservationSet,
    LocalSourceRobustnessProfile,
    LocalSourceSuite,
    RobustnessDisposition,
    evaluate_local_source_robustness,
)


@dataclass(frozen=True)
class AblationRow:
    name: str
    recall: float
    precision: float
    trace: float
    violations: tuple[str, ...]


EXPECTED_ROWS = (
    AblationRow("full", 1.0, 1.0, 1.0, ()),
    AblationRow(
        "without_candidate_recall",
        0.8,
        1.0,
        1.0,
        (
            "candidate_recall_below_minimum",
            "base_quality_gate_failed",
            "framework_mismatch",
        ),
    ),
    AblationRow("without_cross_file_trace", 1.0, 1.0, 1.0, ("cross_file_trace_missing",)),
    AblationRow(
        "without_safe_negative_filter",
        1.0,
        5 / 6,
        1.0,
        (
            "candidate_precision_below_minimum",
            "base_quality_gate_failed",
            "negative_candidate_observed",
        ),
    ),
)


def _replace(
    observations: LocalSourceObservationSet,
    replacement: LocalSourceCaseObservation,
) -> LocalSourceObservationSet:
    return LocalSourceObservationSet.create(
        suite_id=observations.suite_id,
        observations=tuple(
            replacement if item.case_id == replacement.case_id else item
            for item in observations.observations
        ),
        effects=observations.effects,
    )


def run_ablation(root: Path) -> tuple[AblationRow, ...]:
    local = root / "benchmarks" / "m9_4"
    suite = LocalSourceSuite.model_validate_json((local / "suite.json").read_text())
    observations = LocalSourceObservationSet.model_validate_json(
        (local / "observations.json").read_text()
    )
    profile = LocalSourceRobustnessProfile.model_validate_json((local / "profile.json").read_text())
    baseline = BenchmarkBaseline.model_validate_json(
        (root / "benchmarks" / "m6_1" / "baseline.json").read_text()
    )
    requirements = {item.name: item for item in profile.requirements}
    by_case = {item.case_id: item for item in observations.observations}

    missed = by_case[requirements["flask_cross_file_idor"].case_id].model_copy(
        update={"candidates": ()}
    )
    missing_candidate = _replace(observations, missed)

    trace_case = by_case[requirements["fastapi_cross_file_ssrf"].case_id]
    truncated = trace_case.model_copy(
        update={
            "candidates": tuple(
                candidate.model_copy(update={"call_chain_length": 1})
                for candidate in trace_case.candidates
            )
        }
    )
    missing_trace = _replace(observations, truncated)

    negative_requirement = next(
        item for item in profile.requirements if item.disposition is RobustnessDisposition.NEGATIVE
    )
    negative_case = by_case[negative_requirement.case_id]
    false_positive = (
        observations.observations[0]
        .candidates[0]
        .model_copy(
            update={
                "candidate_id": UUID("00000000-0000-5000-8000-000000000956"),
                "duplicate_fingerprint": "f" * 64,
            }
        )
    )
    missing_negative_filter = _replace(
        observations,
        negative_case.model_copy(update={"candidates": (false_positive,)}),
    )

    rows = []
    for name, variant in (
        ("full", observations),
        ("without_candidate_recall", missing_candidate),
        ("without_cross_file_trace", missing_trace),
        ("without_safe_negative_filter", missing_negative_filter),
    ):
        quality, robustness = evaluate_local_source_robustness(suite, variant, baseline, profile)
        rows.append(
            AblationRow(
                name=name,
                recall=quality.metrics.candidate_recall,
                precision=quality.metrics.candidate_precision,
                trace=quality.metrics.trace_completeness,
                violations=(*quality.violations, *robustness.violations),
            )
        )
    return tuple(rows)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    rows = run_ablation(root)
    print("| Variant | Recall | Precision | Trace | Violations |")
    print("|---|---:|---:|---:|---|")
    for row in rows:
        violations = ", ".join(row.violations) or "none"
        print(
            f"| {row.name} | {row.recall:.3f} | {row.precision:.3f} | "
            f"{row.trace:.3f} | {violations} |"
        )
    return int(rows != EXPECTED_ROWS)


if __name__ == "__main__":
    raise SystemExit(main())
