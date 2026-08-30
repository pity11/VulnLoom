"""Pure deterministic benchmark metric and regression evaluation."""

from __future__ import annotations

from collections import Counter

from .models import (
    BenchmarkBaseline,
    BenchmarkMetrics,
    BenchmarkObservationSet,
    BenchmarkRegressionPolicy,
    BenchmarkSuite,
    RegressionViolation,
)


class BenchmarkRejected(ValueError):
    """Benchmark inputs failed a trusted binding or workflow integrity check."""


def _ratio(numerator: int, denominator: int, *, empty: float) -> float:
    return round(numerator / denominator, 9) if denominator else empty


def evaluate_metrics(
    suite: BenchmarkSuite, observations: BenchmarkObservationSet
) -> BenchmarkMetrics:
    cases = {case.case_id: case for case in suite.cases}
    truth_by_case = {
        case.case_id: {truth.truth_id for truth in case.ground_truth} for case in suite.cases
    }
    matched_candidates: set[str] = set()
    matched_findings = 0
    evidence_required = 0
    evidence_present = 0
    fingerprints: Counter[str] = Counter()
    finding_count = 0

    for observation in observations.observations:
        if observation.case_id not in cases:
            raise BenchmarkRejected("observation references a case outside the sealed suite")
        if observation.target_version != cases[observation.case_id].target_version:
            raise BenchmarkRejected("observation Target version does not match its sealed case")
        if observation.matched_truth_id is not None:
            if observation.matched_truth_id not in truth_by_case[observation.case_id]:
                raise BenchmarkRejected(
                    "observation truth match is outside its sealed benchmark case"
                )
            matched_candidates.add(observation.matched_truth_id)
        fingerprints[observation.duplicate_fingerprint] += 1
        evidence_required += observation.evidence_required
        evidence_present += observation.evidence_present
        if observation.finding_id is not None:
            finding_count += 1
            if observation.matched_truth_id is not None:
                matched_findings += 1

    ground_truth_count = sum(len(case.ground_truth) for case in suite.cases)
    candidate_count = len(observations.observations)
    duplicate_count = sum(count - 1 for count in fingerprints.values())
    total_elapsed = sum(item.elapsed_ms for item in observations.observations)
    total_cost = sum(item.cost_microunits for item in observations.observations)
    return BenchmarkMetrics(
        ground_truth_count=ground_truth_count,
        candidate_count=candidate_count,
        finding_count=finding_count,
        matched_finding_count=matched_findings,
        candidate_recall=_ratio(len(matched_candidates), ground_truth_count, empty=1.0),
        finding_precision=_ratio(matched_findings, finding_count, empty=1.0),
        duplicate_rate=_ratio(duplicate_count, candidate_count, empty=0.0),
        evidence_completeness=_ratio(evidence_present, evidence_required, empty=1.0),
        policy_violation_count=sum(
            len(item.policy_violation_codes) for item in observations.observations
        ),
        total_elapsed_ms=total_elapsed,
        total_cost_microunits=total_cost,
        cost_per_finding_microunits=(total_cost + max(finding_count, 1) - 1)
        // max(finding_count, 1),
    )


def evaluate_regressions(
    metrics: BenchmarkMetrics,
    policy: BenchmarkRegressionPolicy,
    baseline: BenchmarkBaseline | None,
) -> tuple[RegressionViolation, ...]:
    failures: list[RegressionViolation] = []

    def minimum(code: str, metric: str, actual: float, limit: float) -> None:
        if actual < limit:
            failures.append(
                RegressionViolation(code=code, metric=metric, actual=actual, limit=limit)
            )

    def maximum(code: str, metric: str, actual: float, limit: float) -> None:
        if actual > limit:
            failures.append(
                RegressionViolation(code=code, metric=metric, actual=actual, limit=limit)
            )

    minimum(
        "threshold.candidate_recall",
        "candidate_recall",
        metrics.candidate_recall,
        policy.min_candidate_recall,
    )
    minimum(
        "threshold.finding_precision",
        "finding_precision",
        metrics.finding_precision,
        policy.min_finding_precision,
    )
    maximum(
        "threshold.duplicate_rate",
        "duplicate_rate",
        metrics.duplicate_rate,
        policy.max_duplicate_rate,
    )
    minimum(
        "threshold.evidence_completeness",
        "evidence_completeness",
        metrics.evidence_completeness,
        policy.min_evidence_completeness,
    )
    maximum(
        "threshold.policy_violations",
        "policy_violation_count",
        metrics.policy_violation_count,
        policy.max_policy_violations,
    )
    if policy.max_total_elapsed_ms is not None:
        maximum(
            "threshold.runtime",
            "total_elapsed_ms",
            metrics.total_elapsed_ms,
            policy.max_total_elapsed_ms,
        )
    if policy.max_cost_per_finding_microunits is not None:
        maximum(
            "threshold.cost_per_finding",
            "cost_per_finding_microunits",
            metrics.cost_per_finding_microunits,
            policy.max_cost_per_finding_microunits,
        )

    if baseline is not None:
        previous = baseline.metrics
        minimum(
            "baseline.candidate_recall",
            "candidate_recall",
            metrics.candidate_recall,
            previous.candidate_recall - policy.max_candidate_recall_drop,
        )
        minimum(
            "baseline.finding_precision",
            "finding_precision",
            metrics.finding_precision,
            previous.finding_precision - policy.max_finding_precision_drop,
        )
        minimum(
            "baseline.evidence_completeness",
            "evidence_completeness",
            metrics.evidence_completeness,
            previous.evidence_completeness - policy.max_evidence_completeness_drop,
        )
        maximum(
            "baseline.duplicate_rate",
            "duplicate_rate",
            metrics.duplicate_rate,
            previous.duplicate_rate + policy.max_duplicate_rate_increase,
        )
        maximum(
            "baseline.runtime",
            "total_elapsed_ms",
            metrics.total_elapsed_ms,
            previous.total_elapsed_ms + policy.max_runtime_increase_ms,
        )
        maximum(
            "baseline.cost_per_finding",
            "cost_per_finding_microunits",
            metrics.cost_per_finding_microunits,
            previous.cost_per_finding_microunits + policy.max_cost_per_finding_increase_microunits,
        )
    return tuple(failures)
