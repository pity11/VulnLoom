"""Pure deterministic evaluation of explicit analyzer truth alignments."""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from collections.abc import Callable, Sequence

from vulnloom.domain.digests import canonical_digest

from .analyzer_evaluation_models import (
    AnalyzerEvaluationBaseline,
    AnalyzerEvaluationLimits,
    AnalyzerEvaluationMetrics,
    AnalyzerEvaluationPolicy,
    AnalyzerMetricSlice,
    AnalyzerTruthAlignment,
)
from .analyzer_models import AnalyzerKind, AnalyzerObservationSet
from .models import BenchmarkSuite, RegressionViolation


class AnalyzerEvaluationRejected(ValueError):
    """Analyzer evaluation inputs failed a trusted semantic or resource gate."""


class EvaluationDeadline:
    def __init__(self, seconds: float, *, clock: Callable[[], float] = time.monotonic):
        if seconds <= 0:
            raise AnalyzerEvaluationRejected("analyzer evaluation deadline is exhausted")
        self._clock = clock
        self._expires_at = clock() + seconds

    def check(self) -> None:
        if self._clock() >= self._expires_at:
            raise AnalyzerEvaluationRejected("analyzer evaluation timed out")


def evaluate_analyzer_metrics(
    suite: BenchmarkSuite,
    observation_sets: Sequence[AnalyzerObservationSet],
    alignment: AnalyzerTruthAlignment,
    *,
    limits: AnalyzerEvaluationLimits,
    deadline: EvaluationDeadline,
) -> AnalyzerEvaluationMetrics:
    deadline.check()
    if alignment.suite_id != suite.suite_id or alignment.suite_digest != canonical_digest(
        suite.model_dump(mode="python")
    ):
        raise AnalyzerEvaluationRejected("analyzer alignment suite binding mismatch")
    if len(observation_sets) > limits.max_observation_sets:
        raise AnalyzerEvaluationRejected("analyzer evaluation exceeds ObservationSet limit")
    if len(alignment.matches) > limits.max_matches:
        raise AnalyzerEvaluationRejected("analyzer evaluation exceeds truth-match limit")

    cases = {case.case_id: case for case in suite.cases}
    truths = {}
    for case in suite.cases:
        deadline.check()
        for truth in case.ground_truth:
            truths[(case.case_id, truth.truth_id)] = truth
    sets = {item.observation_set_id: item for item in observation_sets}
    if len(sets) != len(observation_sets):
        raise AnalyzerEvaluationRejected("analyzer ObservationSets must be unique")
    binding_ids = {item.observation_set_id for item in alignment.bindings}
    if binding_ids != set(sets):
        raise AnalyzerEvaluationRejected("analyzer alignment must bind the exact ObservationSets")

    total_observations = 0
    binding_by_set = {}
    for binding in alignment.bindings:
        deadline.check()
        case = cases.get(binding.case_id)
        observations = sets.get(binding.observation_set_id)
        if case is None or observations is None:
            raise AnalyzerEvaluationRejected("analyzer binding references unknown sealed input")
        if (
            binding.observation_set_digest
            != canonical_digest(observations.model_dump(mode="python"))
            or binding.analyzer is not observations.analyzer
            or binding.target_version != observations.target_version
            or case.target_version != observations.target_version
        ):
            raise AnalyzerEvaluationRejected("analyzer case/Target binding mismatch")
        total_observations += len(observations.observations)
        if total_observations > limits.max_observations:
            raise AnalyzerEvaluationRejected("analyzer evaluation exceeds Observation limit")
        binding_by_set[binding.observation_set_id] = binding

    observations_by_set = {}
    for item in observation_sets:
        by_identity = {}
        for observation in item.observations:
            deadline.check()
            by_identity[observation.observation_id] = observation
        observations_by_set[item.observation_set_id] = by_identity
    matched_observations: set[tuple[str, str]] = set()
    matched_truths: set[tuple[str, str]] = set()
    matched_truths_by_analyzer: dict[AnalyzerKind, set[tuple[str, str]]] = defaultdict(set)
    matched_observations_by_analyzer: Counter[AnalyzerKind] = Counter()
    match_counts: Counter[tuple[str, str]] = Counter()
    match_counts_by_analyzer: dict[AnalyzerKind, Counter[tuple[str, str]]] = defaultdict(Counter)

    for match in alignment.matches:
        deadline.check()
        binding = binding_by_set.get(match.observation_set_id)
        observation = observations_by_set.get(match.observation_set_id, {}).get(
            match.observation_id
        )
        truth = truths.get((match.case_id, match.truth_id))
        if (
            binding is None
            or observation is None
            or truth is None
            or binding.case_id != match.case_id
        ):
            raise AnalyzerEvaluationRejected("analyzer truth match escapes its sealed case")
        if match.matched_cwe != truth.cwe or match.matched_cwe not in observation.cwes:
            raise AnalyzerEvaluationRejected("analyzer truth match has incompatible CWE evidence")
        observation_key = (match.observation_set_id, match.observation_id)
        truth_key = (match.case_id, match.truth_id)
        matched_observations.add(observation_key)
        matched_truths.add(truth_key)
        matched_truths_by_analyzer[binding.analyzer].add(truth_key)
        matched_observations_by_analyzer[binding.analyzer] += 1
        match_counts[truth_key] += 1
        match_counts_by_analyzer[binding.analyzer][truth_key] += 1

    by_analyzer = []
    represented_analyzers = sorted(
        {item.analyzer for item in observation_sets}, key=lambda item: item.value
    )
    for analyzer in represented_analyzers:
        deadline.check()
        analyzer_sets = [item for item in observation_sets if item.analyzer is analyzer]
        analyzer_case_ids = {
            binding_by_set[item.observation_set_id].case_id for item in analyzer_sets
        }
        analyzer_truth_count = sum(
            len(cases[case_id].ground_truth) for case_id in analyzer_case_ids
        )
        observation_count = sum(len(item.observations) for item in analyzer_sets)
        exclusion_count = sum(len(item.exclusions) for item in analyzer_sets)
        matched_observation_count = matched_observations_by_analyzer[analyzer]
        duplicate_count = sum(
            max(count - 1, 0) for count in match_counts_by_analyzer[analyzer].values()
        )
        by_analyzer.append(
            AnalyzerMetricSlice(
                analyzer=analyzer,
                case_count=len(analyzer_case_ids),
                ground_truth_count=analyzer_truth_count,
                observation_count=observation_count,
                matched_truth_count=len(matched_truths_by_analyzer[analyzer]),
                matched_observation_count=matched_observation_count,
                false_positive_count=observation_count - matched_observation_count,
                duplicate_match_count=duplicate_count,
                exclusion_count=exclusion_count,
                truth_recall=_ratio(
                    len(matched_truths_by_analyzer[analyzer]),
                    analyzer_truth_count,
                    empty=1.0,
                ),
                observation_precision=_ratio(
                    matched_observation_count, observation_count, empty=1.0
                ),
                duplicate_rate=_ratio(duplicate_count, observation_count, empty=0.0),
                exclusion_rate=_ratio(
                    exclusion_count,
                    observation_count + exclusion_count,
                    empty=0.0,
                ),
            )
        )

    exclusion_count = sum(len(item.exclusions) for item in observation_sets)
    duplicate_count = sum(max(count - 1, 0) for count in match_counts.values())
    ground_truth_count = len(truths)
    matched_observation_count = len(matched_observations)
    return AnalyzerEvaluationMetrics(
        case_count=len(cases),
        analyzer_count=len(represented_analyzers),
        ground_truth_count=ground_truth_count,
        observation_count=total_observations,
        matched_truth_count=len(matched_truths),
        matched_observation_count=matched_observation_count,
        false_positive_count=total_observations - matched_observation_count,
        duplicate_match_count=duplicate_count,
        exclusion_count=exclusion_count,
        truth_recall=_ratio(len(matched_truths), ground_truth_count, empty=1.0),
        observation_precision=_ratio(matched_observation_count, total_observations, empty=1.0),
        duplicate_rate=_ratio(duplicate_count, total_observations, empty=0.0),
        exclusion_rate=_ratio(exclusion_count, total_observations + exclusion_count, empty=0.0),
        by_analyzer=tuple(by_analyzer),
    )


def evaluate_analyzer_regressions(
    metrics: AnalyzerEvaluationMetrics,
    alignment: AnalyzerTruthAlignment,
    policy: AnalyzerEvaluationPolicy,
    baseline: AnalyzerEvaluationBaseline | None,
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
        "analyzer.threshold.truth_recall",
        "truth_recall",
        metrics.truth_recall,
        policy.min_truth_recall,
    )
    minimum(
        "analyzer.threshold.observation_precision",
        "observation_precision",
        metrics.observation_precision,
        policy.min_observation_precision,
    )
    maximum(
        "analyzer.threshold.duplicate_rate",
        "duplicate_rate",
        metrics.duplicate_rate,
        policy.max_duplicate_rate,
    )
    maximum(
        "analyzer.threshold.exclusion_rate",
        "exclusion_rate",
        metrics.exclusion_rate,
        policy.max_exclusion_rate,
    )

    if policy.apply_thresholds_per_analyzer:
        for item in metrics.by_analyzer:
            prefix = f"analyzer.threshold.{item.analyzer.value}"
            minimum(
                f"{prefix}.truth_recall",
                f"{item.analyzer.value}.truth_recall",
                item.truth_recall,
                policy.min_truth_recall,
            )
            minimum(
                f"{prefix}.observation_precision",
                f"{item.analyzer.value}.observation_precision",
                item.observation_precision,
                policy.min_observation_precision,
            )
            maximum(
                f"{prefix}.duplicate_rate",
                f"{item.analyzer.value}.duplicate_rate",
                item.duplicate_rate,
                policy.max_duplicate_rate,
            )
            maximum(
                f"{prefix}.exclusion_rate",
                f"{item.analyzer.value}.exclusion_rate",
                item.exclusion_rate,
                policy.max_exclusion_rate,
            )

    present = {item.analyzer for item in metrics.by_analyzer}
    for analyzer in policy.required_analyzers:
        minimum(
            f"analyzer.required.{analyzer.value}",
            f"required_analyzer.{analyzer.value}",
            1.0 if analyzer in present else 0.0,
            1.0,
        )
    if policy.require_full_case_matrix:
        matrix_analyzers = set(policy.required_analyzers) or present
        expected = metrics.case_count * len(matrix_analyzers)
        actual = len(
            {
                (binding.case_id, binding.analyzer)
                for binding in alignment.bindings
                if binding.analyzer in matrix_analyzers
            }
        )
        minimum(
            "analyzer.policy.case_matrix",
            "case_analyzer_bindings",
            float(actual),
            float(expected),
        )

    if baseline is not None:
        previous = baseline.metrics
        minimum(
            "analyzer.baseline.truth_recall",
            "truth_recall",
            metrics.truth_recall,
            previous.truth_recall - policy.max_truth_recall_drop,
        )
        minimum(
            "analyzer.baseline.observation_precision",
            "observation_precision",
            metrics.observation_precision,
            previous.observation_precision - policy.max_observation_precision_drop,
        )
        maximum(
            "analyzer.baseline.duplicate_rate",
            "duplicate_rate",
            metrics.duplicate_rate,
            previous.duplicate_rate + policy.max_duplicate_rate_increase,
        )
        maximum(
            "analyzer.baseline.exclusion_rate",
            "exclusion_rate",
            metrics.exclusion_rate,
            previous.exclusion_rate + policy.max_exclusion_rate_increase,
        )
        current_slices = {item.analyzer: item for item in metrics.by_analyzer}
        for previous_slice in previous.by_analyzer:
            current = current_slices.get(previous_slice.analyzer)
            if current is None:
                continue
            prefix = f"analyzer.baseline.{current.analyzer.value}"
            minimum(
                f"{prefix}.truth_recall",
                f"{current.analyzer.value}.truth_recall",
                current.truth_recall,
                previous_slice.truth_recall - policy.max_truth_recall_drop,
            )
            minimum(
                f"{prefix}.observation_precision",
                f"{current.analyzer.value}.observation_precision",
                current.observation_precision,
                previous_slice.observation_precision - policy.max_observation_precision_drop,
            )
            maximum(
                f"{prefix}.duplicate_rate",
                f"{current.analyzer.value}.duplicate_rate",
                current.duplicate_rate,
                previous_slice.duplicate_rate + policy.max_duplicate_rate_increase,
            )
            maximum(
                f"{prefix}.exclusion_rate",
                f"{current.analyzer.value}.exclusion_rate",
                current.exclusion_rate,
                previous_slice.exclusion_rate + policy.max_exclusion_rate_increase,
            )
    return tuple(failures)


def _ratio(numerator: int, denominator: int, *, empty: float) -> float:
    return round(numerator / denominator, 9) if denominator else empty
