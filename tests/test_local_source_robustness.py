from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnloom.analyzers.models import WebFramework
from vulnloom.benchmark import (
    BenchmarkBaseline,
    BenchmarkGateStatus,
    LocalCandidateObservation,
    LocalSourceBenchmarkRejected,
    LocalSourceObservationSet,
    LocalSourceRobustnessProfile,
    LocalSourceSuite,
    evaluate_local_source_robustness,
    local_source_robustness_profile_digest,
    observe_local_source_suite,
)


def _fixtures():
    root = Path(__file__).resolve().parents[1] / "benchmarks"
    local = root / "m9_4"
    return (
        local,
        LocalSourceSuite.model_validate_json((local / "suite.json").read_text()),
        LocalSourceObservationSet.model_validate_json((local / "observations.json").read_text()),
        LocalSourceRobustnessProfile.model_validate_json((local / "profile.json").read_text()),
        BenchmarkBaseline.model_validate_json((root / "m6_1" / "baseline.json").read_text()),
    )


def _replace(observations, case_id, replacement):
    return LocalSourceObservationSet.create(
        suite_id=observations.suite_id,
        observations=tuple(
            replacement if item.case_id == case_id else item for item in observations.observations
        ),
        effects=observations.effects,
    )


def test_real_cross_framework_and_safe_negative_corpus_is_deterministic():
    root, suite, expected, profile, baseline = _fixtures()
    observed = observe_local_source_suite(suite, root / "sources")
    base, result = evaluate_local_source_robustness(suite, observed, baseline, profile)

    assert observed == expected
    assert base.gate_status is BenchmarkGateStatus.PASSED
    assert result.gate_status is BenchmarkGateStatus.PASSED
    assert result.violations == ()
    assert result.metrics.positive_case_count == 5
    assert result.metrics.negative_case_count == 8
    assert result.metrics.cross_file_case_count == 5
    assert result.metrics.framework_count == 3
    assert result.metrics.parse_failure_count == 0
    assert result.metrics.negative_candidate_count == 0


def test_framework_and_cross_file_trace_regressions_have_stable_violations():
    _, suite, observations, profile, baseline = _fixtures()
    requirement = profile.requirements[0]
    original = next(
        item for item in observations.observations if item.case_id == requirement.case_id
    )
    candidate = original.candidates[0]
    changed_candidate = LocalCandidateObservation.model_validate(
        candidate.model_dump(mode="python")
        | {"framework": WebFramework.FASTAPI, "call_chain_length": 1}
    )
    changed_case = original.model_copy(update={"candidates": (changed_candidate,)})
    changed = _replace(observations, original.case_id, changed_case)

    base, result = evaluate_local_source_robustness(suite, changed, baseline, profile)
    assert base.gate_status is BenchmarkGateStatus.PASSED
    assert result.violations == ("framework_mismatch", "cross_file_trace_missing")


def test_parse_failure_and_safe_negative_candidate_fail_closed():
    _, suite, observations, profile, baseline = _fixtures()
    negative_requirement = next(
        item for item in profile.requirements if item.name == "constant_sql"
    )
    negative = next(
        item for item in observations.observations if item.case_id == negative_requirement.case_id
    )
    positive_candidate = observations.observations[0].candidates[0]
    extra = LocalCandidateObservation.model_validate(
        positive_candidate.model_dump(mode="python")
        | {
            "candidate_id": "00000000-0000-5000-8000-000000000994",
            "duplicate_fingerprint": "9" * 64,
        }
    )
    changed_case = negative.model_copy(update={"candidates": (extra,), "parse_failure_count": 1})
    changed = _replace(observations, negative.case_id, changed_case)

    base, result = evaluate_local_source_robustness(suite, changed, baseline, profile)
    assert base.violations == ("candidate_precision_below_minimum",)
    assert result.violations == (
        "base_quality_gate_failed",
        "parse_failure_observed",
        "negative_candidate_observed",
    )


def test_profile_contract_suite_and_baseline_drift_are_rejected():
    _, suite, observations, profile, baseline = _fixtures()
    changed_requirement = profile.requirements[0].model_copy(
        update={"framework": WebFramework.DJANGO}
    )
    partial = profile.model_copy(
        update={"requirements": (changed_requirement, *profile.requirements[1:])}
    )
    raw = partial.model_dump(mode="python")
    raw["profile_id"] = local_source_robustness_profile_digest(partial)
    with pytest.raises(ValidationError, match="case contract cannot be changed"):
        LocalSourceRobustnessProfile.model_validate(raw)

    suite_drift = profile.model_copy(update={"suite_id": "a" * 64})
    suite_drift = LocalSourceRobustnessProfile.model_validate(
        suite_drift.model_dump(mode="python")
        | {"profile_id": local_source_robustness_profile_digest(suite_drift)}
    )
    with pytest.raises(LocalSourceBenchmarkRejected, match="another suite"):
        evaluate_local_source_robustness(
            suite,
            observations,
            baseline,
            suite_drift,
        )
    baseline_drift = profile.model_copy(update={"workflow_baseline_id": "b" * 64})
    baseline_drift = LocalSourceRobustnessProfile.model_validate(
        baseline_drift.model_dump(mode="python")
        | {"profile_id": local_source_robustness_profile_digest(baseline_drift)}
    )
    with pytest.raises(LocalSourceBenchmarkRejected, match="workflow baseline"):
        evaluate_local_source_robustness(
            suite,
            observations,
            baseline,
            baseline_drift,
        )

    with pytest.raises(LocalSourceBenchmarkRejected, match="content-integrity"):
        evaluate_local_source_robustness(
            suite,
            observations,
            baseline,
            profile.model_copy(update={"profile_id": "c" * 64}),
        )


def test_missing_observation_is_rejected_before_robustness_result():
    _, suite, observations, profile, baseline = _fixtures()
    missing = LocalSourceObservationSet.create(
        suite_id=suite.suite_id,
        observations=observations.observations[:-1],
    )
    with pytest.raises(LocalSourceBenchmarkRejected, match="exact suite"):
        evaluate_local_source_robustness(suite, missing, baseline, profile)
