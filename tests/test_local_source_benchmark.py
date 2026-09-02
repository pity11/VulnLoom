from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnloom.benchmark import (
    BenchmarkBaseline,
    BenchmarkGateStatus,
    LocalSourceBenchmarkLimits,
    LocalSourceBenchmarkRejected,
    LocalSourceEffectCounters,
    LocalSourceFile,
    LocalSourceObservationSet,
    LocalSourceQualityPolicy,
    LocalSourceSuite,
    evaluate_local_source_quality,
    observe_local_source_suite,
)


def _fixtures():
    root = Path(__file__).resolve().parents[1] / "benchmarks"
    local = root / "m9_3"
    return (
        local,
        LocalSourceSuite.model_validate_json((local / "suite.json").read_text()),
        LocalSourceObservationSet.model_validate_json((local / "observations.json").read_text()),
        LocalSourceQualityPolicy.model_validate_json((local / "policy.json").read_text()),
        BenchmarkBaseline.model_validate_json((root / "m6_1" / "baseline.json").read_text()),
    )


def test_real_local_static_pipeline_and_joined_quality_gate_are_deterministic():
    root, suite, expected, policy, baseline = _fixtures()
    observed = observe_local_source_suite(suite, root / "sources")
    result = evaluate_local_source_quality(suite, observed, baseline, policy)

    assert observed == expected
    assert result.gate_status is BenchmarkGateStatus.PASSED
    assert result.violations == ()
    assert result.metrics.case_count == 9
    assert result.metrics.truth_count == 8
    assert result.metrics.candidate_count == 8
    assert result.metrics.candidate_recall == 1
    assert result.metrics.candidate_precision == 1
    assert result.metrics.trace_completeness == 1
    assert result.metrics.finding_precision == 1
    assert result.metrics.evidence_completeness == 1
    guarded = next(
        observation
        for case, observation in zip(suite.cases, observed.observations, strict=True)
        if case.name == "guarded_object"
    )
    assert guarded.candidates == ()


def test_missed_truth_and_forbidden_effect_fail_with_stable_codes():
    _, suite, observations, policy, baseline = _fixtures()
    first = observations.observations[0].model_copy(update={"candidates": ()})
    changed = LocalSourceObservationSet.create(
        suite_id=suite.suite_id,
        observations=(first, *observations.observations[1:]),
        effects=LocalSourceEffectCounters(runner_calls=1, submissions=1),
    )
    result = evaluate_local_source_quality(suite, changed, baseline, policy)

    assert result.gate_status is BenchmarkGateStatus.FAILED
    assert result.violations == (
        "candidate_recall_below_minimum",
        "forbidden_effect_observed",
    )


def test_extra_candidate_lowers_precision_and_incomplete_trace_is_rejected_by_schema():
    _, suite, observations, policy, baseline = _fixtures()
    source = observations.observations[0].candidates[0]
    extra = type(source).model_validate(
        source.model_dump(mode="python")
        | {
            "candidate_id": "00000000-0000-5000-8000-000000000999",
            "cwe": "CWE-999",
            "duplicate_fingerprint": "f" * 64,
        }
    )
    first = observations.observations[0].model_copy(
        update={"candidates": (*observations.observations[0].candidates, extra)}
    )
    changed = LocalSourceObservationSet.create(
        suite_id=suite.suite_id, observations=(first, *observations.observations[1:])
    )
    result = evaluate_local_source_quality(suite, changed, baseline, policy)
    assert result.violations == ("candidate_precision_below_minimum",)

    with pytest.raises(ValidationError):
        type(source).model_validate(source.model_dump(mode="python") | {"signal_ids": ()})


def test_suite_observation_and_workflow_baseline_drift_fail_closed():
    _, suite, observations, policy, baseline = _fixtures()
    raw = suite.model_dump(mode="python")
    raw["version"] = "forged"
    with pytest.raises(ValidationError, match="content digest mismatch"):
        LocalSourceSuite.model_validate(raw)

    missing = LocalSourceObservationSet.create(
        suite_id=suite.suite_id, observations=observations.observations[:-1]
    )
    with pytest.raises(LocalSourceBenchmarkRejected, match="exact suite"):
        evaluate_local_source_quality(suite, missing, baseline, policy)

    wrong_policy = policy.model_copy(update={"required_workflow_baseline_id": "f" * 64})
    with pytest.raises(LocalSourceBenchmarkRejected, match="baseline"):
        evaluate_local_source_quality(suite, observations, baseline, wrong_policy)

    with pytest.raises(ValidationError, match="cannot be weakened"):
        LocalSourceQualityPolicy(
            required_workflow_baseline_id=baseline.baseline_id,
            min_candidate_recall=0.99,
        )

    with pytest.raises(ValidationError, match="path is unsafe"):
        LocalSourceFile(path="case//app.py", sha256="a" * 64)


def test_source_digest_symlink_size_timeout_and_cleanup_fail_closed(tmp_path, monkeypatch):
    root, suite, _, _, _ = _fixtures()
    copied = tmp_path / "sources"
    shutil.copytree(root / "sources", copied)
    target = copied / suite.cases[0].files[0].path
    target.write_text(target.read_text() + "# drift\n")
    with pytest.raises(LocalSourceBenchmarkRejected, match="digest mismatch"):
        observe_local_source_suite(suite, copied)

    shutil.rmtree(copied)
    shutil.copytree(root / "sources", copied)
    target = copied / suite.cases[0].files[0].path
    outside = tmp_path / "outside.py"
    outside.write_text(target.read_text())
    target.unlink()
    target.symlink_to(outside)
    with pytest.raises(LocalSourceBenchmarkRejected, match="escapes its root"):
        observe_local_source_suite(suite, copied)

    monkeypatch.setattr("tempfile.tempdir", str(tmp_path))
    with pytest.raises(LocalSourceBenchmarkRejected, match="size limit"):
        observe_local_source_suite(
            suite, root / "sources", limits=LocalSourceBenchmarkLimits(max_source_bytes=1)
        )
    assert not tuple(tmp_path.glob("vulnloom-m9.3-*"))

    ticks = iter((0.0, 31.0))
    monkeypatch.setattr("vulnloom.benchmark.local_source.time.monotonic", lambda: next(ticks))
    with pytest.raises(LocalSourceBenchmarkRejected, match="timed out"):
        observe_local_source_suite(
            suite, root / "sources", limits=LocalSourceBenchmarkLimits(timeout_seconds=30)
        )
    assert not tuple(tmp_path.glob("vulnloom-m9.3-*"))
