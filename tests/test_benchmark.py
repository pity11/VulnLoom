from __future__ import annotations

import json
import sqlite3
import stat
from contextlib import closing
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.benchmark import (
    BenchmarkArtifactStore,
    BenchmarkBaseline,
    BenchmarkCase,
    BenchmarkGateStatus,
    BenchmarkIdempotencyConflict,
    BenchmarkObservation,
    BenchmarkObservationSet,
    BenchmarkPlan,
    BenchmarkRecoveryRequired,
    BenchmarkRegressionPolicy,
    BenchmarkRejected,
    BenchmarkService,
    BenchmarkStore,
    BenchmarkSuite,
    GroundTruthFinding,
    evaluate_metrics,
)
from vulnloom.cli import main
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, CriticVerdict, ValidationResult


def _suite() -> BenchmarkSuite:
    truth = GroundTruthFinding(
        truth_id="1" * 64,
        cwe="CWE-639",
        duplicate_family="2" * 64,
    )
    return BenchmarkSuite.create(
        name="m6.1-local-ground-truth",
        version="1",
        cases=(
            BenchmarkCase(
                case_id="3" * 64,
                target_version="a" * 40,
                ground_truth=(truth,),
            ),
            BenchmarkCase(
                case_id="4" * 64,
                target_version="b" * 40,
                ground_truth=(),
            ),
        ),
    )


def _observation(
    *,
    case_id: str = "3" * 64,
    matched_truth_id: str | None = "1" * 64,
    duplicate_fingerprint: str = "5" * 64,
    finding: bool = True,
    evidence_required: int = 3,
    evidence_present: int = 3,
    elapsed_ms: int = 100,
    cost: int = 200,
    violations: tuple[str, ...] = (),
) -> BenchmarkObservation:
    target_version = "b" * 40 if case_id == "4" * 64 else "a" * 40
    return BenchmarkObservation(
        case_id=case_id,
        target_version=target_version,
        candidate_id=uuid4(),
        candidate_state=CandidateState.PROMOTED if finding else CandidateState.INCONCLUSIVE,
        duplicate_fingerprint=duplicate_fingerprint,
        matched_truth_id=matched_truth_id,
        validation_result=(
            ValidationResult.REPRODUCED if finding else ValidationResult.INCONCLUSIVE
        ),
        critic_verdict=CriticVerdict.ACCEPTED if finding else None,
        finding_id=uuid4() if finding else None,
        evidence_required=evidence_required,
        evidence_present=evidence_present,
        elapsed_ms=elapsed_ms,
        cost_microunits=cost,
        policy_violation_codes=violations,
    )


def _inputs(now, *, observations=None, policy=None, baseline=None, key="benchmark:1"):
    suite = _suite()
    observation_set = BenchmarkObservationSet.create(
        suite_id=suite.suite_id,
        observations=observations or (_observation(),),
    )
    plan = BenchmarkPlan.create(
        suite=suite,
        observations=observation_set,
        policy=policy or BenchmarkRegressionPolicy(),
        baseline=baseline,
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key=key,
    )
    return suite, observation_set, plan


def _service(tmp_path):
    store = BenchmarkStore(tmp_path / "benchmark.db")
    artifacts = BenchmarkArtifactStore(tmp_path / "artifacts")
    return BenchmarkService(store=store, artifact_store=artifacts), store, artifacts


def test_offline_benchmark_passes_and_replays_idempotently(tmp_path, now):
    suite, observations, plan = _inputs(now)
    service, store, artifacts = _service(tmp_path)

    first = service.evaluate(suite, observations, plan, now=now)
    second = service.evaluate(suite, observations, plan, now=now)

    assert first == second
    assert first.result.gate_status is BenchmarkGateStatus.PASSED
    assert first.result.metrics.candidate_recall == 1.0
    assert first.result.metrics.finding_precision == 1.0
    assert first.result.metrics.policy_violation_count == 0
    assert artifacts.read_result(first.artifact) == first.result
    assert "Gate: `passed`" in artifacts.read_markdown(first.artifact)
    object_mode = stat.S_IMODE(
        (artifacts.objects / first.artifact.result_digest).stat().st_mode
    )
    assert object_mode == 0o500
    store.close()


def test_metrics_and_gate_expose_duplicates_incomplete_evidence_and_policy(tmp_path, now):
    observations = (
        _observation(),
        _observation(
            matched_truth_id=None,
            finding=False,
            evidence_required=2,
            evidence_present=1,
            violations=("scope.binding",),
        ),
    )
    policy = BenchmarkRegressionPolicy(max_duplicate_rate=0.25)
    suite, observation_set, plan = _inputs(now, observations=observations, policy=policy)
    service, store, _ = _service(tmp_path)

    outcome = service.evaluate(suite, observation_set, plan, now=now)

    assert outcome.result.gate_status is BenchmarkGateStatus.FAILED
    assert outcome.result.metrics.duplicate_rate == 0.5
    assert outcome.result.metrics.evidence_completeness == 0.8
    assert outcome.result.metrics.policy_violation_count == 1
    assert {item.code for item in outcome.result.violations} == {
        "threshold.duplicate_rate",
        "threshold.evidence_completeness",
        "threshold.policy_violations",
    }
    store.close()


def test_false_positive_finding_reduces_precision():
    suite = _suite()
    observations = BenchmarkObservationSet.create(
        suite_id=suite.suite_id,
        observations=(
            _observation(),
            _observation(case_id="4" * 64, matched_truth_id=None),
        ),
    )
    metrics = evaluate_metrics(suite, observations)
    assert metrics.finding_count == 2
    assert metrics.matched_finding_count == 1
    assert metrics.finding_precision == 0.5


def test_finding_cannot_bypass_validation_critic_or_evidence_gate():
    base = _observation().model_dump(mode="python")
    for update in (
        {"validation_result": ValidationResult.INCONCLUSIVE},
        {"critic_verdict": CriticVerdict.REJECTED},
        {"candidate_state": CandidateState.CRITIC_REVIEWED},
        {"evidence_required": 0, "evidence_present": 0},
        {"evidence_present": 2},
    ):
        with pytest.raises(ValidationError):
            BenchmarkObservation.model_validate({**base, **update})


def test_cross_case_truth_match_is_rejected_before_checkpoint(tmp_path, now):
    suite, observations, plan = _inputs(
        now,
        observations=(
            _observation(case_id="4" * 64, matched_truth_id="1" * 64, finding=False),
        ),
    )
    service, store, _ = _service(tmp_path)
    with pytest.raises(BenchmarkRejected, match="outside its sealed benchmark case"):
        service.evaluate(suite, observations, plan, now=now)
    count = store.connection.execute("SELECT COUNT(*) FROM benchmark_executions").fetchone()[0]
    assert count == 0
    store.close()


def test_target_version_mismatch_is_rejected():
    suite = _suite()
    observation = _observation().model_copy(update={"target_version": "c" * 40})
    observations = BenchmarkObservationSet.create(
        suite_id=suite.suite_id,
        observations=(observation,),
    )
    with pytest.raises(BenchmarkRejected, match="Target version"):
        evaluate_metrics(suite, observations)


def test_expired_plan_is_rejected_without_checkpoint(tmp_path, now):
    suite, observations, plan = _inputs(now)
    service, store, _ = _service(tmp_path)
    with pytest.raises(BenchmarkRejected, match="not active"):
        service.evaluate(suite, observations, plan, now=plan.deadline + timedelta(seconds=1))
    count = store.connection.execute("SELECT COUNT(*) FROM benchmark_executions").fetchone()[0]
    assert count == 0
    store.close()


def test_exact_suite_and_observation_bindings_are_required(tmp_path, now):
    suite, observations, plan = _inputs(now)
    changed = observations.model_copy(
        update={"observations": (_observation(elapsed_ms=101),)}
    )
    service, store, _ = _service(tmp_path)
    with pytest.raises(BenchmarkRejected, match="binding mismatch"):
        service.evaluate(suite, changed, plan, now=now)
    store.close()


def test_baseline_regression_is_reported(tmp_path, now):
    suite, observations, original_plan = _inputs(now)
    metrics = evaluate_metrics(suite, observations)
    baseline = BenchmarkBaseline.create(suite=suite, metrics=metrics)
    assert baseline.suite_digest == original_plan.suite_digest
    slower = BenchmarkObservationSet.create(
        suite_id=suite.suite_id,
        observations=(_observation(elapsed_ms=101, cost=201),),
    )
    plan = BenchmarkPlan.create(
        suite=suite,
        observations=slower,
        policy=BenchmarkRegressionPolicy(),
        baseline=baseline,
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="benchmark:baseline",
    )
    service, store, _ = _service(tmp_path)
    outcome = service.evaluate(suite, slower, plan, now=now)
    assert {item.code for item in outcome.result.violations} == {
        "baseline.runtime",
        "baseline.cost_per_finding",
    }
    store.close()


def test_idempotency_conflict_and_unfinished_recovery(tmp_path, now):
    suite, observations, plan = _inputs(now)
    store = BenchmarkStore(tmp_path / "benchmark.db")
    store.claim(plan, now=now)
    with pytest.raises(BenchmarkRecoveryRequired, match="unfinished STARTED"):
        store.claim(plan, now=now)

    _, changed_observations, changed = _inputs(
        now, observations=(_observation(elapsed_ms=101),), key=plan.idempotency_key
    )
    assert changed_observations.observation_set_id != observations.observation_set_id
    with pytest.raises(BenchmarkIdempotencyConflict, match="different content"):
        store.claim(changed, now=now)
    store.close()


def test_artifact_failure_cleans_temporary_directory(tmp_path, now, monkeypatch):
    suite, observations, plan = _inputs(now)
    service, store, artifacts = _service(tmp_path)
    calls = 0
    original = artifacts._write

    def fail_second_write(path, content):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated artifact failure")
        original(path, content)

    monkeypatch.setattr(artifacts, "_write", fail_second_write)
    with pytest.raises(OSError, match="simulated"):
        service.evaluate(suite, observations, plan, now=now)
    assert not tuple(artifacts.objects.glob("benchmark-*"))
    with pytest.raises(BenchmarkRecoveryRequired):
        service.evaluate(suite, observations, plan, now=now)
    store.close()


def test_symlinked_artifact_is_rejected(tmp_path, now):
    suite, observations, plan = _inputs(now)
    service, store, artifacts = _service(tmp_path)
    outcome = service.evaluate(suite, observations, plan, now=now)
    result_path = artifacts.root / outcome.artifact.json_ref
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(result_path.read_bytes())
    result_path.parent.chmod(0o700)
    result_path.chmod(0o600)
    result_path.unlink()
    result_path.symlink_to(replacement)
    with pytest.raises(ValueError, match="unavailable or unsafe"):
        artifacts.read_result(outcome.artifact)
    store.close()


def test_offline_benchmark_cli_returns_ci_gate_status(tmp_path, now, capsys):
    suite, observations, plan = _inputs(now)
    suite_file = tmp_path / "suite.json"
    observations_file = tmp_path / "observations.json"
    plan_file = tmp_path / "plan.json"
    suite_file.write_text(suite.model_dump_json(), encoding="utf-8")
    observations_file.write_text(observations.model_dump_json(), encoding="utf-8")
    plan_file.write_text(plan.model_dump_json(), encoding="utf-8")

    assert (
        main(
            [
                "benchmark-evaluate-offline",
                "--suite-file",
                str(suite_file),
                "--observations-file",
                str(observations_file),
                "--plan-file",
                str(plan_file),
                "--benchmark-db",
                str(tmp_path / "cli.db"),
                "--result-store",
                str(tmp_path / "results"),
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["gate_status"] == "passed"
    assert "artifact" in output
    with closing(sqlite3.connect(tmp_path / "cli.db")) as connection:
        assert connection.execute(
            "SELECT state FROM benchmark_executions"
        ).fetchone()[0] == "completed"


def test_offline_benchmark_cli_returns_two_when_gate_fails(tmp_path, now, capsys):
    suite, observations, plan = _inputs(
        now,
        observations=(
            _observation(),
            _observation(case_id="4" * 64, matched_truth_id=None),
        ),
    )
    paths = {
        "suite": tmp_path / "suite.json",
        "observations": tmp_path / "observations.json",
        "plan": tmp_path / "plan.json",
    }
    paths["suite"].write_text(suite.model_dump_json(), encoding="utf-8")
    paths["observations"].write_text(observations.model_dump_json(), encoding="utf-8")
    paths["plan"].write_text(plan.model_dump_json(), encoding="utf-8")
    assert (
        main(
            [
                "benchmark-evaluate-offline",
                "--suite-file",
                str(paths["suite"]),
                "--observations-file",
                str(paths["observations"]),
                "--plan-file",
                str(paths["plan"]),
                "--benchmark-db",
                str(tmp_path / "failed.db"),
                "--result-store",
                str(tmp_path / "failed-results"),
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["gate_status"] == "failed"


def test_model_digests_detect_content_drift(now):
    suite, observations, plan = _inputs(now)
    with pytest.raises(ValidationError, match="content digest mismatch"):
        BenchmarkSuite.model_validate(
            {**suite.model_dump(mode="python"), "name": "changed"}
        )
    with pytest.raises(ValidationError, match="content digest mismatch"):
        BenchmarkObservationSet.model_validate(
            {**observations.model_dump(mode="python"), "observations": ()}
        )
    baseline = BenchmarkBaseline.create(
        suite=suite,
        metrics=evaluate_metrics(suite, observations),
    )
    with pytest.raises(ValidationError, match="content digest mismatch"):
        BenchmarkBaseline.model_validate(
            {
                **baseline.model_dump(mode="python"),
                "metrics": {
                    **baseline.metrics.model_dump(mode="python"),
                    "total_elapsed_ms": 999,
                },
            }
        )
    assert canonical_digest(plan.model_dump(mode="python")) != plan.plan_id


def test_store_context_manager_closes_connection(tmp_path):
    with BenchmarkStore(tmp_path / "closed.db") as store:
        connection = store.connection
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


def test_no_network_or_submission_fields_exist_in_protocol():
    schemas = " ".join(
        json.dumps(model.model_json_schema()).lower()
        for model in (
            BenchmarkSuite,
            BenchmarkObservationSet,
            BenchmarkPlan,
        )
    )
    assert "destination_url" not in schemas
    assert "submission" not in schemas
    assert "credential" not in schemas
    assert "network_target" not in schemas
    assert "token" not in schemas
