from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from vulnloom.benchmark import (
    REQUIRED_AGENT_WORKFLOW_STAGES,
    AgentWorkflowCheckpoint,
    AgentWorkflowEffectCounters,
    AgentWorkflowRegressionArtifactStore,
    AgentWorkflowRegressionConflict,
    AgentWorkflowRegressionObservation,
    AgentWorkflowRegressionPlan,
    AgentWorkflowRegressionPolicy,
    AgentWorkflowRegressionRecoveryRequired,
    AgentWorkflowRegressionRejected,
    AgentWorkflowRegressionService,
    AgentWorkflowRegressionStore,
    AgentWorkflowRegressionTimedOut,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    CandidateState,
    CriticVerdict,
    ReportReviewStatus,
    ValidationResult,
)

NOW = datetime(2026, 9, 2, tzinfo=UTC)


def _observation(**updates: object) -> AgentWorkflowRegressionObservation:
    checkpoints = tuple(
        AgentWorkflowCheckpoint(
            stage=stage,
            object_id=canonical_digest(f"id:{stage.value}"),
            object_digest=canonical_digest(f"object:{stage.value}"),
        )
        for stage in REQUIRED_AGENT_WORKFLOW_STAGES
    )
    values: dict[str, object] = {
        "checkpoints": checkpoints,
        "proposed_candidate_state": CandidateState.PROPOSED,
        "critic_candidate_state": CandidateState.CRITIC_REVIEWED,
        "promoted_candidate_state": CandidateState.PROMOTED,
        "validation_result": ValidationResult.REPRODUCED,
        "critic_verdict": CriticVerdict.ACCEPTED,
        "draft_report_status": ReportReviewStatus.DRAFT,
        "reviewed_report_status": ReportReviewStatus.HUMAN_APPROVED,
        "exported_report_status": ReportReviewStatus.EXPORTED,
        "evidence_refs": tuple(sorted(canonical_digest(f"evidence:{i}") for i in range(2))),
        "human_decision_digests": tuple(
            sorted(canonical_digest(f"decision:{i}") for i in range(6))
        ),
        "approval_digests": tuple(
            sorted(canonical_digest(f"approval:{i}") for i in range(3))
        ),
        "validation_effects": AgentWorkflowEffectCounters(
            provider_attempts=3, broker_calls=2, runner_calls=1, target_requests=2
        ),
        "export_effects": AgentWorkflowEffectCounters(
            provider_attempts=3, broker_calls=2, runner_calls=1, target_requests=2
        ),
        "public_network_calls": 0,
        "target_builds": 0,
        "automatic_approvals": 0,
        "submission_calls": 0,
        "exported_artifact_digest": canonical_digest("exported-artifact"),
    }
    values.update(updates)
    return AgentWorkflowRegressionObservation.create(**values)


def _plan(
    observation: AgentWorkflowRegressionObservation, *, key: str = "m9.1:regression"
) -> AgentWorkflowRegressionPlan:
    return AgentWorkflowRegressionPlan.create(
        observation=observation,
        policy=AgentWorkflowRegressionPolicy(),
        created_at=NOW,
        deadline=NOW + timedelta(minutes=1),
        idempotency_key=key,
    )


def test_agent_workflow_regression_passes_and_replays_read_only(tmp_path):
    observation = _observation()
    plan = _plan(observation)
    artifact_store = AgentWorkflowRegressionArtifactStore(tmp_path / "artifacts")
    with AgentWorkflowRegressionStore(tmp_path / "regression.sqlite3") as store:
        service = AgentWorkflowRegressionService(store=store, artifact_store=artifact_store)
        outcome = service.evaluate(plan, observation, now=NOW + timedelta(seconds=1))
        replay = service.evaluate(plan, observation, now=NOW + timedelta(seconds=2))

    assert outcome == replay
    assert outcome.result.gate_status.value == "passed"
    assert not outcome.result.violations
    assert outcome.result.metrics.stage_completeness == 1.0
    assert artifact_store.read_result(outcome.artifact) == outcome.result


def test_agent_workflow_regression_reports_quality_and_safety_failures(tmp_path):
    observation = _observation(
        checkpoints=tuple(
            AgentWorkflowCheckpoint(
                stage=stage,
                object_id=canonical_digest(f"short-id:{stage.value}"),
                object_digest=canonical_digest(f"short-object:{stage.value}"),
            )
            for stage in REQUIRED_AGENT_WORKFLOW_STAGES[:-1]
        ),
        promoted_candidate_state=CandidateState.CRITIC_REVIEWED,
        export_effects=AgentWorkflowEffectCounters(
            provider_attempts=4, broker_calls=3, runner_calls=2, target_requests=3
        ),
        submission_calls=1,
    )
    plan = _plan(observation)
    with AgentWorkflowRegressionStore(tmp_path / "regression.sqlite3") as store:
        outcome = AgentWorkflowRegressionService(
            store=store,
            artifact_store=AgentWorkflowRegressionArtifactStore(tmp_path / "artifacts"),
        ).evaluate(plan, observation, now=NOW + timedelta(seconds=1))

    codes = {item.code for item in outcome.result.violations}
    assert outcome.result.gate_status.value == "failed"
    assert {
        "workflow.stage_order",
        "workflow.checkpoint_count",
        "workflow.promoted_candidate",
        "effects.provider_delta",
        "effects.broker_delta",
        "effects.runner_delta",
        "effects.target_delta",
        "effects.submission",
    } <= codes


def test_agent_workflow_regression_rejects_drift_timeout_and_started_recovery(tmp_path):
    observation = _observation()
    plan = _plan(observation)
    with AgentWorkflowRegressionStore(tmp_path / "regression.sqlite3") as store:
        service = AgentWorkflowRegressionService(
            store=store,
            artifact_store=AgentWorkflowRegressionArtifactStore(tmp_path / "artifacts"),
        )
        drifted = _observation(exported_artifact_digest=canonical_digest("different"))
        with pytest.raises(AgentWorkflowRegressionRejected, match="drifted"):
            service.evaluate(plan, drifted, now=NOW + timedelta(seconds=1))
        with pytest.raises(AgentWorkflowRegressionTimedOut):
            service.evaluate(plan, observation, now=NOW + timedelta(minutes=1))
        assert store.claim(plan, now=NOW + timedelta(seconds=2)).created
        with pytest.raises(AgentWorkflowRegressionRecoveryRequired):
            service.evaluate(plan, observation, now=NOW + timedelta(seconds=3))


def test_agent_workflow_regression_rejects_conflicting_consumption(tmp_path):
    observation = _observation()
    conflicting_observation = _observation(target_builds=1)
    plan = _plan(observation)
    conflicting_plan = _plan(conflicting_observation)
    with AgentWorkflowRegressionStore(tmp_path / "regression.sqlite3") as store:
        service = AgentWorkflowRegressionService(
            store=store,
            artifact_store=AgentWorkflowRegressionArtifactStore(tmp_path / "artifacts"),
        )
        service.evaluate(plan, observation, now=NOW + timedelta(seconds=1))
        with pytest.raises(AgentWorkflowRegressionConflict):
            service.evaluate(
                conflicting_plan,
                conflicting_observation,
                now=NOW + timedelta(seconds=2),
            )


def test_agent_workflow_regression_artifact_failure_cleans_temporary_state(
    tmp_path, monkeypatch
):
    observation = _observation()
    plan = _plan(observation)
    artifact_store = AgentWorkflowRegressionArtifactStore(tmp_path / "artifacts")
    writes = 0
    original_write = artifact_store._write

    def fail_second_write(path, content):
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("injected artifact failure")
        original_write(path, content)

    monkeypatch.setattr(artifact_store, "_write", fail_second_write)
    with AgentWorkflowRegressionStore(tmp_path / "regression.sqlite3") as store:
        service = AgentWorkflowRegressionService(store=store, artifact_store=artifact_store)
        with pytest.raises(OSError, match="injected"):
            service.evaluate(plan, observation, now=NOW + timedelta(seconds=1))
        assert not tuple(artifact_store.objects.iterdir())
        with pytest.raises(AgentWorkflowRegressionRecoveryRequired):
            service.evaluate(plan, observation, now=NOW + timedelta(seconds=2))


def test_agent_workflow_regression_artifact_rejects_symlink(tmp_path):
    observation = _observation()
    plan = _plan(observation)
    artifact_store = AgentWorkflowRegressionArtifactStore(tmp_path / "artifacts")
    with AgentWorkflowRegressionStore(tmp_path / "regression.sqlite3") as store:
        outcome = AgentWorkflowRegressionService(
            store=store, artifact_store=artifact_store
        ).evaluate(plan, observation, now=NOW + timedelta(seconds=1))
    result_path = artifact_store.root / outcome.artifact.json_ref
    original = result_path.read_bytes()
    result_path.parent.chmod(0o700)
    result_path.unlink()
    target = tmp_path / "replacement.json"
    target.write_bytes(original)
    result_path.symlink_to(target)
    with pytest.raises(ValueError, match="unsafe"):
        artifact_store.read_result(outcome.artifact)


def test_agent_workflow_regression_contracts_exclude_operational_parameters():
    forbidden = {
        "prose",
        "prompt",
        "url",
        "path",
        "credential",
        "token",
        "runner",
        "broker",
        "submission",
    }
    for model in (AgentWorkflowRegressionObservation, AgentWorkflowRegressionPlan):
        assert not set(model.model_fields) & forbidden
    with pytest.raises(ValueError, match="cannot be weakened"):
        AgentWorkflowRegressionPolicy(max_submission_calls=1)
    with pytest.raises(ValueError, match="human gates"):
        AgentWorkflowRegressionPolicy(required_approvals=2)
