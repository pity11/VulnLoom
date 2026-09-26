from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    CandidateState,
    ScopeState,
    ValidationResult,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.policy import PolicyEngine
from vulnloom.red_team.campaign_candidate_execution_models import (
    CampaignCandidateFreshEvidenceFact,
    CampaignCandidateValidationCompletionCheckpoint,
    CampaignCandidateValidationExecutionLimits,
    CampaignCandidateValidationExecutionOutcome,
    CampaignCandidateValidationExecutionPlan,
    CampaignCandidateValidationExecutionRole,
    CampaignCandidateValidationExecutionState,
    CampaignCandidateValidationWorkerOutput,
)
from vulnloom.red_team.campaign_candidate_execution_service import (
    CampaignCandidateValidationExecutionRejected,
    CampaignCandidateValidationExecutionService,
    CampaignCandidateValidationExecutionTimedOut,
)
from vulnloom.red_team.campaign_candidate_execution_store import (
    CampaignCandidateValidationExecutionRecoveryRequired,
    CampaignCandidateValidationExecutionStore,
)
from vulnloom.red_team.campaign_candidate_state_machine import (
    CampaignCandidateTransitionRejected,
    complete_campaign_candidate_validation,
    start_campaign_candidate_validation,
)
from vulnloom.red_team.campaign_candidate_validation_models import (
    REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS,
    CampaignCandidateLifecycleCheckpoint,
    CampaignCandidateValidationIntakeLimits,
    CampaignCandidateValidationIntakeOutcome,
    CampaignCandidateValidationIntakePlan,
)
from vulnloom.red_team.evidence_requirement_models import (
    EvidenceFactKind,
    VulnerabilityClass,
)
from vulnloom.runners import (
    CleanupReport,
    DockerCliBackend,
    DockerEnginePolicy,
    DockerSandboxRunner,
    DockerTool,
    RegisteredObjectStore,
    RunnerOutputStore,
    SandboxOutput,
    SandboxRunRequest,
    SandboxRunResult,
    SandboxRunStatus,
    ToolInvocation,
    validation_profile,
)
from vulnloom.runners.models import SandboxUsage, sandbox_profile_digest


def _digest(number: int) -> str:
    return f"{number:064x}"


class _Source:
    def __init__(self, plan, outcome):
        self._plan = plan
        self._outcome = outcome

    def plan(self, plan_id):
        if plan_id != self._plan.validation_intake_plan_id:
            raise KeyError(plan_id)
        return self._plan

    def outcome(self, plan_id):
        self.plan(plan_id)
        return self._outcome

    def checkpoint(self, candidate_id):
        if candidate_id != self._plan.candidate_id:
            raise KeyError(candidate_id)
        return self._outcome.checkpoint


class _Runner:
    def __init__(self, results):
        self.results = results
        self.calls = []

    def execute(self, request, *, now, cancellation=None):
        self.calls.append(request.run_id)
        return self.results[request.run_id]


class _Outputs:
    def __init__(self, content):
        self.content = content

    def read(self, output):
        return self.content[output.object_id]

    def read_snapshot(self, object_id):
        return self.content[object_id]


def _intake(scope, now):
    candidate_id = uuid4()
    candidate_digest = _digest(10)
    context = canonical_digest(
        {
            "candidate_id": candidate_id,
            "candidate_digest": candidate_digest,
            "scope_id": scope.scope_id,
            "scope_version": scope.version,
            "required_fresh_facts": REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS,
            "contract": "campaign-candidate-fresh-validation-v1",
        }
    )
    plan = CampaignCandidateValidationIntakePlan.create(
        candidate_intake_plan_id=_digest(11),
        candidate_intake_plan_digest=_digest(12),
        candidate_intake_outcome_id=_digest(13),
        candidate_intake_outcome_digest=_digest(14),
        candidate_id=candidate_id,
        candidate_digest=candidate_digest,
        target_id=uuid4(),
        target_version=_digest(15),
        scope_id=scope.scope_id,
        scope_version=scope.version,
        vulnerability_class=VulnerabilityClass.UNAUTHENTICATED_SENSITIVE_DATA_EXPOSURE,
        cwe="CWE-200",
        prior_campaign_evidence_refs=tuple(_digest(index) for index in range(20, 25)),
        validation_context_digest=context,
        limits=CampaignCandidateValidationIntakeLimits(),
        created_at=now - timedelta(minutes=1),
        deadline=now + timedelta(minutes=10),
        idempotency_key="b5.8:intake",
    )
    checkpoint = CampaignCandidateLifecycleCheckpoint.create(
        validation_intake_plan_id=plan.validation_intake_plan_id,
        candidate_id=candidate_id,
        candidate_digest=candidate_digest,
        approval_id=uuid4(),
        approval_digest=plan.validation_intake_plan_id,
        validation_context_digest=context,
        prior_campaign_evidence_refs=plan.prior_campaign_evidence_refs,
        required_fresh_facts=plan.required_fresh_facts,
        recorded_at=now - timedelta(seconds=30),
    )
    outcome = CampaignCandidateValidationIntakeOutcome.create(
        validation_intake_plan_id=plan.validation_intake_plan_id,
        checkpoint=checkpoint,
        attempt=1,
        completed_at=now - timedelta(seconds=30),
    )
    return plan, outcome


def _request(scope, intake, now, role, snapshot, *, image="sha256:" + "a" * 64):
    profile = validation_profile(
        image_digest=image,
        snapshot_id=snapshot,
    ).model_copy(update={"allowed_tools": frozenset({"sandbox.test"})})
    task = TaskEnvelope(
        engagement_id=scope.engagement_id,
        target_id=intake.target_id,
        target_version=intake.target_version,
        scope_id=scope.scope_id,
        worker_role=WorkerRole.VALIDATOR,
        scope_version=scope.version,
        policy_digest=PolicyEngine(scope).policy_digest,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest=_digest(30),
        input_refs=(
            f"candidate-validation:{intake.validation_context_digest}",
            f"snapshot:{snapshot}",
        ),
        allowed_tools=frozenset({"sandbox.test"}),
        budget=TaskBudget(wall_seconds=10, model_tokens=0, tool_calls=1),
        deadline=now + timedelta(minutes=5),
        idempotency_key=f"task:b5.8:{role.value}",
    )
    return SandboxRunRequest(
        task=task,
        profile=profile,
        invocation=ToolInvocation(
            tool_id="sandbox.test",
            arguments=(role.value, str(intake.candidate_id), intake.validation_context_digest),
            working_directory="source",
        ),
        environment={
            "VULNLOOM_TASK_ID": str(task.task_id),
            "VULNLOOM_VALIDATION_ROLE": role.value,
        },
        idempotency_key=f"run:b5.8:{role.value}",
    )


def _worker_output(intake, role, *, fingerprint=None):
    facts = (
        (
            EvidenceFactKind.SEALED_GET_SUCCEEDED,
            EvidenceFactKind.UNAUTHENTICATED_REQUEST_PROVEN,
            EvidenceFactKind.SENSITIVE_DATA_CLASS_PRESENT,
            EvidenceFactKind.REDACTION_BOUNDARY_PROVEN,
        )
        if role is CampaignCandidateValidationExecutionRole.PRIMARY
        else (
            EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED,
            EvidenceFactKind.REDACTION_BOUNDARY_PROVEN,
        )
    )
    return (
        CampaignCandidateValidationWorkerOutput(
            candidate_id=intake.candidate_id,
            validation_context_digest=intake.validation_context_digest,
            role=role,
            response_fingerprint=fingerprint or _digest(40),
            facts=facts,
        )
        .model_dump_json()
        .encode()
    )


def _result(request, content, *, status=SandboxRunStatus.COMPLETED):
    digest = hashlib.sha256(content).hexdigest()
    outputs = (
        (
            SandboxOutput(
                object_id=digest,
                logical_name="output.json",
                size=len(content),
                sha256=digest,
                content_ref=f"objects/{digest}/output.json",
            ),
        )
        if status is SandboxRunStatus.COMPLETED
        else ()
    )
    return SandboxRunResult(
        run_id=request.run_id,
        task_id=request.task.task_id,
        status=status,
        sandbox_profile_digest=sandbox_profile_digest(request.profile),
        invocation_digest=canonical_digest(request.invocation.model_dump(mode="python")),
        budget_used=TaskBudget(wall_seconds=1, model_tokens=0, tool_calls=1),
        usage=SandboxUsage(
            wall_seconds=0.01,
            cpu_millis=1,
            peak_memory_bytes=1024,
            pids_peak=1,
            open_files_peak=3,
            output_bytes=len(content) if outputs else 0,
            temporary_bytes=0,
        ),
        outputs=outputs,
        error_codes=("wall_time_budget_exceeded",) if not outputs else (),
        cleanup=CleanupReport(
            processes_terminated=True,
            network_released=True,
            writable_layer_removed=True,
            temporary_mounts_removed=True,
        ),
    )


def _bundle(scope, now, *, primary_content=None, replay_content=None, monotonic=None):
    intake, intake_outcome = _intake(scope, now)
    primary_snapshot = _digest(50)
    replay_snapshot = _digest(51)
    primary = _request(
        scope,
        intake,
        now,
        CampaignCandidateValidationExecutionRole.PRIMARY,
        primary_snapshot,
    )
    replay = _request(
        scope,
        intake,
        now,
        CampaignCandidateValidationExecutionRole.REPLAY,
        replay_snapshot,
    )
    primary_content = primary_content or _worker_output(
        intake, CampaignCandidateValidationExecutionRole.PRIMARY
    )
    replay_content = replay_content or _worker_output(
        intake, CampaignCandidateValidationExecutionRole.REPLAY
    )
    primary_result = _result(primary, primary_content)
    replay_result = _result(replay, replay_content)
    contents = {
        primary_result.outputs[0].object_id: primary_content,
        replay_result.outputs[0].object_id: replay_content,
        primary_snapshot: primary_content,
        replay_snapshot: replay_content,
    }
    runner = _Runner({primary.run_id: primary_result, replay.run_id: replay_result})
    connection = sqlite3.connect(":memory:")
    store = CampaignCandidateValidationExecutionStore(connection)
    service = CampaignCandidateValidationExecutionService(
        intake_source=_Source(intake, intake_outcome),
        runner=runner,
        output_reader=_Outputs(contents),
        store=store,
        **({"monotonic": monotonic} if monotonic is not None else {}),
    )
    plan = service.prepare(
        validation_intake_plan_id=intake.validation_intake_plan_id,
        primary_request=primary,
        replay_request=replay,
        scope=scope,
        limits=CampaignCandidateValidationExecutionLimits(),
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="b5.8:execution",
    )
    return service, store, connection, plan, runner, intake, intake_outcome


def _approval(plan, scope, now, *, action=ApprovalAction.RUN_VALIDATION):
    return ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=plan.target_id,
        action=action,
        action_digest=plan.execution_plan_id,
        expected_side_effects=("run isolated campaign candidate validation",),
        evidence_summary="reviewed exact isolated Campaign Candidate validation",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=5),
        status=ApprovalStatus.GRANTED,
        decided_by="operator",
        decided_at=now,
    )


def test_exact_run_approval_binds_two_fresh_runs_and_advances_to_validated(approved_scope, now):
    service, store, connection, plan, runner, intake, intake_outcome = _bundle(approved_scope, now)
    outcome = service.execute(
        plan,
        approval=_approval(plan, approved_scope, now),
        scope=approved_scope,
        now=now,
    )
    assert intake_outcome.checkpoint.state is CandidateState.VALIDATION_PENDING
    assert outcome.checkpoint.previous_state is CandidateState.VALIDATION_PENDING
    assert outcome.checkpoint.state is CandidateState.VALIDATED
    assert outcome.validation_run.result.value == "reproduced"
    assert {item.fact for item in outcome.fresh_facts} == set(
        REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS
    )
    assert not set(outcome.evidence_bundle.evidence_refs) & set(intake.prior_campaign_evidence_refs)
    assert outcome.critic_required is True
    assert outcome.critic_completed is False
    assert outcome.finding_created is False
    assert runner.calls == [plan.primary_request.run_id, plan.replay_request.run_id]
    assert store.checkpoint(plan.candidate_id) == outcome.checkpoint
    assert store.state(plan.execution_plan_id) == (
        CampaignCandidateValidationExecutionState.COMPLETED,
        1,
    )
    assert (
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
        == outcome
    )
    assert len(runner.calls) == 2
    connection.close()


@pytest.mark.docker_integration
@pytest.mark.rootless_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_DOCKER_INTEGRATION") != "1"
    and os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") != "1",
    reason="set VULNLOOM_DOCKER_INTEGRATION=1 for the actual B5.8 canary",
)
def test_actual_docker_runs_produce_fresh_candidate_bound_evidence_and_cleanup(
    tmp_path: Path, approved_scope
):
    backend = DockerCliBackend()
    image = backend.inspect_image(os.environ.get("VULNLOOM_B5_8_IMAGE", "alpine:3.22"))["Id"]
    now = datetime.now(UTC)
    intake, intake_outcome = _intake(approved_scope, now)
    snapshots = (_digest(150), _digest(151))
    registered = {}
    sealed_inputs = (
        _worker_output(intake, CampaignCandidateValidationExecutionRole.PRIMARY),
        _worker_output(intake, CampaignCandidateValidationExecutionRole.REPLAY),
    )
    for snapshot, sealed_input in zip(snapshots, sealed_inputs, strict=True):
        directory = tmp_path / "objects" / snapshot
        directory.mkdir(parents=True)
        fixture = directory / "sealed-summary.json"
        fixture.write_bytes(sealed_input)
        fixture.chmod(0o444)
        directory.chmod(0o555)
        registered[snapshot] = directory
    primary = _request(
        approved_scope,
        intake,
        now,
        CampaignCandidateValidationExecutionRole.PRIMARY,
        snapshots[0],
        image=image,
    )
    replay = _request(
        approved_scope,
        intake,
        now,
        CampaignCandidateValidationExecutionRole.REPLAY,
        snapshots[1],
        image=image,
    )
    probe = r"""
set -eu
test -r /workspace/source/sealed-summary.json
[ "$(id -u)" = 65532 ]
grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status
grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status
grep -q '^Seccomp:[[:space:]]*2$' /proc/self/status
! touch /workspace/source/must-remain-read-only
[ "$(wc -l < /proc/net/route)" = 1 ]
[ ! -S /var/run/docker.sock ]
[ ! -e /run/host-services/docker.proxy.sock ]
cat /workspace/source/sealed-summary.json
""".strip()
    output_store = RunnerOutputStore(tmp_path / "runner-output")

    class SealedInputReader:
        def read(self, output):
            return output_store.read(output)

        def read_snapshot(self, object_id):
            return (registered[object_id] / "sealed-summary.json").read_bytes()

    docker_runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", registered),
        (
            DockerTool(
                tool_id="sandbox.test",
                argv_prefix=("/bin/sh", "-c", probe, "vulnloom-b5.8-validation"),
            ),
        ),
        engine_policy=(
            DockerEnginePolicy()
            if os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") == "1"
            else DockerEnginePolicy(
                require_rootless=False,
                require_versioned_seccomp=False,
            )
        ),
        output_store=output_store,
        captured_output_tools=frozenset({"sandbox.test"}),
    )

    class RecordingRunner:
        def __init__(self):
            self.inspections = []
            self.container_absence = []

        def execute(self, request, *, now, cancellation=None):
            result = docker_runner.execute(request, now=now, cancellation=cancellation)
            assert docker_runner.last_inspection is not None
            self.inspections.append(docker_runner.last_inspection)
            self.container_absence.append(not backend.exists(docker_runner.last_inspection["Id"]))
            return result

    runner = RecordingRunner()
    connection = sqlite3.connect(":memory:")
    store = CampaignCandidateValidationExecutionStore(connection)
    service = CampaignCandidateValidationExecutionService(
        intake_source=_Source(intake, intake_outcome),
        runner=runner,
        output_reader=SealedInputReader(),
        store=store,
    )
    plan = service.prepare(
        validation_intake_plan_id=intake.validation_intake_plan_id,
        primary_request=primary,
        replay_request=replay,
        scope=approved_scope,
        limits=CampaignCandidateValidationExecutionLimits(timeout_seconds=60),
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="b5.8:docker-execution",
    )
    outcome = service.execute(
        plan,
        approval=_approval(plan, approved_scope, now),
        scope=approved_scope,
        now=now,
    )
    assert outcome.checkpoint.state is CandidateState.VALIDATED
    assert len(set(outcome.evidence_bundle.evidence_refs)) == 2
    assert runner.container_absence == [True, True]
    assert all(
        item["HostConfig"]["NetworkMode"] == "none"
        and item["HostConfig"]["ReadonlyRootfs"] is True
        and item["Config"]["User"] == "65532:65532"
        and not item["HostConfig"].get("Binds")
        for item in runner.inspections
    )
    connection.close()


def test_queue_approval_scope_drift_and_request_drift_fail_before_execution(approved_scope, now):
    service, store, connection, plan, runner, _, _ = _bundle(approved_scope, now)
    with pytest.raises(CampaignCandidateValidationExecutionRejected, match="Approval"):
        service.execute(
            plan,
            approval=_approval(
                plan,
                approved_scope,
                now,
                action=ApprovalAction.QUEUE_CAMPAIGN_CANDIDATE_VALIDATION,
            ),
            scope=approved_scope,
            now=now,
        )
    with pytest.raises(CampaignCandidateValidationExecutionRejected, match="source binding"):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope.model_copy(update={"state": ScopeState.REVOKED}),
            now=now,
        )
    values = plan.model_dump(mode="python", exclude={"execution_plan_id"})
    request = plan.primary_request.model_copy(
        update={"environment": {"VULNLOOM_TASK_ID": str(plan.primary_request.task.task_id)}}
    )
    values.update(
        primary_request=request,
        replay_request=plan.replay_request,
        limits=plan.limits,
        primary_request_digest=canonical_digest(
            request.model_dump(mode="python", exclude={"run_id"})
        ),
    )
    drifted = CampaignCandidateValidationExecutionPlan.create(**values)
    with pytest.raises(CampaignCandidateValidationExecutionRejected, match="request boundary"):
        service.execute(
            drifted,
            approval=_approval(drifted, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    assert runner.calls == []
    assert store.state(plan.execution_plan_id) is None
    connection.close()


def test_mismatched_sealed_replay_is_rejected_without_execution_or_completion(approved_scope, now):
    service, store, connection, plan, runner, intake, _ = _bundle(approved_scope, now)
    mismatched = _worker_output(
        intake,
        CampaignCandidateValidationExecutionRole.REPLAY,
        fingerprint=_digest(99),
    )
    replay_result = _result(plan.replay_request, mismatched)
    runner.results[plan.replay_request.run_id] = replay_result
    service.output_reader.content[replay_result.outputs[0].object_id] = mismatched
    replay_snapshot = next(
        item.object_id for item in plan.replay_request.profile.mounts if item.object_id is not None
    )
    service.output_reader.content[replay_snapshot] = mismatched
    with pytest.raises(CampaignCandidateValidationExecutionRejected, match="sealed inputs"):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    with pytest.raises(KeyError):
        store.checkpoint(plan.candidate_id)
    assert runner.calls == []
    assert store.state(plan.execution_plan_id) is None
    connection.close()


def test_worker_output_cannot_override_trusted_sealed_input(approved_scope, now):
    service, store, connection, plan, runner, intake, _ = _bundle(approved_scope, now)
    forged = _worker_output(
        intake,
        CampaignCandidateValidationExecutionRole.REPLAY,
        fingerprint=_digest(99),
    )
    replay_result = _result(plan.replay_request, forged)
    runner.results[plan.replay_request.run_id] = replay_result
    service.output_reader.content[replay_result.outputs[0].object_id] = forged
    with pytest.raises(CampaignCandidateValidationExecutionRejected, match="disagrees"):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    assert len(runner.calls) == 2
    assert store.state(plan.execution_plan_id) == (
        CampaignCandidateValidationExecutionState.STARTED,
        1,
    )
    with pytest.raises(KeyError):
        store.checkpoint(plan.candidate_id)
    connection.close()


def test_prior_campaign_evidence_cannot_be_mounted_as_fresh_input(approved_scope, now):
    service, _, connection, _, _, intake, _ = _bundle(approved_scope, now)
    primary = _request(
        approved_scope,
        intake,
        now,
        CampaignCandidateValidationExecutionRole.PRIMARY,
        intake.prior_campaign_evidence_refs[0],
    )
    replay = _request(
        approved_scope,
        intake,
        now,
        CampaignCandidateValidationExecutionRole.REPLAY,
        _digest(199),
    )
    with pytest.raises(CampaignCandidateValidationExecutionRejected, match="fresh independent"):
        service.prepare(
            validation_intake_plan_id=intake.validation_intake_plan_id,
            primary_request=primary,
            replay_request=replay,
            scope=approved_scope,
            limits=CampaignCandidateValidationExecutionLimits(),
            now=now,
            deadline=now + timedelta(minutes=5),
            idempotency_key="b5.8:prior-evidence-rejected",
        )
    connection.close()


def test_runner_timeout_is_clean_and_publishes_no_completion_checkpoint(approved_scope, now):
    service, store, connection, plan, runner, _, _ = _bundle(approved_scope, now)
    runner.results[plan.replay_request.run_id] = _result(
        plan.replay_request,
        b"unused",
        status=SandboxRunStatus.TIMED_OUT,
    )
    with pytest.raises(CampaignCandidateValidationExecutionTimedOut, match="replay"):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    assert runner.results[plan.replay_request.run_id].cleanup.complete
    with pytest.raises(KeyError):
        store.checkpoint(plan.candidate_id)
    connection.close()


def test_interrupted_execution_recovers_once_without_duplicate_validation(approved_scope, now):
    service, store, connection, plan, runner, _, _ = _bundle(approved_scope, now)

    def interrupt():
        raise RuntimeError("fixture interruption")

    service.after_claim = interrupt
    with pytest.raises(RuntimeError, match="fixture interruption"):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    service.after_claim = None
    outcome = service.execute(
        plan,
        approval=_approval(plan, approved_scope, now),
        scope=approved_scope,
        now=now,
    )
    assert outcome.attempt == 2
    assert len(runner.calls) == 2
    connection.close()


def test_timeout_budget_recovery_limit_state_machine_and_schema_fail_closed(approved_scope, now):
    ticks = iter((0.0, 31.0))
    service, store, connection, plan, _, _, _ = _bundle(
        approved_scope, now, monotonic=lambda: next(ticks)
    )
    with pytest.raises(CampaignCandidateValidationExecutionTimedOut):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    assert store.state(plan.execution_plan_id) is None

    service.monotonic = lambda: 0.0

    def interrupt():
        raise RuntimeError("fixture interruption")

    service.after_claim = interrupt
    for _ in range(3):
        with pytest.raises(RuntimeError, match="fixture interruption"):
            service.execute(
                plan,
                approval=_approval(plan, approved_scope, now),
                scope=approved_scope,
                now=now,
            )
    with pytest.raises(CampaignCandidateValidationExecutionRecoveryRequired, match="exhausted"):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    with pytest.raises(CampaignCandidateTransitionRejected):
        start_campaign_candidate_validation(CandidateState.PROPOSED)
    with pytest.raises(CampaignCandidateTransitionRejected):
        complete_campaign_candidate_validation(
            CandidateState.VALIDATION_PENDING,
            ValidationResult.REPRODUCED,
        )

    schemas = json.dumps(
        {
            model.__name__: model.model_json_schema()
            for model in (
                CampaignCandidateValidationExecutionPlan,
                CampaignCandidateValidationWorkerOutput,
                CampaignCandidateFreshEvidenceFact,
                CampaignCandidateValidationCompletionCheckpoint,
                CampaignCandidateValidationExecutionOutcome,
            )
        }
    ).lower()
    for forbidden in (
        "target_url",
        "cookie",
        "password",
        "docker_socket",
        "raw_response",
        "payload",
    ):
        assert forbidden not in schemas
    with pytest.raises(ValidationError):
        CampaignCandidateValidationExecutionPlan.model_validate(
            plan.model_dump(mode="python")
            | {
                "network_execution_requested": True,
                "credential_access_requested": True,
                "critic_bypass_requested": True,
                "finding_creation_requested": True,
            }
        )
    connection.close()
