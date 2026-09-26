from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_red_team_campaign_candidate_critic_intake import _approval as intake_approval
from test_red_team_campaign_candidate_critic_intake import _case as intake_case
from test_red_team_campaign_candidate_validation_execution import _digest, _result, _Runner

from vulnloom.critic import CounterevidenceAssessment, CounterevidenceDisposition
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    CandidateState,
    CriticVerdict,
    ScopeState,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.policy import PolicyEngine
from vulnloom.red_team import (
    REQUIRED_CAMPAIGN_CRITIC_ANGLES,
    CampaignCandidateCriticExecutionLimits,
    CampaignCandidateCriticExecutionRecoveryRequired,
    CampaignCandidateCriticExecutionRejected,
    CampaignCandidateCriticExecutionService,
    CampaignCandidateCriticExecutionState,
    CampaignCandidateCriticExecutionStore,
    CampaignCandidateCriticExecutionTimedOut,
    CampaignCandidateCriticWorkerOutput,
)
from vulnloom.runners import (
    CleanupReport,
    DockerCliBackend,
    DockerEnginePolicy,
    DockerSandboxRunner,
    DockerTool,
    RegisteredObjectStore,
    RunnerOutputStore,
    SandboxRunRequest,
    ToolInvocation,
    report_profile,
)
from vulnloom.runners.models import run_request_digest, sandbox_profile_digest


class _Content:
    def __init__(self, values):
        self.values = values

    def read(self, output):
        return self.values[output.object_id]

    def read_evidence(self, object_id):
        return self.values[object_id]


def _worker(plan, evidence_id, disposition=CounterevidenceDisposition.RULED_OUT):
    return (
        CampaignCandidateCriticWorkerOutput(
            candidate_id=plan.candidate_id,
            review_context_digest=plan.review_context_digest,
            review_producer_digest=plan.review_producer_digest,
            assessments=tuple(
                CounterevidenceAssessment(
                    angle=angle,
                    disposition=disposition,
                    evidence_refs=(evidence_id,),
                    rationale_code=f"fixture_{angle.value}",
                )
                for angle in REQUIRED_CAMPAIGN_CRITIC_ANGLES
            ),
        )
        .model_dump_json()
        .encode()
    )


def _request(scope, intake, now, evidence_id):
    profile = report_profile(
        image_digest="sha256:" + "a" * 64, evidence_object_id=evidence_id
    ).model_copy(update={"allowed_tools": frozenset({"critic.review"})})
    task = TaskEnvelope(
        engagement_id=scope.engagement_id,
        target_id=intake.target_id,
        target_version=intake.target_version,
        scope_id=scope.scope_id,
        worker_role=WorkerRole.CRITIC,
        scope_version=scope.version,
        policy_digest=PolicyEngine(scope).policy_digest,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest=_digest(401),
        input_refs=(
            f"candidate-critic:{intake.review_context_digest}",
            f"counterevidence:{evidence_id}",
        ),
        allowed_tools=frozenset({"critic.review"}),
        budget=TaskBudget(wall_seconds=10, model_tokens=0, tool_calls=1),
        deadline=now + timedelta(minutes=5),
        idempotency_key="task:b5.10",
    )
    return SandboxRunRequest(
        task=task,
        profile=profile,
        invocation=ToolInvocation(
            tool_id="critic.review",
            arguments=(
                str(intake.candidate_id),
                intake.review_context_digest,
                intake.review_producer_digest,
            ),
            working_directory="output",
        ),
        environment={
            "VULNLOOM_TASK_ID": str(task.task_id),
            "VULNLOOM_CRITIC_ROLE": "independent_review",
        },
        idempotency_key="run:b5.10",
    )


def _bundle(scope, now, *, disposition=CounterevidenceDisposition.RULED_OUT, monotonic=None):
    intake_service, intake_store, intake_connection, intake_plan, _, validation_connection = (
        intake_case(scope, now)
    )
    intake_service.execute(
        intake_plan, approval=intake_approval(intake_plan, scope, now), scope=scope, now=now
    )
    evidence_id = _digest(402)
    content = _worker(intake_plan, evidence_id, disposition)
    request = _request(scope, intake_plan, now, evidence_id)
    result = _result(request, content)
    reader = _Content({evidence_id: content, result.outputs[0].object_id: content})
    runner = _Runner({request.run_id: result})
    connection = sqlite3.connect(":memory:")
    store = CampaignCandidateCriticExecutionStore(connection)
    service = CampaignCandidateCriticExecutionService(
        intake_source=intake_store,
        validation_source=intake_service.validation_source,
        runner=runner,
        output_reader=reader,
        store=store,
        **({"monotonic": monotonic} if monotonic is not None else {}),
    )
    plan = service.prepare(
        critic_intake_plan_id=intake_plan.critic_intake_plan_id,
        request=request,
        scope=scope,
        limits=CampaignCandidateCriticExecutionLimits(),
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="b5.10:execution",
    )
    return service, store, plan, runner, connection, intake_connection, validation_connection


def _approval(plan, scope, now, action=ApprovalAction.RUN_CRITIC):
    return ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=plan.target_id,
        action=action,
        action_digest=plan.execution_plan_id,
        expected_side_effects=("run isolated campaign candidate critic",),
        evidence_summary="exact isolated critic review",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=5),
        status=ApprovalStatus.GRANTED,
        decided_by="operator",
        decided_at=now,
    )


@pytest.mark.parametrize(
    "disposition,verdict,state",
    [
        (
            CounterevidenceDisposition.RULED_OUT,
            CriticVerdict.ACCEPTED,
            CandidateState.CRITIC_REVIEWED,
        ),
        (CounterevidenceDisposition.CONFIRMED, CriticVerdict.REJECTED, CandidateState.REJECTED),
        (
            CounterevidenceDisposition.INCONCLUSIVE,
            CriticVerdict.INCONCLUSIVE,
            CandidateState.VALIDATED,
        ),
    ],
)
def test_exact_run_critic_approval_materializes_typed_review_without_finding(
    approved_scope, now, disposition, verdict, state
):
    service, store, plan, runner, *connections = _bundle(
        approved_scope, now, disposition=disposition
    )
    outcome = service.execute(
        plan, approval=_approval(plan, approved_scope, now), scope=approved_scope, now=now
    )
    assert outcome.review.verdict is verdict
    assert outcome.checkpoint.candidate_state is state
    assert {fact.angle for fact in outcome.counterevidence_facts} == set(
        REQUIRED_CAMPAIGN_CRITIC_ANGLES
    )
    assert not set(outcome.counterevidence_refs) & set(plan.validation_evidence_refs)
    assert outcome.finding_created is False and outcome.finding_promotion_required is True
    assert store.state(plan.execution_plan_id) == (
        CampaignCandidateCriticExecutionState.COMPLETED,
        1,
    )
    assert (
        service.execute(
            plan, approval=_approval(plan, approved_scope, now), scope=approved_scope, now=now
        )
        == outcome
    )
    assert len(runner.calls) == 1
    for connection in (service.store.connection, *connections):
        connection.close()


def test_wrong_approval_scope_drift_and_timeout_publish_nothing(approved_scope, now):
    service, store, plan, _, *connections = _bundle(approved_scope, now)
    with pytest.raises(CampaignCandidateCriticExecutionRejected, match="Approval"):
        service.execute(
            plan,
            approval=_approval(
                plan, approved_scope, now, ApprovalAction.QUEUE_CAMPAIGN_CANDIDATE_CRITIC
            ),
            scope=approved_scope,
            now=now,
        )
    with pytest.raises(CampaignCandidateCriticExecutionRejected, match="source binding"):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope.model_copy(update={"state": ScopeState.REVOKED}),
            now=now,
        )
    assert store.state(plan.execution_plan_id) is None
    for connection in (service.store.connection, *connections):
        connection.close()


def test_interruption_recovers_once_and_timeout_never_completes(approved_scope, now):
    service, store, plan, _, *connections = _bundle(approved_scope, now)
    service.after_claim = lambda: (_ for _ in ()).throw(RuntimeError("interrupt"))
    with pytest.raises(RuntimeError, match="interrupt"):
        service.execute(
            plan, approval=_approval(plan, approved_scope, now), scope=approved_scope, now=now
        )
    service.after_claim = None
    assert (
        service.execute(
            plan, approval=_approval(plan, approved_scope, now), scope=approved_scope, now=now
        ).attempt
        == 2
    )
    for connection in (service.store.connection, *connections):
        connection.close()

    ticks = iter((0.0, 31.0))
    service, store, plan, _, *connections = _bundle(
        approved_scope, now, monotonic=lambda: next(ticks)
    )
    with pytest.raises(CampaignCandidateCriticExecutionTimedOut):
        service.execute(
            plan, approval=_approval(plan, approved_scope, now), scope=approved_scope, now=now
        )
    assert store.state(plan.execution_plan_id) is None
    for connection in (service.store.connection, *connections):
        connection.close()


def test_three_interrupted_attempts_exhaust_unique_consumption(approved_scope, now):
    service, store, plan, _, *connections = _bundle(approved_scope, now)
    service.after_claim = lambda: (_ for _ in ()).throw(RuntimeError("interrupt"))
    for _ in range(3):
        with pytest.raises(RuntimeError, match="interrupt"):
            service.execute(
                plan, approval=_approval(plan, approved_scope, now), scope=approved_scope, now=now
            )
    with pytest.raises(CampaignCandidateCriticExecutionRecoveryRequired, match="exhausted"):
        service.execute(
            plan, approval=_approval(plan, approved_scope, now), scope=approved_scope, now=now
        )
    assert store.state(plan.execution_plan_id) == (CampaignCandidateCriticExecutionState.STARTED, 3)
    for connection in (service.store.connection, *connections):
        connection.close()


def test_output_cleanup_and_authoritative_source_drift_fail_closed(approved_scope, now):
    service, store, plan, runner, *connections = _bundle(approved_scope, now)
    output_id = runner.results[plan.request.run_id].outputs[0].object_id
    service.output_reader.values[output_id] = b"{}"
    with pytest.raises(CampaignCandidateCriticExecutionRejected, match="typed output"):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    with pytest.raises(KeyError):
        store.outcome(plan.execution_plan_id)
    for connection in (service.store.connection, *connections):
        connection.close()

    service, store, plan, runner, *connections = _bundle(approved_scope, now)
    result = runner.results[plan.request.run_id]
    runner.results[plan.request.run_id] = result.model_copy(
        update={
            "cleanup": CleanupReport(
                processes_terminated=True,
                network_released=True,
                writable_layer_removed=False,
                temporary_mounts_removed=True,
            )
        }
    )
    with pytest.raises(CampaignCandidateCriticExecutionRejected, match="incomplete"):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    with pytest.raises(KeyError):
        store.outcome(plan.execution_plan_id)
    for connection in (service.store.connection, *connections):
        connection.close()

    service, store, plan, _, connection, intake_connection, validation_connection = _bundle(
        approved_scope, now
    )
    validation_connection.execute(
        "UPDATE red_team_campaign_candidate_validation_executions SET state='started'"
    )
    validation_connection.commit()
    with pytest.raises(CampaignCandidateCriticExecutionRejected, match="source"):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    assert store.state(plan.execution_plan_id) is None
    connection.close()
    intake_connection.close()
    validation_connection.close()


def test_schema_rejects_worker_finding_authority_and_validation_evidence_reuse(approved_scope, now):
    service, _, plan, _, *connections = _bundle(approved_scope, now)
    evidence_id = service._evidence_id(plan.request)
    document = CampaignCandidateCriticWorkerOutput.model_validate_json(
        service.output_reader.read_evidence(evidence_id)
    ).model_dump(mode="json")
    document["finding_creation_requested"] = True
    with pytest.raises(ValidationError):
        CampaignCandidateCriticWorkerOutput.model_validate(document)

    values = plan.model_dump(mode="python", exclude={"execution_plan_id"})
    request = plan.request
    mount = next(item for item in request.profile.mounts if item.object_id == evidence_id)
    reused = mount.model_copy(update={"object_id": plan.validation_evidence_refs[0]})
    profile = request.profile.model_copy(
        update={
            "mounts": tuple(reused if item == mount else item for item in request.profile.mounts)
        }
    )
    changed_request = request.model_copy(update={"profile": profile})
    values["request"] = changed_request.model_dump(mode="python")
    values["request_digest"] = run_request_digest(changed_request)
    values["execution_plan_id"] = canonical_digest(values)
    with pytest.raises(ValidationError):
        type(plan).model_validate(values)
    for connection in (service.store.connection, *connections):
        connection.close()


@pytest.mark.docker_integration
@pytest.mark.rootless_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_DOCKER_INTEGRATION") != "1"
    and os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") != "1",
    reason="set VULNLOOM_DOCKER_INTEGRATION=1 for the actual B5.10 canary",
)
def test_actual_docker_critic_is_hardened_read_only_networkless_and_removed(
    tmp_path: Path, approved_scope
):
    backend = DockerCliBackend()
    image = backend.inspect_image(os.environ.get("VULNLOOM_B5_10_IMAGE", "alpine:3.22"))["Id"]
    now = datetime.now(UTC)
    intake_service, intake_store, intake_connection, intake_plan, _, validation_connection = (
        intake_case(approved_scope, now)
    )
    intake_service.execute(
        intake_plan,
        approval=intake_approval(intake_plan, approved_scope, now),
        scope=approved_scope,
        now=now,
    )
    evidence_id = _digest(502)
    content = _worker(intake_plan, evidence_id)
    directory = tmp_path / "objects" / evidence_id
    directory.mkdir(parents=True)
    fixture = directory / "counterevidence.json"
    fixture.write_bytes(content)
    fixture.chmod(0o444)
    directory.chmod(0o555)
    request = _request(approved_scope, intake_plan, now, evidence_id).model_copy(
        update={
            "profile": _request(approved_scope, intake_plan, now, evidence_id).profile.model_copy(
                update={"image_digest": image}
            )
        }
    )
    request = request.model_copy(
        update={
            "task": request.task.model_copy(
                update={"sandbox_profile_digest": sandbox_profile_digest(request.profile)}
            )
        }
    )
    probe = r"""
set -eu
test -r /workspace/evidence/counterevidence.json
[ "$(id -u)" = 65532 ]
grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status
grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status
grep -q '^Seccomp:[[:space:]]*2$' /proc/self/status
! touch /workspace/evidence/must-remain-read-only
[ "$(wc -l < /proc/net/route)" = 1 ]
[ ! -S /var/run/docker.sock ]
[ ! -e /run/host-services/docker.proxy.sock ]
cat /workspace/evidence/counterevidence.json
""".strip()
    output_store = RunnerOutputStore(tmp_path / "runner-output")
    docker = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {evidence_id: directory}),
        (DockerTool(tool_id="critic.review", argv_prefix=("/bin/sh", "-c", probe, "b5.10")),),
        engine_policy=(
            DockerEnginePolicy()
            if os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") == "1"
            else DockerEnginePolicy(require_rootless=False, require_versioned_seccomp=False)
        ),
        output_store=output_store,
        captured_output_tools=frozenset({"critic.review"}),
    )

    class Reader:
        def read(self, output):
            return output_store.read(output)

        def read_evidence(self, object_id):
            return (directory / "counterevidence.json").read_bytes()

    connection = sqlite3.connect(":memory:")
    service = CampaignCandidateCriticExecutionService(
        intake_source=intake_store,
        validation_source=intake_service.validation_source,
        runner=docker,
        output_reader=Reader(),
        store=CampaignCandidateCriticExecutionStore(connection),
    )
    plan = service.prepare(
        critic_intake_plan_id=intake_plan.critic_intake_plan_id,
        request=request,
        scope=approved_scope,
        limits=CampaignCandidateCriticExecutionLimits(timeout_seconds=60),
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="b5.10:docker",
    )
    outcome = service.execute(
        plan,
        approval=_approval(plan, approved_scope, now),
        scope=approved_scope,
        now=now,
    )
    assert outcome.review.verdict is CriticVerdict.ACCEPTED
    assert docker.last_inspection is not None
    assert not backend.exists(docker.last_inspection["Id"])
    assert outcome.result.cleanup.complete
    connection.close()
    intake_connection.close()
    validation_connection.close()
