from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    ScopeState,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.red_team.adaptive_runtime_models import RuntimeAssuranceLevel
from vulnloom.red_team.campaign_models import (
    CampaignBudget,
    CampaignFlowQualificationBinding,
    CampaignGoal,
    CampaignGoalKind,
    CampaignPhase,
    CampaignPhaseKind,
    CampaignQualificationLimits,
    CampaignStopConditions,
    GoalDrivenCampaignPlan,
    GoalDrivenCampaignQualificationOutcome,
)
from vulnloom.red_team.campaign_runtime_docker import (
    CampaignRuntimeDockerEvidenceRejected,
    observe_docker_campaign_phase,
    observe_docker_campaign_stop,
)
from vulnloom.red_team.campaign_runtime_models import (
    CampaignPhaseRuntimeObservation,
    CampaignRuntimeQualificationLimits,
    CampaignRuntimeQualificationPlan,
    CampaignRuntimeQualificationState,
    CampaignRuntimeStopProbeKind,
    CampaignStopRuntimeObservation,
)
from vulnloom.red_team.campaign_runtime_service import (
    CampaignRuntimeQualificationRejected,
    CampaignRuntimeQualificationService,
    CampaignRuntimeQualificationTimedOut,
)
from vulnloom.red_team.campaign_runtime_store import (
    CampaignRuntimeQualificationStore,
    CampaignRuntimeRecoveryRequired,
    CampaignRuntimeStoreRejected,
)
from vulnloom.runners import (
    DockerCliBackend,
    DockerEnginePolicy,
    DockerSandboxRunner,
    DockerTool,
    HostileWorkerProbeExpectation,
    HostileWorkerProbeKind,
    HostileWorkerProbeObservation,
    HostileWorkerQualificationPlan,
    RegisteredObjectStore,
    ResourcePressureProbeExpectation,
    ResourcePressureProbeKind,
    ResourcePressureProbeObservation,
    ResourcePressureQualificationPlan,
    SandboxRunRequest,
    SandboxRunStatus,
    ToolInvocation,
    post_exploitation_profile,
    qualify_hostile_worker,
    qualify_resource_pressure,
    sandbox_profile_digest,
)
from vulnloom.workflows import AutonomyLevel

IMAGE = "sha256:" + "1" * 64
_CONNECTIONS: list[sqlite3.Connection] = []


@pytest.fixture(autouse=True)
def _close_campaign_runtime_connections():
    yield
    while _CONNECTIONS:
        _CONNECTIONS.pop().close()


def _store():
    connection = sqlite3.connect(":memory:")
    _CONNECTIONS.append(connection)
    return CampaignRuntimeQualificationStore(connection)


def _campaign(scope, now, *, assurance=RuntimeAssuranceLevel.LOCAL_DOCKER):
    bindings = tuple(
        CampaignFlowQualificationBinding.create(
            flow_plan_id=f"{100 + index:064x}",
            target_id=uuid4(),
            scope_id=scope.scope_id,
            scope_version=scope.version,
            adaptive_plan_id=f"{110 + index:064x}",
            adaptive_outcome_id=f"{120 + index:064x}",
            coverage_ledger_id=f"{130 + index:064x}",
            runtime_plan_id=f"{140 + index:064x}",
            runtime_outcome_id=f"{150 + index:064x}",
            runtime_outcome_digest=f"{160 + index:064x}",
            assurance_level=assurance,
        )
        for index in (1, 2)
    )
    phases = []
    previous = None
    for ordinal, kind in enumerate(CampaignPhaseKind, start=1):
        phase = CampaignPhase.create(
            ordinal=ordinal,
            kind=kind,
            prerequisite_phase_ids=(() if previous is None else (previous.phase_id,)),
            max_flow_materializations=1,
            max_actions=1,
            wall_seconds=60,
        )
        phases.append(phase)
        previous = phase
    goal = CampaignGoal.create(
        kind=CampaignGoalKind.EVIDENCE_REQUIREMENT_SATISFACTION,
        statement_digest="a" * 64,
        required_evidence_classes=("critic_review", "independent_validation"),
    )
    plan = GoalDrivenCampaignPlan.create(
        goal=goal,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        target_ids=tuple(sorted({item.target_id for item in bindings}, key=str)),
        flow_bindings=tuple(sorted(bindings, key=lambda item: item.flow_plan_id)),
        phases=tuple(phases),
        budget=CampaignBudget(
            max_flow_materializations=12,
            max_actions=12,
            wall_seconds=600,
            max_consecutive_failures=2,
        ),
        stop_conditions=CampaignStopConditions(),
        limits=CampaignQualificationLimits(),
        created_at=now - timedelta(minutes=2),
        deadline=now + timedelta(minutes=10),
        idempotency_key="campaign-runtime-source",
    )
    outcome = GoalDrivenCampaignQualificationOutcome.create(
        campaign_plan_id=plan.campaign_plan_id,
        goal_id=goal.goal_id,
        flow_binding_ids=tuple(item.binding_id for item in plan.flow_bindings),
        target_ids=plan.target_ids,
        minimum_assurance_level=assurance,
        attempt=1,
        completed_at=now - timedelta(minutes=1),
    )
    return plan, outcome


def _shared_isolation(profile, now):
    profile_id = sandbox_profile_digest(profile)
    hostile_probes = tuple(
        HostileWorkerProbeExpectation(
            kind=kind,
            run_id=uuid4(),
            task_id=uuid4(),
            sandbox_profile_digest=profile_id,
            invocation_digest=f"{200 + index:064x}",
            expected_status=(
                SandboxRunStatus.FAILED
                if kind is HostileWorkerProbeKind.CRASH_CLEANUP
                else SandboxRunStatus.TIMED_OUT
                if kind is HostileWorkerProbeKind.TIMEOUT_CLEANUP
                else SandboxRunStatus.COMPLETED
            ),
        )
        for index, kind in enumerate(HostileWorkerProbeKind)
    )
    hostile_plan = HostileWorkerQualificationPlan.create(
        image_digest=profile.image_digest,
        created_at=now,
        expires_at=now + timedelta(minutes=10),
        probes=hostile_probes,
    )
    hostile_outcome = qualify_hostile_worker(
        hostile_plan,
        tuple(
            HostileWorkerProbeObservation(
                kind=item.kind,
                run_id=item.run_id,
                task_id=item.task_id,
                sandbox_profile_digest=item.sandbox_profile_digest,
                invocation_digest=item.invocation_digest,
                status=item.expected_status,
                cleanup_verified=True,
                container_absent=True,
            )
            for item in hostile_probes
        ),
        now=now,
    )
    terminals = {
        ResourcePressureProbeKind.PID_LIMIT: (SandboxRunStatus.COMPLETED, ()),
        ResourcePressureProbeKind.OPEN_FILES_LIMIT: (SandboxRunStatus.COMPLETED, ()),
        ResourcePressureProbeKind.OUTPUT_LIMIT: (
            SandboxRunStatus.FAILED,
            ("output_capture_failed",),
        ),
        ResourcePressureProbeKind.TEMP_STORAGE_LIMIT: (SandboxRunStatus.COMPLETED, ()),
        ResourcePressureProbeKind.MEMORY_LIMIT: (
            SandboxRunStatus.FAILED,
            ("memory_limit_exceeded",),
        ),
        ResourcePressureProbeKind.TIMEOUT_PROCESS_GROUP: (
            SandboxRunStatus.TIMED_OUT,
            ("wall_time_budget_exceeded",),
        ),
    }
    resource_probes = tuple(
        ResourcePressureProbeExpectation(
            kind=kind,
            run_id=uuid4(),
            task_id=uuid4(),
            sandbox_profile_digest=profile_id,
            invocation_digest=f"{300 + index:064x}",
            expected_status=terminals[kind][0],
            expected_error_codes=terminals[kind][1],
        )
        for index, kind in enumerate(ResourcePressureProbeKind)
    )
    resource_plan = ResourcePressureQualificationPlan.create(
        image_digest=profile.image_digest,
        created_at=now,
        expires_at=now + timedelta(minutes=10),
        probes=resource_probes,
    )
    resource_outcome = qualify_resource_pressure(
        resource_plan,
        tuple(
            ResourcePressureProbeObservation(
                kind=item.kind,
                run_id=item.run_id,
                task_id=item.task_id,
                sandbox_profile_digest=item.sandbox_profile_digest,
                invocation_digest=item.invocation_digest,
                status=item.expected_status,
                error_codes=item.expected_error_codes,
                boundary_observed=True,
                cleanup_verified=True,
                container_absent=True,
            )
            for item in resource_probes
        ),
        now=now,
    )
    return hostile_plan, hostile_outcome, resource_plan, resource_outcome


def _runtime(scope, now, *, assurance=RuntimeAssuranceLevel.LOCAL_DOCKER, image=IMAGE):
    campaign_plan, campaign_outcome = _campaign(scope, now, assurance=assurance)
    profile = post_exploitation_profile(
        image_digest=image,
        evidence_object_id=campaign_outcome.outcome_id,
    )
    hostile_plan, hostile_outcome, resource_plan, resource_outcome = _shared_isolation(
        profile, now
    )
    service = CampaignRuntimeQualificationService(store=_store())
    runtime_plan = service.prepare(
        campaign_plan=campaign_plan,
        campaign_outcome=campaign_outcome,
        hostile_plan=hostile_plan,
        hostile_outcome=hostile_outcome,
        resource_plan=resource_plan,
        resource_outcome=resource_outcome,
        profile=profile,
        scope=scope,
        limits=CampaignRuntimeQualificationLimits(),
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="campaign-runtime-qualification",
    )
    approvals = tuple(
        ApprovalRequest(
            engagement_id=scope.engagement_id,
            target_id=None,
            action=ApprovalAction.ADVANCE_CAMPAIGN_PHASE,
            action_digest=phase.phase_id,
            expected_side_effects=(),
            evidence_summary=f"sealed phase {phase.ordinal}",
            policy_version=1,
            expires_at=now + timedelta(minutes=5),
            status=ApprovalStatus.GRANTED,
            decided_by="campaign-operator",
            decided_at=now + timedelta(seconds=phase.ordinal),
        )
        for phase in campaign_plan.phases
    )
    phases = tuple(
        CampaignPhaseRuntimeObservation.create(
            runtime_plan_id=runtime_plan.runtime_plan_id,
            campaign_plan_id=campaign_plan.campaign_plan_id,
            campaign_outcome_id=campaign_outcome.outcome_id,
            phase_id=phase.phase_id,
            phase_kind=phase.kind,
            ordinal=phase.ordinal,
            prerequisite_phase_ids=phase.prerequisite_phase_ids,
            approval_id=approval.approval_id,
            approval_digest=approval.action_digest,
            run_id=uuid4(),
            task_id=uuid4(),
            image_digest=image,
            sandbox_profile_digest=sandbox_profile_digest(profile),
            invocation_digest=f"{400 + phase.ordinal:064x}",
            runner_result_digest=f"{500 + phase.ordinal:064x}",
            assurance_level=assurance,
            observed_at=now + timedelta(seconds=phase.ordinal + 6),
        )
        for phase, approval in zip(campaign_plan.phases, approvals, strict=True)
    )
    stops = tuple(
        CampaignStopRuntimeObservation.create(
            runtime_plan_id=runtime_plan.runtime_plan_id,
            campaign_plan_id=campaign_plan.campaign_plan_id,
            campaign_outcome_id=campaign_outcome.outcome_id,
            kind=kind,
            run_id=uuid4(),
            task_id=uuid4(),
            image_digest=image,
            sandbox_profile_digest=sandbox_profile_digest(profile),
            invocation_digest=f"{600 + index:064x}",
            runner_result_digest=f"{700 + index:064x}",
            status=(
                SandboxRunStatus.COMPLETED
                if kind is CampaignRuntimeStopProbeKind.BUDGET_STOP
                else SandboxRunStatus.TIMED_OUT
            ),
            error_codes=(
                ()
                if kind is CampaignRuntimeStopProbeKind.BUDGET_STOP
                else ("wall_time_budget_exceeded",)
            ),
            worker_exit_code=(
                42 if kind is CampaignRuntimeStopProbeKind.BUDGET_STOP else None
            ),
            assurance_level=assurance,
            observed_at=now + timedelta(seconds=13 + index),
        )
        for index, kind in enumerate(CampaignRuntimeStopProbeKind)
    )
    inputs = {
        "campaign_plan": campaign_plan,
        "campaign_outcome": campaign_outcome,
        "hostile_plan": hostile_plan,
        "hostile_outcome": hostile_outcome,
        "resource_plan": resource_plan,
        "resource_outcome": resource_outcome,
        "profile": profile,
    }
    return service, runtime_plan, phases, stops, approvals, inputs


def _execute(service, plan, phases, stops, approvals, inputs, scope, now):
    return service.execute(
        plan,
        phase_observations=phases,
        stop_observations=stops,
        approvals=approvals,
        scope=scope,
        now=now + timedelta(seconds=20),
        **inputs,
    )


def test_all_admitted_phases_and_stop_probes_qualify_a4_runtime_without_starting(
    approved_scope, now
):
    service, plan, phases, stops, approvals, inputs = _runtime(approved_scope, now)
    outcome = _execute(
        service, plan, phases, stops, approvals, inputs, approved_scope, now
    )
    replay = _execute(
        service, plan, phases, tuple(reversed(stops)), approvals, inputs, approved_scope, now
    )

    assert replay == outcome
    assert outcome.qualified_autonomy is AutonomyLevel.GOAL_DRIVEN_CAMPAIGN
    assert outcome.isolated_runtime_qualified is True
    assert outcome.production_campaign_runtime_admitted is False
    assert outcome.campaign_started is False
    assert outcome.action_execution_authority_granted is False
    assert outcome.dynamic_target_expansion_granted is False
    assert outcome.credential_access_granted is False
    assert outcome.submission_granted is False
    assert outcome.candidate_created is False
    assert outcome.finding_created is False
    assert service.store.state(plan.runtime_plan_id) == (
        CampaignRuntimeQualificationState.COMPLETED,
        1,
    )


def test_phase_order_missing_admission_and_revoked_scope_fail_before_checkpoint(
    approved_scope, now
):
    service, plan, phases, stops, approvals, inputs = _runtime(approved_scope, now)
    with pytest.raises(CampaignRuntimeQualificationRejected, match="provenance"):
        _execute(
            service,
            plan,
            tuple(reversed(phases)),
            stops,
            approvals,
            inputs,
            approved_scope,
            now,
        )
    with pytest.raises(CampaignRuntimeQualificationRejected, match="Admission set"):
        _execute(
            service,
            plan,
            phases,
            stops,
            approvals[:-1],
            inputs,
            approved_scope,
            now,
        )
    revoked = approved_scope.model_copy(update={"state": ScopeState.REVOKED})
    with pytest.raises(CampaignRuntimeQualificationRejected, match="prerequisite"):
        _execute(service, plan, phases, stops, approvals, inputs, revoked, now)
    assert service.store.state(plan.runtime_plan_id) is None


def test_missing_or_tampered_stop_evidence_fails_closed(approved_scope, now):
    service, plan, phases, stops, approvals, inputs = _runtime(approved_scope, now)
    with pytest.raises(CampaignRuntimeQualificationRejected, match="stop evidence"):
        _execute(
            service, plan, phases, stops[:1], approvals, inputs, approved_scope, now
        )
    tampered = stops[0].model_copy(update={"worker_exit_code": 0})
    with pytest.raises(CampaignRuntimeQualificationRejected, match="not authoritative"):
        _execute(
            service,
            plan,
            phases,
            (tampered, stops[1]),
            approvals,
            inputs,
            approved_scope,
            now,
        )
    assert service.store.state(plan.runtime_plan_id) is None


def test_runtime_assurance_is_capped_by_campaign_and_actual_evidence(approved_scope, now):
    service, plan, phases, stops, approvals, inputs = _runtime(
        approved_scope, now, assurance=RuntimeAssuranceLevel.ROOTLESS_PRODUCTION
    )
    local_phase = CampaignPhaseRuntimeObservation.create(
        **{
            **phases[0].model_dump(mode="python", exclude={"observation_id"}),
            "assurance_level": RuntimeAssuranceLevel.LOCAL_DOCKER,
        }
    )
    outcome = _execute(
        service,
        plan,
        (local_phase, *phases[1:]),
        stops,
        approvals,
        inputs,
        approved_scope,
        now,
    )
    assert outcome.assurance_level is RuntimeAssuranceLevel.LOCAL_DOCKER
    assert outcome.production_campaign_runtime_admitted is False


def test_timeout_keeps_started_and_recovery_is_bounded(approved_scope, now):
    service, plan, phases, stops, approvals, inputs = _runtime(approved_scope, now)
    ticks = iter((0.0, 100.0, 0.0, 100.0, 0.0, 100.0))
    service.monotonic = lambda: next(ticks)
    with pytest.raises(CampaignRuntimeQualificationTimedOut):
        _execute(service, plan, phases, stops, approvals, inputs, approved_scope, now)
    for offset in (21, 22):
        with pytest.raises(CampaignRuntimeQualificationTimedOut):
            service.recover(
                plan,
                inputs=inputs,
                phase_observations=phases,
                stop_observations=stops,
                approvals=approvals,
                scope=approved_scope,
                now=now + timedelta(seconds=offset),
            )
    with pytest.raises(CampaignRuntimeRecoveryRequired, match="exhausted"):
        service.recover(
            plan,
            inputs=inputs,
            phase_observations=phases,
            stop_observations=stops,
            approvals=approvals,
            scope=approved_scope,
            now=now + timedelta(seconds=23),
        )
    assert service.store.state(plan.runtime_plan_id) == (
        CampaignRuntimeQualificationState.STARTED,
        3,
    )


def test_runtime_idempotency_key_reuse_with_different_content_is_rejected(
    approved_scope, now
):
    service, plan, phases, stops, approvals, inputs = _runtime(approved_scope, now)
    original = _execute(
        service, plan, phases, stops, approvals, inputs, approved_scope, now
    )
    values = plan.model_dump(mode="python", exclude={"runtime_plan_id"})
    values["limits"] = CampaignRuntimeQualificationLimits(timeout_seconds=11.0)
    conflict = CampaignRuntimeQualificationPlan.create(**values)

    with pytest.raises(CampaignRuntimeStoreRejected, match="different content"):
        service.store.claim(conflict, now=now + timedelta(seconds=21))
    assert _execute(
        service, plan, phases, stops, approvals, inputs, approved_scope, now
    ) == original
    assert service.store.state(conflict.runtime_plan_id) is None


def test_schema_and_ledger_exclude_targets_secrets_commands_and_execution_authority(
    approved_scope, now
):
    service, plan, phases, stops, approvals, inputs = _runtime(approved_scope, now)
    raw = plan.model_dump(mode="python")
    raw["campaign_execution_requested"] = True
    raw["runtime_plan_id"] = "0" * 64
    with pytest.raises(ValidationError):
        CampaignRuntimeQualificationPlan.model_validate(raw)

    _execute(service, plan, phases, stops, approvals, inputs, approved_scope, now)
    row = service.store.connection.execute(
        "SELECT plan_json,outcome_json FROM red_team_campaign_runtime_qualifications"
    ).fetchone()
    serialized = "".join(row).lower()
    schema = json.dumps(CampaignRuntimeQualificationPlan.model_json_schema()).lower()
    for forbidden in (
        "target_url",
        "hostname",
        "password",
        "cookie",
        "credential_value",
        "provider_token",
        "docker_socket",
        "submission_token",
        "payload",
        "command",
    ):
        assert forbidden not in serialized
        assert forbidden not in schema


@pytest.mark.docker_integration
@pytest.mark.rootless_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_DOCKER_INTEGRATION") != "1"
    and os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") != "1",
    reason="set VULNLOOM_DOCKER_INTEGRATION=1 for the actual B5.4 canary",
)
def test_actual_docker_phase_budget_and_timeout_runs_qualify_campaign_runtime(
    tmp_path: Path, approved_scope
):
    backend = DockerCliBackend()
    image = backend.inspect_image("alpine:3.22")["Id"]
    now = datetime.now(UTC)
    service, plan, _, _, approvals, inputs = _runtime(
        approved_scope,
        now,
        assurance=(
            RuntimeAssuranceLevel.ROOTLESS_PRODUCTION
            if os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") == "1"
            else RuntimeAssuranceLevel.LOCAL_DOCKER
        ),
        image=image,
    )
    approvals = tuple(
        item.model_copy(update={"decided_at": now - timedelta(seconds=1)})
        for item in approvals
    )
    campaign_plan = inputs["campaign_plan"]
    profile = inputs["profile"]
    evidence = tmp_path / "objects" / plan.campaign_outcome_id
    evidence.mkdir(parents=True)
    (evidence / "campaign.json").write_text('{"campaign":"sealed"}\n')
    (evidence / "campaign.json").chmod(0o444)
    evidence.chmod(0o555)
    objects = RegisteredObjectStore(
        tmp_path / "objects", {plan.campaign_outcome_id: evidence}
    )
    engine_policy = (
        DockerEnginePolicy()
        if os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") == "1"
        else DockerEnginePolicy(require_rootless=False, require_versioned_seccomp=False)
    )

    def request(arguments, *, wall_seconds=20):
        task = TaskEnvelope(
            engagement_id=approved_scope.engagement_id,
            target_id=campaign_plan.target_ids[0],
            target_version=campaign_plan.campaign_plan_id,
            scope_id=approved_scope.scope_id,
            worker_role=WorkerRole.RED_TEAM_OPERATOR,
            scope_version=approved_scope.version,
            policy_digest="9" * 64,
            sandbox_profile_digest=sandbox_profile_digest(profile),
            tool_registry_digest="8" * 64,
            input_refs=(f"campaign:{plan.campaign_outcome_id}",),
            allowed_tools=frozenset({"red_team.evidence_read"}),
            budget=TaskBudget(
                wall_seconds=wall_seconds,
                model_tokens=0,
                tool_calls=1,
            ),
            deadline=now + timedelta(seconds=90),
            idempotency_key=f"task:b5.4:{uuid4()}",
        )
        return SandboxRunRequest(
            task=task,
            profile=profile,
            invocation=ToolInvocation(
                tool_id="red_team.evidence_read",
                arguments=arguments,
                working_directory="output",
            ),
            environment={"VULNLOOM_TASK_ID": str(task.task_id)},
            idempotency_key=f"run:b5.4:{uuid4()}",
        )

    boundary = (
        "set -eu; test -r /workspace/evidence/campaign.json; "
        "[ \"$(id -u)\" = 65532 ]; "
        "grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status; "
        "grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status; "
        "grep -q '^Seccomp:[[:space:]]*2$' /proc/self/status; "
        "! touch /workspace/evidence/must-remain-read-only; "
        "[ \"$(wc -l < /proc/net/route)\" = 1 ]; "
        "[ ! -S /var/run/docker.sock ]; "
        "[ ! -e /run/host-services/docker.proxy.sock ]"
    )
    phase_observations = []
    for phase, approval in zip(campaign_plan.phases, approvals, strict=True):
        run_request = request((phase.phase_id, phase.kind.value, str(phase.ordinal)))
        runner = DockerSandboxRunner(
            backend,
            objects,
            (
                DockerTool(
                    tool_id="red_team.evidence_read",
                    argv_prefix=("/bin/sh", "-c", boundary, "vulnloom-b5.4-phase"),
                ),
            ),
            engine_policy=engine_policy,
        )
        result = runner.execute(run_request, now=now)
        assert runner.last_inspection is not None
        assert runner.last_terminal_inspection is not None
        phase_observations.append(
            observe_docker_campaign_phase(
                plan=plan,
                campaign_plan=campaign_plan,
                phase=phase,
                approval=approval,
                request=run_request,
                result=result,
                inspection=runner.last_inspection,
                terminal_inspection=runner.last_terminal_inspection,
                engine_info=backend.engine_info(),
                container_absent=not backend.exists(runner.last_inspection["Id"]),
                now=datetime.now(UTC),
            )
        )

    stop_observations = []
    for kind, tool, wall_seconds in (
        (
            CampaignRuntimeStopProbeKind.BUDGET_STOP,
            DockerTool(
                tool_id="red_team.evidence_read",
                argv_prefix=(
                    "/bin/sh",
                    "-c",
                    f"{boundary}; [ \"$1\" = budget_stop ]; exit 42",
                    "vulnloom-b5.4-budget",
                ),
                successful_exit_codes=frozenset({0, 42}),
            ),
            20,
        ),
        (
            CampaignRuntimeStopProbeKind.TIMEOUT_CLEANUP,
            DockerTool(
                tool_id="red_team.evidence_read",
                argv_prefix=(
                    "/bin/sh",
                    "-c",
                    "sleep 300",
                    "vulnloom-b5.4-timeout",
                ),
            ),
            1,
        ),
    ):
        run_request = request((kind.value,), wall_seconds=wall_seconds)
        runner = DockerSandboxRunner(
            backend,
            objects,
            (tool,),
            engine_policy=engine_policy,
        )
        result = runner.execute(run_request, now=now)
        assert runner.last_inspection is not None
        stop_observations.append(
            observe_docker_campaign_stop(
                plan=plan,
                campaign_plan=campaign_plan,
                kind=kind,
                request=run_request,
                result=result,
                inspection=runner.last_inspection,
                terminal_inspection=runner.last_terminal_inspection,
                engine_info=backend.engine_info(),
                container_absent=not backend.exists(runner.last_inspection["Id"]),
                now=datetime.now(UTC),
            )
        )

    drifted = {
        **runner.last_inspection,
        "HostConfig": {**runner.last_inspection["HostConfig"], "NetworkMode": "bridge"},
    }
    with pytest.raises(CampaignRuntimeDockerEvidenceRejected, match="boundary"):
        observe_docker_campaign_stop(
            plan=plan,
            campaign_plan=campaign_plan,
            kind=CampaignRuntimeStopProbeKind.TIMEOUT_CLEANUP,
            request=run_request,
            result=result,
            inspection=drifted,
            terminal_inspection=runner.last_terminal_inspection,
            engine_info=backend.engine_info(),
            container_absent=True,
            now=datetime.now(UTC),
        )

    outcome = service.execute(
        plan,
        phase_observations=tuple(phase_observations),
        stop_observations=tuple(stop_observations),
        approvals=approvals,
        scope=approved_scope,
        now=datetime.now(UTC),
        **inputs,
    )
    assert outcome.isolated_runtime_qualified is True
    assert all(item.cleanup_verified and item.container_absent for item in phase_observations)
    assert all(item.cleanup_verified and item.container_absent for item in stop_observations)
    assert outcome.production_campaign_runtime_admitted == (
        os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") == "1"
    )
