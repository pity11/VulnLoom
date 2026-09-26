from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.domain.models import ScopeState
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.red_team.adaptive_qualification_models import (
    AdaptiveCoverageLedger,
    AdaptiveFlowQualificationOutcome,
    AdaptiveFlowQualificationPlan,
    AdaptiveQualificationLimits,
    AdaptiveRoundCoverage,
)
from vulnloom.red_team.adaptive_runtime_docker import (
    AdaptiveRuntimeDockerEvidenceRejected,
    observe_docker_adaptive_runtime,
)
from vulnloom.red_team.adaptive_runtime_models import (
    AdaptiveRuntimeProbeKind,
    AdaptiveRuntimeProbeObservation,
    AdaptiveRuntimeQualificationLimits,
    AdaptiveRuntimeQualificationPlan,
    RuntimeAssuranceLevel,
)
from vulnloom.red_team.adaptive_runtime_service import (
    AdaptiveRuntimeQualificationRejected,
    AdaptiveRuntimeQualificationService,
    AdaptiveRuntimeQualificationTimedOut,
)
from vulnloom.red_team.adaptive_runtime_store import (
    AdaptiveRuntimeQualificationState,
    AdaptiveRuntimeQualificationStore,
    AdaptiveRuntimeRecoveryRequired,
)
from vulnloom.red_team.models import ReconOutcome, RedTeamActionKind
from vulnloom.runners import (
    DockerCliBackend,
    DockerEnginePolicy,
    DockerSandboxRunner,
    DockerTool,
    HostileWorkerProbeExpectation,
    HostileWorkerProbeKind,
    HostileWorkerProbeObservation,
    HostileWorkerQualificationPlan,
    HostileWorkerQualificationStatus,
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


def _adaptive(scope, now):
    rounds = tuple(
        AdaptiveRoundCoverage.create(
            ordinal=index,
            execution_receipt_id=f"{10 + index:064x}",
            admission_id=f"{20 + index:064x}",
            source_checkpoint_id=f"{30 + index:064x}",
            result_checkpoint_id=f"{40 + index:064x}",
            source_observation_ids=(f"{50 + index:064x}",),
            produced_observation_id=f"{60 + index:064x}",
            action_id=f"{70 + index:064x}",
            action_kind=(
                RedTeamActionKind.HTTP_HEAD
                if index == 1
                else RedTeamActionKind.TLS_INSPECT
            ),
            test_class="read_only",
            outcome=ReconOutcome.SUCCEEDED,
        )
        for index in (1, 2)
    )
    flow_id = "a" * 64
    ledger = AdaptiveCoverageLedger.create(
        flow_plan_id=flow_id,
        final_checkpoint_id="b" * 64,
        rounds=rounds,
        covered_action_kinds=tuple(
            sorted({item.action_kind for item in rounds}, key=str)
        ),
        covered_test_classes=("read_only",),
        source_observation_count=1,
        produced_observation_count=2,
    )
    plan = AdaptiveFlowQualificationPlan.create(
        flow_plan_id=flow_id,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        target_id=uuid4(),
        target_url_digest="c" * 64,
        final_checkpoint_id=ledger.final_checkpoint_id,
        replan_execution_receipt_ids=("d" * 64, "e" * 64),
        limits=AdaptiveQualificationLimits(),
        created_at=now,
        deadline=now + timedelta(minutes=10),
        idempotency_key="adaptive-flow-runtime-fixture",
    )
    outcome = AdaptiveFlowQualificationOutcome.create(
        plan_id=plan.plan_id,
        flow_plan_id=flow_id,
        coverage_ledger=ledger,
        attempt=1,
        completed_at=now,
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
            invocation_digest=f"{100 + index:064x}",
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
    hostile_observations = tuple(
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
    )
    hostile_outcome = qualify_hostile_worker(
        hostile_plan, hostile_observations, now=now
    )

    terminals = {
        ResourcePressureProbeKind.PID_LIMIT: (SandboxRunStatus.COMPLETED, ()),
        ResourcePressureProbeKind.OPEN_FILES_LIMIT: (SandboxRunStatus.COMPLETED, ()),
        ResourcePressureProbeKind.OUTPUT_LIMIT: (
            SandboxRunStatus.FAILED,
            ("output_capture_failed",),
        ),
        ResourcePressureProbeKind.TEMP_STORAGE_LIMIT: (
            SandboxRunStatus.COMPLETED,
            (),
        ),
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
            invocation_digest=f"{200 + index:064x}",
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
    resource_observations = tuple(
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
    )
    resource_outcome = qualify_resource_pressure(
        resource_plan, resource_observations, now=now
    )
    return hostile_plan, hostile_outcome, resource_plan, resource_outcome


def _runtime(
    tmp_path,
    scope,
    now,
    *,
    assurance=RuntimeAssuranceLevel.LOCAL_DOCKER,
    image=IMAGE,
):
    adaptive_plan, adaptive_outcome = _adaptive(scope, now)
    profile = post_exploitation_profile(
        image_digest=image,
        evidence_object_id=adaptive_outcome.coverage_ledger.ledger_id,
    )
    hostile_plan, hostile_outcome, resource_plan, resource_outcome = (
        _shared_isolation(profile, now)
    )
    store = AdaptiveRuntimeQualificationStore(sqlite3.connect(":memory:"))
    service = AdaptiveRuntimeQualificationService(store=store)
    plan = service.prepare(
        adaptive_plan=adaptive_plan,
        adaptive_outcome=adaptive_outcome,
        hostile_plan=hostile_plan,
        hostile_outcome=hostile_outcome,
        resource_plan=resource_plan,
        resource_outcome=resource_outcome,
        profile=profile,
        scope=scope,
        limits=AdaptiveRuntimeQualificationLimits(),
        now=now + timedelta(seconds=1),
        deadline=now + timedelta(minutes=5),
        idempotency_key="adaptive-runtime-qualification",
    )
    observations = tuple(
        AdaptiveRuntimeProbeObservation.create(
            plan_id=plan.plan_id,
            adaptive_outcome_id=adaptive_outcome.outcome_id,
            coverage_ledger_id=adaptive_outcome.coverage_ledger.ledger_id,
            kind=kind,
            run_id=uuid4(),
            task_id=uuid4(),
            image_digest=profile.image_digest,
            sandbox_profile_digest=sandbox_profile_digest(profile),
            invocation_digest=f"{300 + index:064x}",
            runner_result_digest=f"{400 + index:064x}",
            status=(
                SandboxRunStatus.COMPLETED
                if kind is AdaptiveRuntimeProbeKind.BOUNDARY
                else SandboxRunStatus.TIMED_OUT
            ),
            error_codes=(
                ()
                if kind is AdaptiveRuntimeProbeKind.BOUNDARY
                else ("wall_time_budget_exceeded",)
            ),
            assurance_level=assurance,
            observed_at=now + timedelta(seconds=2 + index),
        )
        for index, kind in enumerate(AdaptiveRuntimeProbeKind)
    )
    inputs = {
        "adaptive_plan": adaptive_plan,
        "adaptive_outcome": adaptive_outcome,
        "hostile_plan": hostile_plan,
        "hostile_outcome": hostile_outcome,
        "resource_plan": resource_plan,
        "resource_outcome": resource_outcome,
        "profile": profile,
    }
    return service, plan, observations, inputs


def test_actual_isolation_evidence_qualifies_only_the_bound_a3_flow(
    tmp_path, approved_scope, now
):
    service, plan, observations, inputs = _runtime(tmp_path, approved_scope, now)
    outcome = service.execute(
        plan,
        observations=observations,
        scope=approved_scope,
        now=now + timedelta(seconds=5),
        **inputs,
    )
    replay = service.execute(
        plan,
        observations=observations,
        scope=approved_scope,
        now=now + timedelta(seconds=6),
        **inputs,
    )

    assert replay == outcome
    assert outcome.qualified_autonomy is AutonomyLevel.ADAPTIVE_FLOW
    assert outcome.isolated_lab_qualified is True
    assert outcome.assurance_level is RuntimeAssuranceLevel.LOCAL_DOCKER
    assert outcome.production_runner_admitted is False
    assert outcome.execution_authority_granted is False
    assert outcome.campaign_qualified is False
    assert outcome.candidate_created is False
    assert outcome.finding_created is False
    assert service.store.state(plan.plan_id) == (
        AdaptiveRuntimeQualificationState.COMPLETED,
        1,
    )


def test_rootless_evidence_is_explicitly_distinguished_from_local_docker(
    tmp_path, approved_scope, now
):
    service, plan, observations, inputs = _runtime(
        tmp_path,
        approved_scope,
        now,
        assurance=RuntimeAssuranceLevel.ROOTLESS_PRODUCTION,
    )
    outcome = service.execute(
        plan,
        observations=observations,
        scope=approved_scope,
        now=now + timedelta(seconds=5),
        **inputs,
    )
    assert outcome.production_runner_admitted is True
    assert outcome.assurance_level is RuntimeAssuranceLevel.ROOTLESS_PRODUCTION


def test_missing_or_drifted_runtime_probe_fails_before_checkpoint(
    tmp_path, approved_scope, now
):
    service, plan, observations, inputs = _runtime(tmp_path, approved_scope, now)
    with pytest.raises(AdaptiveRuntimeQualificationRejected, match="binding"):
        service.execute(
            plan,
            observations=observations[:1],
            scope=approved_scope,
            now=now + timedelta(seconds=5),
            **inputs,
        )
    drifted = observations[0].model_copy(update={"plan_id": "f" * 64})
    with pytest.raises(AdaptiveRuntimeQualificationRejected, match="provenance"):
        service.execute(
            plan,
            observations=(drifted, observations[1]),
            scope=approved_scope,
            now=now + timedelta(seconds=5),
            **inputs,
        )
    assert service.store.state(plan.plan_id) is None


def test_scope_or_shared_isolation_admission_drift_is_rejected(
    tmp_path, approved_scope, now
):
    service, plan, observations, inputs = _runtime(tmp_path, approved_scope, now)
    revoked = approved_scope.model_copy(update={"state": ScopeState.REVOKED})
    with pytest.raises(AdaptiveRuntimeQualificationRejected, match="prerequisite"):
        service.execute(
            plan,
            observations=observations,
            scope=revoked,
            now=now + timedelta(seconds=5),
            **inputs,
        )
    denied = inputs["hostile_outcome"].model_copy(
        update={
            "status": HostileWorkerQualificationStatus.DENIED,
            "denial_codes": ("cleanup_unproven",),
        }
    )
    with pytest.raises(AdaptiveRuntimeQualificationRejected, match="prerequisite"):
        service.execute(
            plan,
            observations=observations,
            scope=approved_scope,
            now=now + timedelta(seconds=5),
            **{**inputs, "hostile_outcome": denied},
        )
    assert service.store.state(plan.plan_id) is None


def test_timeout_keeps_started_and_bounded_recovery_completes(
    tmp_path, approved_scope, now
):
    service, plan, observations, inputs = _runtime(tmp_path, approved_scope, now)
    ticks = iter((0.0, 100.0))
    service.monotonic = lambda: next(ticks)
    with pytest.raises(AdaptiveRuntimeQualificationTimedOut):
        service.execute(
            plan,
            observations=observations,
            scope=approved_scope,
            now=now + timedelta(seconds=5),
            **inputs,
        )
    assert service.store.state(plan.plan_id) == (
        AdaptiveRuntimeQualificationState.STARTED,
        1,
    )
    service.monotonic = time.monotonic
    outcome = service.recover(
        plan,
        inputs=inputs,
        observations=observations,
        scope=approved_scope,
        now=now + timedelta(seconds=6),
    )
    assert outcome.attempt == 2
    with pytest.raises(AdaptiveRuntimeRecoveryRequired, match="not awaiting"):
        service.recover(
            plan,
            inputs=inputs,
            observations=observations,
            scope=approved_scope,
            now=now + timedelta(seconds=7),
        )


def test_timeout_recovery_is_capped_at_three_attempts(
    tmp_path, approved_scope, now
):
    service, plan, observations, inputs = _runtime(tmp_path, approved_scope, now)
    ticks = iter((0.0, 100.0, 0.0, 100.0, 0.0, 100.0))
    service.monotonic = lambda: next(ticks)
    with pytest.raises(AdaptiveRuntimeQualificationTimedOut):
        service.execute(
            plan,
            observations=observations,
            scope=approved_scope,
            now=now + timedelta(seconds=5),
            **inputs,
        )
    for offset in (6, 7):
        with pytest.raises(AdaptiveRuntimeQualificationTimedOut):
            service.recover(
                plan,
                inputs=inputs,
                observations=observations,
                scope=approved_scope,
                now=now + timedelta(seconds=offset),
            )
    with pytest.raises(AdaptiveRuntimeRecoveryRequired, match="exhausted"):
        service.recover(
            plan,
            inputs=inputs,
            observations=observations,
            scope=approved_scope,
            now=now + timedelta(seconds=8),
        )
    assert service.store.state(plan.plan_id) == (
        AdaptiveRuntimeQualificationState.STARTED,
        3,
    )


def test_schema_and_ledger_cannot_carry_target_secret_or_a4_authority(
    tmp_path, approved_scope, now
):
    service, plan, observations, inputs = _runtime(tmp_path, approved_scope, now)
    raw = plan.model_dump(mode="python")
    raw["campaign_qualification_requested"] = True
    raw["plan_id"] = "0" * 64
    with pytest.raises(ValidationError):
        AdaptiveRuntimeQualificationPlan.model_validate(raw)

    service.execute(
        plan,
        observations=observations,
        scope=approved_scope,
        now=now + timedelta(seconds=5),
        **inputs,
    )
    row = service.store.connection.execute(
        "SELECT plan_json,outcome_json FROM red_team_adaptive_runtime_qualifications"
    ).fetchone()
    serialized = "".join(row).lower()
    schema = json.dumps(AdaptiveRuntimeQualificationPlan.model_json_schema()).lower()
    for forbidden in (
        "target_url",
        "password",
        "cookie",
        "credential_value",
        "provider_token",
        "docker_socket",
        "submission",
    ):
        assert forbidden not in serialized
        assert forbidden not in schema


@pytest.mark.docker_integration
@pytest.mark.rootless_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_DOCKER_INTEGRATION") != "1"
    and os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") != "1",
    reason="set VULNLOOM_DOCKER_INTEGRATION=1 for the actual B5.2 canary",
)
def test_actual_docker_success_and_timeout_probes_qualify_bound_a3_runtime(
    tmp_path: Path, approved_scope
):
    backend = DockerCliBackend()
    image = backend.inspect_image("alpine:3.22")["Id"]
    now = datetime.now(UTC)
    service, plan, _, inputs = _runtime(
        tmp_path,
        approved_scope,
        now,
        image=image,
    )
    profile = inputs["profile"]
    evidence = tmp_path / "objects" / plan.coverage_ledger_id
    evidence.mkdir(parents=True)
    (evidence / "coverage.json").write_text('{"coverage":"sealed"}\n')
    (evidence / "coverage.json").chmod(0o444)
    evidence.chmod(0o555)
    object_store = RegisteredObjectStore(
        tmp_path / "objects", {plan.coverage_ledger_id: evidence}
    )
    engine_policy = (
        DockerEnginePolicy()
        if os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") == "1"
        else DockerEnginePolicy(
            require_rootless=False,
            require_versioned_seccomp=False,
        )
    )

    def request(kind: AdaptiveRuntimeProbeKind):
        wall_seconds = 1 if kind is AdaptiveRuntimeProbeKind.TIMEOUT_CLEANUP else 20
        task = TaskEnvelope(
            engagement_id=approved_scope.engagement_id,
            target_id=inputs["adaptive_plan"].target_id,
            target_version=plan.flow_plan_id,
            scope_id=approved_scope.scope_id,
            worker_role=WorkerRole.RED_TEAM_OPERATOR,
            scope_version=approved_scope.version,
            policy_digest="9" * 64,
            sandbox_profile_digest=sandbox_profile_digest(profile),
            tool_registry_digest="8" * 64,
            input_refs=(f"coverage:{plan.coverage_ledger_id}",),
            allowed_tools=frozenset({"red_team.evidence_read"}),
            budget=TaskBudget(
                wall_seconds=wall_seconds,
                model_tokens=0,
                tool_calls=1,
            ),
            deadline=now + timedelta(seconds=30),
            idempotency_key=f"task:b5.2:{kind.value}:{uuid4()}",
        )
        return SandboxRunRequest(
            task=task,
            profile=profile,
            invocation=ToolInvocation(
                tool_id="red_team.evidence_read",
                working_directory="output",
            ),
            environment={"VULNLOOM_TASK_ID": str(task.task_id)},
            idempotency_key=f"run:b5.2:{kind.value}:{uuid4()}",
        )

    boundary_script = (
        "set -eu; "
        "[ \"$(id -u)\" = 65532 ]; "
        "grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status; "
        "grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status; "
        "grep -q '^Seccomp:[[:space:]]*2$' /proc/self/status; "
        "! touch /workspace/evidence/must-remain-read-only; "
        "[ \"$(wc -l < /proc/net/route)\" = 1 ]; "
        "[ ! -S /var/run/docker.sock ]; "
        "[ ! -e /run/host-services/docker.proxy.sock ]"
    )
    observations = []
    for kind, command in (
        (
            AdaptiveRuntimeProbeKind.BOUNDARY,
            ("/bin/sh", "-c", boundary_script, "vulnloom-b5.2-boundary"),
        ),
        (AdaptiveRuntimeProbeKind.TIMEOUT_CLEANUP, ("/bin/sleep", "300")),
    ):
        run_request = request(kind)
        runner = DockerSandboxRunner(
            backend,
            object_store,
            (
                DockerTool(
                    tool_id="red_team.evidence_read",
                    argv_prefix=command,
                ),
            ),
            engine_policy=engine_policy,
        )
        result = runner.execute(run_request, now=now)
        assert runner.last_inspection is not None
        observations.append(
            observe_docker_adaptive_runtime(
                plan=plan,
                request=run_request,
                result=result,
                inspection=runner.last_inspection,
                engine_info=backend.engine_info(),
                container_absent=not backend.exists(runner.last_inspection["Id"]),
                kind=kind,
                now=datetime.now(UTC),
            )
        )

    assert runner.last_inspection is not None
    drifted_inspection = {
        **runner.last_inspection,
        "HostConfig": {
            **runner.last_inspection["HostConfig"],
            "NetworkMode": "bridge",
        },
    }
    with pytest.raises(AdaptiveRuntimeDockerEvidenceRejected, match="boundary"):
        observe_docker_adaptive_runtime(
            plan=plan,
            request=run_request,
            result=result,
            inspection=drifted_inspection,
            engine_info=backend.engine_info(),
            container_absent=True,
            kind=AdaptiveRuntimeProbeKind.TIMEOUT_CLEANUP,
            now=datetime.now(UTC),
        )

    outcome = service.execute(
        plan,
        observations=tuple(observations),
        scope=approved_scope,
        now=now + timedelta(seconds=5),
        **inputs,
    )
    assert outcome.isolated_lab_qualified is True
    assert all(item.cleanup_verified and item.container_absent for item in observations)
    assert outcome.production_runner_admitted == (
        os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") == "1"
    )
