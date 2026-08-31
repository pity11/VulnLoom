from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest

from vulnloom.benchmark import (
    AlignmentProvenance,
    AnalyzerCaseBinding,
    AnalyzerDockerExecutionStore,
    AnalyzerEvaluationArtifactStore,
    AnalyzerEvaluationLimits,
    AnalyzerEvaluationPlan,
    AnalyzerEvaluationPolicy,
    AnalyzerEvaluationService,
    AnalyzerEvaluationStore,
    AnalyzerExecutionEvidenceBinding,
    AnalyzerExecutionPlan,
    AnalyzerImportOutcome,
    AnalyzerKind,
    AnalyzerObservation,
    AnalyzerObservationArtifact,
    AnalyzerObservationSet,
    AnalyzerQualificationIdempotencyConflict,
    AnalyzerQualificationPlan,
    AnalyzerQualificationRecoveryRequired,
    AnalyzerQualificationRejected,
    AnalyzerQualificationService,
    AnalyzerQualificationStore,
    AnalyzerResultFile,
    AnalyzerResultSnapshot,
    AnalyzerSeverity,
    AnalyzerToolRegistration,
    AnalyzerTruthAlignment,
    AnalyzerTruthMatch,
    BenchmarkCase,
    BenchmarkGateStatus,
    BenchmarkSuite,
    DockerAnalyzerExecutionOutcome,
    DockerAnalyzerExecutionStatus,
    GroundTruthFinding,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    Artifact,
    ArtifactKind,
    StaticFileCategory,
    Target,
    TargetKind,
    TargetManifest,
    TargetSnapshot,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.runners import (
    CleanupReport,
    SandboxLimits,
    SandboxOutput,
    SandboxRunRequest,
    SandboxRunResult,
    SandboxRunStatus,
    ToolInvocation,
    analyzer_profile,
    sandbox_profile_digest,
)
from vulnloom.runners.models import SandboxUsage, invocation_digest

CASE_ID = "a" * 64
TRUTH_ID = "b" * 64
MANIFEST_ID = "c" * 64
TARGET_VERSION = "d" * 40
IMAGE = "sha256:" + "e" * 64
ALL_ANALYZERS = tuple(sorted(AnalyzerKind, key=lambda item: item.value))


def _target(scope, now):
    target = Target(
        engagement_id=scope.engagement_id,
        kind=TargetKind.REPOSITORY,
        source_ref="https://example.test/app.git",
        version=TARGET_VERSION,
        ingested_at=now,
    )
    artifact = Artifact(
        artifact_id="f" * 64,
        engagement_id=scope.engagement_id,
        kind=ArtifactKind.GIT_REPOSITORY,
        source_name="fixture.git",
        source_ref=target.source_ref,
        original_size=1,
        detected_format="git",
        captured_at=now,
    )
    manifest = TargetManifest(
        manifest_id=MANIFEST_ID,
        artifact_id=artifact.artifact_id,
        target_id=target.target_id,
        target_version=target.version,
        files=(
            {
                "path": "deploy.yaml",
                "size": 1,
                "sha256": "1" * 64,
                "category": StaticFileCategory.KUBERNETES,
            },
        ),
        total_size=1,
        created_at=now,
    )
    return TargetSnapshot(target=target, artifact=artifact, manifest=manifest)


def _execution(kind, target, scope, now, index):
    rules = canonical_digest({"rules": kind.value})
    registration = AnalyzerToolRegistration.create(
        tool_id=f"analyzer.{kind.value}",
        analyzer=kind,
        tool_version="1.0.0",
        image_digest=IMAGE,
        rules_digest=rules,
        adapter_id=f"{kind.value}.fixture.v1",
        adapter_digest=canonical_digest({"adapter": kind.value}),
        argv=("/bin/analyzer", kind.value),
        output_mode="stdout",
    )
    limits = SandboxLimits(
        wall_seconds=30,
        cpu_millis=30_000,
        memory_bytes=64 * 1024 * 1024,
        pids=32,
        open_files=128,
        file_bytes=1024 * 1024,
        tmp_bytes=1024 * 1024,
    )
    profile = analyzer_profile(
        image_digest=IMAGE,
        snapshot_id=MANIFEST_ID,
        tool_id=registration.tool_id,
        limits=limits,
    )
    registry_digest = canonical_digest({"registration": registration.registration_id})
    task = TaskEnvelope(
        engagement_id=scope.engagement_id,
        target_id=target.target.target_id,
        target_version=target.target.version,
        scope_id=scope.scope_id,
        worker_role=WorkerRole.ANALYZER,
        scope_version=scope.version,
        policy_digest=canonical_digest({"scope": str(scope.scope_id)}),
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest=registry_digest,
        input_refs=(f"snapshot:{MANIFEST_ID}",),
        allowed_tools=frozenset({registration.tool_id}),
        budget=TaskBudget(wall_seconds=30, model_tokens=0, tool_calls=1),
        deadline=now + timedelta(seconds=30),
        idempotency_key=f"qualification-task:{index}",
    )
    request = SandboxRunRequest(
        task=task,
        profile=profile,
        invocation=ToolInvocation(tool_id=registration.tool_id, working_directory="source"),
        idempotency_key=f"qualification-runner:{index}",
    )
    plan = AnalyzerExecutionPlan.create(
        target=target,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        registration=registration,
        registry_digest=registry_digest,
        runner_request=request,
        created_at=now - timedelta(seconds=1),
        deadline=now + timedelta(minutes=2),
        idempotency_key=f"qualification-execution:{index}",
    )
    output_digest = canonical_digest({"output": kind.value})
    result_file = AnalyzerResultFile(
        logical_name="output.json", size=2, sha256=output_digest
    )
    snapshot = AnalyzerResultSnapshot.create(
        analyzer=kind,
        target_id=target.target.target_id,
        target_version=target.target.version,
        tool_version=registration.tool_version,
        rules_digest=registration.rules_digest,
        output=result_file,
    )
    observation = AnalyzerObservation.create(
        analyzer=kind,
        target_id=target.target.target_id,
        target_version=target.target.version,
        rule_id=f"{kind.value}/fixture",
        rule_fingerprint=canonical_digest({"rule": kind.value}),
        cwes=("CWE-79",),
        severity=AnalyzerSeverity.HIGH,
        message_digest=canonical_digest({"message": kind.value}),
    )
    observation_set = AnalyzerObservationSet.create(
        snapshot=snapshot,
        adapter_id=registration.adapter_id,
        adapter_digest=registration.adapter_digest,
        observations=(observation,),
        exclusions=(),
    )
    import_outcome = AnalyzerImportOutcome(
        plan_id=canonical_digest({"import": kind.value}),
        snapshot_id=snapshot.snapshot_id,
        observation_set=observation_set,
        artifact=AnalyzerObservationArtifact(
            observation_set_id=observation_set.observation_set_id,
            json_sha256=canonical_digest({"artifact": kind.value}),
            json_ref=f"objects/{observation_set.observation_set_id}/observations.json",
        ),
        completed_at=now,
    )
    runner_output = SandboxOutput(
        object_id=output_digest,
        logical_name="output.json",
        size=2,
        sha256=output_digest,
        content_ref=f"objects/{output_digest}/output.json",
    )
    runner_result = SandboxRunResult(
        run_id=request.run_id,
        task_id=task.task_id,
        status=SandboxRunStatus.COMPLETED,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        invocation_digest=invocation_digest(request.invocation),
        budget_used=TaskBudget(wall_seconds=1, model_tokens=0, tool_calls=1),
        usage=SandboxUsage(
            wall_seconds=0.1,
            cpu_millis=1,
            peak_memory_bytes=1,
            pids_peak=1,
            open_files_peak=1,
            output_bytes=2,
            temporary_bytes=0,
        ),
        outputs=(runner_output,),
        cleanup=CleanupReport(
            processes_terminated=True,
            network_released=True,
            writable_layer_removed=True,
            temporary_mounts_removed=True,
        ),
    )
    outcome = DockerAnalyzerExecutionOutcome(
        plan_id=plan.plan_id,
        registration_id=registration.registration_id,
        target_id=target.target.target_id,
        target_version=target.target.version,
        status=DockerAnalyzerExecutionStatus.COMPLETED,
        runner_result=runner_result,
        analyzer_result_snapshot=snapshot,
        import_outcome=import_outcome,
        completed_at=now,
    )
    binding = AnalyzerExecutionEvidenceBinding.create(
        case_id=CASE_ID,
        execution_plan=plan,
        registration=registration,
        outcome=outcome,
    )
    return registration, plan, outcome, binding, observation_set


def _setup(
    tmp_path,
    approved_scope,
    now,
    *,
    kinds=ALL_ANALYZERS,
):
    target = _target(approved_scope, now)
    executions = tuple(
        _execution(kind, target, approved_scope, now, index)
        for index, kind in enumerate(kinds)
    )
    registrations, plans, outcomes, bindings, sets = map(tuple, zip(*executions, strict=True))
    suite = BenchmarkSuite.create(
        name="m6.5-qualification",
        version="1",
        cases=(
            BenchmarkCase(
                case_id=CASE_ID,
                target_version=TARGET_VERSION,
                ground_truth=(
                    GroundTruthFinding(
                        truth_id=TRUTH_ID,
                        cwe="CWE-79",
                        duplicate_family="2" * 64,
                    ),
                ),
            ),
        ),
    )
    case_bindings = tuple(
        AnalyzerCaseBinding.create(case_id=CASE_ID, observations=item) for item in sets
    )
    matches = tuple(
        AnalyzerTruthMatch(
            case_id=CASE_ID,
            observation_set_id=item.observation_set_id,
            observation_id=item.observations[0].observation_id,
            truth_id=TRUTH_ID,
            matched_cwe="CWE-79",
        )
        for item in sets
    )
    alignment = AnalyzerTruthAlignment.create(
        suite=suite,
        provenance=AlignmentProvenance.FIXTURE,
        producer_id="m6.5.fixture",
        bindings=case_bindings,
        matches=matches,
    )
    policy = AnalyzerEvaluationPolicy(
        min_truth_recall=1.0,
        min_observation_precision=1.0,
        max_duplicate_rate=1.0,
        max_exclusion_rate=0.0,
        required_analyzers=tuple(sorted(kinds, key=lambda item: item.value)),
        require_full_case_matrix=True,
    )
    evaluation_plan = AnalyzerEvaluationPlan.create(
        suite=suite,
        alignment=alignment,
        policy=policy,
        limits=AnalyzerEvaluationLimits(),
        created_at=now - timedelta(seconds=1),
        deadline=now + timedelta(minutes=2),
        idempotency_key="m6.5:evaluation",
    )
    qualification_plan = AnalyzerQualificationPlan.create(
        suite=suite,
        alignment=alignment,
        evaluation_plan=evaluation_plan,
        execution_bindings=bindings,
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="m6.5:qualification",
    )
    evaluation_store = AnalyzerEvaluationStore(tmp_path / "evaluation.db")
    evaluation_service = AnalyzerEvaluationService(
        store=evaluation_store,
        artifact_store=AnalyzerEvaluationArtifactStore(tmp_path / "evaluation-artifacts"),
    )
    qualification_store = AnalyzerQualificationStore(tmp_path / "qualification.db")
    execution_store = AnalyzerDockerExecutionStore(tmp_path / "execution.db")
    for execution_plan, execution_outcome in zip(plans, outcomes, strict=True):
        assert execution_store.claim(execution_plan, now=now).created
        execution_store.complete(execution_outcome)
    service = AnalyzerQualificationService(
        store=qualification_store,
        execution_store=execution_store,
        evaluation_service=evaluation_service,
    )
    return (
        service,
        qualification_store,
        evaluation_store,
        execution_store,
        suite,
        plans,
        registrations,
        outcomes,
        alignment,
        evaluation_plan,
        qualification_plan,
    )


def test_completed_execution_matrix_qualifies_and_replays(tmp_path, approved_scope, now):
    values = _setup(tmp_path, approved_scope, now)
    service, qualification_store, evaluation_store, execution_store, *inputs = values

    first = service.qualify(*inputs, now=now)
    second = service.qualify(*inputs, now=now)

    assert first == second
    assert first.gate_status is BenchmarkGateStatus.PASSED
    assert first.execution_count == 4
    qualification_store.close()
    evaluation_store.close()
    execution_store.close()


def test_incomplete_matrix_is_rejected_before_any_checkpoint(tmp_path, approved_scope, now):
    values = _setup(tmp_path, approved_scope, now)
    service, qualification_store, evaluation_store, execution_store, *inputs = values
    suite, plans, registrations, outcomes, alignment, evaluation_plan, qualification_plan = inputs

    with pytest.raises(AnalyzerQualificationRejected, match="exact execution set"):
        service.qualify(
            suite,
            plans,
            registrations[:1],
            outcomes,
            alignment,
            evaluation_plan,
            qualification_plan,
            now=now,
        )
    assert qualification_store.connection.execute(
        "SELECT COUNT(*) FROM analyzer_qualifications"
    ).fetchone()[0] == 0
    assert evaluation_store.connection.execute(
        "SELECT COUNT(*) FROM analyzer_evaluations"
    ).fetchone()[0] == 0
    qualification_store.close()
    evaluation_store.close()
    execution_store.close()


def test_one_case_cannot_mix_target_or_scope_provenance(tmp_path, approved_scope, now):
    values = _setup(tmp_path, approved_scope, now)
    _, qualification_store, evaluation_store, execution_store, *inputs = values
    suite, _, _, _, alignment, evaluation_plan, qualification_plan = inputs
    mixed = qualification_plan.execution_bindings[1].model_copy(
        update={"target_id": uuid4()}
    )
    with pytest.raises(ValueError, match="share Target and Scope provenance"):
        AnalyzerQualificationPlan.create(
            suite=suite,
            alignment=alignment,
            evaluation_plan=evaluation_plan,
            execution_bindings=(qualification_plan.execution_bindings[0], mixed),
            created_at=now,
            deadline=now + timedelta(minutes=1),
            idempotency_key="m6.5:mixed-target",
        )
    qualification_store.close()
    evaluation_store.close()
    execution_store.close()


def test_execution_outcome_drift_is_rejected(tmp_path, approved_scope, now):
    values = _setup(tmp_path, approved_scope, now)
    service, qualification_store, evaluation_store, execution_store, *inputs = values
    suite, plans, registrations, outcomes, alignment, evaluation_plan, qualification_plan = inputs
    changed = outcomes[0].model_copy(update={"completed_at": now + timedelta(seconds=1)})

    with pytest.raises(AnalyzerQualificationRejected, match="provenance"):
        service.qualify(
            suite,
            plans,
            registrations,
            (changed, *outcomes[1:]),
            alignment,
            evaluation_plan,
            qualification_plan,
            now=now,
        )
    qualification_store.close()
    evaluation_store.close()
    execution_store.close()


def test_missing_authoritative_execution_checkpoint_is_rejected(
    tmp_path, approved_scope, now
):
    values = _setup(tmp_path, approved_scope, now)
    service, qualification_store, evaluation_store, execution_store, *inputs = values
    execution_store.connection.execute(
        "DELETE FROM analyzer_docker_executions WHERE plan_id = ?", (inputs[1][0].plan_id,)
    )
    execution_store.connection.commit()

    with pytest.raises(AnalyzerQualificationRejected, match="authoritative completed"):
        service.qualify(*inputs, now=now)
    assert qualification_store.connection.execute(
        "SELECT COUNT(*) FROM analyzer_qualifications"
    ).fetchone()[0] == 0
    assert evaluation_store.connection.execute(
        "SELECT COUNT(*) FROM analyzer_evaluations"
    ).fetchone()[0] == 0
    qualification_store.close()
    evaluation_store.close()
    execution_store.close()


def test_metric_regression_is_a_typed_failed_qualification(
    tmp_path, approved_scope, now
):
    values = _setup(tmp_path, approved_scope, now)
    service, qualification_store, evaluation_store, execution_store, *inputs = values
    suite, plans, registrations, outcomes, alignment, evaluation_plan, qualification_plan = inputs
    failed_alignment = AnalyzerTruthAlignment.create(
        suite=suite,
        provenance=AlignmentProvenance.FIXTURE,
        producer_id="m6.5.fixture",
        bindings=alignment.bindings,
        matches=(),
    )
    failed_evaluation = AnalyzerEvaluationPlan.create(
        suite=suite,
        alignment=failed_alignment,
        policy=evaluation_plan.policy,
        limits=evaluation_plan.limits,
        created_at=now - timedelta(seconds=1),
        deadline=now + timedelta(minutes=2),
        idempotency_key="m6.5:evaluation:failed",
    )
    failed_plan = AnalyzerQualificationPlan.create(
        suite=suite,
        alignment=failed_alignment,
        evaluation_plan=failed_evaluation,
        execution_bindings=qualification_plan.execution_bindings,
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="m6.5:qualification:failed",
    )

    outcome = service.qualify(
        suite,
        plans,
        registrations,
        outcomes,
        failed_alignment,
        failed_evaluation,
        failed_plan,
        now=now,
    )
    assert outcome.gate_status is BenchmarkGateStatus.FAILED
    assert outcome.evaluation_outcome.result.violations
    qualification_store.close()
    evaluation_store.close()
    execution_store.close()


def test_failed_or_timed_out_execution_cannot_form_a_binding(approved_scope, now):
    target = _target(approved_scope, now)
    registration, plan, outcome, _, _ = _execution(
        AnalyzerKind.CHECKOV, target, approved_scope, now, 0
    )
    failed = outcome.model_copy(
        update={
            "status": DockerAnalyzerExecutionStatus.TIMED_OUT,
            "analyzer_result_snapshot": None,
            "import_outcome": None,
        }
    )
    with pytest.raises(ValueError, match="completed bound execution"):
        AnalyzerExecutionEvidenceBinding.create(
            case_id=CASE_ID,
            execution_plan=plan,
            registration=registration,
            outcome=failed,
        )


def test_incomplete_cleanup_cannot_form_a_binding(approved_scope, now):
    target = _target(approved_scope, now)
    registration, plan, outcome, _, _ = _execution(
        AnalyzerKind.CHECKOV, target, approved_scope, now, 0
    )
    incomplete_result = outcome.runner_result.model_construct(
        **outcome.runner_result.model_dump(mode="python", exclude={"cleanup"}),
        cleanup=CleanupReport(
            processes_terminated=True,
            network_released=True,
            writable_layer_removed=False,
            temporary_mounts_removed=True,
        ),
    )
    incomplete = outcome.model_construct(
        **outcome.model_dump(mode="python", exclude={"runner_result"}),
        runner_result=incomplete_result,
    )
    with pytest.raises(ValueError, match="completed bound execution"):
        AnalyzerExecutionEvidenceBinding.create(
            case_id=CASE_ID,
            execution_plan=plan,
            registration=registration,
            outcome=incomplete,
        )


def test_expired_qualification_is_rejected_without_checkpoint(
    tmp_path, approved_scope, now
):
    values = _setup(tmp_path, approved_scope, now)
    service, qualification_store, evaluation_store, execution_store, *inputs = values
    plan = inputs[-1]
    with pytest.raises(AnalyzerQualificationRejected, match="not active"):
        service.qualify(*inputs, now=plan.deadline)
    assert qualification_store.connection.execute(
        "SELECT COUNT(*) FROM analyzer_qualifications"
    ).fetchone()[0] == 0
    assert evaluation_store.connection.execute(
        "SELECT COUNT(*) FROM analyzer_evaluations"
    ).fetchone()[0] == 0
    qualification_store.close()
    evaluation_store.close()
    execution_store.close()


def test_store_rejects_conflicting_or_unfinished_replay(tmp_path, approved_scope, now):
    values = _setup(tmp_path, approved_scope, now)
    _, store, evaluation_store, execution_store, *inputs = values
    plan = inputs[-1]
    assert store.claim(plan, now=now).created
    with pytest.raises(AnalyzerQualificationRecoveryRequired):
        store.claim(plan, now=now)

    changed = plan.model_copy(
        update={
            "plan_id": "9" * 64,
        }
    )
    with pytest.raises(AnalyzerQualificationIdempotencyConflict):
        store.claim(changed, now=now)
    store.close()
    evaluation_store.close()
    execution_store.close()
