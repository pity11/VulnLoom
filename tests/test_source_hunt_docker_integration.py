from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

import pytest
from test_source_hunt import _execution_fixture

from vulnloom.benchmark import BenchmarkGateStatus
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, ApprovalRequest, ApprovalStatus
from vulnloom.runners import (
    DockerCliBackend,
    DockerEnginePolicy,
    DockerSandboxRunner,
    DockerTool,
    RegisteredObjectStore,
    RunnerOutputStore,
)
from vulnloom.source_hunt import (
    RunnerOutputEvidenceAdapter,
    SourceCrashDeduplicationService,
    SourceCrashStore,
    SourceDynamicToolRegistry,
    SourceExecutionPlanningService,
    SourceExecutionService,
    SourceExecutionStage,
    SourceExecutionStatus,
    SourceExecutionStore,
    SourcePovBenchmarkCase,
    SourcePovBenchmarkService,
    SourceSanitizer,
    SourceStageReceipt,
    SourceToolReport,
    StructuredSourceToolEvidenceAdapter,
    native_coverage_asan_registrations,
    source_execution_approval_digest,
)


def _engine_policy() -> DockerEnginePolicy:
    if os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") == "1":
        return DockerEnginePolicy()
    return DockerEnginePolicy(require_rootless=False, require_versioned_seccomp=False)


@pytest.mark.docker_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_DOCKER_INTEGRATION") != "1",
    reason="set VULNLOOM_DOCKER_INTEGRATION=1 to run real Source Hunt isolation",
)
def test_real_source_execution_chain_is_networkless_secretless_and_clean(
    tmp_path, approved_scope, now
):
    backend = DockerCliBackend()
    image = backend.inspect_image("alpine:3.22")["Id"]
    fixture = _execution_fixture(tmp_path, approved_scope, now, image=image)
    (
        hunt_store,
        index,
        scope,
        checkpoint,
        candidate,
        plan,
        approval,
        evidence_store,
        _,
    ) = fixture
    source = tmp_path / "objects" / "snapshots" / index.manifest_id
    outputs = RunnerOutputStore(tmp_path / "runner-outputs")
    probe = """
set -eu
[ "$(id -u)" = "65532" ]
grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status
grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status
! touch /workspace/source/must-remain-read-only
[ "$(wc -l < /proc/net/route)" = "1" ]
[ ! -S /var/run/docker.sock ]
[ -z "${VULNLOOM_MODEL_API_KEY+x}" ]
printf '%s' '__RECEIPT__'
""".strip()
    tools = []
    input_digest = plan.candidate_digest
    for stage in SourceExecutionStage:
        output_digest = canonical_digest(
            {"stage": stage.value, "input_digest": input_digest}
        )
        receipt = SourceStageReceipt.create(
            stage=stage,
            input_digest=input_digest,
            output_digest=output_digest,
            coverage_edges=17 if stage is SourceExecutionStage.FUZZ else 0,
            crash_fingerprint=(
                "9" * 64
                if stage
                in {
                    SourceExecutionStage.FUZZ,
                    SourceExecutionStage.SANITIZER,
                    SourceExecutionStage.POV_REPLAY,
                }
                else None
            ),
            sanitizer=(
                SourceSanitizer.ADDRESS
                if stage is SourceExecutionStage.SANITIZER
                else None
            ),
            pov_reproduced=stage is SourceExecutionStage.POV_REPLAY,
        )
        tools.append(
            DockerTool(
                tool_id=f"source.{stage.value}",
                argv_prefix=(
                    "/bin/sh",
                    "-c",
                    probe.replace("__RECEIPT__", receipt.model_dump_json()),
                    "source-hunt-stage",
                ),
            )
        )
        input_digest = output_digest
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {index.manifest_id: source}),
        tuple(tools),
        engine_policy=_engine_policy(),
        output_store=outputs,
        captured_output_tools=frozenset(
            {
                "source.build",
                "source.harness",
                "source.fuzz",
                "source.sanitizer",
                "source.pov_replay",
            }
        ),
    )
    with SourceExecutionStore(tmp_path / "docker-execution.sqlite3") as store:
        outcome = SourceExecutionService(
            scope=scope,
            runner=runner,
            evidence_store=evidence_store,
            store=store,
            output_evidence_adapter=RunnerOutputEvidenceAdapter(
                output_store=outputs, evidence_store=evidence_store
            ),
        ).execute(
            plan=plan,
            index=index,
            investigation=checkpoint,
            candidate=candidate,
            approval=approval,
            now=now,
        )
    assert outcome.status is SourceExecutionStatus.COMPLETED
    assert outcome.reproducible_pov
    assert len(outcome.evidence_refs) == 5
    assert all(item.cleanup.complete for item in outcome.runner_results)
    assert runner.last_inspection is not None
    assert not backend.exists(runner.last_inspection["Id"])
    hunt_store.close()


@pytest.mark.docker_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_R9_NATIVE_INTEGRATION") != "1",
    reason="set VULNLOOM_R9_NATIVE_INTEGRATION=1 for the fixed native R9 Benchmark",
)
def test_real_native_coverage_asan_crash_and_independent_pov_replay(
    tmp_path, approved_scope, now
):
    backend = DockerCliBackend()
    image = backend.inspect_image("vulnloom-r9-native:local")["Id"]
    fixture_root = Path(__file__).parent / "fixtures" / "r9_native" / "source"
    fixture = _execution_fixture(
        tmp_path,
        approved_scope,
        now,
        image=image,
        extra_files={
            "target.c": (fixture_root / "target.c").read_text(),
            "harness.c": (fixture_root / "harness.c").read_text(),
        },
    )
    (
        hunt_store,
        index,
        scope,
        checkpoint,
        candidate,
        _,
        _,
        evidence_store,
        _,
    ) = fixture
    registry = SourceDynamicToolRegistry(
        native_coverage_asan_registrations(
            image_digest=image,
            image_environment={"DEBIAN_FRONTEND": "noninteractive"},
        )
    )
    plan = SourceExecutionPlanningService().prepare(
        index=index,
        investigation=checkpoint,
        candidate=candidate,
        scope=scope,
        image_digest=image,
        tool_registry_digest=registry.digest,
        tool_registry=registry,
        now=now,
        deadline=now + timedelta(minutes=10),
        idempotency_key="r9:native-docker:execution",
        stage_wall_seconds=60,
    )
    approval = ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=index.target_id,
        action=ApprovalAction.RUN_UNTRUSTED_BUILD,
        action_digest=source_execution_approval_digest(plan),
        expected_side_effects=("execute fixed native benchmark in isolated containers",),
        evidence_summary="Operator approved the exact native R9 Benchmark plan",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=10),
        status=ApprovalStatus.GRANTED,
        decided_by="integration-operator",
        decided_at=now,
    )
    source = tmp_path / "objects" / "snapshots" / index.manifest_id
    outputs = RunnerOutputStore(tmp_path / "native-runner-outputs", max_output_bytes=1_048_576)
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {index.manifest_id: source}),
        registry.docker_tools,
        engine_policy=_engine_policy(),
        output_store=outputs,
        captured_output_tools=frozenset(item.tool_id for item in registry.docker_tools),
    )
    with SourceExecutionStore(tmp_path / "native-execution.sqlite3") as store:
        outcome = SourceExecutionService(
            scope=scope,
            runner=runner,
            evidence_store=evidence_store,
            store=store,
            output_evidence_adapter=StructuredSourceToolEvidenceAdapter(
                registry=registry,
                output_store=outputs,
                evidence_store=evidence_store,
            ),
        ).execute(
            plan=plan,
            index=index,
            investigation=checkpoint,
            candidate=candidate,
            approval=approval,
            now=now,
        )
        fuzz_report = SourceToolReport.model_validate_json(
            evidence_store.read_text_ref(outcome.evidence_refs[4])
        )
        assert fuzz_report.crash_signature is not None
        with SourceCrashStore(tmp_path / "native-crashes.sqlite3") as crash_store:
            registration = SourceCrashDeduplicationService(store=crash_store).register(
                signature=fuzz_report.crash_signature,
                plan=plan,
                outcome=outcome,
                observed_at=now,
                idempotency_key="r9:native-docker:crash",
            )
            case = SourcePovBenchmarkCase.create(
                name="fixed_heap_overflow",
                target_version=plan.target_version,
                candidate_digest=plan.candidate_digest,
                expected_crash_fingerprint=fuzz_report.crash_signature.fingerprint,
                expected_sanitizer=SourceSanitizer.ADDRESS,
            )
            benchmark = SourcePovBenchmarkService(
                execution_store=store, crash_store=crash_store
            ).evaluate(case=case, plan=plan, outcome=outcome, now=now)
    assert outcome.status is SourceExecutionStatus.COMPLETED
    assert outcome.reproducible_pov
    assert outcome.stage_receipts[2].coverage_edges > 0
    assert len({item.crash_fingerprint for item in outcome.stage_receipts[2:]}) == 1
    assert len({item.crash_input_digest for item in outcome.stage_receipts[2:]}) == 1
    assert all(item.cleanup.complete for item in outcome.runner_results)
    assert registration.record.observation_count == 1
    assert benchmark.gate_status is BenchmarkGateStatus.PASSED
    assert runner.last_inspection is not None
    tmpfs = runner.last_inspection["HostConfig"]["Tmpfs"]
    assert "noexec" in tmpfs["/tmp"]
    assert "exec" in tmpfs["/workspace/output"]
    assert not backend.exists(runner.last_inspection["Id"])
    hunt_store.close()
