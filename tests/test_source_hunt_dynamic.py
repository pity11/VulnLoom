from __future__ import annotations

import hashlib
import json
from datetime import timedelta

import pytest
from pydantic import ValidationError
from test_source_hunt import _execution_fixture

from vulnloom.benchmark import BenchmarkGateStatus
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, ApprovalRequest, ApprovalStatus
from vulnloom.runners import OfflineSandboxRunner, RunnerOutputStore, SandboxRunResult
from vulnloom.source_hunt import (
    SourceCrashDeduplicationService,
    SourceCrashDisposition,
    SourceCrashFrame,
    SourceCrashSignal,
    SourceCrashSignature,
    SourceCrashStore,
    SourceDynamicToolRegistry,
    SourceExecutionPlanningService,
    SourceExecutionRejected,
    SourceExecutionService,
    SourceExecutionStage,
    SourceExecutionStatus,
    SourceExecutionStore,
    SourcePovBenchmarkCase,
    SourcePovBenchmarkResult,
    SourcePovBenchmarkService,
    SourcePovQualificationRejected,
    SourceSanitizer,
    SourceToolReport,
    StructuredSourceToolEvidenceAdapter,
    native_coverage_asan_registrations,
    source_execution_approval_digest,
)


def _signature() -> SourceCrashSignature:
    return SourceCrashSignature.create(
        sanitizer=SourceSanitizer.ADDRESS,
        signal=SourceCrashSignal.SEGV,
        failure_class="heap-buffer-overflow",
        frames=(
            SourceCrashFrame(
                module="benchmark",
                symbol="parse_packet",
                source_path="src/parser.c",
                source_line=27,
            ),
            SourceCrashFrame(
                module="benchmark",
                symbol="LLVMFuzzerTestOneInput",
                source_path="harness/fuzz.c",
                source_line=11,
            ),
        ),
    )


class _StructuredRunner:
    def __init__(self, *, registry, output_store, candidate_digest, signature):
        self.delegate = OfflineSandboxRunner(
            frozenset(f"source.{stage.value}" for stage in SourceExecutionStage)
        )
        self.registry = registry
        self.output_store = output_store
        self.input_digest = candidate_digest
        self.signature = signature
        self.crash_input_digest = hashlib.sha256(b"trigger-input").hexdigest()
        self.calls = 0

    def execute(self, request, *, now):
        stage = SourceExecutionStage(request.environment["VULNLOOM_STAGE"])
        output_digest = canonical_digest(
            {"stage": stage.value, "input_digest": self.input_digest}
        )
        crash_stage = stage in {
            SourceExecutionStage.FUZZ,
            SourceExecutionStage.SANITIZER,
            SourceExecutionStage.POV_REPLAY,
        }
        report = SourceToolReport(
            protocol="vulnloom.source-tool-report.v1",
            registration_id=self.registry.get(stage).registration_id,
            toolchain=self.registry.get(stage).toolchain,
            tool_version=self.registry.get(stage).tool_version,
            adapter_digest=self.registry.get(stage).adapter_digest,
            stage=stage,
            input_digest=self.input_digest,
            output_digest=output_digest,
            coverage_edges=23 if stage is SourceExecutionStage.FUZZ else 0,
            crash_input_digest=self.crash_input_digest if crash_stage else None,
            crash_signature=self.signature if crash_stage else None,
            pov_reproduced=stage is SourceExecutionStage.POV_REPLAY,
        )
        output = self.output_store._publish(report.model_dump_json().encode())
        base = self.delegate.execute(request, now=now)
        self.input_digest = output_digest
        self.calls += 1
        return SandboxRunResult.model_validate(
            base.model_copy(update={"outputs": (output,)}).model_dump(mode="python")
        )


def _dynamic_execution(tmp_path, approved_scope, now):
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
    ) = _execution_fixture(tmp_path, approved_scope, now)
    image_digest = "sha256:" + "4" * 64
    registry = SourceDynamicToolRegistry(
        native_coverage_asan_registrations(image_digest=image_digest)
    )
    plan = SourceExecutionPlanningService().prepare(
        index=index,
        investigation=checkpoint,
        candidate=candidate,
        scope=scope,
        image_digest=image_digest,
        tool_registry_digest=registry.digest,
        tool_registry=registry,
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="r9:dynamic:execution",
        stage_wall_seconds=60,
    )
    approval = ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=index.target_id,
        action=ApprovalAction.RUN_UNTRUSTED_BUILD,
        action_digest=source_execution_approval_digest(plan),
        expected_side_effects=("execute fixed native benchmark in isolated sandbox",),
        evidence_summary="Operator approved the exact sealed native toolchain plan",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=5),
        status=ApprovalStatus.GRANTED,
        decided_by="benchmark-operator",
        decided_at=now,
    )
    output_store = RunnerOutputStore(tmp_path / "dynamic-outputs", max_output_bytes=1_048_576)
    signature = _signature()
    runner = _StructuredRunner(
        registry=registry,
        output_store=output_store,
        candidate_digest=plan.candidate_digest,
        signature=signature,
    )
    execution_store = SourceExecutionStore(tmp_path / "dynamic-executions.sqlite3")
    outcome = SourceExecutionService(
        scope=scope,
        runner=runner,
        evidence_store=evidence_store,
        store=execution_store,
        output_evidence_adapter=StructuredSourceToolEvidenceAdapter(
            registry=registry,
            output_store=output_store,
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
    return hunt_store, plan, outcome, signature, registry, execution_store


def test_native_toolchain_normalizes_deduplicates_and_replays_benchmark_after_restart(
    tmp_path, approved_scope, now
):
    hunt_store, plan, outcome, signature, registry, execution_store = _dynamic_execution(
        tmp_path, approved_scope, now
    )
    assert outcome.status is SourceExecutionStatus.COMPLETED
    assert outcome.reproducible_pov
    assert len(outcome.evidence_refs) == 10
    assert outcome.stage_receipts[2].coverage_edges == 23
    assert {item.crash_fingerprint for item in outcome.stage_receipts[2:]} == {
        signature.fingerprint
    }
    assert len({item.crash_input_digest for item in outcome.stage_receipts[2:]}) == 1
    assert all(item.cleanup.complete for item in outcome.runner_results)
    assert all(tool.argv_prefix[0].startswith("/") for tool in registry.docker_tools)

    crash_path = tmp_path / "crashes.sqlite3"
    with SourceCrashStore(crash_path) as crash_store:
        registered = SourceCrashDeduplicationService(store=crash_store).register(
            signature=signature,
            plan=plan,
            outcome=outcome,
            observed_at=now,
            idempotency_key="r9:crash:one",
        )
        replayed = SourceCrashDeduplicationService(store=crash_store).register(
            signature=signature,
            plan=plan,
            outcome=outcome,
            observed_at=now,
            idempotency_key="r9:crash:one",
        )
        assert registered == replayed
        assert registered.disposition is SourceCrashDisposition.NEW
        assert registered.record.observation_count == 1

    case = SourcePovBenchmarkCase.create(
        name="heap_overflow",
        target_version=plan.target_version,
        candidate_digest=plan.candidate_digest,
        expected_crash_fingerprint=signature.fingerprint,
        expected_sanitizer=SourceSanitizer.ADDRESS,
    )
    execution_store.close()
    with (
        SourceExecutionStore(tmp_path / "dynamic-executions.sqlite3") as restarted_execution,
        SourceCrashStore(crash_path) as restarted_crashes,
    ):
        result = SourcePovBenchmarkService(
            execution_store=restarted_execution, crash_store=restarted_crashes
        ).evaluate(case=case, plan=plan, outcome=outcome, now=now + timedelta(seconds=1))
    assert result.gate_status is BenchmarkGateStatus.PASSED
    assert result.pov_artifact.crash_fingerprint == signature.fingerprint
    assert result.pov_artifact.input_digest == outcome.stage_receipts[-1].crash_input_digest
    hunt_store.close()


def test_crash_catalog_deduplicates_across_distinct_plans_and_rejects_collisions(
    tmp_path, approved_scope, now
):
    hunt_store, plan, outcome, signature, _, execution_store = _dynamic_execution(
        tmp_path, approved_scope, now
    )
    input_digest = outcome.stage_receipts[-1].crash_input_digest
    assert input_digest is not None
    with SourceCrashStore(tmp_path / "dedup.sqlite3") as store:
        first = store.register(
            signature=signature,
            plan_id=plan.plan_id,
            input_digest=input_digest,
            observed_at=now,
            idempotency_key="r9:dedup:one",
        )
        second = store.register(
            signature=signature,
            plan_id="e" * 64,
            input_digest=hashlib.sha256(b"smaller-trigger").hexdigest(),
            observed_at=now + timedelta(seconds=1),
            idempotency_key="r9:dedup:two",
        )
        assert first.disposition is SourceCrashDisposition.NEW
        assert second.disposition is SourceCrashDisposition.DUPLICATE
        assert second.record.observation_count == 2
        assert second.record.canonical_input_digest == input_digest
        with pytest.raises(ValueError, match="idempotency collision"):
            store.register(
                signature=signature,
                plan_id="d" * 64,
                input_digest=input_digest,
                observed_at=now,
                idempotency_key="r9:dedup:one",
            )
    execution_store.close()
    hunt_store.close()


def test_native_report_registry_timeout_and_security_paths_fail_closed(
    tmp_path, approved_scope, now
):
    hunt_store, plan, outcome, signature, registry, execution_store = _dynamic_execution(
        tmp_path, approved_scope, now
    )
    with pytest.raises(ValidationError, match="source path"):
        SourceCrashFrame(
            module="benchmark",
            symbol="parse_packet",
            source_path="/host/private/parser.c",
            source_line=1,
        )
    with pytest.raises(ValidationError, match="content digest"):
        SourceCrashSignature.model_validate(
            signature.model_dump(mode="python") | {"failure_class": "stack-buffer-overflow"}
        )
    with pytest.raises(ValidationError, match="does not prove"):
        SourceToolReport(
            protocol="vulnloom.source-tool-report.v1",
            registration_id=registry.get(SourceExecutionStage.FUZZ).registration_id,
            toolchain=registry.get(SourceExecutionStage.FUZZ).toolchain,
            tool_version=registry.get(SourceExecutionStage.FUZZ).tool_version,
            adapter_digest=registry.get(SourceExecutionStage.FUZZ).adapter_digest,
            stage=SourceExecutionStage.FUZZ,
            input_digest="1" * 64,
            output_digest=canonical_digest(
                {"stage": "fuzz", "input_digest": "1" * 64}
            ),
            coverage_edges=0,
            crash_input_digest="3" * 64,
            crash_signature=signature,
        )

    schema = json.dumps(
        {
            "signature": SourceCrashSignature.model_json_schema(),
            "report": SourceToolReport.model_json_schema(),
            "result": SourcePovBenchmarkResult.model_json_schema(),
        }
    ).lower()
    for forbidden in ("authorization", "cookie", "api_key", "endpoint", "raw_response"):
        assert forbidden not in schema

    drifted = plan.model_copy(
        update={
            "steps": tuple(
                step.model_copy(
                    update={
                        "request": step.request.model_copy(
                            update={
                                "task": step.request.task.model_copy(
                                    update={"tool_registry_digest": "a" * 64}
                                )
                            }
                        )
                    }
                )
                for step in plan.steps
            )
        }
    )
    with pytest.raises(ValidationError, match="content digest"):
        type(plan).model_validate(drifted.model_dump(mode="python"))

    wrong_case = SourcePovBenchmarkCase.create(
        name="wrong_heap_overflow",
        target_version=plan.target_version,
        candidate_digest=plan.candidate_digest,
        expected_crash_fingerprint="f" * 64,
        expected_sanitizer=SourceSanitizer.ADDRESS,
    )
    with SourceCrashStore(tmp_path / "security-crashes.sqlite3") as crash_store:
        SourceCrashDeduplicationService(store=crash_store).register(
            signature=signature,
            plan=plan,
            outcome=outcome,
            observed_at=now,
            idempotency_key="r9:security:crash",
        )
        with pytest.raises(SourcePovQualificationRejected, match="drifted"):
            SourcePovBenchmarkService(
                execution_store=execution_store, crash_store=crash_store
            ).evaluate(case=wrong_case, plan=plan, outcome=outcome, now=now)
    execution_store.close()
    hunt_store.close()


def test_structured_adapter_rejects_duplicate_keys_without_persisting_receipt(
    tmp_path, approved_scope, now
):
    fixture = _execution_fixture(tmp_path, approved_scope, now)
    hunt_store, index, _, _, _, _, _, evidence_store, _ = fixture
    image_digest = "sha256:" + "4" * 64
    registry = SourceDynamicToolRegistry(
        native_coverage_asan_registrations(image_digest=image_digest)
    )
    output_store = RunnerOutputStore(tmp_path / "bad-output")
    output = output_store._publish(
        b'{"protocol":"vulnloom.source-tool-report.v1","protocol":"duplicate"}'
    )
    existing_objects = set(evidence_store.objects.iterdir())
    request = _execution_fixture(tmp_path / "other", approved_scope, now)[5].steps[0].request
    result = OfflineSandboxRunner(frozenset({"source.build"})).execute(request, now=now)
    result = SandboxRunResult.model_validate(
        result.model_copy(update={"outputs": (output,)}).model_dump(mode="python")
    )
    adapter = StructuredSourceToolEvidenceAdapter(
        registry=registry, output_store=output_store, evidence_store=evidence_store
    )
    with pytest.raises(SourceExecutionRejected, match="report is invalid"):
        adapter.capture(
            stage=SourceExecutionStage.BUILD,
            result=result,
            target_version=index.target_version,
        )
    assert set(evidence_store.objects.iterdir()) == existing_objects
    hunt_store.close()
