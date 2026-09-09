"""Approval-gated orchestration of isolated source validation stages."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import NAMESPACE_URL, uuid5

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    Candidate,
    CandidateState,
    Evidence,
    EvidenceBundle,
    EvidenceKind,
    Scope,
    ScopeState,
    ValidationResult,
    ValidationRun,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.domain.state_machine import (
    complete_validation,
    queue_validation,
    transition_candidate,
)
from vulnloom.evidence import EvidenceStore
from vulnloom.policy import PolicyEngine
from vulnloom.runners import (
    NetworkMode,
    RunnerOutputStore,
    SandboxProfileKind,
    SandboxRunRequest,
    SandboxRunResult,
    SandboxRunStatus,
    ToolInvocation,
)
from vulnloom.runners.models import invocation_digest, sandbox_profile_digest
from vulnloom.validation import candidate_content_digest

from .execution_models import (
    SOURCE_EXECUTION_STAGES,
    SOURCE_EXECUTION_TOOLS,
    SourceExecutionOutcome,
    SourceExecutionPlan,
    SourceExecutionStatus,
    SourceExecutionStep,
    SourceStageReceipt,
    SourceValidationBinding,
    source_execution_approval_digest,
    source_execution_profile,
)
from .execution_store import SourceExecutionStore
from .models import InvestigationCheckpoint, InvestigationStatus, RepositoryIndex


class SourceExecutionRejected(ValueError):
    pass


class SourceExecutionPlanningService:
    """Builds the fixed, digest-bound validation chain from trusted inputs."""

    def prepare(
        self,
        *,
        index: RepositoryIndex,
        investigation: InvestigationCheckpoint,
        candidate: Candidate,
        scope: Scope,
        image_digest: str,
        tool_registry_digest: str,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
        stage_wall_seconds: int = 600,
    ) -> SourceExecutionPlan:
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or not now < deadline <= scope.valid_until
            or investigation.status is not InvestigationStatus.READY_FOR_CANDIDATES
            or investigation.index_id != index.index_id
            or index.scope_id != scope.scope_id
            or index.scope_version != scope.version
            or candidate.state is not CandidateState.PROPOSED
            or candidate.source_graph_id != index.index_id
            or candidate.target_id != index.target_id
            or candidate.target_version != index.target_version
            or candidate.scope_id != scope.scope_id
            or candidate.scope_version != scope.version
        ):
            raise SourceExecutionRejected("source execution planning preflight failed")
        if not 0 < stage_wall_seconds <= 600:
            raise SourceExecutionRejected("source execution stage budget is invalid")
        profile = source_execution_profile(
            image_digest=image_digest, snapshot_id=index.manifest_id
        )
        candidate_digest = candidate_content_digest(candidate)
        profile_digest = sandbox_profile_digest(profile)
        policy_digest = PolicyEngine(scope).policy_digest
        steps = []
        for stage in SOURCE_EXECUTION_STAGES:
            stable_name = f"vulnloom:source-execution:{idempotency_key}:{stage.value}"
            task = TaskEnvelope(
                task_id=uuid5(NAMESPACE_URL, f"{stable_name}:task"),
                engagement_id=scope.engagement_id,
                target_id=index.target_id,
                target_version=index.target_version,
                scope_id=scope.scope_id,
                worker_role=WorkerRole.VALIDATOR,
                scope_version=scope.version,
                policy_digest=policy_digest,
                sandbox_profile_digest=profile_digest,
                tool_registry_digest=tool_registry_digest,
                input_refs=(
                    f"source-hunt:{investigation.checkpoint_id}",
                    f"candidate:{candidate_digest}",
                ),
                allowed_tools=profile.allowed_tools,
                budget=TaskBudget(
                    wall_seconds=stage_wall_seconds, model_tokens=0, tool_calls=1
                ),
                deadline=deadline,
                idempotency_key=f"{idempotency_key}:{stage.value}:task",
            )
            steps.append(
                SourceExecutionStep(
                    stage=stage,
                    request=SandboxRunRequest(
                        run_id=uuid5(NAMESPACE_URL, f"{stable_name}:run"),
                        task=task,
                        profile=profile,
                        invocation=ToolInvocation(
                            tool_id=SOURCE_EXECUTION_TOOLS[stage],
                            arguments=(),
                            working_directory="source",
                        ),
                        environment={"VULNLOOM_STAGE": stage.value},
                        idempotency_key=f"{idempotency_key}:{stage.value}:run",
                    ),
                )
            )
        return SourceExecutionPlan.create(
            investigation_plan_id=investigation.plan_id,
            investigation_checkpoint_id=investigation.checkpoint_id,
            index_id=index.index_id,
            candidate_id=candidate.candidate_id,
            candidate_digest=candidate_digest,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            target_version=index.target_version,
            steps=tuple(steps),
            created_at=now,
            deadline=deadline,
            idempotency_key=idempotency_key,
        )


class SourceRunner(Protocol):
    def execute(self, request, *, now: datetime) -> SandboxRunResult: ...


class SourceExecutionEvidenceAdapter(Protocol):
    def capture(
        self, *, stage, result: SandboxRunResult, target_version: str
    ) -> tuple[str, ...]: ...


class RunnerOutputEvidenceAdapter:
    """Turns bounded Runner outputs into redacted, content-addressed Evidence."""

    def __init__(self, *, output_store: RunnerOutputStore, evidence_store: EvidenceStore):
        self.output_store = output_store
        self.evidence_store = evidence_store

    def capture(self, *, stage, result, target_version):
        references = []
        for output in result.outputs:
            try:
                content = self.output_store.read(output).decode("utf-8", "strict")
            except (UnicodeDecodeError, ValueError) as exc:
                raise SourceExecutionRejected(
                    "source execution output is unavailable or not UTF-8"
                ) from exc
            evidence = self.evidence_store.capture_text(
                content,
                kind=EvidenceKind.TEST,
                source_ref=f"runner-output:{output.object_id}",
                producer=f"source-hunt.{stage.value}",
                target_version=target_version,
                summary=f"Isolated {stage.value} output",
            )
            references.append(evidence.evidence_id)
        return tuple(references)


class SourceExecutionService:
    def __init__(
        self,
        *,
        scope: Scope,
        runner: SourceRunner,
        evidence_store: EvidenceStore,
        store: SourceExecutionStore,
        output_evidence_adapter: SourceExecutionEvidenceAdapter | None = None,
    ):
        self.scope = scope
        self.runner = runner
        self.evidence_store = evidence_store
        self.store = store
        self.output_evidence_adapter = output_evidence_adapter

    def execute(
        self,
        *,
        plan: SourceExecutionPlan,
        index: RepositoryIndex,
        investigation: InvestigationCheckpoint,
        candidate: Candidate,
        approval: ApprovalRequest,
        now: datetime,
    ) -> SourceExecutionOutcome:
        self.preflight(plan, index, investigation, candidate, approval, now=now)
        initial = SourceExecutionOutcome(
            plan_id=plan.plan_id,
            status=SourceExecutionStatus.RUNNING,
            executed_stages=(),
            runner_results=(),
            stage_receipts=(),
            evidence_refs=(),
            reason_code="execution_started",
            updated_at=now,
        )
        outcome = self.store.claim(plan, initial)
        if outcome.status is not SourceExecutionStatus.RUNNING:
            return outcome
        for step in plan.steps[len(outcome.runner_results) :]:
            result = self.runner.execute(step.request, now=now)
            if (
                result.run_id != step.request.run_id
                or result.task_id != step.request.task.task_id
                or result.sandbox_profile_digest != sandbox_profile_digest(step.request.profile)
                or result.invocation_digest != invocation_digest(step.request.invocation)
            ):
                raise SourceExecutionRejected("source Runner result provenance mismatch")
            captured = (
                self.output_evidence_adapter.capture(
                    stage=step.stage,
                    result=result,
                    target_version=index.target_version,
                )
                if self.output_evidence_adapter is not None and result.outputs
                else ()
            )
            if captured:
                result = result.model_copy(
                    update={
                        "evidence_refs": tuple(
                            dict.fromkeys((*result.evidence_refs, *captured))
                        )
                    }
                )
                result = SandboxRunResult.model_validate(result.model_dump(mode="python"))
            for evidence_ref in result.evidence_refs:
                if not self.evidence_store.contains(evidence_ref):
                    raise SourceExecutionRejected("source Runner returned unavailable Evidence")
            status, reason = self._status(result)
            receipt = (
                self._receipt(
                    step.stage,
                    result,
                    expected_input=(
                        plan.candidate_digest
                        if not outcome.stage_receipts
                        else outcome.stage_receipts[-1].output_digest
                    ),
                    prior=outcome.stage_receipts,
                )
                if status is SourceExecutionStatus.RUNNING
                else None
            )
            executed = (*outcome.executed_stages, step.stage)
            results = (*outcome.runner_results, result)
            receipts = (
                (*outcome.stage_receipts, receipt)
                if receipt is not None
                else outcome.stage_receipts
            )
            refs = tuple(
                dict.fromkeys((*outcome.evidence_refs, *result.evidence_refs))
            )
            next_outcome = SourceExecutionOutcome(
                plan_id=plan.plan_id,
                status=status,
                executed_stages=executed,
                runner_results=results,
                stage_receipts=receipts,
                evidence_refs=refs,
                reproducible_pov=(
                    status is SourceExecutionStatus.COMPLETED
                    and executed == SOURCE_EXECUTION_STAGES
                    and bool(result.evidence_refs)
                ),
                reason_code=reason,
                updated_at=now,
            )
            self.store.save(plan, outcome, next_outcome)
            outcome = next_outcome
            if status is not SourceExecutionStatus.RUNNING:
                return outcome
        final = outcome.model_copy(
            update={
                "status": SourceExecutionStatus.COMPLETED,
                "reproducible_pov": True,
                "reason_code": "pov_reproduced",
            }
        )
        # Revalidate the derived terminal claim before committing it.
        final = SourceExecutionOutcome.model_validate(final.model_dump(mode="python"))
        self.store.save(plan, outcome, final)
        return final

    def preflight(
        self, plan, index, investigation, candidate, approval, *, now: datetime
    ) -> None:
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or now >= plan.deadline
        ):
            raise SourceExecutionRejected("source execution is outside approved Scope")
        if (
            plan.scope_id != self.scope.scope_id
            or plan.scope_version != self.scope.version
            or plan.index_id != index.index_id
            or plan.target_version != index.target_version
            or plan.investigation_plan_id != investigation.plan_id
            or plan.investigation_checkpoint_id != investigation.checkpoint_id
            or investigation.status is not InvestigationStatus.READY_FOR_CANDIDATES
            or candidate.state is not CandidateState.PROPOSED
            or plan.candidate_id != candidate.candidate_id
            or plan.candidate_digest != candidate_content_digest(candidate)
            or candidate.source_graph_id != index.index_id
            or candidate.target_id != index.target_id
            or candidate.target_version != index.target_version
        ):
            raise SourceExecutionRejected("source execution provenance is incomplete")
        if not approval.is_valid_for(
            action=ApprovalAction.RUN_UNTRUSTED_BUILD,
            digest=source_execution_approval_digest(plan),
            now=now,
        ) or (
            approval.engagement_id != self.scope.engagement_id
            or approval.target_id != index.target_id
            or approval.policy_version != self.scope.version
            or approval.decided_by is None
            or approval.decided_at is None
        ):
            raise SourceExecutionRejected(
                "source execution requires exact untrusted-build approval"
            )
        expected_input = f"source-hunt:{investigation.checkpoint_id}"
        expected_candidate = f"candidate:{plan.candidate_digest}"
        for step in plan.steps:
            request = step.request
            snapshot_mounts = tuple(
                mount
                for mount in request.profile.mounts
                if mount.kind.value == "snapshot"
            )
            if (
                request.task.engagement_id != self.scope.engagement_id
                or request.task.target_id != index.target_id
                or request.task.target_version != index.target_version
                or request.task.scope_id != self.scope.scope_id
                or request.task.scope_version != self.scope.version
                or request.task.worker_role is not WorkerRole.VALIDATOR
                or request.task.policy_digest != PolicyEngine(self.scope).policy_digest
                or request.task.deadline > plan.deadline
                or expected_input not in request.task.input_refs
                or expected_candidate not in request.task.input_refs
                or request.profile.kind is not SandboxProfileKind.VALIDATION
                or request.profile.network_mode is not NetworkMode.NONE
                or not request.profile.execute_target_code
                or request.invocation.tool_id != SOURCE_EXECUTION_TOOLS[step.stage]
                or len(snapshot_mounts) != 1
                or snapshot_mounts[0].object_id != index.manifest_id
                or request.task.sandbox_profile_digest
                != sandbox_profile_digest(request.profile)
            ):
                raise SourceExecutionRejected("source execution step is not safely bound")
    @staticmethod
    def _status(result: SandboxRunResult):
        if result.status is SandboxRunStatus.COMPLETED:
            if not result.evidence_refs:
                return SourceExecutionStatus.FAILED, "stage_evidence_missing"
            return SourceExecutionStatus.RUNNING, "stage_completed"
        if result.status is SandboxRunStatus.TIMED_OUT:
            return SourceExecutionStatus.TIMED_OUT, "stage_timed_out"
        if result.status is SandboxRunStatus.CANCELLED:
            return SourceExecutionStatus.CANCELLED, "stage_cancelled"
        return SourceExecutionStatus.FAILED, "stage_failed"

    def _receipt(self, stage, result, *, expected_input, prior):
        receipts = []
        for evidence_ref in result.evidence_refs:
            try:
                receipts.append(
                    SourceStageReceipt.model_validate_json(
                        self.evidence_store.read_text_ref(evidence_ref)
                    )
                )
            except (ValidationError, ValueError):
                continue
        if len(receipts) != 1 or receipts[0].stage is not stage:
            raise SourceExecutionRejected("source stage requires one typed receipt")
        receipt = receipts[0]
        if receipt.input_digest != expected_input:
            raise SourceExecutionRejected("source stage receipt chain is broken")
        crash_receipts = tuple(item for item in prior if item.crash_fingerprint is not None)
        if crash_receipts and receipt.crash_fingerprint != crash_receipts[-1].crash_fingerprint:
            raise SourceExecutionRejected("source crash fingerprint changed before PoV replay")
        return receipt


class SourceExecutionValidationService:
    """Binds a reproduced PoV chain into the shared Validation domain objects."""

    def __init__(self, *, scope: Scope, evidence_store: EvidenceStore, store: SourceExecutionStore):
        self.scope = scope
        self.evidence_store = evidence_store
        self.store = store

    def bind(
        self,
        *,
        plan: SourceExecutionPlan,
        candidate: Candidate,
        outcome: SourceExecutionOutcome,
        evidence: tuple[Evidence, ...],
        now: datetime,
    ) -> SourceValidationBinding:
        persisted = self.store.load(plan.plan_id)
        if (
            persisted != outcome
            or outcome.status is not SourceExecutionStatus.COMPLETED
            or not outcome.reproducible_pov
            or plan.candidate_id != candidate.candidate_id
            or plan.candidate_digest != candidate_content_digest(candidate)
            or candidate.state is not CandidateState.PROPOSED
            or self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or candidate.scope_id != self.scope.scope_id
            or candidate.scope_version != self.scope.version
        ):
            raise SourceExecutionRejected("Source validation binding preflight failed")
        catalog = {item.evidence_id: item for item in evidence}
        if set(outcome.evidence_refs) != set(catalog):
            raise SourceExecutionRejected("Source validation Evidence catalog is incomplete")
        for reference, item in catalog.items():
            if item.target_version != candidate.target_version:
                raise SourceExecutionRejected("Source validation Evidence target drifted")
            self.evidence_store.read_text(item)
            if reference != item.evidence_id:
                raise SourceExecutionRejected("Source validation Evidence identity drifted")
        queued = queue_validation(candidate, self.scope, now=now)
        running = transition_candidate(queued, CandidateState.VALIDATION_RUNNING)
        usage = {
            "wall_seconds": sum(item.usage.wall_seconds for item in outcome.runner_results),
            "cpu_millis": sum(item.usage.cpu_millis for item in outcome.runner_results),
            "peak_memory_bytes": max(
                item.usage.peak_memory_bytes for item in outcome.runner_results
            ),
            "tool_calls": sum(
                item.budget_used.tool_calls for item in outcome.runner_results
            ),
        }
        validation_run = ValidationRun(
            run_id=uuid5(
                NAMESPACE_URL, f"vulnloom:source-validation-run:{plan.plan_id}"
            ),
            candidate_id=candidate.candidate_id,
            target_version=candidate.target_version,
            scope_version=candidate.scope_version,
            sandbox_image_digest=plan.steps[-1].request.profile.image_digest,
            policy_digest=plan.steps[-1].request.task.policy_digest,
            plan=tuple(f"source-execution:{item.value}" for item in SOURCE_EXECUTION_STAGES),
            started_at=plan.created_at,
            finished_at=now,
            result=ValidationResult.REPRODUCED,
            evidence_refs=outcome.evidence_refs,
            resource_usage=usage,
        )
        validated = complete_validation(running, validation_run)
        bundle = EvidenceBundle(
            bundle_id=uuid5(
                NAMESPACE_URL, f"vulnloom:source-evidence-bundle:{plan.plan_id}"
            ),
            candidate_id=candidate.candidate_id,
            evidence_refs=outcome.evidence_refs,
            sealed_at=now,
        )
        values = {
            "execution_plan_id": plan.plan_id,
            "execution_outcome_digest": canonical_digest(outcome.model_dump(mode="python")),
            "source_candidate_digest": candidate_content_digest(candidate),
            "validated_candidate": validated,
            "validation_run": validation_run,
            "evidence_bundle": bundle,
            "bound_at": now,
        }
        digest_values = {
            **values,
            "validated_candidate": validated.model_dump(mode="python"),
            "validation_run": validation_run.model_dump(mode="python"),
            "evidence_bundle": bundle.model_dump(mode="python"),
        }
        binding = SourceValidationBinding(
            binding_id=canonical_digest(digest_values), **values
        )
        return self.store.put_validation_binding(binding)
