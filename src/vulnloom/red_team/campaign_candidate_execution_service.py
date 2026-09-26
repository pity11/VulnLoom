"""Fail-closed B5.8 execution of one queued Campaign Candidate validation."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    CandidateState,
    EvidenceBundle,
    Scope,
    ScopeState,
    ValidationResult,
    ValidationRun,
)
from vulnloom.domain.protocol import WorkerRole
from vulnloom.policy import PolicyEngine
from vulnloom.runners import NetworkMode, SandboxProfileKind, SandboxRunStatus
from vulnloom.runners.base import SandboxRunner
from vulnloom.runners.models import (
    MountKind,
    SandboxOutput,
    SandboxRunRequest,
    invocation_digest,
    run_request_digest,
    sandbox_profile_digest,
)

from .campaign_candidate_execution_models import (
    CampaignCandidateFreshEvidenceFact,
    CampaignCandidateValidationCompletionCheckpoint,
    CampaignCandidateValidationExecutionLimits,
    CampaignCandidateValidationExecutionOutcome,
    CampaignCandidateValidationExecutionPlan,
    CampaignCandidateValidationExecutionRole,
    CampaignCandidateValidationWorkerOutput,
)
from .campaign_candidate_execution_store import CampaignCandidateValidationExecutionStore
from .campaign_candidate_state_machine import (
    complete_campaign_candidate_validation,
    start_campaign_candidate_validation,
)
from .campaign_candidate_validation_models import (
    REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS,
    CampaignCandidateLifecycleCheckpoint,
    CampaignCandidateValidationIntakeOutcome,
    CampaignCandidateValidationIntakePlan,
)
from .evidence_requirement_models import EvidenceFactKind


class CampaignCandidateValidationIntakeSource(Protocol):
    def plan(self, plan_id: str) -> CampaignCandidateValidationIntakePlan: ...

    def outcome(self, plan_id: str) -> CampaignCandidateValidationIntakeOutcome: ...

    def checkpoint(self, candidate_id) -> CampaignCandidateLifecycleCheckpoint: ...


class CampaignCandidateValidationOutputReader(Protocol):
    def read(self, output: SandboxOutput) -> bytes: ...

    def read_snapshot(self, object_id: str) -> bytes: ...


class CampaignCandidateValidationExecutionRejected(ValueError):
    pass


class CampaignCandidateValidationExecutionTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.started = clock()
        self.seconds = seconds
        self.clock = clock

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise CampaignCandidateValidationExecutionTimedOut(
                "Campaign Candidate validation execution timed out"
            )


class CampaignCandidateValidationExecutionService:
    def __init__(
        self,
        *,
        intake_source: CampaignCandidateValidationIntakeSource,
        runner: SandboxRunner,
        output_reader: CampaignCandidateValidationOutputReader,
        store: CampaignCandidateValidationExecutionStore,
        monotonic: Callable[[], float] = time.monotonic,
        after_claim: Callable[[], None] | None = None,
    ) -> None:
        self.intake_source = intake_source
        self.runner = runner
        self.output_reader = output_reader
        self.store = store
        self.monotonic = monotonic
        self.after_claim = after_claim

    def prepare(
        self,
        *,
        validation_intake_plan_id: str,
        primary_request: SandboxRunRequest,
        replay_request: SandboxRunRequest,
        scope: Scope,
        limits: CampaignCandidateValidationExecutionLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> CampaignCandidateValidationExecutionPlan:
        intake_plan, intake_outcome, checkpoint = self._read(validation_intake_plan_id)
        self._validate_source(intake_plan, intake_outcome, checkpoint, scope=scope, now=now)
        self._validate_request(
            primary_request,
            CampaignCandidateValidationExecutionRole.PRIMARY,
            intake_plan,
            scope,
        )
        self._validate_request(
            replay_request,
            CampaignCandidateValidationExecutionRole.REPLAY,
            intake_plan,
            scope,
        )
        primary_snapshot = self._snapshot_id(primary_request)
        replay_snapshot = self._snapshot_id(replay_request)
        if (
            primary_snapshot == replay_snapshot
            or primary_snapshot in intake_plan.prior_campaign_evidence_refs
            or replay_snapshot in intake_plan.prior_campaign_evidence_refs
        ):
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate validation requires two fresh independent sealed inputs"
            )
        stop_at = min(
            deadline,
            intake_plan.deadline,
            primary_request.task.deadline,
            replay_request.task.deadline,
            scope.valid_until,
        )
        if not now < stop_at:
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate validation execution deadline is invalid"
            )
        return CampaignCandidateValidationExecutionPlan.create(
            validation_intake_plan_id=intake_plan.validation_intake_plan_id,
            validation_intake_plan_digest=canonical_digest(intake_plan.model_dump(mode="python")),
            validation_intake_outcome_id=intake_outcome.outcome_id,
            validation_intake_outcome_digest=canonical_digest(
                intake_outcome.model_dump(mode="python")
            ),
            lifecycle_checkpoint_id=checkpoint.checkpoint_id,
            lifecycle_checkpoint_digest=canonical_digest(checkpoint.model_dump(mode="python")),
            candidate_id=intake_plan.candidate_id,
            candidate_digest=intake_plan.candidate_digest,
            target_id=intake_plan.target_id,
            target_version=intake_plan.target_version,
            scope_id=intake_plan.scope_id,
            scope_version=intake_plan.scope_version,
            vulnerability_class=intake_plan.vulnerability_class,
            cwe=intake_plan.cwe,
            validation_context_digest=intake_plan.validation_context_digest,
            prior_campaign_evidence_refs=intake_plan.prior_campaign_evidence_refs,
            primary_request_digest=run_request_digest(primary_request),
            primary_request=primary_request,
            replay_request_digest=run_request_digest(replay_request),
            replay_request=replay_request,
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        plan: CampaignCandidateValidationExecutionPlan,
        *,
        approval: ApprovalRequest,
        scope: Scope,
        now: datetime,
    ) -> CampaignCandidateValidationExecutionOutcome:
        authoritative = CampaignCandidateValidationExecutionPlan.model_validate(
            plan.model_dump(mode="python")
        )
        intake_plan, intake_outcome, checkpoint = self._read(
            authoritative.validation_intake_plan_id
        )
        self._validate_source(intake_plan, intake_outcome, checkpoint, scope=scope, now=now)
        self._validate_plan(authoritative, intake_plan, intake_outcome, checkpoint)
        self._validate_request(
            authoritative.primary_request,
            CampaignCandidateValidationExecutionRole.PRIMARY,
            intake_plan,
            scope,
        )
        self._validate_request(
            authoritative.replay_request,
            CampaignCandidateValidationExecutionRole.REPLAY,
            intake_plan,
            scope,
        )
        if not authoritative.created_at <= now < authoritative.deadline:
            raise CampaignCandidateValidationExecutionTimedOut(
                "Campaign Candidate Validation Execution Plan is not active"
            )
        if (
            approval.engagement_id != scope.engagement_id
            or approval.target_id != authoritative.target_id
            or approval.policy_version != scope.version
            or approval.expected_side_effects != ("run isolated campaign candidate validation",)
            or approval.decided_at is None
            or not authoritative.created_at <= approval.decided_at <= now < approval.expires_at
            or not approval.is_valid_for(
                action=ApprovalAction.RUN_VALIDATION,
                digest=authoritative.execution_plan_id,
                now=now,
            )
        ):
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate validation execution Approval is invalid"
            )
        deadline = _Deadline(authoritative.limits.timeout_seconds, self.monotonic)
        deadline.check()
        primary_snapshot = self._snapshot_id(authoritative.primary_request)
        replay_snapshot = self._snapshot_id(authoritative.replay_request)
        primary_sealed = self._read_sealed_input(
            primary_snapshot,
            role=CampaignCandidateValidationExecutionRole.PRIMARY,
            plan=authoritative,
        )
        replay_sealed = self._read_sealed_input(
            replay_snapshot,
            role=CampaignCandidateValidationExecutionRole.REPLAY,
            plan=authoritative,
        )
        if primary_sealed.response_fingerprint != replay_sealed.response_fingerprint:
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate sealed inputs are not replay-matched"
            )
        claim = self.store.claim(authoritative, now=now)
        if claim.outcome is not None:
            return claim.outcome
        if self.after_claim is not None:
            self.after_claim()
        running = start_campaign_candidate_validation(checkpoint.state)
        primary_result = self.runner.execute(authoritative.primary_request, now=now)
        deadline.check()
        primary_output = self._result_output(primary_result, "primary")
        replay_result = self.runner.execute(authoritative.replay_request, now=now)
        deadline.check()
        replay_output = self._result_output(replay_result, "replay")
        primary = self._read_output(
            primary_output,
            role=CampaignCandidateValidationExecutionRole.PRIMARY,
            plan=authoritative,
        )
        replay = self._read_output(
            replay_output,
            role=CampaignCandidateValidationExecutionRole.REPLAY,
            plan=authoritative,
        )
        if primary != primary_sealed or replay != replay_sealed:
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate Worker output disagrees with trusted sealed input"
            )
        refs = tuple(sorted((primary_snapshot, replay_snapshot)))
        if (
            set(refs) & set(authoritative.prior_campaign_evidence_refs)
            or primary.response_fingerprint != replay.response_fingerprint
        ):
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate fresh Evidence is not independent or replay-matched"
            )
        facts = self._facts(authoritative, primary_snapshot, replay_snapshot, now=now)
        if {item.fact for item in facts} != set(REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS):
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate validation fresh Evidence is incomplete"
            )
        result = ValidationResult.REPRODUCED
        final_state = complete_campaign_candidate_validation(running, result)
        if final_state is not CandidateState.VALIDATED:
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate validation did not reproduce"
            )
        validation_run = ValidationRun(
            candidate_id=authoritative.candidate_id,
            target_version=authoritative.target_version,
            scope_version=authoritative.scope_version,
            sandbox_image_digest=authoritative.primary_request.profile.image_digest,
            policy_digest=authoritative.primary_request.task.policy_digest,
            plan=(
                f"campaign-candidate:{authoritative.execution_plan_id}",
                f"primary:{authoritative.primary_request_digest}",
                f"replay:{authoritative.replay_request_digest}",
            ),
            started_at=now,
            finished_at=now,
            result=result,
            side_effects=(),
            evidence_refs=refs,
            resource_usage={
                "wall_seconds": primary_result.usage.wall_seconds
                + replay_result.usage.wall_seconds,
                "cpu_millis": primary_result.usage.cpu_millis + replay_result.usage.cpu_millis,
                "peak_memory_bytes": max(
                    primary_result.usage.peak_memory_bytes,
                    replay_result.usage.peak_memory_bytes,
                ),
                "tool_calls": primary_result.budget_used.tool_calls
                + replay_result.budget_used.tool_calls,
            },
        )
        bundle = EvidenceBundle(
            candidate_id=authoritative.candidate_id,
            evidence_refs=refs,
            sealed_at=now,
        )
        checkpoint_out = CampaignCandidateValidationCompletionCheckpoint.create(
            execution_plan_id=authoritative.execution_plan_id,
            candidate_id=authoritative.candidate_id,
            candidate_digest=authoritative.candidate_digest,
            validation_context_digest=authoritative.validation_context_digest,
            approval_id=approval.approval_id,
            approval_digest=approval.action_digest,
            validation_run_id=validation_run.run_id,
            validation_run_digest=canonical_digest(validation_run.model_dump(mode="python")),
            evidence_bundle_id=bundle.bundle_id,
            evidence_bundle_digest=canonical_digest(bundle.model_dump(mode="python")),
            fresh_fact_ids=tuple(sorted(item.fact_id for item in facts)),
            recorded_at=now,
        )
        outcome = CampaignCandidateValidationExecutionOutcome.create(
            execution_plan_id=authoritative.execution_plan_id,
            primary_result=primary_result,
            replay_result=replay_result,
            fresh_evidence_refs=refs,
            fresh_facts=facts,
            validation_run=validation_run,
            evidence_bundle=bundle,
            checkpoint=checkpoint_out,
            attempt=claim.attempt,
            completed_at=now,
        )
        deadline.check()
        self.store.complete(authoritative, outcome)
        return outcome

    def _read(self, plan_id):
        try:
            plan = self.intake_source.plan(plan_id)
            outcome = self.intake_source.outcome(plan_id)
            checkpoint = self.intake_source.checkpoint(plan.candidate_id)
            return plan, outcome, checkpoint
        except (KeyError, LookupError) as exc:
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate Validation Intake source is unavailable"
            ) from exc

    @staticmethod
    def _validate_source(plan, outcome, checkpoint, *, scope, now):
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or "read_only" not in scope.allowed_test_classes
            or plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
            or outcome.validation_intake_plan_id != plan.validation_intake_plan_id
            or outcome.checkpoint != checkpoint
            or checkpoint.candidate_id != plan.candidate_id
            or checkpoint.candidate_digest != plan.candidate_digest
            or checkpoint.state is not CandidateState.VALIDATION_PENDING
            or checkpoint.validation_started
            or checkpoint.critic_completed
            or checkpoint.finding_created
        ):
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate Validation Intake source binding is invalid"
            )

    @staticmethod
    def _validate_request(request, role, intake_plan, scope):
        profile = request.profile
        task = request.task
        expected_arguments = (
            role.value,
            str(intake_plan.candidate_id),
            intake_plan.validation_context_digest,
        )
        snapshot = CampaignCandidateValidationExecutionService._snapshot_id(request)
        if (
            task.engagement_id != scope.engagement_id
            or task.target_id != intake_plan.target_id
            or task.target_version != intake_plan.target_version
            or task.scope_id != scope.scope_id
            or task.scope_version != scope.version
            or task.worker_role is not WorkerRole.VALIDATOR
            or task.policy_digest != PolicyEngine(scope).policy_digest
            or task.sandbox_profile_digest != sandbox_profile_digest(profile)
            or task.allowed_tools != frozenset({"sandbox.test"})
            or task.budget.model_tokens != 0
            or task.budget.tool_calls != 1
            or task.input_refs
            != (
                f"candidate-validation:{intake_plan.validation_context_digest}",
                f"snapshot:{snapshot}",
            )
            or profile.kind is not SandboxProfileKind.VALIDATION
            or profile.network_mode is not NetworkMode.NONE
            or profile.network_grants
            or profile.allowed_tools != frozenset({"sandbox.test"})
            or request.invocation.tool_id != "sandbox.test"
            or request.invocation.arguments != expected_arguments
            or request.invocation.working_directory.value != "source"
            or request.environment
            != {
                "VULNLOOM_TASK_ID": str(task.task_id),
                "VULNLOOM_VALIDATION_ROLE": role.value,
            }
            or invocation_digest(request.invocation) == "0" * 64
        ):
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate validation request boundary is invalid"
            )

    @staticmethod
    def _snapshot_id(request: SandboxRunRequest) -> str:
        mounts = tuple(item for item in request.profile.mounts if item.kind is MountKind.SNAPSHOT)
        if len(mounts) != 1 or mounts[0].object_id is None:
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate validation requires one sealed snapshot"
            )
        return mounts[0].object_id

    @staticmethod
    def _validate_plan(plan, intake_plan, intake_outcome, checkpoint):
        expected = {
            "validation_intake_plan_digest": canonical_digest(
                intake_plan.model_dump(mode="python")
            ),
            "validation_intake_outcome_id": intake_outcome.outcome_id,
            "validation_intake_outcome_digest": canonical_digest(
                intake_outcome.model_dump(mode="python")
            ),
            "lifecycle_checkpoint_id": checkpoint.checkpoint_id,
            "lifecycle_checkpoint_digest": canonical_digest(checkpoint.model_dump(mode="python")),
            "candidate_id": intake_plan.candidate_id,
            "candidate_digest": intake_plan.candidate_digest,
            "target_id": intake_plan.target_id,
            "target_version": intake_plan.target_version,
            "scope_id": intake_plan.scope_id,
            "scope_version": intake_plan.scope_version,
            "vulnerability_class": intake_plan.vulnerability_class,
            "cwe": intake_plan.cwe,
            "validation_context_digest": intake_plan.validation_context_digest,
            "prior_campaign_evidence_refs": intake_plan.prior_campaign_evidence_refs,
        }
        if any(getattr(plan, key) != value for key, value in expected.items()):
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate Validation Execution Plan source binding drifted"
            )

    @staticmethod
    def _result_output(result, label):
        if result.status is SandboxRunStatus.TIMED_OUT:
            raise CampaignCandidateValidationExecutionTimedOut(
                f"Campaign Candidate {label} validation run timed out"
            )
        if (
            result.status is not SandboxRunStatus.COMPLETED
            or not result.cleanup.complete
            or len(result.outputs) != 1
            or result.evidence_refs
        ):
            raise CampaignCandidateValidationExecutionRejected(
                f"Campaign Candidate {label} validation run is incomplete"
            )
        return result.outputs[0]

    def _read_output(self, output, *, role, plan):
        try:
            content = self.output_reader.read(output)
            if len(content) > 16 * 1024:
                raise ValueError("output exceeds limit")
            document = json.loads(content.decode("utf-8", "strict"))
            parsed = CampaignCandidateValidationWorkerOutput.model_validate(document)
        except (OSError, UnicodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate validation Worker output is invalid"
            ) from exc
        if (
            parsed.role is not role
            or parsed.candidate_id != plan.candidate_id
            or parsed.validation_context_digest != plan.validation_context_digest
        ):
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate validation Worker output binding drifted"
            )
        return parsed

    def _read_sealed_input(self, object_id, *, role, plan):
        try:
            content = self.output_reader.read_snapshot(object_id)
            if len(content) > 16 * 1024:
                raise ValueError("sealed input exceeds limit")
            document = json.loads(content.decode("utf-8", "strict"))
            parsed = CampaignCandidateValidationWorkerOutput.model_validate(document)
        except (OSError, UnicodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate trusted sealed input is invalid"
            ) from exc
        if (
            parsed.role is not role
            or parsed.candidate_id != plan.candidate_id
            or parsed.validation_context_digest != plan.validation_context_digest
        ):
            raise CampaignCandidateValidationExecutionRejected(
                "Campaign Candidate trusted sealed input binding drifted"
            )
        return parsed

    @staticmethod
    def _facts(plan, primary, replay, *, now):
        roles = CampaignCandidateValidationExecutionRole
        refs_by_fact = {
            EvidenceFactKind.SEALED_GET_SUCCEEDED: ((primary,), (roles.PRIMARY,)),
            EvidenceFactKind.UNAUTHENTICATED_REQUEST_PROVEN: (
                (primary,),
                (roles.PRIMARY,),
            ),
            EvidenceFactKind.SENSITIVE_DATA_CLASS_PRESENT: (
                (primary,),
                (roles.PRIMARY,),
            ),
            EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED: (
                tuple(sorted((primary, replay))),
                tuple(sorted((roles.PRIMARY, roles.REPLAY), key=str)),
            ),
            EvidenceFactKind.REDACTION_BOUNDARY_PROVEN: (
                tuple(sorted((primary, replay))),
                tuple(sorted((roles.PRIMARY, roles.REPLAY), key=str)),
            ),
        }
        facts = tuple(
            CampaignCandidateFreshEvidenceFact.create(
                execution_plan_id=plan.execution_plan_id,
                candidate_id=plan.candidate_id,
                validation_context_digest=plan.validation_context_digest,
                fact=fact,
                evidence_refs=refs_by_fact[fact][0],
                producer_roles=refs_by_fact[fact][1],
                observed_at=now,
            )
            for fact in REQUIRED_FRESH_CAMPAIGN_VALIDATION_FACTS
        )
        return tuple(sorted(facts, key=lambda item: item.fact_id))
