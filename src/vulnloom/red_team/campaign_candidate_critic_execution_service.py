"""Fail-closed B5.10 isolated Campaign Candidate Critic execution."""

import json
import time
from collections.abc import Callable
from datetime import datetime
from typing import Protocol
from uuid import NAMESPACE_URL, uuid5

from pydantic import ValidationError

from vulnloom.critic.models import CRITIC_RULESET_DIGEST, CounterevidenceDisposition
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    CandidateState,
    CriticReview,
    CriticVerdict,
    Scope,
    ScopeState,
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

from .campaign_candidate_critic_execution_models import (
    CampaignCandidateCounterevidenceFact,
    CampaignCandidateCriticCompletionCheckpoint,
    CampaignCandidateCriticExecutionLimits,
    CampaignCandidateCriticExecutionOutcome,
    CampaignCandidateCriticExecutionPlan,
    CampaignCandidateCriticWorkerOutput,
)
from .campaign_candidate_critic_execution_store import CampaignCandidateCriticExecutionStore
from .campaign_candidate_critic_models import (
    CampaignCandidateCriticIntakeCheckpoint,
    CampaignCandidateCriticIntakeOutcome,
    CampaignCandidateCriticIntakePlan,
    CampaignCandidateCriticLifecycleState,
)


class CampaignCandidateCriticIntakeSource(Protocol):
    def plan(self, plan_id: str) -> CampaignCandidateCriticIntakePlan: ...
    def outcome(self, plan_id: str) -> CampaignCandidateCriticIntakeOutcome: ...
    def checkpoint(self, candidate_id) -> CampaignCandidateCriticIntakeCheckpoint: ...


class CampaignCandidateCriticOutputReader(Protocol):
    def read(self, output: SandboxOutput) -> bytes: ...
    def read_evidence(self, object_id: str) -> bytes: ...


class CampaignCandidateCriticExecutionRejected(ValueError):
    pass


class CampaignCandidateCriticExecutionTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.started, self.seconds, self.clock = clock(), seconds, clock

    def check(self):
        if self.clock() - self.started >= self.seconds:
            raise CampaignCandidateCriticExecutionTimedOut(
                "Campaign Candidate Critic execution timed out"
            )


class CampaignCandidateCriticExecutionService:
    def __init__(
        self,
        *,
        intake_source: CampaignCandidateCriticIntakeSource,
        validation_source,
        runner: SandboxRunner,
        output_reader: CampaignCandidateCriticOutputReader,
        store: CampaignCandidateCriticExecutionStore,
        monotonic=time.monotonic,
        after_claim=None,
    ):
        self.intake_source, self.validation_source, self.runner, self.output_reader, self.store = (
            intake_source,
            validation_source,
            runner,
            output_reader,
            store,
        )
        self.monotonic, self.after_claim = monotonic, after_claim

    def prepare(
        self,
        *,
        critic_intake_plan_id: str,
        request: SandboxRunRequest,
        scope: Scope,
        limits: CampaignCandidateCriticExecutionLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ):
        intake, outcome, checkpoint = self._read(critic_intake_plan_id)
        self._validate_source(intake, outcome, checkpoint, scope=scope, now=now)
        self._validate_request(request, intake, scope)
        stop_at = min(deadline, intake.deadline, request.task.deadline, scope.valid_until)
        if not now < stop_at:
            raise CampaignCandidateCriticExecutionRejected(
                "Campaign Candidate Critic execution deadline is invalid"
            )
        _, validation, _ = self._validation_sources(intake)
        return CampaignCandidateCriticExecutionPlan.create(
            critic_intake_plan_id=intake.critic_intake_plan_id,
            critic_intake_plan_digest=canonical_digest(intake.model_dump(mode="python")),
            critic_intake_outcome_id=outcome.outcome_id,
            critic_intake_outcome_digest=canonical_digest(outcome.model_dump(mode="python")),
            intake_checkpoint_id=checkpoint.checkpoint_id,
            intake_checkpoint_digest=canonical_digest(checkpoint.model_dump(mode="python")),
            candidate_id=intake.candidate_id,
            candidate_digest=intake.candidate_digest,
            target_id=intake.target_id,
            target_version=intake.target_version,
            scope_id=intake.scope_id,
            scope_version=intake.scope_version,
            validation_run_id=intake.validation_run_id,
            validation_run_digest=intake.validation_run_digest,
            evidence_bundle_id=intake.evidence_bundle_id,
            evidence_bundle_digest=intake.evidence_bundle_digest,
            fresh_fact_ids=intake.fresh_fact_ids,
            validation_evidence_refs=validation.fresh_evidence_refs,
            validation_context_digest=intake.validation_context_digest,
            review_context_digest=intake.review_context_digest,
            validation_producer_digest=intake.validation_producer_digest,
            review_producer_digest=intake.review_producer_digest,
            request_digest=run_request_digest(request),
            request=request,
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def execute(self, plan, *, approval, scope, now):
        plan = CampaignCandidateCriticExecutionPlan.model_validate(plan.model_dump(mode="python"))
        intake, intake_outcome, checkpoint = self._read(plan.critic_intake_plan_id)
        self._validate_source(intake, intake_outcome, checkpoint, scope=scope, now=now)
        expected = self.prepare(
            critic_intake_plan_id=plan.critic_intake_plan_id,
            request=plan.request,
            scope=scope,
            limits=plan.limits,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise CampaignCandidateCriticExecutionRejected(
                "Campaign Candidate Critic Execution Plan source binding drifted"
            )
        if not plan.created_at <= now < plan.deadline:
            raise CampaignCandidateCriticExecutionTimedOut(
                "Campaign Candidate Critic Execution Plan is not active"
            )
        if (
            approval.engagement_id != scope.engagement_id
            or approval.target_id != plan.target_id
            or approval.policy_version != scope.version
            or approval.expected_side_effects != ("run isolated campaign candidate critic",)
            or approval.decided_at is None
            or not plan.created_at <= approval.decided_at <= now < approval.expires_at
            or not approval.is_valid_for(
                action=ApprovalAction.RUN_CRITIC, digest=plan.execution_plan_id, now=now
            )
        ):
            raise CampaignCandidateCriticExecutionRejected(
                "Campaign Candidate Critic execution Approval is invalid"
            )
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        deadline.check()
        evidence_id = self._evidence_id(plan.request)
        sealed = self._read_document(self.output_reader.read_evidence(evidence_id), plan)
        self._validate_counterevidence(sealed, plan, evidence_id)
        claim = self.store.claim(plan, now=now)
        if claim.outcome is not None:
            return claim.outcome
        if self.after_claim:
            self.after_claim()
        result = self.runner.execute(plan.request, now=now)
        deadline.check()
        if result.status is SandboxRunStatus.TIMED_OUT:
            raise CampaignCandidateCriticExecutionTimedOut(
                "Campaign Candidate Critic Worker timed out"
            )
        if (
            result.status is not SandboxRunStatus.COMPLETED
            or not result.cleanup.complete
            or len(result.outputs) != 1
            or result.evidence_refs
        ):
            raise CampaignCandidateCriticExecutionRejected(
                "Campaign Candidate Critic Worker run is incomplete"
            )
        worker = self._read_document(self.output_reader.read(result.outputs[0]), plan)
        if worker != sealed:
            raise CampaignCandidateCriticExecutionRejected(
                "Campaign Candidate Critic Worker output disagrees with trusted sealed input"
            )
        counter_refs = tuple(
            sorted(set(ref for item in worker.assessments for ref in item.evidence_refs))
        )
        if set(counter_refs) & set(plan.validation_evidence_refs):
            raise CampaignCandidateCriticExecutionRejected(
                "Validation Evidence cannot be used as counterevidence"
            )
        facts = tuple(
            sorted(
                (
                    CampaignCandidateCounterevidenceFact.create(
                        execution_plan_id=plan.execution_plan_id,
                        candidate_id=plan.candidate_id,
                        review_context_digest=plan.review_context_digest,
                        review_producer_digest=plan.review_producer_digest,
                        angle=a.angle,
                        disposition=a.disposition,
                        evidence_refs=tuple(sorted(a.evidence_refs)),
                        rationale_code=a.rationale_code,
                        observed_at=now,
                    )
                    for a in worker.assessments
                ),
                key=lambda x: x.fact_id,
            )
        )
        confirmed = tuple(
            sorted(
                set(
                    ref
                    for item in worker.assessments
                    if item.disposition is CounterevidenceDisposition.CONFIRMED
                    for ref in item.evidence_refs
                )
            )
        )
        if confirmed:
            verdict, rationale, state = (
                CriticVerdict.REJECTED,
                "counterevidence_confirmed",
                CandidateState.REJECTED,
            )
        elif any(
            item.disposition is CounterevidenceDisposition.INCONCLUSIVE
            for item in worker.assessments
        ):
            verdict, rationale, state = (
                CriticVerdict.INCONCLUSIVE,
                "counterevidence_review_inconclusive",
                CandidateState.VALIDATED,
            )
        else:
            verdict, rationale, state = (
                CriticVerdict.ACCEPTED,
                "all_counterevidence_angles_ruled_out",
                CandidateState.CRITIC_REVIEWED,
            )
        review = CriticReview(
            review_id=uuid5(NAMESPACE_URL, f"vulnloom:critic-review:{plan.execution_plan_id}"),
            plan_id=plan.execution_plan_id,
            candidate_id=plan.candidate_id,
            validation_run_id=plan.validation_run_id,
            evidence_bundle_id=plan.evidence_bundle_id,
            validation_context_id=plan.validation_context_digest,
            review_context_id=plan.review_context_digest,
            ruleset_digest=CRITIC_RULESET_DIGEST,
            verdict=verdict,
            counterevidence_refs=confirmed,
            rationale_code=rationale,
            reviewed_at=now,
        )
        checkpoint_out = CampaignCandidateCriticCompletionCheckpoint.create(
            execution_plan_id=plan.execution_plan_id,
            candidate_id=plan.candidate_id,
            candidate_digest=plan.candidate_digest,
            candidate_state=state,
            approval_id=approval.approval_id,
            approval_digest=approval.action_digest,
            critic_review_id=review.review_id,
            critic_review_digest=canonical_digest(review.model_dump(mode="python")),
            counterevidence_fact_ids=tuple(sorted(f.fact_id for f in facts)),
            recorded_at=now,
        )
        outcome = CampaignCandidateCriticExecutionOutcome.create(
            execution_plan_id=plan.execution_plan_id,
            result=result,
            counterevidence_refs=counter_refs,
            counterevidence_facts=facts,
            review=review,
            checkpoint=checkpoint_out,
            attempt=claim.attempt,
            completed_at=now,
        )
        deadline.check()
        self.store.complete(plan, outcome)
        return outcome

    def _read(self, plan_id):
        try:
            plan = self.intake_source.plan(plan_id)
            outcome = self.intake_source.outcome(plan_id)
            return plan, outcome, self.intake_source.checkpoint(plan.candidate_id)
        except (KeyError, LookupError) as exc:
            raise CampaignCandidateCriticExecutionRejected(
                "Campaign Candidate Critic Intake source is unavailable"
            ) from exc

    def _validation_sources(self, intake):
        try:
            validation_plan = self.validation_source.plan(intake.validation_execution_plan_id)
            validation_outcome = self.validation_source.outcome(intake.validation_execution_plan_id)
            validation_checkpoint = self.validation_source.checkpoint(intake.candidate_id)
            return validation_plan, validation_outcome, validation_checkpoint
        except (KeyError, LookupError) as exc:
            raise CampaignCandidateCriticExecutionRejected(
                "Campaign Candidate validation source is unavailable"
            ) from exc

    def _validate_source(self, plan, outcome, checkpoint, *, scope, now):
        validation_plan, validation, validation_checkpoint = self._validation_sources(plan)
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or "read_only" not in scope.allowed_test_classes
            or plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
            or outcome.critic_intake_plan_id != plan.critic_intake_plan_id
            or outcome.checkpoint != checkpoint
            or checkpoint.critic_state is not CampaignCandidateCriticLifecycleState.PENDING
            or checkpoint.candidate_state is not CandidateState.VALIDATED
            or checkpoint.candidate_id != plan.candidate_id
            or checkpoint.candidate_digest != plan.candidate_digest
            or checkpoint.review_context_digest != plan.review_context_digest
            or checkpoint.validation_run_id != plan.validation_run_id
            or checkpoint.evidence_bundle_id != plan.evidence_bundle_id
            or validation.outcome_id != plan.validation_execution_outcome_id
            or validation.execution_plan_id != validation_plan.execution_plan_id
            or canonical_digest(validation_plan.model_dump(mode="python"))
            != plan.validation_execution_plan_digest
            or canonical_digest(validation.model_dump(mode="python"))
            != plan.validation_execution_outcome_digest
            or validation.checkpoint != validation_checkpoint
            or validation_checkpoint.checkpoint_id != plan.validation_checkpoint_id
            or canonical_digest(validation_checkpoint.model_dump(mode="python"))
            != plan.validation_checkpoint_digest
            or validation_plan.candidate_id != plan.candidate_id
            or validation_plan.candidate_digest != plan.candidate_digest
            or validation_plan.target_id != plan.target_id
            or validation_plan.target_version != plan.target_version
            or validation_plan.scope_id != plan.scope_id
            or validation_plan.scope_version != plan.scope_version
            or validation.validation_run.run_id != plan.validation_run_id
            or canonical_digest(validation.validation_run.model_dump(mode="python"))
            != plan.validation_run_digest
            or validation.evidence_bundle.bundle_id != plan.evidence_bundle_id
            or canonical_digest(validation.evidence_bundle.model_dump(mode="python"))
            != plan.evidence_bundle_digest
            or tuple(sorted(f.fact_id for f in validation.fresh_facts)) != plan.fresh_fact_ids
            or validation.validation_run.evidence_refs != validation.fresh_evidence_refs
            or validation.evidence_bundle.evidence_refs != validation.fresh_evidence_refs
            or any(
                fact.candidate_id != plan.candidate_id
                or fact.execution_plan_id != validation_plan.execution_plan_id
                or fact.validation_context_digest != plan.validation_context_digest
                or not set(fact.evidence_refs) <= set(validation.fresh_evidence_refs)
                for fact in validation.fresh_facts
            )
            or not validation.cleanup_complete
            or not outcome.cleanup_complete
        ):
            raise CampaignCandidateCriticExecutionRejected(
                "Campaign Candidate Critic Intake source binding is invalid"
            )

    @staticmethod
    def _evidence_id(request):
        mounts = tuple(m for m in request.profile.mounts if m.kind is MountKind.EVIDENCE)
        if len(mounts) != 1 or mounts[0].object_id is None:
            raise CampaignCandidateCriticExecutionRejected(
                "Campaign Candidate Critic requires one sealed counterevidence input"
            )
        return mounts[0].object_id

    @staticmethod
    def _validate_request(request, intake, scope):
        p, t = request.profile, request.task
        evidence = CampaignCandidateCriticExecutionService._evidence_id(request)
        if (
            t.engagement_id != scope.engagement_id
            or t.target_id != intake.target_id
            or t.target_version != intake.target_version
            or t.scope_id != scope.scope_id
            or t.scope_version != scope.version
            or t.worker_role is not WorkerRole.CRITIC
            or t.policy_digest != PolicyEngine(scope).policy_digest
            or t.sandbox_profile_digest != sandbox_profile_digest(p)
            or t.allowed_tools != frozenset({"critic.review"})
            or t.budget.model_tokens != 0
            or t.budget.tool_calls != 1
            or t.input_refs
            != (f"candidate-critic:{intake.review_context_digest}", f"counterevidence:{evidence}")
            or p.kind is not SandboxProfileKind.REPORT
            or p.network_mode is not NetworkMode.NONE
            or p.network_grants
            or p.allowed_tools != frozenset({"critic.review"})
            or request.invocation.tool_id != "critic.review"
            or request.invocation.arguments
            != (
                str(intake.candidate_id),
                intake.review_context_digest,
                intake.review_producer_digest,
            )
            or request.invocation.working_directory.value != "output"
            or request.environment
            != {"VULNLOOM_TASK_ID": str(t.task_id), "VULNLOOM_CRITIC_ROLE": "independent_review"}
            or invocation_digest(request.invocation) == "0" * 64
        ):
            raise CampaignCandidateCriticExecutionRejected(
                "Campaign Candidate Critic request boundary is invalid"
            )

    def _read_document(self, content, plan):
        try:
            if len(content) > 16 * 1024:
                raise ValueError("output exceeds limit")
            parsed = CampaignCandidateCriticWorkerOutput.model_validate(
                json.loads(content.decode("utf-8", "strict"))
            )
        except (OSError, UnicodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
            raise CampaignCandidateCriticExecutionRejected(
                "Campaign Candidate Critic typed output is invalid"
            ) from exc
        if (
            parsed.candidate_id != plan.candidate_id
            or parsed.review_context_digest != plan.review_context_digest
            or parsed.review_producer_digest != plan.review_producer_digest
        ):
            raise CampaignCandidateCriticExecutionRejected(
                "Campaign Candidate Critic output binding drifted"
            )
        return parsed

    @staticmethod
    def _validate_counterevidence(output, plan, evidence_id):
        refs = {ref for item in output.assessments for ref in item.evidence_refs}
        if (
            refs != {evidence_id}
            or refs & set(plan.validation_evidence_refs)
            or tuple(a.angle for a in output.assessments) != plan.required_counterevidence_angles
        ):
            raise CampaignCandidateCriticExecutionRejected(
                "Campaign Candidate counterevidence is incomplete or not independent"
            )
