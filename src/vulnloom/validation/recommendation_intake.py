"""Fail-closed Intake from accepted model Recommendation to an offline ValidationPlan."""

import time

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, ScopeState
from vulnloom.domain.protocol import WorkerRole
from vulnloom.policy import PolicyEngine
from vulnloom.recommendations.selection_models import CandidateRecommendationSelectionDecision
from vulnloom.recommendations.selection_service import (
    CandidateRecommendationSelectionRejected,
    CandidateRecommendationSelectionTimedOut,
)
from vulnloom.runners import NetworkMode, SandboxProfileKind
from vulnloom.runners.models import sandbox_profile_digest

from .models import ValidationPlan, candidate_content_digest, validation_plan_digest
from .recommendation_intake_models import (
    CandidateRecommendationValidationIntakePlan,
    CandidateRecommendationValidationIntakeRecord,
    candidate_recommendation_validation_intake_plan_digest,
)


class CandidateRecommendationValidationIntakeRejected(ValueError):
    pass


class CandidateRecommendationValidationIntakeTimedOut(TimeoutError):
    pass


class CandidateRecommendationValidationIntakeService:
    def __init__(
        self,
        *,
        scope,
        selection_service,
        store,
        timeout_seconds=2.0,
        clock=time.monotonic,
    ):
        if scope != selection_service.scope:
            raise ValueError("Recommendation Validation Intake Scope mismatch")
        if not 0 < timeout_seconds <= 30:
            raise ValueError("Recommendation Validation Intake timeout is invalid")
        self.scope = scope
        self.selection_service = selection_service
        self.store = store
        self.timeout_seconds = timeout_seconds
        self.clock = clock

    def prepare(
        self,
        *,
        selection_record_id,
        validation_plan,
        now,
        deadline,
        idempotency_key,
    ):
        started = self.clock()
        selection, admission, outcome, candidate_set, graph, candidate = self._inputs(
            selection_record_id, validation_plan, at=now, started=started
        )
        task_deadline = validation_plan.runner_request.task.deadline
        if not now < deadline <= min(task_deadline, self.scope.valid_until):
            raise CandidateRecommendationValidationIntakeRejected(
                "Recommendation Validation Intake deadline exceeds an authoritative boundary"
            )
        values = {
            "selection_record_id": selection.record_id,
            "selection_record_digest": canonical_digest(selection.model_dump(mode="python")),
            "admission_record_id": admission.record_id,
            "recommendation_id": admission.recommendation_id,
            "generation_outcome_id": outcome.outcome_id,
            "candidate_set_id": candidate_set.candidate_set_id,
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate_content_digest(candidate),
            "source_graph_id": graph.graph_id,
            "target_id": candidate.target_id,
            "target_version_digest": canonical_digest(candidate.target_version),
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "validation_plan_id": validation_plan.plan_id,
            "validation_plan_digest": validation_plan_digest(validation_plan),
            "created_at": now,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        try:
            return CandidateRecommendationValidationIntakePlan.create(**values)
        except ValidationError as exc:
            raise CandidateRecommendationValidationIntakeRejected(
                "Recommendation Validation Intake plan is invalid"
            ) from exc

    def intake(self, plan, *, validation_plan, now):
        started = self.clock()
        try:
            plan = CandidateRecommendationValidationIntakePlan.model_validate(plan)
            validation_plan = ValidationPlan.model_validate(validation_plan)
        except ValidationError as exc:
            raise CandidateRecommendationValidationIntakeRejected(
                "Recommendation Validation Intake boundary rejected"
            ) from exc
        if now < plan.created_at or now >= plan.deadline:
            raise CandidateRecommendationValidationIntakeTimedOut(
                "Recommendation Validation Intake window expired"
            )
        selection, admission, outcome, candidate_set, graph, candidate = self._inputs(
            plan.selection_record_id, validation_plan, at=now, started=started
        )
        expected = self.prepare(
            selection_record_id=selection.record_id,
            validation_plan=validation_plan,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
        )
        if (
            plan != expected
            or plan.plan_id != candidate_recommendation_validation_intake_plan_digest(plan)
        ):
            raise CandidateRecommendationValidationIntakeRejected(
                "Recommendation Validation Intake binding drifted"
            )
        claim = self.store.claim(plan)
        if not claim.created:
            if claim.record is None:
                raise CandidateRecommendationValidationIntakeRejected(
                    "completed Recommendation Validation Intake has no record"
                )
            self._verify_record(claim.record, plan, selection, validation_plan)
            return claim.record
        self._check(started)
        record = CandidateRecommendationValidationIntakeRecord.create(
            plan_id=plan.plan_id,
            selection_record_id=selection.record_id,
            selection_record_digest=plan.selection_record_digest,
            admission_record_id=admission.record_id,
            recommendation_id=admission.recommendation_id,
            generation_outcome_id=outcome.outcome_id,
            candidate_set_id=candidate_set.candidate_set_id,
            candidate_id=candidate.candidate_id,
            candidate_digest=candidate_content_digest(candidate),
            source_graph_id=graph.graph_id,
            target_id=candidate.target_id,
            target_version_digest=canonical_digest(candidate.target_version),
            scope_id=self.scope.scope_id,
            scope_version=self.scope.version,
            validation_plan_id=validation_plan.plan_id,
            validation_plan_digest=validation_plan_digest(validation_plan),
            selected_by=selection.reviewer_id,
            selected_at=selection.decided_at,
            completed_at=now,
        )
        self.store.complete(record)
        return record

    @staticmethod
    def _verify_record(record, plan, selection, validation_plan):
        if (
            record.plan_id != plan.plan_id
            or record.selection_record_id != selection.record_id
            or record.selection_record_digest != plan.selection_record_digest
            or record.admission_record_id != plan.admission_record_id
            or record.recommendation_id != plan.recommendation_id
            or record.generation_outcome_id != plan.generation_outcome_id
            or record.candidate_set_id != plan.candidate_set_id
            or record.candidate_id != plan.candidate_id
            or record.candidate_digest != plan.candidate_digest
            or record.source_graph_id != plan.source_graph_id
            or record.target_id != plan.target_id
            or record.target_version_digest != plan.target_version_digest
            or record.scope_id != plan.scope_id
            or record.scope_version != plan.scope_version
            or record.validation_plan_id != validation_plan.plan_id
            or record.validation_plan_digest != validation_plan_digest(validation_plan)
            or record.selected_by != selection.reviewer_id
            or record.selected_at != selection.decided_at
            or not record.candidate_unchanged
            or record.validation_executed
            or not record.requires_run_validation_approval
        ):
            raise CandidateRecommendationValidationIntakeRejected(
                "Recommendation Validation Intake record drifted"
            )

    def _inputs(self, selection_record_id, validation_plan, *, at, started):
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= at < self.scope.valid_until
        ):
            raise CandidateRecommendationValidationIntakeRejected(
                "Recommendation Validation Intake requires approved Scope"
            )
        try:
            validation_plan = ValidationPlan.model_validate(validation_plan)
        except ValidationError as exc:
            raise CandidateRecommendationValidationIntakeRejected(
                "Recommendation Validation Intake authoritative inputs rejected"
            ) from exc
        try:
            values = self.selection_service.load_verified(selection_record_id, at=at)
        except CandidateRecommendationSelectionTimedOut as exc:
            raise CandidateRecommendationValidationIntakeTimedOut(
                "Recommendation Validation Intake upstream verification timed out"
            ) from exc
        except CandidateRecommendationSelectionRejected as exc:
            raise CandidateRecommendationValidationIntakeRejected(
                "Recommendation Validation Intake authoritative inputs rejected"
            ) from exc
        selection, admission, outcome, candidate_set, graph, candidate = values
        self._check(started)
        if (
            selection.decision is not CandidateRecommendationSelectionDecision.ACCEPT
            or not selection.eligible_for_validation_intake
            or not selection.candidate_unchanged
            or not selection.requires_separate_validation_approval
            or candidate.state is not CandidateState.PROPOSED
            or validation_plan.candidate_id != candidate.candidate_id
            or validation_plan.candidate_digest != candidate_content_digest(candidate)
            or validation_plan.target_id != candidate.target_id
            or validation_plan.target_version != candidate.target_version
            or validation_plan.scope_id != self.scope.scope_id
            or validation_plan.scope_version != self.scope.version
            or validation_plan.selected_at < selection.decided_at
            or validation_plan.selected_at > at
            or validation_plan.plan_id != validation_plan_digest(validation_plan)
            or validation_plan.broker_calls
        ):
            raise CandidateRecommendationValidationIntakeRejected(
                "Recommendation selection does not match the offline ValidationPlan"
            )
        request = validation_plan.runner_request
        task = request.task
        if (
            request.profile.kind is not SandboxProfileKind.VALIDATION
            or request.profile.network_mode is not NetworkMode.NONE
            or request.task.sandbox_profile_digest != sandbox_profile_digest(request.profile)
            or task.engagement_id != self.scope.engagement_id
            or task.target_id != candidate.target_id
            or task.target_version != candidate.target_version
            or task.scope_id != self.scope.scope_id
            or task.scope_version != self.scope.version
            or task.worker_role is not WorkerRole.VALIDATOR
            or task.policy_digest != PolicyEngine(self.scope).policy_digest
            or f"candidate:{candidate_content_digest(candidate)}" not in task.input_refs
            or at >= task.deadline
            or task.deadline > self.scope.valid_until
        ):
            raise CandidateRecommendationValidationIntakeRejected(
                "Recommendation ValidationPlan task or Sandbox binding rejected"
            )
        return selection, admission, outcome, candidate_set, graph, candidate

    def _check(self, started):
        if self.clock() - started >= self.timeout_seconds:
            raise CandidateRecommendationValidationIntakeTimedOut(
                "Recommendation Validation Intake timed out"
            )
