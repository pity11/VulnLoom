"""Approval-gated execution of one exact M9.8-bound ValidationPlan."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    CandidateState,
    ScopeState,
)
from vulnloom.hypotheses.models import candidate_set_digest

from .intake_models import (
    AgentValidationIntakeDecision,
    AgentValidationIntakeReason,
    agent_validation_intake_record_digest,
)
from .models import ValidationPlan, candidate_content_digest, validation_plan_digest
from .pilot_execution_models import (
    PILOT_VALIDATION_EFFECTS,
    PilotValidationApprovalAction,
    PilotValidationExecutionBinding,
    PilotValidationExecutionPlan,
    pilot_validation_execution_plan_digest,
)
from .pilot_execution_store import PilotValidationExecutionStore
from .pilot_intake import PilotValidationIntakeService
from .pilot_intake_models import pilot_validation_intake_binding_digest
from .service import ValidationRejected, ValidationService


class PilotValidationExecutionRejected(ValueError):
    pass


class PilotValidationExecutionTimedOut(TimeoutError):
    pass


class PilotValidationExecutionService:
    """Consumes exact human gates; it never constructs a ValidationPlan or Approval."""

    def __init__(
        self,
        *,
        pilot_intake_service: PilotValidationIntakeService,
        validation_service: ValidationService,
        store: PilotValidationExecutionStore,
    ):
        if validation_service.scope != pilot_intake_service.intake_service.scope:
            raise ValueError("pilot Validation execution services use different Scope objects")
        self.pilot_intake_service = pilot_intake_service
        self.validation_service = validation_service
        self.store = store
        self.scope = validation_service.scope

    def approval_action(
        self,
        *,
        pilot_intake_plan_id: str,
        intake_plan_id: str,
        validation_plan: ValidationPlan,
        now: datetime,
    ) -> PilotValidationApprovalAction:
        binding, record, candidate_set, candidate = self._load_authoritative(
            pilot_intake_plan_id=pilot_intake_plan_id,
            intake_plan_id=intake_plan_id,
            validation_plan=validation_plan,
            now=now,
        )
        return PilotValidationApprovalAction.create(
            engagement_id=self.scope.engagement_id,
            target_id=candidate.target_id,
            pilot_intake_plan_id=pilot_intake_plan_id,
            pilot_intake_binding_id=binding.binding_id,
            pilot_intake_binding_digest=pilot_validation_intake_binding_digest(binding),
            intake_record_id=record.record_id,
            intake_record_digest=agent_validation_intake_record_digest(record),
            validation_plan_id=validation_plan.plan_id,
            validation_plan_digest=validation_plan_digest(validation_plan),
            candidate_set_id=candidate_set.candidate_set_id,
            candidate_id=candidate.candidate_id,
            candidate_digest=candidate_content_digest(candidate),
            scope_id=self.scope.scope_id,
            scope_version=self.scope.version,
            expected_side_effects=PILOT_VALIDATION_EFFECTS,
        )

    def prepare(
        self,
        *,
        pilot_intake_plan_id: str,
        intake_plan_id: str,
        validation_plan: ValidationPlan,
        approval: ApprovalRequest,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> PilotValidationExecutionPlan:
        binding, record, candidate_set, candidate, action = self._load(
            pilot_intake_plan_id=pilot_intake_plan_id,
            intake_plan_id=intake_plan_id,
            validation_plan=validation_plan,
            approval=approval,
            now=now,
        )
        if (
            not now
            < deadline
            <= min(self.scope.valid_until, record.expires_at, approval.expires_at)
        ):
            raise PilotValidationExecutionRejected(
                "pilot Validation execution deadline exceeds active authority"
            )
        values = {
            "approval_action_id": action.action_id,
            "approval_id": approval.approval_id,
            "approval_digest": canonical_digest(approval.model_dump(mode="python")),
            "pilot_intake_plan_id": pilot_intake_plan_id,
            "pilot_intake_binding_id": binding.binding_id,
            "pilot_intake_binding_digest": pilot_validation_intake_binding_digest(binding),
            "intake_record_id": record.record_id,
            "validation_plan_id": validation_plan.plan_id,
            "validation_plan_digest": validation_plan_digest(validation_plan),
            "candidate_set_id": candidate_set.candidate_set_id,
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate_content_digest(candidate),
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "created_at": now,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        return PilotValidationExecutionPlan.create(**values)

    def execute(
        self,
        plan: PilotValidationExecutionPlan,
        *,
        intake_plan_id: str,
        validation_plan: ValidationPlan,
        approval: ApprovalRequest,
        now: datetime,
    ) -> PilotValidationExecutionBinding:
        try:
            plan = PilotValidationExecutionPlan.model_validate(plan)
        except ValidationError as exc:
            raise PilotValidationExecutionRejected(
                "pilot Validation execution plan drifted"
            ) from exc
        if now < plan.created_at or now >= plan.deadline:
            raise PilotValidationExecutionTimedOut(
                "pilot Validation execution is outside its window"
            )
        binding, record, _candidate_set, candidate, _action = self._load(
            pilot_intake_plan_id=plan.pilot_intake_plan_id,
            intake_plan_id=intake_plan_id,
            validation_plan=validation_plan,
            approval=approval,
            now=now,
        )
        expected = self.prepare(
            pilot_intake_plan_id=plan.pilot_intake_plan_id,
            intake_plan_id=intake_plan_id,
            validation_plan=validation_plan,
            approval=approval,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan or plan.execution_plan_id != pilot_validation_execution_plan_digest(
            plan
        ):
            raise PilotValidationExecutionRejected("pilot Validation execution plan drifted")
        if self.validation_service.store.has_checkpoint(
            validation_plan.plan_id
        ) and not self.store.has_validation_plan_checkpoint(validation_plan.plan_id):
            raise PilotValidationExecutionRejected(
                "Validation checkpoint predates approved pilot execution"
            )
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.binding is not None
            try:
                stored_plan, persisted = self.validation_service.store.load_completed(
                    validation_plan.plan_id
                )
            except (ValueError, RuntimeError) as exc:
                raise PilotValidationExecutionRejected(
                    "pilot Validation completed outcome is unavailable"
                ) from exc
            expected_binding = self._create_binding(
                plan=plan,
                pilot_intake_binding=binding,
                intake_record=record,
                candidate=candidate,
                validation_plan=validation_plan,
                outcome=persisted,
                completed_at=claim.binding.completed_at,
            )
            if stored_plan != validation_plan or expected_binding != claim.binding:
                raise PilotValidationExecutionRejected("pilot Validation completed binding drifted")
            return claim.binding
        if self.validation_service.store.has_checkpoint(validation_plan.plan_id):
            raise PilotValidationExecutionRejected(
                "Validation checkpoint predates approved pilot execution"
            )
        try:
            outcome = self.validation_service.execute(
                candidate,
                validation_plan,
                now=now,
                approvals=(),
            )
        except (ValidationRejected, ValueError, RuntimeError) as exc:
            raise PilotValidationExecutionRejected("pilot Validation execution failed") from exc
        stored_plan, persisted = self.validation_service.store.load_completed(
            validation_plan.plan_id
        )
        if stored_plan != validation_plan or persisted != outcome:
            raise PilotValidationExecutionRejected("pilot Validation outcome drifted")
        result = self._create_binding(
            plan=plan,
            pilot_intake_binding=binding,
            intake_record=record,
            candidate=candidate,
            validation_plan=validation_plan,
            outcome=outcome,
            completed_at=now,
        )
        self.store.complete(result)
        return result

    @staticmethod
    def _create_binding(
        *,
        plan,
        pilot_intake_binding,
        intake_record,
        candidate,
        validation_plan,
        outcome,
        completed_at,
    ) -> PilotValidationExecutionBinding:
        evidence_bundle = outcome.evidence_bundle
        values = {
            "execution_plan_id": plan.execution_plan_id,
            "approval_action_id": plan.approval_action_id,
            "approval_id": plan.approval_id,
            "approval_digest": plan.approval_digest,
            "pilot_intake_binding_id": pilot_intake_binding.binding_id,
            "intake_record_id": intake_record.record_id,
            "validation_plan_id": validation_plan.plan_id,
            "validation_outcome_digest": canonical_digest(outcome.model_dump(mode="python")),
            "validation_run_id": outcome.validation_run.run_id,
            "candidate_id": candidate.candidate_id,
            "source_candidate_digest": candidate_content_digest(candidate),
            "final_candidate_state": outcome.candidate.state,
            "final_candidate_digest": candidate_content_digest(outcome.candidate),
            "result": outcome.verdict.result,
            "evidence_bundle_id": None if evidence_bundle is None else evidence_bundle.bundle_id,
            "evidence_bundle_digest": None
            if evidence_bundle is None
            else canonical_digest(evidence_bundle.model_dump(mode="python")),
            "evidence_refs": tuple(sorted(outcome.verdict.evidence_refs)),
            "completed_at": completed_at,
        }
        return PilotValidationExecutionBinding(binding_id=canonical_digest(values), **values)

    def _load(self, *, approval: ApprovalRequest, **kwargs):
        binding, record, candidate_set, candidate = self._load_authoritative(**kwargs)
        try:
            approval = ApprovalRequest.model_validate(approval)
        except ValidationError as exc:
            raise PilotValidationExecutionRejected("pilot Validation Approval is invalid") from exc
        action = self.approval_action(**kwargs)
        if (
            approval.status is not ApprovalStatus.GRANTED
            or approval.action is not ApprovalAction.RUN_VALIDATION
            or approval.action_digest != action.action_id
            or approval.engagement_id != self.scope.engagement_id
            or approval.target_id != candidate.target_id
            or approval.policy_version != self.scope.version
            or approval.expected_side_effects != PILOT_VALIDATION_EFFECTS
            or not approval.decided_by
            or approval.decided_at is None
            or not record.decided_at <= approval.decided_at <= kwargs["now"] < approval.expires_at
        ):
            raise PilotValidationExecutionRejected("pilot Validation Intake or Approval drifted")
        return binding, record, candidate_set, candidate, action

    def _load_authoritative(
        self,
        *,
        pilot_intake_plan_id: str,
        intake_plan_id: str,
        validation_plan: ValidationPlan,
        now: datetime,
    ):
        intake = self.pilot_intake_service.intake_service
        try:
            validation_plan = ValidationPlan.model_validate(validation_plan)
            binding = self.pilot_intake_service.store.load_completed(pilot_intake_plan_id)
            record = intake.store.load_completed(intake_plan_id)
            candidate_set = intake.candidate_set_store.load(binding.candidate_set_id)
        except (ValueError, RuntimeError, ValidationError) as exc:
            raise PilotValidationExecutionRejected(
                "pilot Validation authoritative input unavailable"
            ) from exc
        matches = tuple(
            item for item in candidate_set.candidates if item.candidate_id == binding.candidate_id
        )
        if len(matches) != 1:
            raise PilotValidationExecutionRejected("pilot Validation Candidate is unavailable")
        candidate = matches[0]
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or binding.plan_id != pilot_intake_plan_id
            or binding.intake_record_id != record.record_id
            or binding.intake_record_digest != agent_validation_intake_record_digest(record)
            or binding.validation_plan_id != validation_plan.plan_id
            or binding.candidate_set_id != candidate_set.candidate_set_id
            or binding.candidate_id != candidate.candidate_id
            or binding.candidate_digest != candidate_content_digest(candidate)
            or binding.scope_id != self.scope.scope_id
            or binding.scope_version != self.scope.version
            or record.decision is not AgentValidationIntakeDecision.ACCEPT
            or record.reason_code is not AgentValidationIntakeReason.HUMAN_ACCEPTED_EXACT_PLAN
            or not record.decided_at <= now < record.expires_at
            or record.validation_plan_id != validation_plan.plan_id
            or record.validation_plan_digest != validation_plan_digest(validation_plan)
            or record.candidate_set_id != candidate_set.candidate_set_id
            or record.candidate_id != candidate.candidate_id
            or record.candidate_digest != candidate_content_digest(candidate)
            or record.scope_id != self.scope.scope_id
            or record.scope_version != self.scope.version
            or candidate_set.candidate_set_id != candidate_set_digest(candidate_set)
            or candidate.state is not CandidateState.PROPOSED
            or validation_plan.broker_calls
        ):
            raise PilotValidationExecutionRejected("pilot Validation authoritative binding drifted")
        try:
            self.validation_service.preflight(candidate, validation_plan, now=now)
        except (ValidationRejected, ValueError) as exc:
            raise PilotValidationExecutionRejected(
                "pilot Validation trusted preflight failed"
            ) from exc
        return binding, record, candidate_set, candidate
