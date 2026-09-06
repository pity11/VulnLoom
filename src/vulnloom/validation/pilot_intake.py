"""Pilot-only bridge that requires M9.7 selection before an M8.1 Intake decision."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from vulnloom.benchmark.pilot_selection_models import (
    pilot_candidate_selection_record_digest,
)
from vulnloom.benchmark.pilot_selection_store import (
    PilotCandidateSelectionRecoveryRequired,
    PilotCandidateSelectionStore,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState
from vulnloom.hypotheses.models import candidate_set_digest

from .intake import AgentValidationIntakeService
from .intake_models import (
    AgentValidationIntakeCommand,
    AgentValidationIntakeDecision,
    AgentValidationIntakePlan,
    agent_validation_intake_command_digest,
    agent_validation_intake_plan_digest,
    agent_validation_intake_record_digest,
)
from .models import ValidationPlan, candidate_content_digest, validation_plan_digest
from .pilot_intake_models import (
    PilotValidationIntakeBinding,
    PilotValidationIntakePlan,
    pilot_validation_intake_plan_digest,
)
from .pilot_intake_store import PilotValidationIntakeStore


class PilotValidationIntakeRejected(ValueError):
    pass


class PilotValidationIntakeTimedOut(TimeoutError):
    pass


class PilotValidationIntakeService:
    def __init__(
        self,
        *,
        selection_store: PilotCandidateSelectionStore,
        intake_service: AgentValidationIntakeService,
        store: PilotValidationIntakeStore,
    ):
        self.selection_store = selection_store
        self.intake_service = intake_service
        self.store = store

    def prepare(
        self,
        *,
        selection_readiness_plan_id: str,
        intake_plan: AgentValidationIntakePlan,
        intake_command: AgentValidationIntakeCommand,
        validation_plan: ValidationPlan,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> PilotValidationIntakePlan:
        selection, candidate_set, candidate = self._verify_inputs(
            selection_readiness_plan_id=selection_readiness_plan_id,
            intake_plan=intake_plan,
            intake_command=intake_command,
            validation_plan=validation_plan,
            now=now,
        )
        if (
            not now
            < deadline
            <= min(
                selection.expires_at,
                intake_plan.decision_deadline,
                self.intake_service.scope.valid_until,
            )
        ):
            raise PilotValidationIntakeRejected(
                "pilot Validation Intake deadline exceeds an authoritative boundary"
            )
        values = {
            "selection_record_id": selection.record_id,
            "selection_record_digest": pilot_candidate_selection_record_digest(selection),
            "selection_readiness_plan_id": selection.readiness_plan_id,
            "intake_plan_id": intake_plan.intake_plan_id,
            "intake_plan_digest": agent_validation_intake_plan_digest(intake_plan),
            "intake_command_id": intake_command.command_id,
            "intake_command_digest": agent_validation_intake_command_digest(intake_command),
            "validation_plan_id": validation_plan.plan_id,
            "validation_plan_digest": validation_plan_digest(validation_plan),
            "candidate_set_id": candidate_set.candidate_set_id,
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate_content_digest(candidate),
            "scope_id": self.intake_service.scope.scope_id,
            "scope_version": self.intake_service.scope.version,
            "created_at": now,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        try:
            return PilotValidationIntakePlan.create(**values)
        except ValidationError as exc:
            raise PilotValidationIntakeRejected("pilot Validation Intake plan is invalid") from exc

    def execute(
        self,
        plan: PilotValidationIntakePlan,
        *,
        selection_readiness_plan_id: str,
        intake_plan: AgentValidationIntakePlan,
        intake_command: AgentValidationIntakeCommand,
        audit_artifact,
        validation_plan: ValidationPlan,
        now: datetime,
    ) -> PilotValidationIntakeBinding:
        try:
            plan = PilotValidationIntakePlan.model_validate(plan)
        except ValidationError as exc:
            raise PilotValidationIntakeRejected(
                "pilot Validation Intake boundary validation failed"
            ) from exc
        if now < plan.created_at or now >= plan.deadline:
            raise PilotValidationIntakeTimedOut(
                "pilot Validation Intake is outside its validity window"
            )
        selection, candidate_set, candidate = self._verify_inputs(
            selection_readiness_plan_id=selection_readiness_plan_id,
            intake_plan=intake_plan,
            intake_command=intake_command,
            validation_plan=validation_plan,
            now=now,
        )
        if (
            plan.plan_id != pilot_validation_intake_plan_digest(plan)
            or plan.selection_record_id != selection.record_id
            or plan.selection_record_digest != pilot_candidate_selection_record_digest(selection)
            or plan.selection_readiness_plan_id != selection.readiness_plan_id
            or plan.intake_plan_id != intake_plan.intake_plan_id
            or plan.intake_plan_digest != agent_validation_intake_plan_digest(intake_plan)
            or plan.intake_command_id != intake_command.command_id
            or plan.intake_command_digest != agent_validation_intake_command_digest(intake_command)
            or plan.validation_plan_id != validation_plan.plan_id
            or plan.validation_plan_digest != validation_plan_digest(validation_plan)
            or plan.candidate_set_id != candidate_set.candidate_set_id
            or plan.candidate_id != candidate.candidate_id
            or plan.candidate_digest != candidate_content_digest(candidate)
            or plan.scope_id != self.intake_service.scope.scope_id
            or plan.scope_version != self.intake_service.scope.version
        ):
            raise PilotValidationIntakeRejected("pilot Validation Intake plan binding drifted")
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.binding is not None
            return claim.binding
        intake_record = self.intake_service.decide(
            intake_plan,
            intake_command,
            audit_artifact=audit_artifact,
            validation_plan=validation_plan,
            now=now,
        )
        values = {
            "plan_id": plan.plan_id,
            "selection_record_id": selection.record_id,
            "intake_record_id": intake_record.record_id,
            "intake_record_digest": agent_validation_intake_record_digest(intake_record),
            "validation_plan_id": validation_plan.plan_id,
            "candidate_set_id": candidate_set.candidate_set_id,
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate_content_digest(candidate),
            "scope_id": self.intake_service.scope.scope_id,
            "scope_version": self.intake_service.scope.version,
            "completed_at": now,
        }
        binding = PilotValidationIntakeBinding(binding_id=canonical_digest(values), **values)
        self.store.complete(binding)
        return binding

    def _verify_inputs(
        self,
        *,
        selection_readiness_plan_id: str,
        intake_plan: AgentValidationIntakePlan,
        intake_command: AgentValidationIntakeCommand,
        validation_plan: ValidationPlan,
        now: datetime,
    ):
        try:
            selection = self.selection_store.load_completed(selection_readiness_plan_id)
            candidate_set = self.intake_service.candidate_set_store.load(
                intake_plan.candidate_set_id
            )
            intake_plan = AgentValidationIntakePlan.model_validate(intake_plan)
            intake_command = AgentValidationIntakeCommand.model_validate(intake_command)
            validation_plan = ValidationPlan.model_validate(validation_plan)
        except (
            OSError,
            ValueError,
            ValidationError,
            PilotCandidateSelectionRecoveryRequired,
        ) as exc:
            raise PilotValidationIntakeRejected(
                "pilot Validation Intake authoritative input verification failed"
            ) from exc
        matches = tuple(
            item for item in candidate_set.candidates if item.candidate_id == selection.candidate_id
        )
        if len(matches) != 1:
            raise PilotValidationIntakeRejected("pilot selected Candidate is unavailable")
        candidate = matches[0]
        scope = self.intake_service.scope
        if (
            now >= selection.expires_at
            or candidate.state is not CandidateState.PROPOSED
            or selection.candidate_set_id != candidate_set.candidate_set_id
            or selection.candidate_digest != candidate_content_digest(candidate)
            or selection.target_id != candidate.target_id
            or selection.scope_id != scope.scope_id
            or selection.scope_version != scope.version
            or intake_plan.candidate_set_id != candidate_set.candidate_set_id
            or intake_plan.candidate_set_digest != candidate_set_digest(candidate_set)
            or intake_plan.candidate_id != candidate.candidate_id
            or intake_plan.candidate_digest != candidate_content_digest(candidate)
            or intake_plan.scope_id != scope.scope_id
            or intake_plan.scope_version != scope.version
            or intake_plan.validation_plan_id != validation_plan.plan_id
            or intake_plan.validation_plan_digest != validation_plan_digest(validation_plan)
            or intake_plan.created_at < selection.decided_at
            or intake_command.intake_plan_id != intake_plan.intake_plan_id
            or intake_command.candidate_id != candidate.candidate_id
            or intake_command.validation_plan_id != validation_plan.plan_id
            or intake_command.decision is not AgentValidationIntakeDecision.ACCEPT
            or intake_command.decided_at < selection.decided_at
            or intake_command.decided_at > now
        ):
            raise PilotValidationIntakeRejected(
                "pilot selection does not match the exact accepted M8.1 Intake"
            )
        return selection, candidate_set, candidate
