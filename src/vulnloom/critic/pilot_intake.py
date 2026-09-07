"""Pilot-only human Critic Intake; no Critic, Validation, or execution dependency."""

from datetime import datetime

from vulnloom.domain.digests import canonical_digest
from vulnloom.validation import PilotValidationOutcomePlan, PilotValidationOutcomeService

from .intake import AgentCriticIntakeService
from .intake_models import (
    AgentCriticIntakeCommand,
    AgentCriticIntakeDecision,
    AgentCriticIntakePlan,
    AgentCriticIntakeRecord,
)
from .pilot_intake_models import PilotCriticIntakeBinding, PilotCriticIntakePlan
from .pilot_intake_store import PilotCriticIntakeStore


def _digest(value):
    return canonical_digest(value.model_dump(mode="python"))


class PilotCriticIntakeRejected(ValueError):
    pass


class PilotCriticIntakeTimedOut(TimeoutError):
    pass


class PilotCriticIntakeService:
    def __init__(
        self,
        *,
        pilot_outcome_service: PilotValidationOutcomeService,
        intake_service: AgentCriticIntakeService,
        store: PilotCriticIntakeStore,
    ):
        self.pilot_outcome_service = pilot_outcome_service
        self.intake_service = intake_service
        self.store = store

    def prepare(
        self,
        *,
        pilot_outcome_plan: PilotValidationOutcomePlan,
        intake_plan: AgentCriticIntakePlan,
        command: AgentCriticIntakeCommand,
        outcome_plan,
        audit_artifact,
        validation_plan,
        critic_plan,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> PilotCriticIntakePlan:
        binding = self._verify(
            pilot_outcome_plan=pilot_outcome_plan,
            intake_plan=intake_plan,
            command=command,
            outcome_plan=outcome_plan,
            audit_artifact=audit_artifact,
            validation_plan=validation_plan,
            critic_plan=critic_plan,
            now=now,
        )
        if (
            not now
            < deadline
            <= min(
                intake_plan.decision_deadline,
                outcome_plan.deadline,
                critic_plan.deadline,
                self.intake_service.scope.valid_until,
            )
        ):
            raise PilotCriticIntakeRejected("pilot Critic Intake deadline exceeds upstream window")
        return PilotCriticIntakePlan.create(
            pilot_outcome_plan_id=pilot_outcome_plan.plan_id,
            pilot_outcome_plan_digest=_digest(pilot_outcome_plan),
            pilot_outcome_binding_id=binding.binding_id,
            pilot_outcome_binding_digest=_digest(binding),
            intake_plan_id=intake_plan.intake_plan_id,
            intake_plan_digest=_digest(intake_plan),
            command_id=command.command_id,
            command_digest=_digest(command),
            critic_plan_id=critic_plan.plan_id,
            critic_plan_digest=_digest(critic_plan),
            candidate_id=intake_plan.candidate_id,
            validated_candidate_digest=intake_plan.validated_candidate_digest,
            scope_id=intake_plan.scope_id,
            scope_version=intake_plan.scope_version,
            created_at=now,
            deadline=deadline,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        plan: PilotCriticIntakePlan,
        *,
        pilot_outcome_plan: PilotValidationOutcomePlan,
        intake_plan: AgentCriticIntakePlan,
        command: AgentCriticIntakeCommand,
        outcome_plan,
        audit_artifact,
        validation_plan,
        critic_plan,
        now: datetime,
    ) -> PilotCriticIntakeBinding:
        plan = PilotCriticIntakePlan.model_validate(plan.model_dump(mode="python"))
        if not plan.created_at <= now < plan.deadline:
            raise PilotCriticIntakeTimedOut("pilot Critic Intake outside its window")
        inputs = dict(
            pilot_outcome_plan=pilot_outcome_plan,
            intake_plan=intake_plan,
            command=command,
            outcome_plan=outcome_plan,
            audit_artifact=audit_artifact,
            validation_plan=validation_plan,
            critic_plan=critic_plan,
        )
        self._verify(**inputs, now=now)
        expected = self.prepare(
            **inputs,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise PilotCriticIntakeRejected("pilot Critic Intake plan drifted")
        if self.intake_service.store.has_critic_checkpoint(plan.critic_plan_id) and not (
            self.store.has_critic_checkpoint(plan.critic_plan_id)
        ):
            raise PilotCriticIntakeRejected("M8.3 checkpoint predates pilot Intake gate")
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.binding is not None
            record = self.intake_service.store.load_completed(intake_plan.intake_plan_id)
            self._verify_record(record, intake_plan, command)
            if claim.binding != self._binding(plan, record, claim.binding.completed_at):
                raise PilotCriticIntakeRejected("pilot Critic Intake completed binding drifted")
            if claim.binding.completed_at > now:
                raise PilotCriticIntakeRejected("pilot Critic Intake completion is in the future")
            return claim.binding
        if self.intake_service.store.has_critic_checkpoint(plan.critic_plan_id):
            raise PilotCriticIntakeRejected("M8.3 checkpoint predates pilot Intake gate")
        record = self.intake_service.decide(
            intake_plan,
            command,
            outcome_binding_plan=outcome_plan,
            audit_artifact=audit_artifact,
            critic_plan=critic_plan,
            now=now,
        )
        persisted = self.intake_service.store.load_completed(intake_plan.intake_plan_id)
        self._verify_record(persisted, intake_plan, command)
        if persisted != record:
            raise PilotCriticIntakeRejected("M8.3 authoritative record drifted")
        binding = self._binding(plan, record, now)
        self.store.complete(binding)
        return binding

    def load_verified(self, plan: PilotCriticIntakePlan, *, now: datetime, **inputs):
        """Read completed human Intake without deciding or claiming again."""
        plan = PilotCriticIntakePlan.model_validate(plan.model_dump(mode="python"))
        self._verify(**inputs, now=now)
        expected = self.prepare(
            **inputs,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise PilotCriticIntakeRejected("pilot Critic Intake plan drifted")
        binding = self.store.load_completed(plan.plan_id)
        record = self.intake_service.store.load_completed(plan.intake_plan_id)
        self._verify_record(record, inputs["intake_plan"], inputs["command"])
        if (
            binding != self._binding(plan, record, binding.completed_at)
            or binding.completed_at > now
        ):
            raise PilotCriticIntakeRejected("pilot Critic completed Intake drifted")
        return binding

    def _verify(
        self,
        *,
        pilot_outcome_plan,
        intake_plan,
        command,
        outcome_plan,
        audit_artifact,
        validation_plan,
        critic_plan,
        now,
    ):
        try:
            binding = self.pilot_outcome_service.load_verified(
                pilot_outcome_plan,
                outcome_plan=outcome_plan,
                audit_artifact=audit_artifact,
                validation_plan=validation_plan,
                now=now,
            )
            self.intake_service.preflight(
                intake_plan,
                command,
                outcome_binding_plan=outcome_plan,
                audit_artifact=audit_artifact,
                critic_plan=critic_plan,
                now=now,
            )
            m8 = self.intake_service.outcome_binding_store.load_completed(
                outcome_plan.binding_plan_id
            )
        except (ValueError, RuntimeError, OSError, TimeoutError) as exc:
            raise PilotCriticIntakeRejected(
                "pilot Critic authoritative inputs unavailable"
            ) from exc
        if (
            command.decision is not AgentCriticIntakeDecision.ACCEPT
            or self.intake_service.scope != self.pilot_outcome_service.outcome_service.scope
            or not binding.completed_at <= intake_plan.created_at <= command.decided_at <= now
            or critic_plan.created_at < binding.completed_at
            or binding.outcome_binding_plan_id != outcome_plan.binding_plan_id
            or binding.outcome_binding_id != m8.binding_id
            or binding.outcome_binding_digest != _digest(m8)
            or binding.validation_plan_id != intake_plan.validation_plan_id
            or binding.validation_outcome_digest != intake_plan.validation_outcome_digest
        ):
            raise PilotCriticIntakeRejected(
                "pilot outcome does not match exact accepted Critic Intake"
            )
        return binding

    @staticmethod
    def _verify_record(record, plan, command):
        values = {
            field: getattr(plan, field)
            for field in (
                "intake_plan_id",
                "outcome_binding_id",
                "audit_bundle_id",
                "candidate_id",
                "validation_run_id",
                "evidence_bundle_id",
                "critic_plan_id",
                "critic_plan_digest",
                "scope_id",
                "scope_version",
            )
        }
        values.update(
            {
                field: getattr(command, field)
                for field in (
                    "command_id",
                    "decision",
                    "reason_code",
                    "reviewer",
                    "decided_at",
                )
            }
        )
        values["expires_at"] = plan.decision_deadline
        expected = AgentCriticIntakeRecord(record_id=canonical_digest(values), **values)
        if record != expected:
            raise PilotCriticIntakeRejected("M8.3 completed record provenance drifted")

    @staticmethod
    def _binding(plan, record, now):
        values = {
            field: getattr(plan, field)
            for field in (
                "plan_id",
                "pilot_outcome_binding_id",
                "intake_plan_id",
                "command_id",
                "critic_plan_id",
                "candidate_id",
                "validated_candidate_digest",
                "scope_id",
                "scope_version",
            )
        }
        values.update(
            intake_record_id=record.record_id,
            intake_record_digest=_digest(record),
            completed_at=now,
        )
        return PilotCriticIntakeBinding(binding_id=canonical_digest(values), **values)
