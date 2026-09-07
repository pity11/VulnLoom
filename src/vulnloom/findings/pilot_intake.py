"""Read-only pilot provenance bridge to human Finding Intake; never promotes."""

from datetime import datetime

from vulnloom.critic import PilotCriticExecutionPlan, PilotCriticExecutionService
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, CriticVerdict

from .intake import AgentFindingIntakeService
from .intake_models import (
    AgentFindingIntakeCommand,
    AgentFindingIntakeDecision,
    AgentFindingIntakePlan,
    AgentFindingIntakeRecord,
)
from .pilot_intake_models import PilotFindingIntakeBinding, PilotFindingIntakePlan
from .pilot_intake_store import PilotFindingIntakeStore


def _digest(value):
    return canonical_digest(value.model_dump(mode="python"))


class PilotFindingIntakeRejected(ValueError):
    pass


class PilotFindingIntakeTimedOut(TimeoutError):
    pass


class PilotFindingIntakeService:
    def __init__(
        self,
        *,
        critic_execution_service: PilotCriticExecutionService,
        intake_service: AgentFindingIntakeService,
        store: PilotFindingIntakeStore,
    ):
        self.critic_execution_service = critic_execution_service
        self.intake_service = intake_service
        self.store = store
        upstream = critic_execution_service.outcome_service
        if (
            intake_service.scope != critic_execution_service.scope
            or intake_service.critic_binding_store is not upstream.binding_store
            or intake_service.validation_binding_store is not upstream.outcome_binding_store
            or intake_service.validation_store is not upstream.validation_store
            or intake_service.critic_store is not upstream.critic_store
            or intake_service.evidence_store is not upstream.evidence_store
        ):
            raise ValueError("pilot Finding services must share authoritative provenance stores")

    def prepare(
        self,
        *,
        critic_execution_plan: PilotCriticExecutionPlan,
        execution_approval,
        execution_inputs,
        intake_plan: AgentFindingIntakePlan,
        command: AgentFindingIntakeCommand,
        critic_binding_plan,
        promotion_plan,
        duplicate_check,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> PilotFindingIntakePlan:
        binding = self._verify(
            critic_execution_plan=critic_execution_plan,
            execution_approval=execution_approval,
            execution_inputs=execution_inputs,
            intake_plan=intake_plan,
            command=command,
            critic_binding_plan=critic_binding_plan,
            promotion_plan=promotion_plan,
            duplicate_check=duplicate_check,
            now=now,
        )
        if (
            not now
            < deadline
            <= min(
                intake_plan.decision_deadline,
                promotion_plan.deadline,
                duplicate_check.expires_at,
                self.intake_service.scope.valid_until,
                execution_inputs["intake_plan"].decision_deadline,
                execution_inputs["outcome_plan"].deadline,
                execution_inputs["critic_plan"].deadline,
            )
        ):
            raise PilotFindingIntakeRejected("pilot Finding deadline exceeds current authority")
        return PilotFindingIntakePlan.create(
            critic_execution_plan_id=critic_execution_plan.execution_plan_id,
            critic_execution_plan_digest=_digest(critic_execution_plan),
            critic_execution_binding_id=binding.binding_id,
            critic_execution_binding_digest=_digest(binding),
            intake_plan_id=intake_plan.intake_plan_id,
            intake_plan_digest=_digest(intake_plan),
            command_id=command.command_id,
            command_digest=_digest(command),
            promotion_plan_id=promotion_plan.promotion_plan_id,
            promotion_plan_digest=_digest(promotion_plan),
            duplicate_check_id=duplicate_check.check_id,
            duplicate_check_digest=_digest(duplicate_check),
            finding_id=intake_plan.finding_id,
            candidate_id=intake_plan.candidate_id,
            candidate_digest=intake_plan.candidate_digest,
            scope_id=intake_plan.scope_id,
            scope_version=intake_plan.scope_version,
            created_at=now,
            deadline=deadline,
            idempotency_key=idempotency_key,
        )

    def execute(self, plan: PilotFindingIntakePlan, *, now: datetime, **inputs):
        plan = PilotFindingIntakePlan.model_validate(plan.model_dump(mode="python"))
        if not plan.created_at <= now < plan.deadline:
            raise PilotFindingIntakeTimedOut("pilot Finding Intake outside its window")
        self._verify(**inputs, now=now)
        expected = self.prepare(
            **inputs,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise PilotFindingIntakeRejected("pilot Finding Intake plan drifted")
        intake_plan, command = inputs["intake_plan"], inputs["command"]
        if self.intake_service.store.has_input_checkpoint(intake_plan, command) and not (
            self.store.has_promotion_checkpoint(plan.promotion_plan_id)
        ):
            raise PilotFindingIntakeRejected("M8.5 checkpoint predates pilot Finding gate")
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.binding is not None
            record = self.intake_service.store.load_completed(plan.intake_plan_id)
            self._verify_record(record, intake_plan, command)
            if (
                claim.binding != self._binding(plan, record, claim.binding.completed_at)
                or claim.binding.completed_at > now
            ):
                raise PilotFindingIntakeRejected("pilot Finding completed binding drifted")
            return claim.binding
        if self.intake_service.store.has_input_checkpoint(intake_plan, command):
            raise PilotFindingIntakeRejected("M8.5 checkpoint predates pilot Finding gate")
        record = self.intake_service.decide(
            intake_plan,
            command,
            critic_binding_plan=inputs["critic_binding_plan"],
            promotion_plan=inputs["promotion_plan"],
            duplicate_check=inputs["duplicate_check"],
            now=now,
        )
        persisted = self.intake_service.store.load_completed(plan.intake_plan_id)
        self._verify_record(persisted, intake_plan, command)
        if record != persisted:
            raise PilotFindingIntakeRejected("M8.5 authoritative record drifted")
        binding = self._binding(plan, record, now)
        self.store.complete(binding)
        return binding

    def load_verified(self, plan: PilotFindingIntakePlan, *, now: datetime, **inputs):
        """Read exact completed Intake provenance without creating or deciding an Intake."""
        plan = PilotFindingIntakePlan.model_validate(plan.model_dump(mode="python"))
        if not plan.created_at <= now < plan.deadline:
            raise PilotFindingIntakeTimedOut("pilot Finding Intake outside its window")
        self._verify(**inputs, now=now)
        expected = self.prepare(
            **inputs,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
        )
        binding = self.store.load_completed(plan.plan_id)
        record = self.intake_service.store.load_completed(plan.intake_plan_id)
        self._verify_record(record, inputs["intake_plan"], inputs["command"])
        if (
            expected != plan
            or self.store.load_completed_plan(plan.plan_id) != plan
            or binding != self._binding(plan, record, binding.completed_at)
            or binding.completed_at > now
        ):
            raise PilotFindingIntakeRejected("pilot Finding completed provenance drifted")
        return binding

    def _verify(
        self,
        *,
        critic_execution_plan,
        execution_approval,
        execution_inputs,
        intake_plan,
        command,
        critic_binding_plan,
        promotion_plan,
        duplicate_check,
        now,
    ):
        try:
            binding = self.critic_execution_service.load_verified(
                critic_execution_plan, approval=execution_approval, now=now, **execution_inputs
            )
            self.intake_service.preflight(
                intake_plan,
                command,
                critic_binding_plan=critic_binding_plan,
                promotion_plan=promotion_plan,
                duplicate_check=duplicate_check,
                now=now,
            )
            m8 = self.intake_service.critic_binding_store.load_completed(
                critic_binding_plan.binding_plan_id
            )
        except (ValueError, RuntimeError, OSError) as exc:
            raise PilotFindingIntakeRejected(
                "pilot Finding authoritative inputs unavailable"
            ) from exc
        if (
            self.intake_service.scope != self.critic_execution_service.scope
            or command.decision is not AgentFindingIntakeDecision.ACCEPT
            or binding.verdict is not CriticVerdict.ACCEPTED
            or binding.final_candidate_state is not CandidateState.CRITIC_REVIEWED
            or not binding.completed_at <= duplicate_check.checked_at <= promotion_plan.created_at
            or not promotion_plan.created_at <= intake_plan.created_at <= command.decided_at <= now
            or binding.outcome_binding_plan_id != critic_binding_plan.binding_plan_id
            or binding.outcome_binding_plan_digest != _digest(critic_binding_plan)
            or binding.outcome_binding_id != m8.binding_id
            or binding.outcome_binding_digest != _digest(m8)
            or binding.candidate_id != intake_plan.candidate_id
            or binding.final_candidate_digest != intake_plan.candidate_digest
            or binding.critic_review_id != intake_plan.critic_review_id
            or binding.critic_review_digest != intake_plan.critic_review_digest
        ):
            raise PilotFindingIntakeRejected(
                "pilot Critic does not match exact accepted Finding Intake"
            )
        return binding

    @staticmethod
    def _verify_record(record, plan, command):
        values = {
            field: getattr(plan, field)
            for field in (
                "intake_plan_id",
                "critic_outcome_binding_id",
                "promotion_plan_id",
                "promotion_plan_digest",
                "duplicate_check_id",
                "candidate_id",
                "finding_id",
                "evidence_bundle_id",
                "critic_review_id",
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
        expected = AgentFindingIntakeRecord(record_id=canonical_digest(values), **values)
        if record != expected:
            raise PilotFindingIntakeRejected("M8.5 completed record provenance drifted")

    @staticmethod
    def _binding(plan, record, now):
        values = {
            field: getattr(plan, field)
            for field in (
                "plan_id",
                "critic_execution_binding_id",
                "intake_plan_id",
                "command_id",
                "promotion_plan_id",
                "duplicate_check_id",
                "finding_id",
                "candidate_id",
                "candidate_digest",
                "scope_id",
                "scope_version",
            )
        }
        values.update(
            intake_record_id=record.record_id,
            intake_record_digest=_digest(record),
            completed_at=now,
        )
        return PilotFindingIntakeBinding(binding_id=canonical_digest(values), **values)
