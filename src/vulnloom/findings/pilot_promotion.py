"""Pilot provenance gate for an explicitly approved, local Finding state transition."""

from datetime import datetime

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalRequest

from .pilot_intake import PilotFindingIntakeService
from .pilot_intake_models import PilotFindingIntakePlan
from .pilot_promotion_models import PilotFindingPromotionBinding, PilotFindingPromotionPlan
from .pilot_promotion_store import PilotFindingPromotionStore
from .promotion import FindingPromotionService
from .promotion_models import FindingPromotionExecutionPlan


def _digest(value):
    return canonical_digest(value.model_dump(mode="python"))


class PilotFindingPromotionRejected(ValueError):
    pass


class PilotFindingPromotionTimedOut(TimeoutError):
    pass


class PilotFindingPromotionService:
    def __init__(
        self,
        *,
        pilot_intake_service: PilotFindingIntakeService,
        promotion_service: FindingPromotionService,
        store: PilotFindingPromotionStore,
    ):
        if promotion_service.intake_service is not pilot_intake_service.intake_service:
            raise ValueError("pilot promotion must share authoritative Finding Intake service")
        self.pilot_intake_service = pilot_intake_service
        self.promotion_service = promotion_service
        self.store = store

    def prepare(
        self,
        *,
        pilot_intake_plan: PilotFindingIntakePlan,
        intake_inputs: dict,
        execution_plan: FindingPromotionExecutionPlan,
        approval: ApprovalRequest,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> PilotFindingPromotionPlan:
        binding = self._verify(
            pilot_intake_plan=pilot_intake_plan,
            intake_inputs=intake_inputs,
            execution_plan=execution_plan,
            approval=approval,
            now=now,
        )
        if not now < deadline <= min(pilot_intake_plan.deadline, execution_plan.deadline):
            raise PilotFindingPromotionRejected("pilot promotion deadline exceeds authority")
        values = {
            field: getattr(execution_plan, field)
            for field in (
                "execution_plan_id",
                "approval_action_id",
                "approval_id",
                "approval_digest",
                "intake_record_id",
                "promotion_plan_id",
                "finding_id",
                "candidate_id",
                "candidate_digest",
                "scope_id",
                "scope_version",
            )
        }
        return PilotFindingPromotionPlan.create(
            **values,
            pilot_intake_plan_id=pilot_intake_plan.plan_id,
            pilot_intake_plan_digest=_digest(pilot_intake_plan),
            pilot_intake_binding_id=binding.binding_id,
            pilot_intake_binding_digest=_digest(binding),
            execution_plan_digest=_digest(execution_plan),
            duplicate_check_id=pilot_intake_plan.duplicate_check_id,
            created_at=now,
            deadline=deadline,
            idempotency_key=idempotency_key,
        )

    @staticmethod
    def _promotion_inputs(intake_inputs, approval):
        return {
            **{
                field: intake_inputs[field]
                for field in (
                    "intake_plan",
                    "critic_binding_plan",
                    "promotion_plan",
                    "duplicate_check",
                )
            },
            "approval": approval,
        }

    def _verify(self, *, pilot_intake_plan, intake_inputs, execution_plan, approval, now):
        try:
            binding = self.pilot_intake_service.load_verified(
                pilot_intake_plan,
                **intake_inputs,
                now=now,
            )
            self.promotion_service.preflight(
                execution_plan,
                **self._promotion_inputs(intake_inputs, approval),
                now=now,
            )
        except (ValueError, RuntimeError, OSError) as exc:
            raise PilotFindingPromotionRejected("pilot promotion authority unavailable") from exc
        if (
            self.promotion_service.scope != self.pilot_intake_service.intake_service.scope
            or not binding.completed_at <= execution_plan.created_at <= now
            or approval.decided_at is None
            or approval.decided_at < binding.completed_at
            or binding.intake_record_id != execution_plan.intake_record_id
            or binding.intake_plan_id != execution_plan.intake_plan_id
            or binding.promotion_plan_id != execution_plan.promotion_plan_id
            or binding.finding_id != execution_plan.finding_id
            or binding.candidate_id != execution_plan.candidate_id
            or binding.candidate_digest != execution_plan.candidate_digest
            or binding.scope_id != execution_plan.scope_id
            or binding.scope_version != execution_plan.scope_version
        ):
            raise PilotFindingPromotionRejected("pilot Finding promotion inputs drifted")
        return binding

    def execute(self, plan: PilotFindingPromotionPlan, *, now: datetime, **inputs):
        plan = PilotFindingPromotionPlan.model_validate(plan.model_dump(mode="python"))
        if not plan.created_at <= now < plan.deadline:
            raise PilotFindingPromotionTimedOut("pilot promotion outside execution window")
        self._verify(**inputs, now=now)
        expected = self.prepare(
            **inputs,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise PilotFindingPromotionRejected("pilot promotion plan drifted")
        execution_plan = inputs["execution_plan"]
        if self.promotion_service.store.has_input_checkpoint(execution_plan) and not (
            self.store.has_promotion_checkpoint(plan.promotion_plan_id)
        ):
            raise PilotFindingPromotionRejected("M8.6 checkpoint predates pilot promotion gate")
        claim = self.store.claim(plan, now=now)
        promotion_inputs = self._promotion_inputs(inputs["intake_inputs"], inputs["approval"])
        if not claim.created:
            outcome = self.promotion_service.load_verified(
                execution_plan,
                **promotion_inputs,
                now=now,
            )
            if claim.binding != self._binding(plan, outcome):
                raise PilotFindingPromotionRejected("pilot promotion completed binding drifted")
            return claim.binding
        if self.promotion_service.store.has_input_checkpoint(execution_plan):
            raise PilotFindingPromotionRejected("M8.6 checkpoint predates pilot promotion gate")
        outcome = self.promotion_service.execute(execution_plan, **promotion_inputs, now=now)
        persisted = self.promotion_service.load_verified(
            execution_plan, **promotion_inputs, now=now
        )
        if outcome != persisted or persisted.completed_at != now:
            raise PilotFindingPromotionRejected("pilot promotion outcome drifted")
        binding = self._binding(plan, outcome)
        self.store.complete(binding)
        return binding

    @staticmethod
    def _binding(plan, outcome):
        values = {
            field: getattr(plan, field)
            for field in (
                "plan_id",
                "pilot_intake_binding_id",
                "execution_plan_id",
                "approval_id",
                "approval_digest",
                "intake_record_id",
                "promotion_plan_id",
                "finding_id",
                "candidate_id",
                "candidate_digest",
                "scope_id",
                "scope_version",
            )
        }
        values.update(
            outcome_id=outcome.outcome_id,
            outcome_digest=_digest(outcome),
            promoted_candidate_digest=outcome.promoted_candidate_digest,
            finding_digest=outcome.finding_digest,
            completed_at=outcome.completed_at,
        )
        return PilotFindingPromotionBinding(binding_id=canonical_digest(values), **values)
