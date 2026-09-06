"""Read-only pilot M8.2 boundary; never executes Validation or grants authority."""

from datetime import datetime

from vulnloom.domain.digests import canonical_digest
from vulnloom.validation.models import candidate_content_digest

from .outcome_binding import AgentValidationOutcomeBindingService
from .outcome_binding_models import AgentValidationOutcomeBindingPlan
from .pilot_execution_store import PilotValidationExecutionStore
from .pilot_intake_models import pilot_validation_intake_binding_digest
from .pilot_intake_store import PilotValidationIntakeStore
from .pilot_outcome_models import PilotValidationOutcomeBinding, PilotValidationOutcomePlan
from .pilot_outcome_store import PilotValidationOutcomeStore


def _digest(value):
    return canonical_digest(value.model_dump(mode="python"))


class PilotValidationOutcomeRejected(ValueError):
    pass


class PilotValidationOutcomeTimedOut(TimeoutError):
    pass


class PilotValidationOutcomeService:
    def __init__(
        self,
        *,
        execution_store: PilotValidationExecutionStore,
        pilot_intake_store: PilotValidationIntakeStore,
        outcome_service: AgentValidationOutcomeBindingService,
        store: PilotValidationOutcomeStore,
    ):
        self.execution_store = execution_store
        self.pilot_intake_store = pilot_intake_store
        self.outcome_service = outcome_service
        self.store = store

    def prepare(
        self,
        *,
        execution_plan_id: str,
        outcome_plan: AgentValidationOutcomeBindingPlan,
        audit_artifact,
        validation_plan,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> PilotValidationOutcomePlan:
        execution, binding = self._verify(
            execution_plan_id, outcome_plan, audit_artifact, validation_plan, now
        )
        record = self.outcome_service.intake_store.load_completed(outcome_plan.intake_plan_id)
        if (
            not now
            < deadline
            <= min(outcome_plan.deadline, self.outcome_service.scope.valid_until, record.expires_at)
        ):
            raise PilotValidationOutcomeRejected("pilot outcome deadline exceeds upstream window")
        return PilotValidationOutcomePlan.create(
            execution_plan_id=execution.execution_plan_id,
            execution_plan_digest=_digest(execution),
            execution_binding_id=binding.binding_id,
            execution_binding_digest=_digest(binding),
            outcome_binding_plan_id=outcome_plan.binding_plan_id,
            outcome_binding_plan_digest=_digest(outcome_plan),
            validation_plan_id=outcome_plan.validation_plan_id,
            validation_outcome_digest=outcome_plan.validation_outcome_digest,
            created_at=now,
            deadline=deadline,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        plan: PilotValidationOutcomePlan,
        *,
        outcome_plan: AgentValidationOutcomeBindingPlan,
        audit_artifact,
        validation_plan,
        now: datetime,
    ) -> PilotValidationOutcomeBinding:
        plan = PilotValidationOutcomePlan.model_validate(plan.model_dump(mode="python"))
        if not plan.created_at <= now < plan.deadline:
            raise PilotValidationOutcomeTimedOut("pilot outcome is outside its window")
        self._verify(plan.execution_plan_id, outcome_plan, audit_artifact, validation_plan, now)
        expected = self.prepare(
            execution_plan_id=plan.execution_plan_id,
            outcome_plan=outcome_plan,
            audit_artifact=audit_artifact,
            validation_plan=validation_plan,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise PilotValidationOutcomeRejected("pilot outcome plan drifted")
        # An existing bare M8.2 checkpoint cannot be retrospectively blessed as pilot provenance.
        if self._has_outcome_checkpoint(plan) and not self.store.has_validation_checkpoint(
            plan.validation_plan_id
        ):
            raise PilotValidationOutcomeRejected("M8.2 checkpoint predates pilot outcome gate")
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.binding is not None
            result = self.outcome_service.binding_store.load_completed(outcome_plan.binding_plan_id)
            self._verify_result(plan, outcome_plan, result)
            expected_binding = self._binding(plan, result, claim.binding.completed_at)
            if claim.binding != expected_binding:
                raise PilotValidationOutcomeRejected("pilot outcome completed binding drifted")
            return claim.binding
        if self._has_outcome_checkpoint(plan):
            raise PilotValidationOutcomeRejected("M8.2 checkpoint predates pilot outcome gate")
        result = self.outcome_service.execute(
            outcome_plan, audit_artifact=audit_artifact, validation_plan=validation_plan, now=now
        )
        persisted = self.outcome_service.binding_store.load_completed(outcome_plan.binding_plan_id)
        if result != persisted:
            raise PilotValidationOutcomeRejected("M8.2 authoritative binding drifted")
        self._verify_result(plan, outcome_plan, result)
        binding = self._binding(plan, result, now)
        self.store.complete(binding)
        return binding

    def _verify_result(self, plan, outcome_plan, result):
        execution = self.execution_store.load_completed(plan.execution_plan_id)
        if (
            result.binding_plan_id != outcome_plan.binding_plan_id
            or not plan.created_at <= result.completed_at < plan.deadline
            or any(
                getattr(result, field) != getattr(outcome_plan, field)
                for field in (
                    "intake_record_id",
                    "audit_bundle_id",
                    "candidate_id",
                    "candidate_digest",
                    "validation_plan_id",
                    "validation_outcome_digest",
                    "validation_run_id",
                    "result",
                    "evidence_refs",
                )
            )
            or any(
                getattr(result, field) != getattr(execution, field)
                for field in (
                    "final_candidate_state",
                    "final_candidate_digest",
                    "evidence_bundle_id",
                    "evidence_bundle_digest",
                )
            )
        ):
            raise PilotValidationOutcomeRejected("M8.2 completed provenance drifted")

    def _has_outcome_checkpoint(self, plan):
        return self.outcome_service.binding_store.has_validation_checkpoint(plan.validation_plan_id)

    @staticmethod
    def _binding(plan, result, now):
        if result.completed_at != now:
            raise PilotValidationOutcomeRejected("pilot/M8.2 completion time drifted")
        values = dict(
            plan_id=plan.plan_id,
            execution_binding_id=plan.execution_binding_id,
            outcome_binding_plan_id=result.binding_plan_id,
            outcome_binding_id=result.binding_id,
            outcome_binding_digest=_digest(result),
            validation_plan_id=result.validation_plan_id,
            validation_outcome_digest=result.validation_outcome_digest,
            completed_at=now,
        )
        return PilotValidationOutcomeBinding(binding_id=canonical_digest(values), **values)

    def _verify(self, execution_plan_id, outcome_plan, artifact, validation_plan, now):
        try:
            outcome_plan = AgentValidationOutcomeBindingPlan.model_validate(
                outcome_plan.model_dump(mode="python")
            )
            binding = self.execution_store.load_completed(execution_plan_id)
            execution = self.execution_store.load_completed_plan(execution_plan_id)
            intake = self.pilot_intake_store.load_completed(execution.pilot_intake_plan_id)
            # M8.2 rechecks accepted Intake, current Scope, Audit, CandidateSet, every Runner/
            # Broker/result binding and Evidence integrity without any execution dependency.
            expected = self.outcome_service.prepare(
                intake_plan_id=outcome_plan.intake_plan_id,
                audit_artifact=artifact,
                candidate_set_id=outcome_plan.candidate_set_id,
                candidate_id=outcome_plan.candidate_id,
                validation_plan=validation_plan,
                now=outcome_plan.created_at,
                idempotency_key=outcome_plan.idempotency_key,
            )
            _, _, _, _, _, outcome = self.outcome_service._load(
                outcome_plan.intake_plan_id,
                artifact,
                outcome_plan.candidate_set_id,
                outcome_plan.candidate_id,
                validation_plan,
                now,
            )
        except (ValueError, RuntimeError, OSError) as exc:
            raise PilotValidationOutcomeRejected(
                "pilot outcome authoritative input unavailable"
            ) from exc
        evidence = outcome.evidence_bundle
        if (
            expected != outcome_plan
            or validation_plan.broker_calls
            or not binding.completed_at <= outcome_plan.created_at <= now < outcome_plan.deadline
            or outcome.completed_at != binding.completed_at
            or intake.binding_id != execution.pilot_intake_binding_id
            or pilot_validation_intake_binding_digest(intake)
            != execution.pilot_intake_binding_digest
            or intake.intake_record_id != outcome_plan.intake_record_id
            or intake.intake_record_digest != outcome_plan.intake_record_digest
            or any(
                getattr(execution, field) != getattr(outcome_plan, field)
                for field in (
                    "intake_record_id",
                    "candidate_set_id",
                    "candidate_id",
                    "candidate_digest",
                    "scope_id",
                    "scope_version",
                    "validation_plan_id",
                    "validation_plan_digest",
                )
            )
            or any(
                getattr(intake, field) != getattr(outcome_plan, field)
                for field in (
                    "candidate_set_id",
                    "candidate_id",
                    "candidate_digest",
                    "scope_id",
                    "scope_version",
                    "validation_plan_id",
                )
            )
            or any(
                getattr(binding, field) != getattr(outcome_plan, field)
                for field in (
                    "validation_outcome_digest",
                    "validation_run_id",
                    "result",
                    "evidence_refs",
                )
            )
            or binding.final_candidate_digest != candidate_content_digest(outcome.candidate)
            or binding.final_candidate_state != outcome.candidate.state
            or binding.evidence_bundle_id != (None if evidence is None else evidence.bundle_id)
            or binding.evidence_bundle_digest != (None if evidence is None else _digest(evidence))
        ):
            raise PilotValidationOutcomeRejected("pilot execution/outcome provenance drifted")
        return execution, binding
