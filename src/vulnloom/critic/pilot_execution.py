"""Exact human Approval gates deterministic Critic and its M8.4 result binding."""

from datetime import datetime

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, ApprovalRequest, ApprovalStatus, Evidence

from .outcome_binding import AgentCriticOutcomeBindingService
from .outcome_binding_models import AgentCriticOutcomeBinding
from .pilot_execution_models import (
    PILOT_CRITIC_EFFECTS,
    PilotCriticApprovalAction,
    PilotCriticExecutionBinding,
    PilotCriticExecutionPlan,
)
from .pilot_execution_store import PilotCriticExecutionStore
from .pilot_intake import PilotCriticIntakeService
from .service import DeterministicCritic


def _digest(value):
    return canonical_digest(value.model_dump(mode="python"))


def _catalog_digest(evidence):
    return canonical_digest(tuple(item.model_dump(mode="python") for item in evidence))


class PilotCriticExecutionRejected(ValueError):
    pass


class PilotCriticExecutionTimedOut(TimeoutError):
    pass


class PilotCriticExecutionService:
    def __init__(
        self,
        *,
        pilot_intake_service: PilotCriticIntakeService,
        critic: DeterministicCritic,
        outcome_service: AgentCriticOutcomeBindingService,
        store: PilotCriticExecutionStore,
    ):
        self.pilot_intake_service = pilot_intake_service
        self.critic = critic
        self.outcome_service = outcome_service
        self.store = store
        if (
            critic.scope != pilot_intake_service.intake_service.scope
            or critic.scope != outcome_service.scope
        ):
            raise ValueError("pilot Critic services use different Scope")
        if critic.store is not outcome_service.critic_store:
            raise ValueError(
                "pilot Critic and outcome service must share authoritative Critic store"
            )
        intake = pilot_intake_service.intake_service
        if (
            outcome_service.critic_intake_store is not intake.store
            or outcome_service.outcome_binding_store is not intake.outcome_binding_store
            or outcome_service.validation_store is not intake.validation_store
            or outcome_service.evidence_store is not intake.evidence_store
            or critic.evidence_store is not intake.evidence_store
        ):
            raise ValueError("pilot Critic services must share authoritative provenance stores")
        self.scope = critic.scope

    def _load(self, *, pilot_intake_plan, evidence: tuple[Evidence, ...], now, **inputs):
        try:
            binding = self.pilot_intake_service.load_verified(pilot_intake_plan, **inputs, now=now)
            record = self.pilot_intake_service.intake_service.store.load_completed(
                inputs["intake_plan"].intake_plan_id
            )
            _, outcome = self.pilot_intake_service.intake_service.validation_store.load_completed(
                inputs["validation_plan"].plan_id
            )
            if len(evidence) > 256:
                raise ValueError("Evidence catalog over budget")
            evidence = tuple(
                Evidence.model_validate(item.model_dump(mode="python")) for item in evidence
            )
            if (
                self.scope != self.pilot_intake_service.intake_service.scope
                or self.scope != self.outcome_service.scope
                or self.scope != self.critic.scope
            ):
                raise ValueError("Scope drifted")
            bundle = outcome.evidence_bundle
            if bundle is None or len(evidence) > 256:
                raise ValueError("Evidence catalog missing or over budget")
            if tuple(item.evidence_id for item in evidence) != tuple(
                sorted(set(bundle.evidence_refs))
            ):
                raise ValueError("Evidence catalog must exactly cover ordered bundle refs")
            self.critic.preflight(
                outcome.candidate,
                outcome.validation_run,
                bundle,
                evidence,
                inputs["critic_plan"],
                now=now,
            )
        except (ValueError, RuntimeError, OSError) as exc:
            raise PilotCriticExecutionRejected(
                "pilot Critic authoritative inputs unavailable"
            ) from exc
        return binding, record, outcome

    def approval_action(self, *, pilot_intake_plan, evidence, now, **inputs):
        binding, record, outcome = self._load(
            pilot_intake_plan=pilot_intake_plan, evidence=evidence, now=now, **inputs
        )
        return PilotCriticApprovalAction.create(
            engagement_id=self.scope.engagement_id,
            target_id=outcome.candidate.target_id,
            pilot_intake_plan_id=pilot_intake_plan.plan_id,
            pilot_intake_binding_id=binding.binding_id,
            pilot_intake_binding_digest=_digest(binding),
            intake_record_id=record.record_id,
            intake_record_digest=_digest(record),
            critic_plan_id=inputs["critic_plan"].plan_id,
            critic_plan_digest=_digest(inputs["critic_plan"]),
            evidence_catalog_digest=_catalog_digest(evidence),
            candidate_id=outcome.candidate.candidate_id,
            validated_candidate_digest=_digest(outcome.candidate),
            scope_id=self.scope.scope_id,
            scope_version=self.scope.version,
            expected_side_effects=PILOT_CRITIC_EFFECTS,
        )

    def prepare(
        self,
        *,
        approval: ApprovalRequest,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
        **inputs,
    ) -> PilotCriticExecutionPlan:
        approval = ApprovalRequest.model_validate(approval.model_dump(mode="python"))
        action = self.approval_action(now=now, **inputs)
        binding = self.pilot_intake_service.store.load_completed(
            inputs["pilot_intake_plan"].plan_id
        )
        if (
            approval.status is not ApprovalStatus.GRANTED
            or approval.action is not ApprovalAction.RUN_CRITIC
            or approval.action_digest != action.action_id
            or approval.engagement_id != action.engagement_id
            or approval.target_id != action.target_id
            or approval.policy_version != self.scope.version
            or approval.expected_side_effects != PILOT_CRITIC_EFFECTS
            or not approval.decided_by
            or approval.decided_at is None
            or not binding.completed_at <= approval.decided_at <= now < approval.expires_at
        ):
            raise PilotCriticExecutionRejected("pilot Critic exact human Approval required")
        if (
            not now
            < deadline
            <= min(
                self.scope.valid_until,
                approval.expires_at,
                inputs["intake_plan"].decision_deadline,
                inputs["critic_plan"].deadline,
                inputs["outcome_plan"].deadline,
            )
        ):
            raise PilotCriticExecutionRejected("pilot Critic deadline exceeds upstream authority")
        values = {
            field: getattr(action, field)
            for field in (
                "pilot_intake_plan_id",
                "pilot_intake_binding_id",
                "pilot_intake_binding_digest",
                "intake_record_id",
                "critic_plan_id",
                "critic_plan_digest",
                "evidence_catalog_digest",
                "candidate_id",
                "validated_candidate_digest",
                "scope_id",
                "scope_version",
            )
        }
        values.update(
            approval_action_id=action.action_id,
            approval_id=approval.approval_id,
            approval_digest=_digest(approval),
            created_at=now,
            deadline=deadline,
            idempotency_key=idempotency_key,
        )
        return PilotCriticExecutionPlan.create(**values)

    def execute(
        self, plan: PilotCriticExecutionPlan, *, approval: ApprovalRequest, now: datetime, **inputs
    ) -> PilotCriticExecutionBinding:
        plan = PilotCriticExecutionPlan.model_validate(plan.model_dump(mode="python"))
        if not plan.created_at <= now < plan.deadline:
            raise PilotCriticExecutionTimedOut("pilot Critic execution outside its window")
        self.prepare(
            approval=approval,
            now=now,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
            **inputs,
        )
        expected = self.prepare(
            approval=approval,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
            **inputs,
        )
        if expected != plan:
            raise PilotCriticExecutionRejected("pilot Critic execution plan drifted")
        if self._has_bare_checkpoint(plan) and not self.store.has_critic_plan_checkpoint(
            plan.critic_plan_id
        ):
            raise PilotCriticExecutionRejected(
                "Critic or M8.4 checkpoint predates pilot Approval gate"
            )
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.binding is not None
            completed = self._completed(
                plan, inputs["intake_plan"], claim.binding.completed_at, now
            )
            if completed != claim.binding:
                raise PilotCriticExecutionRejected("pilot Critic completed binding drifted")
            return claim.binding
        if self._has_bare_checkpoint(plan):
            raise PilotCriticExecutionRejected(
                "Critic or M8.4 checkpoint predates pilot Approval gate"
            )
        _, _, validation = self._load(now=now, **inputs)
        outcome = self.critic.review(
            validation.candidate,
            validation.validation_run,
            validation.evidence_bundle,
            inputs["evidence"],
            inputs["critic_plan"],
            now=now,
        )
        stored_plan, persisted = self.critic.store.load_completed(plan.critic_plan_id)
        if stored_plan != inputs["critic_plan"] or persisted != outcome:
            raise PilotCriticExecutionRejected("Critic authoritative outcome drifted")
        binding_plan = self.outcome_service.prepare(
            critic_intake_plan=inputs["intake_plan"],
            now=now,
            idempotency_key=f"pilot-critic:{plan.execution_plan_id}",
        )
        result = self.outcome_service.execute(
            binding_plan, critic_intake_plan=inputs["intake_plan"], now=now
        )
        binding = self._completed(plan, inputs["intake_plan"], now, now)
        if binding.outcome_binding_digest != _digest(result):
            raise PilotCriticExecutionRejected("M8.4 returned binding drifted")
        self.store.complete(binding)
        return binding

    def load_verified(
        self,
        plan: PilotCriticExecutionPlan,
        *,
        approval: ApprovalRequest,
        now: datetime,
        **inputs,
    ) -> PilotCriticExecutionBinding:
        """Read an approved completed result without claiming, reviewing or binding again."""
        plan = PilotCriticExecutionPlan.model_validate(plan.model_dump(mode="python"))
        self._load(now=now, **inputs)
        expected = self.prepare(
            approval=approval,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
            **inputs,
        )
        if expected != plan:
            raise PilotCriticExecutionRejected("pilot Critic execution plan drifted")
        stored_plan = self.store.load_completed_plan(plan.execution_plan_id)
        binding = self.store.load_completed(plan.execution_plan_id)
        if stored_plan != plan or binding != self._completed(
            plan, inputs["intake_plan"], binding.completed_at, now
        ):
            raise PilotCriticExecutionRejected("pilot Critic completed binding drifted")
        return binding

    def _has_bare_checkpoint(self, plan):
        return self.critic.store.has_checkpoint(plan.critic_plan_id) or (
            self.outcome_service.binding_store.has_critic_checkpoint(plan.critic_plan_id)
        )

    def _completed(self, plan, intake_plan, completed_at, now):
        # The existing M8.4 verifier recomputes the verdict from the exact CriticPlan and
        # checks Candidate, Review, Evidence and Validation provenance without reviewing again.
        self.outcome_service._load(intake_plan, now)
        binding_plan = self.outcome_service.prepare(
            critic_intake_plan=intake_plan,
            now=completed_at,
            idempotency_key=f"pilot-critic:{plan.execution_plan_id}",
        )
        result = self.outcome_service.binding_store.load_completed(binding_plan.binding_plan_id)
        values = {
            name: getattr(binding_plan, name)
            for name in AgentCriticOutcomeBinding.model_fields
            if name not in {"binding_id", "completed_at"}
        }
        values["completed_at"] = completed_at
        expected = AgentCriticOutcomeBinding(binding_id=canonical_digest(values), **values)
        _, outcome = self.critic.store.load_completed(plan.critic_plan_id)
        if (
            result != expected
            or outcome.completed_at != completed_at
            or not plan.created_at <= completed_at <= now
        ):
            raise PilotCriticExecutionRejected("pilot Critic completed result provenance drifted")
        values = {
            field: getattr(plan, field)
            for field in (
                "execution_plan_id",
                "approval_action_id",
                "approval_id",
                "approval_digest",
                "pilot_intake_binding_id",
                "intake_record_id",
                "critic_plan_id",
                "candidate_id",
                "validated_candidate_digest",
            )
        }
        values.update(
            {
                field: getattr(result, field)
                for field in (
                    "critic_outcome_digest",
                    "critic_review_id",
                    "critic_review_digest",
                    "final_candidate_digest",
                    "verdict",
                    "final_candidate_state",
                )
            }
        )
        values.update(
            outcome_binding_plan_id=binding_plan.binding_plan_id,
            outcome_binding_plan_digest=_digest(binding_plan),
            outcome_binding_id=result.binding_id,
            outcome_binding_digest=_digest(result),
            completed_at=completed_at,
        )
        return PilotCriticExecutionBinding(binding_id=canonical_digest(values), **values)
