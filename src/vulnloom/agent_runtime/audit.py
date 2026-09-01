"""Pure verification and deterministic projection for completed Agent sessions."""

from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.evidence.redaction import Redactor
from vulnloom.evidence.store import EvidenceStore

from .audit_models import (
    AgentSessionAuditBundle,
    AgentSessionAuditLimits,
    AgentSessionAuditOutcome,
    AgentSessionAuditPlan,
    AgentSessionRecommendation,
    AgentSessionRecommendationDisposition,
    AgentSessionRecommendationReason,
)
from .audit_store import (
    AgentSessionAuditArtifactStore,
    AgentSessionAuditStore,
    render_agent_session_audit_markdown,
)
from .continuation_models import agent_continuation_outcome_digest
from .continuation_store import (
    AgentContinuationRecoveryRequired,
    AgentContinuationStore,
)
from .models import AgentRunOutcome
from .session_models import (
    AgentSessionBudgetLedger,
    AgentSessionOutcome,
    AgentSessionPlan,
    AgentSessionStatus,
    agent_session_outcome_digest,
    agent_session_plan_digest,
)
from .session_store import AgentSessionRecoveryRequired, AgentSessionStore
from .store import AgentRunRecoveryRequired, AgentRunStore
from .tool_handoff_models import agent_tool_handoff_outcome_digest
from .tool_handoff_store import (
    AgentToolHandoffRecoveryRequired,
    AgentToolHandoffStore,
)


class AgentSessionAuditRejected(ValueError):
    pass


class AgentSessionAuditTimedOut(TimeoutError):
    pass


class AgentSessionAuditService:
    def __init__(
        self,
        *,
        session_store: AgentSessionStore,
        root_agent_store: AgentRunStore,
        round_agent_store: AgentRunStore,
        handoff_store: AgentToolHandoffStore,
        continuation_store: AgentContinuationStore,
        evidence_store: EvidenceStore,
        audit_store: AgentSessionAuditStore,
        artifact_store: AgentSessionAuditArtifactStore,
    ):
        self.session_store = session_store
        self.root_agent_store = root_agent_store
        self.round_agent_store = round_agent_store
        self.handoff_store = handoff_store
        self.continuation_store = continuation_store
        self.evidence_store = evidence_store
        self.audit_store = audit_store
        self.artifact_store = artifact_store

    def prepare(
        self,
        *,
        session_plan: AgentSessionPlan,
        now: datetime,
        idempotency_key: str,
        limits: AgentSessionAuditLimits | None = None,
    ) -> AgentSessionAuditPlan:
        audit_limits = limits or AgentSessionAuditLimits()
        session_plan, outcome, _ = self._verify_chain(session_plan, audit_limits)
        if now < outcome.completed_at:
            raise AgentSessionAuditRejected(
                "Agent session audit cannot precede Session completion"
            )
        deadline = now + timedelta(seconds=audit_limits.timeout_seconds)
        task = session_plan.root_plan.task
        return AgentSessionAuditPlan.create(
            session_id=session_plan.session_id,
            session_plan_digest=agent_session_plan_digest(session_plan),
            session_outcome_id=outcome.outcome_id,
            session_outcome_digest=agent_session_outcome_digest(outcome),
            target_id=task.target_id,
            target_version_digest=canonical_digest(task.target_version),
            scope_id=task.scope_id,
            scope_version=task.scope_version,
            limits=audit_limits,
            created_at=now,
            deadline=deadline,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        plan: AgentSessionAuditPlan,
        *,
        session_plan: AgentSessionPlan,
        now: datetime,
    ) -> AgentSessionAuditOutcome:
        plan = self._validate_plan(plan, now=now)
        session_plan, session_outcome, evidence_refs = self._verify_chain(
            session_plan, plan.limits
        )
        self._verify_plan_binding(plan, session_plan, session_outcome)
        claim = self.audit_store.claim(plan, now=now)
        if not claim.created:
            assert claim.outcome is not None
            self.artifact_store.read_bundle(claim.outcome.artifact)
            return claim.outcome
        bundle = self._build_bundle(
            plan=plan,
            session_plan=session_plan,
            session_outcome=session_outcome,
            evidence_refs=evidence_refs,
            now=now,
        )
        json_bytes = (bundle.model_dump_json(indent=2) + "\n").encode()
        markdown_bytes = render_agent_session_audit_markdown(bundle).encode()
        if max(len(json_bytes), len(markdown_bytes)) > plan.limits.max_artifact_bytes:
            raise AgentSessionAuditRejected("Agent session audit artifact exceeds plan limits")
        artifact = self.artifact_store.put(bundle)
        values = {
            "audit_plan_id": plan.audit_plan_id,
            "session_id": plan.session_id,
            "bundle": bundle,
            "artifact": artifact,
            "completed_at": now,
        }
        outcome = AgentSessionAuditOutcome(
            outcome_id=canonical_digest(
                {
                    **values,
                    "bundle": bundle.model_dump(mode="python"),
                    "artifact": artifact.model_dump(mode="python"),
                }
            ),
            **values,
        )
        self.audit_store.complete(outcome)
        return outcome

    @staticmethod
    def _validate_plan(
        plan: AgentSessionAuditPlan, *, now: datetime
    ) -> AgentSessionAuditPlan:
        try:
            plan = AgentSessionAuditPlan.model_validate(plan.model_dump(mode="python"))
        except ValidationError as exc:
            raise AgentSessionAuditRejected(
                "Agent session audit failed boundary validation"
            ) from exc
        if now < plan.created_at or now >= plan.deadline:
            raise AgentSessionAuditTimedOut("Agent session audit is outside its wall budget")
        return plan

    def _verify_chain(
        self,
        session_plan: AgentSessionPlan,
        limits: AgentSessionAuditLimits,
    ) -> tuple[AgentSessionPlan, AgentSessionOutcome, tuple[str, ...]]:
        try:
            session_plan = AgentSessionPlan.model_validate(
                session_plan.model_dump(mode="python")
            )
            outcome = self.session_store.require_completed(session_plan.session_id)
            root_outcome = self.root_agent_store.require_completed(session_plan.root_plan)
            round_outcome = self.round_agent_store.require_completed(session_plan.round_plan)
            first_handoff = self.handoff_store.require_completed(
                session_plan.first_handoff_outcome.handoff_id
            )
            if outcome.approval_handoff_outcome is not None:
                approval_handoff = self.handoff_store.require_completed(
                    outcome.approval_handoff_outcome.handoff_id
                )
            else:
                approval_handoff = None
            if outcome.second_handoff_outcome is not None:
                second_handoff = self.handoff_store.require_completed(
                    outcome.second_handoff_outcome.handoff_id
                )
            else:
                second_handoff = None
            if outcome.terminal_continuation is not None:
                continuation = self.continuation_store.require_completed(
                    outcome.terminal_continuation.continuation_id
                )
            else:
                continuation = None
        except (
            ValidationError,
            AgentSessionRecoveryRequired,
            AgentRunRecoveryRequired,
            AgentToolHandoffRecoveryRequired,
            AgentContinuationRecoveryRequired,
        ) as exc:
            raise AgentSessionAuditRejected(
                "Agent session audit requires authoritative completed checkpoints"
            ) from exc
        if (
            root_outcome != session_plan.root_outcome
            or round_outcome != outcome.round_agent_outcome
            or first_handoff != session_plan.first_handoff_outcome
            or approval_handoff != outcome.approval_handoff_outcome
            or second_handoff != outcome.second_handoff_outcome
            or continuation != outcome.terminal_continuation
        ):
            raise AgentSessionAuditRejected("Agent session audit checkpoint chain drifted")
        self._verify_selected_call(session_plan, outcome)
        self._verify_budget(session_plan, outcome)
        observations = [first_handoff.observation]
        if second_handoff is not None and second_handoff.observation is not None:
            observations.append(second_handoff.observation)
        evidence_refs = tuple(
            sorted(
                {
                    ref
                    for observation in observations
                    if observation is not None
                    for ref in observation.evidence_refs
                }
            )
        )
        if not evidence_refs or len(evidence_refs) > limits.max_evidence_refs:
            raise AgentSessionAuditRejected("Agent session audit Evidence set is invalid")
        redactor = Redactor()
        try:
            for ref in evidence_refs:
                content = self.evidence_store.read_text_ref(ref)
                if redactor.text(content) != content:
                    raise AgentSessionAuditRejected(
                        "Agent session audit Evidence is not fully redacted"
                    )
        except (UnicodeDecodeError, ValueError) as exc:
            raise AgentSessionAuditRejected(
                "Agent session audit Evidence verification failed"
            ) from exc
        return session_plan, outcome, evidence_refs

    @staticmethod
    def _verify_selected_call(
        plan: AgentSessionPlan, outcome: AgentSessionOutcome
    ) -> None:
        if outcome.selected_call_commitment is None:
            if outcome.second_handoff_outcome is not None:
                raise AgentSessionAuditRejected(
                    "Agent session audit found an uncommitted handoff"
                )
            return
        matches = tuple(
            item
            for item in plan.authorized_calls.options
            if item.call_commitment == outcome.selected_call_commitment
            and item.broker_call_digest == outcome.selected_broker_call_digest
        )
        if len(matches) != 1:
            raise AgentSessionAuditRejected(
                "Agent session audit call commitment is not uniquely authorized"
            )

    @staticmethod
    def _verify_budget(plan: AgentSessionPlan, outcome: AgentSessionOutcome) -> None:
        agent_outcomes: tuple[AgentRunOutcome, ...] = (
            plan.root_outcome,
            outcome.round_agent_outcome,
        )
        if outcome.terminal_continuation is not None:
            agent_outcomes += (outcome.terminal_continuation.agent_outcome,)
        handoffs = (plan.first_handoff_outcome,)
        if outcome.approval_handoff_outcome is not None:
            handoffs += (outcome.approval_handoff_outcome,)
        if outcome.second_handoff_outcome is not None:
            handoffs += (outcome.second_handoff_outcome,)
        consumed_tokens = sum(
            item.input_tokens + item.output_tokens for item in agent_outcomes
        )
        consumed_tools = sum(item.broker_result.tool_calls_used for item in handoffs)
        expected = AgentSessionBudgetLedger(
            original_model_tokens=plan.budget.original_model_tokens,
            original_tool_calls=plan.budget.original_tool_calls,
            consumed_model_tokens=consumed_tokens,
            remaining_model_tokens=plan.budget.original_model_tokens - consumed_tokens,
            consumed_agent_steps=sum(item.steps for item in agent_outcomes),
            consumed_tool_calls=consumed_tools,
            remaining_tool_calls=plan.budget.original_tool_calls - consumed_tools,
            provider_attempts=len(agent_outcomes),
            broker_attempts=len(handoffs),
            remaining_wall_seconds=max(
                0, int((plan.deadline - outcome.completed_at).total_seconds())
            ),
        )
        if expected != outcome.budget:
            raise AgentSessionAuditRejected("Agent session audit budget ledger drifted")

    @staticmethod
    def _verify_plan_binding(
        plan: AgentSessionAuditPlan,
        session_plan: AgentSessionPlan,
        outcome: AgentSessionOutcome,
    ) -> None:
        task = session_plan.root_plan.task
        if (
            plan.session_id != session_plan.session_id
            or plan.session_plan_digest != agent_session_plan_digest(session_plan)
            or plan.session_outcome_id != outcome.outcome_id
            or plan.session_outcome_digest != agent_session_outcome_digest(outcome)
            or plan.target_id != task.target_id
            or plan.target_version_digest != canonical_digest(task.target_version)
            or plan.scope_id != task.scope_id
            or plan.scope_version != task.scope_version
            or plan.created_at < outcome.completed_at
        ):
            raise AgentSessionAuditRejected("Agent session audit plan binding drifted")

    @staticmethod
    def _build_bundle(
        *,
        plan: AgentSessionAuditPlan,
        session_plan: AgentSessionPlan,
        session_outcome: AgentSessionOutcome,
        evidence_refs: tuple[str, ...],
        now: datetime,
    ) -> AgentSessionAuditBundle:
        disposition, reason = _recommendation_for_status(session_outcome.status)
        recommendation_values = {
            "session_id": session_plan.session_id,
            "disposition": disposition,
            "reason_code": reason,
            "evidence_refs": evidence_refs,
            "budget_digest": canonical_digest(
                session_outcome.budget.model_dump(mode="python")
            ),
            "projected_at": now,
        }
        recommendation = AgentSessionRecommendation(
            recommendation_id=canonical_digest(recommendation_values),
            **recommendation_values,
        )
        first_observation = session_plan.first_handoff_outcome.observation
        assert first_observation is not None
        second_handoff = session_outcome.second_handoff_outcome
        continuation = session_outcome.terminal_continuation
        observation_ids = (first_observation.observation_id,) + (
            ()
            if second_handoff is None or second_handoff.observation is None
            else (second_handoff.observation.observation_id,)
        )
        values = {
            "audit_plan_id": plan.audit_plan_id,
            "session_id": session_plan.session_id,
            "session_plan_digest": agent_session_plan_digest(session_plan),
            "session_outcome_id": session_outcome.outcome_id,
            "session_outcome_digest": agent_session_outcome_digest(session_outcome),
            "target_id": session_plan.root_plan.task.target_id,
            "target_version_digest": canonical_digest(
                session_plan.root_plan.task.target_version
            ),
            "scope_id": session_plan.root_plan.task.scope_id,
            "scope_version": session_plan.root_plan.task.scope_version,
            "root_plan_id": session_plan.root_plan.plan_id,
            "root_outcome_digest": canonical_digest(
                session_plan.root_outcome.model_dump(mode="python")
            ),
            "first_handoff_id": session_plan.first_handoff_outcome.handoff_id,
            "first_handoff_outcome_digest": agent_tool_handoff_outcome_digest(
                session_plan.first_handoff_outcome
            ),
            "round_plan_id": session_plan.round_plan.plan_id,
            "round_outcome_digest": canonical_digest(
                session_outcome.round_agent_outcome.model_dump(mode="python")
            ),
            "authorized_call_set_id": session_plan.authorized_calls.call_set_id,
            "selected_call_commitment": session_outcome.selected_call_commitment,
            "approval_digests": session_outcome.approval_digests,
            "second_handoff_id": None if second_handoff is None else second_handoff.handoff_id,
            "second_handoff_outcome_digest": (
                None
                if second_handoff is None
                else agent_tool_handoff_outcome_digest(second_handoff)
            ),
            "continuation_id": (
                None if continuation is None else continuation.continuation_id
            ),
            "continuation_outcome_digest": (
                None
                if continuation is None
                else agent_continuation_outcome_digest(continuation)
            ),
            "observation_ids": observation_ids,
            "evidence_refs": evidence_refs,
            "budget": session_outcome.budget,
            "cleanup": session_outcome.cleanup,
            "recommendation": recommendation,
            "completed_at": now,
        }
        digest_values = {
            **values,
            "budget": session_outcome.budget.model_dump(mode="python"),
            "cleanup": session_outcome.cleanup.model_dump(mode="python"),
            "recommendation": recommendation.model_dump(mode="python"),
        }
        return AgentSessionAuditBundle(
            bundle_id=canonical_digest(digest_values), **values
        )


def _recommendation_for_status(
    status: AgentSessionStatus,
) -> tuple[AgentSessionRecommendationDisposition, AgentSessionRecommendationReason]:
    return {
        AgentSessionStatus.COMPLETED: (
            AgentSessionRecommendationDisposition.COMPLETED,
            AgentSessionRecommendationReason.SESSION_COMPLETED,
        ),
        AgentSessionStatus.BLOCKED: (
            AgentSessionRecommendationDisposition.BLOCKED,
            AgentSessionRecommendationReason.AGENT_BLOCKED,
        ),
        AgentSessionStatus.DENIED: (
            AgentSessionRecommendationDisposition.BLOCKED,
            AgentSessionRecommendationReason.BROKER_DENIED,
        ),
        AgentSessionStatus.FAILED: (
            AgentSessionRecommendationDisposition.FAILED,
            AgentSessionRecommendationReason.SESSION_FAILED,
        ),
        AgentSessionStatus.TIMED_OUT: (
            AgentSessionRecommendationDisposition.TIMED_OUT,
            AgentSessionRecommendationReason.SESSION_TIMED_OUT,
        ),
    }[status]
