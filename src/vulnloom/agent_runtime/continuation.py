"""Trusted one-shot continuation from a sealed Tool Observation."""

from __future__ import annotations

import json
from datetime import datetime
from uuid import UUID, uuid4

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore

from .context import (
    AgentContextAssembler,
    AgentContextLimits,
    AgentContextRejected,
    AgentContextSource,
    AgentContextSourceKind,
    AgentContextStore,
    AgentContextTimedOut,
)
from .continuation_models import (
    AgentContinuationBudgetLedger,
    AgentContinuationCleanup,
    AgentContinuationOutcome,
    AgentContinuationPlan,
    AgentContinuationStatus,
    agent_continuation_input_refs,
)
from .continuation_store import AgentContinuationStore
from .models import AgentRunLimits, AgentRunOutcome, AgentRunPlan, AgentRunStatus
from .service import OfflineAgentRuntime
from .store import AgentRunRecoveryRequired, AgentRunStore
from .tool_handoff_models import (
    AgentToolHandoffOutcome,
    AgentToolHandoffStatus,
    AgentToolObservation,
)
from .tool_handoff_store import (
    AgentToolHandoffRecoveryRequired,
    AgentToolHandoffStore,
)


class AgentContinuationRejected(ValueError):
    pass


class AgentContinuationTimedOut(TimeoutError):
    pass


class AgentContinuationService:
    def __init__(
        self,
        *,
        root_agent_store: AgentRunStore,
        handoff_store: AgentToolHandoffStore,
        continuation_store: AgentContinuationStore,
        continuation_runtime: OfflineAgentRuntime,
        evidence_store: EvidenceStore,
        context_store: AgentContextStore,
        context_assembler: AgentContextAssembler | None = None,
    ):
        self.root_agent_store = root_agent_store
        self.handoff_store = handoff_store
        self.continuation_store = continuation_store
        self.continuation_runtime = continuation_runtime
        self.evidence_store = evidence_store
        self.context_store = context_store
        self.context_assembler = context_assembler or AgentContextAssembler()

    def prepare(
        self,
        *,
        root_plan: AgentRunPlan,
        handoff_id: str,
        now: datetime,
        idempotency_key: str,
        continuation_run_key: str,
        context_limits: AgentContextLimits | None = None,
        continuation_task_id: UUID | None = None,
    ) -> AgentContinuationPlan:
        root_outcome, handoff_outcome = self._authoritative_inputs(
            root_plan=root_plan, handoff_id=handoff_id
        )
        observation = handoff_outcome.observation
        assert observation is not None
        deadline = min(root_plan.deadline, root_plan.task.deadline)
        remaining_wall = min(
            root_plan.task.budget.wall_seconds,
            int((deadline - now).total_seconds()),
        )
        consumed_tokens = root_outcome.input_tokens + root_outcome.output_tokens
        remaining_tokens = root_plan.task.budget.model_tokens - consumed_tokens
        if remaining_wall <= 0 or now >= deadline:
            raise AgentContinuationTimedOut("Agent continuation deadline expired")
        if remaining_tokens <= 0:
            raise AgentContinuationRejected("Agent continuation model budget is exhausted")
        if handoff_outcome.broker_result.tool_calls_used < 1:
            raise AgentContinuationRejected(
                "Agent continuation requires a consumed Broker tool call"
            )
        input_refs = agent_continuation_input_refs(
            observation.observation_id, observation.evidence_refs
        )
        root_task = root_plan.task
        continuation_task = TaskEnvelope(
            task_id=continuation_task_id or uuid4(),
            engagement_id=root_task.engagement_id,
            target_id=root_task.target_id,
            target_version=root_task.target_version,
            scope_id=root_task.scope_id,
            worker_role=WorkerRole.VALIDATOR,
            scope_version=root_task.scope_version,
            policy_digest=root_task.policy_digest,
            sandbox_profile_digest=root_task.sandbox_profile_digest,
            tool_registry_digest=root_task.tool_registry_digest,
            input_refs=input_refs,
            allowed_tools=frozenset(),
            budget=TaskBudget(
                wall_seconds=remaining_wall,
                model_tokens=remaining_tokens,
                tool_calls=0,
            ),
            deadline=root_task.deadline,
            idempotency_key=f"{idempotency_key}:task",
        )
        sources = self._sources(observation)
        limits = context_limits or AgentContextLimits()
        try:
            snapshot = self.context_assembler.assemble(
                task=continuation_task,
                sources=sources,
                limits=limits,
                now=now,
                deadline=deadline,
            )
            self.context_store.publish(snapshot)
        except (AgentContextRejected, AgentContextTimedOut, ValueError) as exc:
            raise AgentContinuationRejected(
                "Agent continuation context materialization failed"
            ) from exc
        run_limits = AgentRunLimits(
            max_steps=1,
            max_output_tokens_per_step=min(
                root_plan.limits.max_output_tokens_per_step, remaining_tokens
            ),
            timeout_seconds=min(root_plan.limits.timeout_seconds, remaining_wall),
        )
        continuation_plan = AgentRunPlan.create(
            task=continuation_task,
            registration=self.continuation_runtime.registration,
            limits=run_limits,
            created_at=now,
            deadline=root_plan.deadline,
            idempotency_key=continuation_run_key,
            context_snapshot=snapshot,
        )
        budget = AgentContinuationBudgetLedger(
            original_model_tokens=root_task.budget.model_tokens,
            consumed_model_tokens=consumed_tokens,
            remaining_model_tokens=remaining_tokens,
            consumed_agent_steps=root_outcome.steps,
            consumed_tool_calls=handoff_outcome.broker_result.tool_calls_used,
            remaining_wall_seconds=remaining_wall,
        )
        values = {
            "root_plan": root_plan,
            "root_plan_digest": canonical_digest(root_plan.model_dump(mode="python")),
            "root_outcome": root_outcome,
            "root_outcome_digest": canonical_digest(
                root_outcome.model_dump(mode="python")
            ),
            "handoff_outcome": handoff_outcome,
            "handoff_outcome_digest": canonical_digest(
                handoff_outcome.model_dump(
                    mode="python", exclude={"outcome_id"}
                )
            ),
            "observation_id": observation.observation_id,
            "context_snapshot": snapshot,
            "continuation_plan": continuation_plan,
            "continuation_plan_digest": canonical_digest(
                continuation_plan.model_dump(mode="python")
            ),
            "budget": budget,
            "created_at": now,
            "deadline": root_plan.deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {
            **values,
            "root_plan": root_plan.model_dump(mode="python"),
            "root_outcome": root_outcome.model_dump(mode="python"),
            "handoff_outcome": handoff_outcome.model_dump(mode="python"),
            "context_snapshot": snapshot.model_dump(mode="python"),
            "continuation_plan": continuation_plan.model_dump(mode="python"),
            "budget": budget.model_dump(mode="python"),
        }
        return AgentContinuationPlan(
            continuation_id=canonical_digest(digest_values), **values
        )

    def execute(
        self, plan: AgentContinuationPlan, *, now: datetime
    ) -> AgentContinuationOutcome:
        plan = self._preflight(plan, now=now)
        claim = self.continuation_store.claim(plan, now=now)
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome
        agent_outcome = self.continuation_runtime.execute(
            plan.continuation_plan, now=now
        )
        if agent_outcome.status is AgentRunStatus.TOOL_PROPOSED:
            raise AgentContinuationRejected(
                "Agent continuation cannot produce another tool proposal"
            )
        status = AgentContinuationStatus(agent_outcome.status.value)
        values = {
            "continuation_id": plan.continuation_id,
            "root_plan_id": plan.root_plan.plan_id,
            "observation_id": plan.observation_id,
            "continuation_plan_id": plan.continuation_plan.plan_id,
            "status": status,
            "agent_outcome": agent_outcome,
            "cleanup": AgentContinuationCleanup(
                evidence_buffers_released=True,
                context_reverified=True,
                raw_provider_response_absent=True,
                no_tool_executed=True,
                no_vulnloom_domain_state_changed=True,
            ),
            "completed_at": now,
        }
        digest_values = {
            **values,
            "agent_outcome": agent_outcome.model_dump(mode="python"),
            "cleanup": values["cleanup"].model_dump(mode="python"),
        }
        outcome = AgentContinuationOutcome(
            outcome_id=canonical_digest(digest_values), **values
        )
        self.continuation_store.complete(outcome)
        return outcome

    def _preflight(
        self, plan: AgentContinuationPlan, *, now: datetime
    ) -> AgentContinuationPlan:
        try:
            plan = AgentContinuationPlan.model_validate(plan.model_dump(mode="python"))
        except ValidationError as exc:
            raise AgentContinuationRejected(
                "Agent continuation failed boundary validation"
            ) from exc
        if now < plan.created_at or now >= min(
            plan.deadline,
            plan.root_plan.task.deadline,
            plan.continuation_plan.task.deadline,
        ):
            raise AgentContinuationTimedOut("Agent continuation is outside its wall budget")
        root_outcome, handoff_outcome = self._authoritative_inputs(
            root_plan=plan.root_plan,
            handoff_id=plan.handoff_outcome.handoff_id,
        )
        if root_outcome != plan.root_outcome or handoff_outcome != plan.handoff_outcome:
            raise AgentContinuationRejected(
                "Agent continuation authoritative checkpoint binding mismatch"
            )
        if (
            self.continuation_runtime.registration.registration_id
            != plan.continuation_plan.model_registration_id
            or canonical_digest(
                self.continuation_runtime.registration.model_dump(mode="python")
            )
            != plan.continuation_plan.model_registration_digest
        ):
            raise AgentContinuationRejected(
                "Agent continuation model registration binding mismatch"
            )
        try:
            stored = self.context_store.read(plan.context_snapshot.snapshot_id)
            expected = self.context_assembler.assemble(
                task=plan.continuation_plan.task,
                sources=self._sources(plan.handoff_outcome.observation),
                limits=AgentContextLimits(
                    max_fragments=max(1, len(plan.context_snapshot.fragments)),
                    max_source_bytes_per_fragment=max(
                        1,
                        max(
                            (item.byte_size for item in plan.context_snapshot.fragments),
                            default=1,
                        ),
                    ),
                    max_fragment_bytes=max(
                        1,
                        max(
                            (item.byte_size for item in plan.context_snapshot.fragments),
                            default=1,
                        ),
                    ),
                    max_total_bytes=max(1, plan.context_snapshot.total_bytes),
                    timeout_seconds=5.0,
                ),
                now=plan.context_snapshot.assembled_at,
                deadline=plan.continuation_plan.task.deadline,
            )
        except (AgentContextRejected, AgentContextTimedOut, ValueError) as exc:
            raise AgentContinuationRejected(
                "Agent continuation context revalidation failed"
            ) from exc
        if stored != plan.context_snapshot or expected != plan.context_snapshot:
            raise AgentContinuationRejected(
                "Agent continuation context snapshot drifted"
            )
        return plan

    def _authoritative_inputs(
        self, *, root_plan: AgentRunPlan, handoff_id: str
    ) -> tuple[AgentRunOutcome, AgentToolHandoffOutcome]:
        try:
            root_outcome = self.root_agent_store.require_completed(root_plan)
            handoff_outcome = self.handoff_store.require_completed(handoff_id)
        except (AgentRunRecoveryRequired, AgentToolHandoffRecoveryRequired) as exc:
            raise AgentContinuationRejected(
                "Agent continuation requires authoritative completed inputs"
            ) from exc
        if (
            root_outcome.status is not AgentRunStatus.TOOL_PROPOSED
            or handoff_outcome.status is not AgentToolHandoffStatus.COMPLETED
            or handoff_outcome.observation is None
            or handoff_outcome.agent_plan_id != root_plan.plan_id
            or handoff_outcome.agent_outcome_digest
            != canonical_digest(root_outcome.model_dump(mode="python"))
        ):
            raise AgentContinuationRejected(
                "Agent continuation inputs are not a completed tool feedback chain"
            )
        return root_outcome, handoff_outcome

    def _sources(
        self, observation: AgentToolObservation
    ) -> tuple[AgentContextSource, ...]:
        return agent_observation_context_sources(
            evidence_store=self.evidence_store, observation=observation
        )


def agent_observation_context_sources(
    *, evidence_store: EvidenceStore, observation: AgentToolObservation
) -> tuple[AgentContextSource, ...]:
    """Reopen one typed Observation and its exact redacted Evidence refs."""
    try:
        observation_text = json.dumps(
            observation.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        sources = [
            AgentContextSource(
                source_ref=f"agent-observation:{observation.observation_id}",
                kind=AgentContextSourceKind.OBSERVATION_SUMMARY,
                text=observation_text,
            )
        ]
        for evidence_ref in observation.evidence_refs:
            sources.append(
                AgentContextSource(
                    source_ref=f"evidence:{evidence_ref}",
                    kind=AgentContextSourceKind.EVIDENCE_SUMMARY,
                    text=evidence_store.read_text_ref(evidence_ref),
                )
            )
    except (UnicodeDecodeError, ValueError) as exc:
        raise AgentContinuationRejected(
            "Agent continuation Evidence is unavailable or unsafe"
        ) from exc
    return tuple(sources)
