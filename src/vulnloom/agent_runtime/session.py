"""Trusted orchestration for one fixed, two-tool Agent session."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalRequest
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore

from .context import (
    AgentContextAssembler,
    AgentContextLimits,
    AgentContextRejected,
    AgentContextStore,
    AgentContextTimedOut,
)
from .continuation import (
    AgentContinuationRejected,
    AgentContinuationService,
    agent_observation_context_sources,
)
from .continuation_models import AgentContinuationOutcome
from .models import AgentRunLimits, AgentRunOutcome, AgentRunPlan, AgentRunStatus
from .service import OfflineAgentRuntime
from .session_models import (
    AgentAuthorizedCallOption,
    AgentAuthorizedCallSet,
    AgentSessionBudgetLedger,
    AgentSessionCallTemplate,
    AgentSessionCleanup,
    AgentSessionLimits,
    AgentSessionOutcome,
    AgentSessionPlan,
    AgentSessionStatus,
)
from .session_store import AgentSessionStore
from .store import AgentRunRecoveryRequired, AgentRunStore
from .tool_handoff import AgentToolHandoffService
from .tool_handoff_models import (
    AgentToolHandoffLimits,
    AgentToolHandoffOutcome,
    AgentToolHandoffPlan,
    AgentToolHandoffStatus,
    agent_tool_intent_for_broker_call,
)
from .tool_handoff_store import (
    AgentToolHandoffRecoveryRequired,
    AgentToolHandoffStore,
)


class AgentSessionRejected(ValueError):
    pass


class AgentSessionTimedOut(TimeoutError):
    pass


class AgentSessionService:
    def __init__(
        self,
        *,
        root_agent_store: AgentRunStore,
        handoff_store: AgentToolHandoffStore,
        session_store: AgentSessionStore,
        round_runtime: OfflineAgentRuntime,
        round_handoff_service: AgentToolHandoffService,
        terminal_continuation_service: AgentContinuationService,
        evidence_store: EvidenceStore,
        context_store: AgentContextStore,
        context_assembler: AgentContextAssembler | None = None,
    ):
        self.root_agent_store = root_agent_store
        self.handoff_store = handoff_store
        self.session_store = session_store
        self.round_runtime = round_runtime
        self.round_handoff_service = round_handoff_service
        self.terminal_continuation_service = terminal_continuation_service
        self.evidence_store = evidence_store
        self.context_store = context_store
        self.context_assembler = context_assembler or AgentContextAssembler()

    def prepare(
        self,
        *,
        root_plan: AgentRunPlan,
        first_handoff_id: str,
        call_templates: tuple[AgentSessionCallTemplate, ...],
        now: datetime,
        idempotency_key: str,
        round_run_key: str,
        context_limits: AgentContextLimits | None = None,
        limits: AgentSessionLimits | None = None,
        round_task_id: UUID | None = None,
    ) -> AgentSessionPlan:
        root_outcome, first_handoff = self._authoritative_inputs(
            root_plan=root_plan, first_handoff_id=first_handoff_id
        )
        observation = first_handoff.observation
        assert observation is not None
        session_limits = limits or AgentSessionLimits()
        if not call_templates:
            raise AgentSessionRejected("Agent session requires an authorized call set")
        if len(call_templates) > session_limits.max_authorized_calls_per_round:
            raise AgentSessionRejected("Agent session authorized call set is too large")
        if len({item.template_id for item in call_templates}) != len(call_templates):
            raise AgentSessionRejected("Agent session call templates must be unique")
        deadline = min(root_plan.deadline, root_plan.task.deadline)
        remaining_wall = min(
            root_plan.task.budget.wall_seconds,
            int((deadline - now).total_seconds()),
        )
        consumed_tokens = root_outcome.input_tokens + root_outcome.output_tokens
        remaining_tokens = root_plan.task.budget.model_tokens - consumed_tokens
        consumed_tools = first_handoff.broker_result.tool_calls_used
        remaining_tools = root_plan.task.budget.tool_calls - consumed_tools
        if now >= deadline or remaining_wall <= 0:
            raise AgentSessionTimedOut("Agent session deadline expired")
        if remaining_tokens <= 0:
            raise AgentSessionRejected("Agent session model budget is exhausted")
        if root_plan.task.budget.tool_calls != 2 or consumed_tools != 1 or remaining_tools != 1:
            raise AgentSessionRejected("Agent session requires exactly one remaining tool round")
        root_task = root_plan.task
        input_refs = (f"agent-observation:{observation.observation_id}",) + tuple(
            f"evidence:{item}" for item in observation.evidence_refs
        )
        allowed_tools = frozenset(item.tool_id for item in call_templates)
        round_task = TaskEnvelope(
            task_id=round_task_id or uuid4(),
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
            allowed_tools=allowed_tools,
            budget=TaskBudget(
                wall_seconds=remaining_wall,
                model_tokens=remaining_tokens,
                tool_calls=1,
            ),
            deadline=root_task.deadline,
            idempotency_key=f"{idempotency_key}:round-2-task",
        )
        authorized_calls = AgentAuthorizedCallSet.create(
            task=round_task, templates=call_templates
        )
        root_intent = root_outcome.tool_intent
        assert root_intent is not None
        if any(
            agent_tool_intent_for_broker_call(item.broker_call) == root_intent
            for item in authorized_calls.options
        ):
            raise AgentSessionRejected("Agent session cannot repeat the first tool commitment")
        for option in authorized_calls.options:
            try:
                self.round_handoff_service.broker.validate_call(option.broker_call)
            except ValueError as exc:
                raise AgentSessionRejected(
                    "Agent session authorized call failed Broker preflight"
                ) from exc
        try:
            snapshot = self.context_assembler.assemble(
                task=round_task,
                sources=agent_observation_context_sources(
                    evidence_store=self.evidence_store, observation=observation
                ),
                limits=context_limits or AgentContextLimits(),
                now=now,
                deadline=deadline,
            )
            self.context_store.publish(snapshot)
        except (
            AgentContextRejected,
            AgentContextTimedOut,
            AgentContinuationRejected,
            ValueError,
        ) as exc:
            raise AgentSessionRejected(
                "Agent session context materialization failed"
            ) from exc
        round_plan = AgentRunPlan.create(
            task=round_task,
            registration=self.round_runtime.registration,
            limits=AgentRunLimits(
                max_steps=1,
                max_output_tokens_per_step=min(
                    root_plan.limits.max_output_tokens_per_step, remaining_tokens
                ),
                timeout_seconds=min(root_plan.limits.timeout_seconds, remaining_wall),
            ),
            created_at=now,
            deadline=deadline,
            idempotency_key=round_run_key,
            context_snapshot=snapshot,
            authorized_call_set_id=authorized_calls.call_set_id,
            authorized_call_commitments=tuple(
                item.call_commitment for item in authorized_calls.options
            ),
        )
        budget = AgentSessionBudgetLedger(
            original_model_tokens=root_task.budget.model_tokens,
            original_tool_calls=root_task.budget.tool_calls,
            consumed_model_tokens=consumed_tokens,
            remaining_model_tokens=remaining_tokens,
            consumed_agent_steps=root_outcome.steps,
            consumed_tool_calls=consumed_tools,
            remaining_tool_calls=remaining_tools,
            provider_attempts=1,
            broker_attempts=1,
            remaining_wall_seconds=remaining_wall,
        )
        values = {
            "root_plan": root_plan,
            "root_plan_digest": canonical_digest(root_plan.model_dump(mode="python")),
            "root_outcome": root_outcome,
            "root_outcome_digest": canonical_digest(
                root_outcome.model_dump(mode="python")
            ),
            "first_handoff_outcome": first_handoff,
            "first_handoff_outcome_digest": canonical_digest(
                first_handoff.model_dump(mode="python", exclude={"outcome_id"})
            ),
            "first_observation_id": observation.observation_id,
            "context_snapshot": snapshot,
            "round_plan": round_plan,
            "round_plan_digest": canonical_digest(round_plan.model_dump(mode="python")),
            "authorized_calls": authorized_calls,
            "budget": budget,
            "limits": session_limits,
            "created_at": now,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {
            **values,
            "root_plan": root_plan.model_dump(mode="python"),
            "root_outcome": root_outcome.model_dump(mode="python"),
            "first_handoff_outcome": first_handoff.model_dump(mode="python"),
            "context_snapshot": snapshot.model_dump(mode="python"),
            "round_plan": round_plan.model_dump(mode="python"),
            "authorized_calls": authorized_calls.model_dump(mode="python"),
            "budget": budget.model_dump(mode="python"),
            "limits": session_limits.model_dump(mode="python"),
        }
        return AgentSessionPlan(session_id=canonical_digest(digest_values), **values)

    def execute(
        self,
        plan: AgentSessionPlan,
        *,
        now: datetime,
        terminal_continuation_key: str,
        terminal_run_key: str,
    ) -> AgentSessionOutcome:
        plan = self._preflight(plan, now=now)
        claim = self.session_store.claim(plan, now=now)
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome
        round_outcome = self.round_runtime.execute(plan.round_plan, now=now)
        selected = self._selected_option(plan, round_outcome)
        second_handoff = None
        terminal = None
        if round_outcome.status is AgentRunStatus.TOOL_PROPOSED and selected is not None:
            handoff_plan = AgentToolHandoffPlan.create(
                agent_plan=plan.round_plan,
                agent_outcome=round_outcome,
                broker_call=selected.broker_call,
                limits=AgentToolHandoffLimits(),
                created_at=now,
                deadline=plan.deadline,
                idempotency_key=f"{plan.idempotency_key}:round-2-handoff",
            )
            second_handoff = self.round_handoff_service.execute(handoff_plan, now=now)
            if second_handoff.status is AgentToolHandoffStatus.COMPLETED:
                terminal_plan = self.terminal_continuation_service.prepare(
                    root_plan=plan.round_plan,
                    handoff_id=handoff_plan.handoff_id,
                    now=now,
                    idempotency_key=terminal_continuation_key,
                    continuation_run_key=terminal_run_key,
                )
                terminal = self.terminal_continuation_service.execute(
                    terminal_plan, now=now
                )
        outcome = self._build_outcome(
            plan=plan,
            round_outcome=round_outcome,
            selected=selected,
            approval_handoff=None,
            approvals=(),
            second_handoff=second_handoff,
            terminal=terminal,
            now=now,
        )
        if outcome.status is AgentSessionStatus.APPROVAL_REQUIRED:
            self.session_store.pause_for_approval(outcome)
        else:
            self.session_store.complete(outcome)
        return outcome

    def resume_after_approval(
        self,
        plan: AgentSessionPlan,
        waiting_outcome: AgentSessionOutcome,
        *,
        approvals: tuple[ApprovalRequest, ...],
        now: datetime,
        retry_idempotency_key: str,
        terminal_continuation_key: str,
        terminal_run_key: str,
    ) -> AgentSessionOutcome:
        plan = self._preflight(plan, now=now)
        claim = self.session_store.claim_resume(
            plan, waiting_outcome, now=now
        )
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome
        round_outcome = self.round_runtime.store.require_completed(plan.round_plan)
        selected = self._selected_option(plan, round_outcome)
        approval_handoff = waiting_outcome.second_handoff_outcome
        if (
            selected is None
            or approval_handoff is None
            or approval_handoff.status
            is not AgentToolHandoffStatus.APPROVAL_REQUIRED
        ):
            raise AgentSessionRejected(
                "Agent session Approval resume binding is invalid"
            )
        retry_call = selected.broker_call.model_copy(
            update={
                "call_id": uuid4(),
                "idempotency_key": f"{retry_idempotency_key}:broker",
            }
        )
        retry_plan = AgentToolHandoffPlan.create(
            agent_plan=plan.round_plan,
            agent_outcome=round_outcome,
            broker_call=retry_call,
            limits=AgentToolHandoffLimits(),
            created_at=now,
            deadline=plan.deadline,
            idempotency_key=retry_idempotency_key,
            attempt=2,
            previous_handoff_id=approval_handoff.handoff_id,
        )
        second_handoff = self.round_handoff_service.execute(
            retry_plan, now=now, approvals=approvals
        )
        terminal = None
        if second_handoff.status is AgentToolHandoffStatus.COMPLETED:
            terminal_plan = self.terminal_continuation_service.prepare(
                root_plan=plan.round_plan,
                handoff_id=retry_plan.handoff_id,
                now=now,
                idempotency_key=terminal_continuation_key,
                continuation_run_key=terminal_run_key,
            )
            terminal = self.terminal_continuation_service.execute(
                terminal_plan, now=now
            )
        outcome = self._build_outcome(
            plan=plan,
            round_outcome=round_outcome,
            selected=selected,
            approval_handoff=approval_handoff,
            approvals=approvals,
            second_handoff=second_handoff,
            terminal=terminal,
            now=now,
        )
        self.session_store.complete(outcome)
        return outcome

    def _build_outcome(
        self,
        *,
        plan: AgentSessionPlan,
        round_outcome: AgentRunOutcome,
        selected: AgentAuthorizedCallOption | None,
        approval_handoff: AgentToolHandoffOutcome | None,
        approvals: tuple[ApprovalRequest, ...],
        second_handoff: AgentToolHandoffOutcome | None,
        terminal: AgentContinuationOutcome | None,
        now: datetime,
    ) -> AgentSessionOutcome:
        status = self._status(round_outcome, selected, second_handoff, terminal)
        budget = self._final_budget(
            plan=plan,
            round_outcome=round_outcome,
            approval_handoff=approval_handoff,
            second_handoff=second_handoff,
            terminal=terminal,
            now=now,
        )
        values = {
            "session_id": plan.session_id,
            "root_plan_id": plan.root_plan.plan_id,
            "first_observation_id": plan.first_observation_id,
            "round_plan_id": plan.round_plan.plan_id,
            "authorized_call_set_id": plan.authorized_calls.call_set_id,
            "status": status,
            "round_agent_outcome": round_outcome,
            "selected_call_commitment": (
                None if selected is None else selected.call_commitment
            ),
            "selected_broker_call_digest": (
                None if selected is None else selected.broker_call_digest
            ),
            "approval_handoff_outcome": approval_handoff,
            "approval_digests": tuple(
                sorted(
                    {
                        canonical_digest(item.model_dump(mode="python"))
                        for item in approvals
                    }
                )
            ),
            "second_handoff_outcome": second_handoff,
            "terminal_continuation": terminal,
            "budget": budget,
            "cleanup": AgentSessionCleanup(
                evidence_buffers_released=True,
                context_reverified=True,
                raw_provider_responses_absent=True,
                broker_authorization_enforced=True,
                no_vulnloom_domain_state_changed=True,
            ),
            "completed_at": now,
        }
        digest_values = {
            **values,
            "round_agent_outcome": round_outcome.model_dump(mode="python"),
            "second_handoff_outcome": (
                None
                if second_handoff is None
                else second_handoff.model_dump(mode="python")
            ),
            "approval_handoff_outcome": (
                None
                if approval_handoff is None
                else approval_handoff.model_dump(mode="python")
            ),
            "terminal_continuation": (
                None if terminal is None else terminal.model_dump(mode="python")
            ),
            "budget": budget.model_dump(mode="python"),
            "cleanup": values["cleanup"].model_dump(mode="python"),
        }
        return AgentSessionOutcome(
            outcome_id=canonical_digest(digest_values), **values
        )

    def _preflight(self, plan: AgentSessionPlan, *, now: datetime) -> AgentSessionPlan:
        try:
            plan = AgentSessionPlan.model_validate(plan.model_dump(mode="python"))
        except ValidationError as exc:
            raise AgentSessionRejected("Agent session failed boundary validation") from exc
        if now < plan.created_at or now >= plan.deadline:
            raise AgentSessionTimedOut("Agent session is outside its wall budget")
        root_outcome, first_handoff = self._authoritative_inputs(
            root_plan=plan.root_plan,
            first_handoff_id=plan.first_handoff_outcome.handoff_id,
        )
        if root_outcome != plan.root_outcome or first_handoff != plan.first_handoff_outcome:
            raise AgentSessionRejected(
                "Agent session authoritative checkpoint binding mismatch"
            )
        if (
            self.round_runtime.registration.registration_id
            != plan.round_plan.model_registration_id
            or canonical_digest(
                self.round_runtime.registration.model_dump(mode="python")
            )
            != plan.round_plan.model_registration_digest
        ):
            raise AgentSessionRejected("Agent session model registration binding mismatch")
        observation = first_handoff.observation
        assert observation is not None
        try:
            stored = self.context_store.read(plan.context_snapshot.snapshot_id)
            expected = self.context_assembler.assemble(
                task=plan.round_plan.task,
                sources=agent_observation_context_sources(
                    evidence_store=self.evidence_store, observation=observation
                ),
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
                ),
                now=plan.context_snapshot.assembled_at,
                deadline=plan.deadline,
            )
        except (
            AgentContextRejected,
            AgentContextTimedOut,
            AgentContinuationRejected,
            ValueError,
        ) as exc:
            raise AgentSessionRejected("Agent session context revalidation failed") from exc
        if stored != plan.context_snapshot or expected != plan.context_snapshot:
            raise AgentSessionRejected("Agent session context snapshot drifted")
        for option in plan.authorized_calls.options:
            try:
                self.round_handoff_service.broker.validate_call(option.broker_call)
            except ValueError as exc:
                raise AgentSessionRejected(
                    "Agent session authorized call failed Broker revalidation"
                ) from exc
        return plan

    def _authoritative_inputs(
        self, *, root_plan: AgentRunPlan, first_handoff_id: str
    ) -> tuple[AgentRunOutcome, AgentToolHandoffOutcome]:
        try:
            root_outcome = self.root_agent_store.require_completed(root_plan)
            first_handoff = self.handoff_store.require_completed(first_handoff_id)
        except (AgentRunRecoveryRequired, AgentToolHandoffRecoveryRequired) as exc:
            raise AgentSessionRejected(
                "Agent session requires authoritative completed inputs"
            ) from exc
        if (
            root_outcome.status is not AgentRunStatus.TOOL_PROPOSED
            or root_outcome.tool_intent is None
            or not root_outcome.cleanup.complete
            or first_handoff.status is not AgentToolHandoffStatus.COMPLETED
            or first_handoff.observation is None
            or not first_handoff.cleanup.complete
            or first_handoff.agent_plan_id != root_plan.plan_id
            or first_handoff.agent_outcome_digest
            != canonical_digest(root_outcome.model_dump(mode="python"))
        ):
            raise AgentSessionRejected(
                "Agent session inputs are not one completed tool feedback chain"
            )
        return root_outcome, first_handoff

    @staticmethod
    def _selected_option(
        plan: AgentSessionPlan, outcome: AgentRunOutcome
    ) -> AgentAuthorizedCallOption | None:
        if outcome.status is not AgentRunStatus.TOOL_PROPOSED or outcome.tool_intent is None:
            return None
        matches = tuple(
            item
            for item in plan.authorized_calls.options
            if agent_tool_intent_for_broker_call(item.broker_call) == outcome.tool_intent
        )
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _status(
        round_outcome: AgentRunOutcome,
        selected: AgentAuthorizedCallOption | None,
        second_handoff: AgentToolHandoffOutcome | None,
        terminal: AgentContinuationOutcome | None,
    ) -> AgentSessionStatus:
        if round_outcome.status is not AgentRunStatus.TOOL_PROPOSED:
            return AgentSessionStatus(round_outcome.status.value)
        if selected is None or second_handoff is None:
            return AgentSessionStatus.FAILED
        if second_handoff.status is not AgentToolHandoffStatus.COMPLETED:
            return AgentSessionStatus(second_handoff.status.value)
        assert terminal is not None
        return AgentSessionStatus(terminal.status.value)

    @staticmethod
    def _final_budget(
        *,
        plan: AgentSessionPlan,
        round_outcome: AgentRunOutcome,
        approval_handoff: AgentToolHandoffOutcome | None,
        second_handoff: AgentToolHandoffOutcome | None,
        terminal: AgentContinuationOutcome | None,
        now: datetime,
    ) -> AgentSessionBudgetLedger:
        terminal_outcome = None if terminal is None else terminal.agent_outcome
        outcomes = (plan.root_outcome, round_outcome) + (
            () if terminal_outcome is None else (terminal_outcome,)
        )
        consumed_tokens = sum(item.input_tokens + item.output_tokens for item in outcomes)
        consumed_tools = plan.first_handoff_outcome.broker_result.tool_calls_used
        if approval_handoff is not None:
            consumed_tools += approval_handoff.broker_result.tool_calls_used
        if second_handoff is not None:
            consumed_tools += second_handoff.broker_result.tool_calls_used
        return AgentSessionBudgetLedger(
            original_model_tokens=plan.budget.original_model_tokens,
            original_tool_calls=plan.budget.original_tool_calls,
            consumed_model_tokens=consumed_tokens,
            remaining_model_tokens=plan.budget.original_model_tokens - consumed_tokens,
            consumed_agent_steps=sum(item.steps for item in outcomes),
            consumed_tool_calls=consumed_tools,
            remaining_tool_calls=plan.budget.original_tool_calls - consumed_tools,
            provider_attempts=len(outcomes),
            broker_attempts=1
            + int(approval_handoff is not None)
            + int(second_handoff is not None),
            remaining_wall_seconds=max(0, int((plan.deadline - now).total_seconds())),
        )
