"""Trusted offline Agent loop that validates proposals but executes no tools."""

from __future__ import annotations

import json
from datetime import datetime

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest

from .context import AgentContextRejected, AgentContextSnapshot, AgentContextStore
from .messages import (
    AgentMessageEnvelope,
    AgentMessageRejected,
    AgentMessageRenderer,
    AgentMessageTimedOut,
)
from .models import (
    AgentAdapterKind,
    AgentCleanupReport,
    AgentDecisionKind,
    AgentDecisionPayload,
    AgentModelRegistration,
    AgentRunOutcome,
    AgentRunPlan,
    AgentRunStatus,
    AgentStepRequest,
    AgentToolIntent,
)
from .replay import AgentModelAdapter
from .store import AgentRunStore
from .transport import AgentProviderTransportRejected, AgentProviderTransportTimedOut


class AgentRuntimeRejected(ValueError):
    pass


class AgentRuntimeAdapterFailure(RuntimeError):
    pass


class OfflineAgentRuntime:
    def __init__(
        self,
        *,
        store: AgentRunStore,
        registration: AgentModelRegistration,
        adapter: AgentModelAdapter,
        context_store: AgentContextStore | None = None,
        message_renderer: AgentMessageRenderer | None = None,
    ):
        self.store = store
        self.registration = registration
        self.adapter = adapter
        self.context_store = context_store
        self.message_renderer = message_renderer

    def execute(self, plan: AgentRunPlan, *, now: datetime) -> AgentRunOutcome:
        if now < plan.created_at or now >= plan.deadline or now >= plan.task.deadline:
            raise AgentRuntimeRejected("Agent run plan is not active")
        if (
            plan.model_registration_id != self.registration.registration_id
            or plan.model_registration_digest
            != canonical_digest(self.registration.model_dump(mode="python"))
            or self.adapter.registration != self.registration
            or self.registration.adapter_kind
            not in {
                AgentAdapterKind.OFFLINE_REPLAY,
                AgentAdapterKind.LOCAL_FAKE_PROVIDER,
                AgentAdapterKind.ADMISSION_FAKE_TRANSPORT,
                AgentAdapterKind.SUBPROCESS_HTTPS_PROVIDER,
            }
            or plan.task.worker_role not in self.registration.supported_roles
        ):
            raise AgentRuntimeRejected("Agent model registration binding mismatch")
        snapshot = None
        if plan.context_snapshot_id is not None:
            if self.context_store is None:
                raise AgentRuntimeRejected("Agent context store is required")
            if self.message_renderer is None:
                raise AgentRuntimeRejected("Agent message renderer is required")
            try:
                snapshot = self.context_store.read(plan.context_snapshot_id)
                snapshot.assert_for_task(plan.task)
            except AgentContextRejected as exc:
                raise AgentRuntimeRejected("Agent context binding mismatch") from exc
        initial_remaining = plan.task.budget.model_tokens
        try:
            first_request, first_envelope = self._prepare_request(
                plan,
                step=1,
                remaining=initial_remaining,
                snapshot=snapshot,
            )
        except (AgentMessageRejected, AgentMessageTimedOut) as exc:
            raise AgentRuntimeRejected("Agent message rendering rejected") from exc
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            if claim.outcome is None:
                raise RuntimeError("completed Agent checkpoint has no outcome")
            return claim.outcome

        total_input = 0
        total_output = 0
        elapsed = 0.0
        available_wall = min(
            plan.limits.timeout_seconds,
            float(plan.task.budget.wall_seconds),
            (plan.deadline - now).total_seconds(),
            (plan.task.deadline - now).total_seconds(),
        )
        for step in range(1, plan.limits.max_steps + 1):
            remaining = plan.task.budget.model_tokens - total_input - total_output
            if remaining <= 0:
                return self._finish(
                    plan,
                    now=now,
                    status=AgentRunStatus.FAILED,
                    steps=step,
                    input_tokens=total_input,
                    output_tokens=total_output,
                    error_codes=("model_token_budget_exhausted",),
                )
            if step == 1:
                request, message_envelope = first_request, first_envelope
            else:
                try:
                    request, message_envelope = self._prepare_request(
                        plan,
                        step=step,
                        remaining=remaining,
                        snapshot=snapshot,
                    )
                except AgentMessageTimedOut:
                    return self._finish(
                        plan,
                        now=now,
                        status=AgentRunStatus.TIMED_OUT,
                        steps=step,
                        input_tokens=total_input,
                        output_tokens=total_output,
                        error_codes=("message_rendering_wall_time_exceeded",),
                    )
                except AgentMessageRejected:
                    return self._finish(
                        plan,
                        now=now,
                        status=AgentRunStatus.FAILED,
                        steps=step,
                        input_tokens=total_input,
                        output_tokens=total_output,
                        error_codes=("message_rendering_rejected",),
                    )
            try:
                reply = self.adapter.complete(
                    request, message_envelope=message_envelope
                )
            except AgentProviderTransportTimedOut:
                return self._finish(
                    plan,
                    now=now,
                    status=AgentRunStatus.TIMED_OUT,
                    steps=step,
                    input_tokens=total_input,
                    output_tokens=total_output,
                    error_codes=("provider_transport_timeout",),
                )
            except AgentProviderTransportRejected:
                return self._finish(
                    plan,
                    now=now,
                    status=AgentRunStatus.FAILED,
                    steps=step,
                    input_tokens=total_input,
                    output_tokens=total_output,
                    error_codes=("provider_transport_rejected",),
                )
            except Exception as exc:
                raise AgentRuntimeAdapterFailure(
                    "offline Agent adapter failed after STARTED checkpoint"
                ) from exc
            total_input += reply.input_tokens
            total_output += reply.output_tokens
            elapsed += reply.latency_seconds
            try:
                structured_output_bytes = len(
                    json.dumps(
                        reply.structured_output,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("utf-8")
                )
            except (TypeError, ValueError):
                structured_output_bytes = -1
            structured_output_limit = min(
                1_048_576, max(4096, request.max_output_tokens * 16)
            )
            if structured_output_bytes < 0 or structured_output_bytes > structured_output_limit:
                return self._finish(
                    plan,
                    now=now,
                    status=AgentRunStatus.FAILED,
                    steps=step,
                    input_tokens=total_input,
                    output_tokens=total_output,
                    error_codes=("structured_output_size_exceeded",),
                )
            if elapsed > available_wall:
                return self._finish(
                    plan,
                    now=now,
                    status=AgentRunStatus.TIMED_OUT,
                    steps=step,
                    input_tokens=total_input,
                    output_tokens=total_output,
                    error_codes=("agent_wall_time_budget_exceeded",),
                )
            if (
                reply.provider_id != self.registration.provider_id
                or reply.model != self.registration.model
            ):
                return self._finish(
                    plan,
                    now=now,
                    status=AgentRunStatus.FAILED,
                    steps=step,
                    input_tokens=total_input,
                    output_tokens=total_output,
                    error_codes=("model_identity_mismatch",),
                )
            if (
                reply.output_tokens > request.max_output_tokens
                or total_input + total_output > plan.task.budget.model_tokens
            ):
                return self._finish(
                    plan,
                    now=now,
                    status=AgentRunStatus.FAILED,
                    steps=step,
                    input_tokens=total_input,
                    output_tokens=total_output,
                    error_codes=("model_token_budget_exceeded",),
                )
            try:
                decision = AgentDecisionPayload.model_validate(reply.structured_output)
            except ValidationError:
                if step < plan.limits.max_steps:
                    continue
                return self._finish(
                    plan,
                    now=now,
                    status=AgentRunStatus.FAILED,
                    steps=step,
                    input_tokens=total_input,
                    output_tokens=total_output,
                    error_codes=("structured_output_invalid",),
                )
            if decision.kind is AgentDecisionKind.PROPOSE_TOOL:
                assert decision.tool_call is not None
                if (
                    plan.task.budget.tool_calls < 1
                    or decision.tool_call.tool_id not in plan.task.allowed_tools
                ):
                    return self._finish(
                        plan,
                        now=now,
                        status=AgentRunStatus.FAILED,
                        steps=step,
                        input_tokens=total_input,
                        output_tokens=total_output,
                        error_codes=("tool_proposal_not_allowed",),
                    )
                try:
                    tool_intent = AgentToolIntent.from_payload(decision.tool_call)
                except ValidationError:
                    return self._finish(
                        plan,
                        now=now,
                        status=AgentRunStatus.FAILED,
                        steps=step,
                        input_tokens=total_input,
                        output_tokens=total_output,
                        error_codes=("tool_proposal_invalid",),
                    )
                return self._finish(
                    plan,
                    now=now,
                    status=AgentRunStatus.TOOL_PROPOSED,
                    steps=step,
                    input_tokens=total_input,
                    output_tokens=total_output,
                    tool_intent=tool_intent,
                    supporting_ref_digests=decision.supporting_ref_digests,
                )
            return self._finish(
                plan,
                now=now,
                status=(
                    AgentRunStatus.COMPLETED
                    if decision.kind is AgentDecisionKind.COMPLETE
                    else AgentRunStatus.BLOCKED
                ),
                steps=step,
                input_tokens=total_input,
                output_tokens=total_output,
                summary_digest=decision.summary_digest,
                supporting_ref_digests=decision.supporting_ref_digests,
            )
        raise RuntimeError("Agent loop exhausted without a terminal outcome")

    def _prepare_request(
        self,
        plan: AgentRunPlan,
        *,
        step: int,
        remaining: int,
        snapshot: AgentContextSnapshot | None,
    ) -> tuple[AgentStepRequest, AgentMessageEnvelope | None]:
        base = AgentStepRequest.create(
            plan=plan, step=step, remaining_model_tokens=remaining
        )
        if snapshot is None:
            return base, None
        assert self.message_renderer is not None
        envelope = self.message_renderer.render(
            plan=plan, snapshot=snapshot, request=base
        )
        request = AgentStepRequest.create(
            plan=plan,
            step=step,
            remaining_model_tokens=remaining,
            message_envelope_id=envelope.envelope_id,
        )
        return request, envelope

    def _finish(
        self,
        plan: AgentRunPlan,
        *,
        now: datetime,
        status: AgentRunStatus,
        steps: int,
        input_tokens: int,
        output_tokens: int,
        tool_intent: AgentToolIntent | None = None,
        summary_digest: str | None = None,
        supporting_ref_digests: tuple[str, ...] = (),
        error_codes: tuple[str, ...] = (),
    ) -> AgentRunOutcome:
        outcome = AgentRunOutcome(
            plan_id=plan.plan_id,
            task_id=plan.task.task_id,
            model_registration_id=self.registration.registration_id,
            status=status,
            steps=steps,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            tool_intent=tool_intent,
            summary_digest=summary_digest,
            supporting_ref_digests=supporting_ref_digests,
            error_codes=error_codes,
            cleanup=AgentCleanupReport(
                model_request_released=True,
                raw_response_discarded=True,
                no_tool_executed=True,
            ),
            completed_at=now,
        )
        self.store.complete(outcome)
        return outcome
