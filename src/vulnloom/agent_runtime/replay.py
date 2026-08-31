"""Deterministic model replay adapter; never opens a socket or resolves credentials."""

from __future__ import annotations

from typing import Protocol

from pydantic import Field

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

from .messages import AgentMessageEnvelope
from .models import AgentModelRegistration, AgentModelReply, AgentStepRequest


class AgentModelAdapter(Protocol):
    registration: AgentModelRegistration

    def complete(
        self,
        request: AgentStepRequest,
        *,
        message_envelope: AgentMessageEnvelope | None = None,
    ) -> AgentModelReply: ...


class ReplayTurn(DomainModel):
    expected_request_digest: Digest
    expected_message_envelope_id: Digest | None = None
    structured_output: dict[str, object]
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    latency_seconds: float = Field(default=0.01, ge=0, le=600)


class OfflineReplayExhausted(RuntimeError):
    pass


class OfflineReplayMismatch(ValueError):
    pass


class OfflineReplayModelAdapter:
    def __init__(
        self, *, registration: AgentModelRegistration, turns: tuple[ReplayTurn, ...]
    ):
        self.registration = registration
        self.turns = turns
        self.requests: list[AgentStepRequest] = []
        self.message_envelope_ids: list[str | None] = []
        self._index = 0

    def complete(
        self,
        request: AgentStepRequest,
        *,
        message_envelope: AgentMessageEnvelope | None = None,
    ) -> AgentModelReply:
        if self._index >= len(self.turns):
            raise OfflineReplayExhausted("offline Agent replay is exhausted")
        turn = self.turns[self._index]
        observed = canonical_digest(request.model_dump(mode="python"))
        if observed != turn.expected_request_digest:
            raise OfflineReplayMismatch("offline Agent replay request digest mismatch")
        observed_envelope = (
            None if message_envelope is None else message_envelope.envelope_id
        )
        if observed_envelope != request.message_envelope_id:
            raise OfflineReplayMismatch("offline Agent request/envelope binding mismatch")
        if observed_envelope != turn.expected_message_envelope_id:
            raise OfflineReplayMismatch("offline Agent replay message envelope mismatch")
        self._index += 1
        self.requests.append(request)
        self.message_envelope_ids.append(observed_envelope)
        return AgentModelReply(
            structured_output=turn.structured_output,
            provider_id=self.registration.provider_id,
            model=self.registration.model,
            input_tokens=turn.input_tokens,
            output_tokens=turn.output_tokens,
            latency_seconds=turn.latency_seconds,
        )
