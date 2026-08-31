"""Deterministic model replay adapter; never opens a socket or resolves credentials."""

from __future__ import annotations

from typing import Protocol

from pydantic import Field

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

from .models import AgentModelRegistration, AgentModelReply, AgentStepRequest


class AgentModelAdapter(Protocol):
    registration: AgentModelRegistration

    def complete(self, request: AgentStepRequest) -> AgentModelReply: ...


class ReplayTurn(DomainModel):
    expected_request_digest: Digest
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
        self._index = 0

    def complete(self, request: AgentStepRequest) -> AgentModelReply:
        if self._index >= len(self.turns):
            raise OfflineReplayExhausted("offline Agent replay is exhausted")
        turn = self.turns[self._index]
        observed = canonical_digest(request.model_dump(mode="python"))
        if observed != turn.expected_request_digest:
            raise OfflineReplayMismatch("offline Agent replay request digest mismatch")
        self._index += 1
        self.requests.append(request)
        return AgentModelReply(
            structured_output=turn.structured_output,
            provider_id=self.registration.provider_id,
            model=self.registration.model,
            input_tokens=turn.input_tokens,
            output_tokens=turn.output_tokens,
            latency_seconds=turn.latency_seconds,
        )
