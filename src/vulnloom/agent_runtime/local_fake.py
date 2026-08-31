"""Credential-isolated local fake model adapter with no socket capability."""

from __future__ import annotations

import hashlib
import hmac

from pydantic import Field

from vulnloom.adapters.model_credentials import (
    ModelCredentialLease,
    ModelCredentialProvider,
    ModelCredentialReference,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

from .models import (
    AgentAdapterKind,
    AgentModelRegistration,
    AgentModelReply,
    AgentStepRequest,
)


class LocalFakeTurn(DomainModel):
    expected_request_digest: Digest
    expected_credential_digest: Digest
    structured_output: dict[str, object]
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    latency_seconds: float = Field(default=0.01, ge=0, le=600)


class LocalFakeProviderExhausted(RuntimeError):
    pass


class LocalFakeProviderMismatch(ValueError):
    pass


class LocalFakeModelAdapter:
    def __init__(
        self,
        *,
        registration: AgentModelRegistration,
        credential_reference: ModelCredentialReference,
        credential_provider: ModelCredentialProvider,
        turns: tuple[LocalFakeTurn, ...],
    ):
        if (
            registration.adapter_kind is not AgentAdapterKind.LOCAL_FAKE_PROVIDER
            or registration.credential_reference_id != credential_reference.reference_id
        ):
            raise ValueError("local fake adapter registration binding mismatch")
        self.registration = registration
        self.credential_reference = credential_reference
        self.credential_provider = credential_provider
        self.turns = turns
        self.requests: list[AgentStepRequest] = []
        self.released_leases: list[ModelCredentialLease] = []
        self._index = 0

    def complete(self, request: AgentStepRequest) -> AgentModelReply:
        if self._index >= len(self.turns):
            raise LocalFakeProviderExhausted("local fake model turns are exhausted")
        turn = self.turns[self._index]
        observed_request = canonical_digest(request.model_dump(mode="python"))
        if observed_request != turn.expected_request_digest:
            raise LocalFakeProviderMismatch("local fake request digest mismatch")
        lease = self.credential_provider.acquire(self.credential_reference)
        try:
            with lease:
                observed_credential = hashlib.sha256(lease.view()).hexdigest()
                if not hmac.compare_digest(
                    observed_credential, turn.expected_credential_digest
                ):
                    raise LocalFakeProviderMismatch("local fake credential mismatch")
        finally:
            lease.close()
            self.released_leases.append(lease)
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
