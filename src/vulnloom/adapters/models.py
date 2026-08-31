"""Control-plane-only model provider configuration.

This module deliberately exposes only a content-addressed credential reference
on serializable configuration. A future HTTP/SDK adapter must acquire a scoped
Control Plane lease and must never include secret material in Worker envelopes.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import Field, HttpUrl

from vulnloom.domain.models import DomainModel

from .model_credentials import ModelCredentialReference


class ModelProviderConfig(DomainModel):
    provider_id: str = Field(min_length=1)
    base_url: HttpUrl
    model: str = Field(min_length=1)
    credential_reference: ModelCredentialReference
    max_output_tokens: int = Field(default=8192, ge=1)
    timeout_seconds: float = Field(default=60, gt=0, le=600)

class ModelRequest(DomainModel):
    system: str
    prompt: str
    schema_name: str


class ModelResponse(DomainModel):
    structured_output: dict
    provider_id: str
    model: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)


class ModelAdapter(Protocol):
    def complete(self, request: ModelRequest) -> ModelResponse: ...
