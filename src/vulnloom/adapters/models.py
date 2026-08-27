"""Control-plane-only model provider configuration.

This module deliberately does not expose a resolved API key on serializable
task objects. A future HTTP/SDK adapter should resolve it immediately before a
request and must never include it in Worker envelopes.
"""

from __future__ import annotations

import os
from typing import Protocol

from pydantic import Field, HttpUrl

from vulnloom.domain.models import DomainModel


class ModelProviderConfig(DomainModel):
    provider_id: str = Field(min_length=1)
    base_url: HttpUrl
    model: str = Field(min_length=1)
    api_key_env: str = Field(min_length=1, pattern=r"^[A-Z][A-Z0-9_]*$")
    max_output_tokens: int = Field(default=8192, ge=1)
    timeout_seconds: float = Field(default=60, gt=0, le=600)

    def resolve_api_key(self) -> str:
        value = os.environ.get(self.api_key_env)
        if not value:
            raise RuntimeError(
                f"model credential environment variable is not set: {self.api_key_env}"
            )
        return value


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
