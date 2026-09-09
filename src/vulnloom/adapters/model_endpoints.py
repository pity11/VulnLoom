"""Opaque references to restricted model endpoint configuration."""

from __future__ import annotations

from typing import Self

from pydantic import Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest


class ModelEndpointReference(DomainModel):
    """Identify a Control Plane configuration slot without exposing its URL."""

    reference_id: Digest
    configuration_key: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,127}$")

    @model_validator(mode="after")
    def sealed_reference(self) -> Self:
        expected = canonical_digest({"configuration_key": self.configuration_key})
        if self.reference_id != expected:
            raise ValueError("model endpoint reference content digest mismatch")
        return self

    @classmethod
    def create(cls, *, configuration_key: str) -> ModelEndpointReference:
        return cls(
            reference_id=canonical_digest({"configuration_key": configuration_key}),
            configuration_key=configuration_key,
        )
