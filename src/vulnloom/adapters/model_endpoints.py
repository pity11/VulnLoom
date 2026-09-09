"""Opaque references to restricted model endpoint configuration."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, Self
from urllib.parse import urlsplit

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


class ModelEndpointUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class ResolvedModelEndpoint:
    """Transient parsed endpoint; never a checkpoint or domain event."""

    hostname: str
    port: int
    base_path: str

    def admits(self, request_path: str) -> bool:
        prefix = self.base_path.rstrip("/")
        return not prefix or request_path == prefix or request_path.startswith(prefix + "/")


class ModelEndpointProvider(Protocol):
    def resolve(self, reference: ModelEndpointReference) -> ResolvedModelEndpoint: ...


class EnvironmentModelEndpointProvider:
    """Resolve only explicitly allowed HTTPS endpoint references from Control Plane input."""

    def __init__(
        self,
        environment: Mapping[str, str],
        *,
        allowed_references: tuple[ModelEndpointReference, ...],
    ):
        references = {item.reference_id: item for item in allowed_references}
        if not references or len(references) != len(allowed_references):
            raise ValueError("model endpoint references must be non-empty and unique")
        self._environment = environment
        self._references = references

    def resolve(self, reference: ModelEndpointReference) -> ResolvedModelEndpoint:
        if self._references.get(reference.reference_id) != reference:
            raise ModelEndpointUnavailable("model endpoint reference is not allowed")
        raw = self._environment.get(reference.configuration_key)
        if not raw or len(raw) > 2048 or any(character.isspace() for character in raw):
            raise ModelEndpointUnavailable("referenced model endpoint is unavailable")
        try:
            parsed = urlsplit(raw)
            port = parsed.port or 443
        except ValueError as exc:
            raise ModelEndpointUnavailable("referenced model endpoint is invalid") from exc
        hostname = parsed.hostname
        if (
            parsed.scheme != "https"
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or port != 443
            or parsed.path.endswith("/") and parsed.path != "/"
        ):
            raise ModelEndpointUnavailable("referenced model endpoint is invalid")
        base_path = "" if parsed.path in {"", "/"} else parsed.path
        return ResolvedModelEndpoint(
            hostname=hostname.lower(),
            port=port,
            base_path=base_path,
        )
