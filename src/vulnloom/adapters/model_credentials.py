"""Control Plane model credentials with scoped, zeroed leases."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Protocol, Self

from pydantic import Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest


class ModelCredentialUnavailable(RuntimeError):
    pass


class ModelCredentialReference(DomainModel):
    reference_id: Digest
    environment_variable: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,127}$")

    @model_validator(mode="after")
    def sealed_reference(self) -> Self:
        expected = canonical_digest({"environment_variable": self.environment_variable})
        if self.reference_id != expected:
            raise ValueError("model credential reference content digest mismatch")
        return self

    @classmethod
    def create(cls, *, environment_variable: str) -> ModelCredentialReference:
        return cls(
            reference_id=canonical_digest(
                {"environment_variable": environment_variable}
            ),
            environment_variable=environment_variable,
        )


class ModelCredentialLease:
    """Non-serializable secret buffer that is zeroed when its scope ends."""

    __slots__ = ("_released", "_secret")

    def __init__(self, secret: str):
        encoded = secret.encode("utf-8")
        if not encoded or b"\x00" in encoded or len(encoded) > 16_384:
            raise ModelCredentialUnavailable("model credential is empty or invalid")
        self._secret = bytearray(encoded)
        self._released = False

    @property
    def released(self) -> bool:
        return self._released

    @property
    def zeroed(self) -> bool:
        return self._released and not any(self._secret)

    def view(self) -> memoryview:
        if self._released:
            raise ModelCredentialUnavailable("model credential lease is released")
        return memoryview(self._secret).toreadonly()

    def close(self) -> None:
        if not self._released:
            self._secret[:] = b"\x00" * len(self._secret)
            self._released = True

    def __enter__(self) -> ModelCredentialLease:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class ModelCredentialProvider(Protocol):
    def acquire(self, reference: ModelCredentialReference) -> ModelCredentialLease: ...


class EnvironmentModelCredentialProvider:
    """Resolve exactly one referenced variable without exporting an environment."""

    def __init__(
        self,
        environment: Mapping[str, str] | None = None,
        *,
        allowed_references: tuple[ModelCredentialReference, ...],
    ):
        references = {item.reference_id: item for item in allowed_references}
        if not references or len(references) != len(allowed_references):
            raise ValueError("model credential references must be non-empty and unique")
        self._environment = os.environ if environment is None else environment
        self._references = references

    def acquire(self, reference: ModelCredentialReference) -> ModelCredentialLease:
        if self._references.get(reference.reference_id) != reference:
            raise ModelCredentialUnavailable(
                "model credential reference is not allowed"
            )
        value = self._environment.get(reference.environment_variable)
        if not value:
            raise ModelCredentialUnavailable(
                "referenced model credential is unavailable"
            )
        return ModelCredentialLease(value)
