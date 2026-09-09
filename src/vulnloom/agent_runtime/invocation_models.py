"""Provider-neutral, content-addressed result for one bounded model invocation."""

from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

from .provider_diagnostics import ProviderDiagnostic


class ModelInvocationResult(DomainModel):
    result_id: Digest
    plan_id: Digest
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    status: Literal["passed", "rejected", "timed_out"]
    input_tokens: int = Field(ge=0, le=10_000_000)
    output_tokens: int = Field(ge=0, le=65_536)
    process_started: bool
    cleanup_verified: bool
    attempt_digest: Digest | None
    receipt_digest: Digest | None
    completed_at: AwareDatetime
    diagnostic: ProviderDiagnostic | None = None
    response_model: Annotated[
        str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._:/+-]{0,255}$")
    ] | None = None

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.status == "passed" and not (
            self.process_started
            and self.cleanup_verified
            and self.attempt_digest
            and self.receipt_digest
            and self.response_model
        ):
            raise ValueError("successful model invocation requires identity and cleanup proof")
        if self.diagnostic is not None and self.status == "passed" and (
            self.diagnostic.error_code is not None
            or self.diagnostic.http_status != 200
        ):
            raise ValueError("passed model invocation cannot contain failure diagnostic")
        if self.result_id != canonical_digest(
            self.model_dump(mode="python", exclude={"result_id"})
        ):
            raise ValueError("model invocation result digest mismatch")
        return self

    @classmethod
    def create(cls, **values) -> "ModelInvocationResult":
        if isinstance(values.get("diagnostic"), ProviderDiagnostic):
            values["diagnostic"] = values["diagnostic"].model_dump(mode="python")
        return cls(result_id=canonical_digest(values), **values)
