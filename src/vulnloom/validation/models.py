"""Typed, sealed contracts for one authorized Candidate validation attempt."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.broker.models import BrokerCall, BrokerResult
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    Candidate,
    DomainModel,
    EvidenceBundle,
    ValidationResult,
    ValidationRun,
)
from vulnloom.runners.models import Digest, SandboxRunRequest, SandboxRunResult


class ValidationPlan(DomainModel):
    """Human-selected, content-addressed execution plan.

    The plan contains typed runner and Broker requests; free-form text cannot grant
    tools, network, credentials, or a reproduced verdict.
    """

    plan_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    target_id: UUID
    target_version: str = Field(min_length=1)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    selected_by: str = Field(min_length=1, max_length=256)
    selected_at: AwareDatetime
    selection_reason: str = Field(min_length=1, max_length=2048)
    runner_request: SandboxRunRequest
    broker_calls: Annotated[tuple[BrokerCall, ...], Field(max_length=16)] = ()
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def content_address_is_valid(self) -> Self:
        if self.plan_id != validation_plan_digest(self):
            raise ValueError("ValidationPlan content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        candidate_id: UUID,
        candidate_digest: str,
        target_id: UUID,
        target_version: str,
        scope_id: UUID,
        scope_version: int,
        selected_by: str,
        selected_at: datetime,
        selection_reason: str,
        runner_request: SandboxRunRequest,
        broker_calls: tuple[BrokerCall, ...] = (),
        idempotency_key: str,
    ) -> ValidationPlan:
        values = {
            "candidate_id": candidate_id,
            "candidate_digest": candidate_digest,
            "target_id": target_id,
            "target_version": target_version,
            "scope_id": scope_id,
            "scope_version": scope_version,
            "selected_by": selected_by,
            "selected_at": selected_at,
            "selection_reason": selection_reason,
            "runner_request": runner_request,
            "broker_calls": broker_calls,
            "idempotency_key": idempotency_key,
        }
        digest_values = {
            **values,
            "runner_request": runner_request.model_dump(mode="python"),
            "broker_calls": tuple(call.model_dump(mode="python") for call in broker_calls),
        }
        return cls(plan_id=canonical_digest(digest_values), **values)


def validation_plan_digest(plan: ValidationPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"plan_id"}))


def candidate_content_digest(candidate: Candidate) -> str:
    return canonical_digest(candidate.model_dump(mode="python"))


class ValidationVerdict(DomainModel):
    """Conclusion from a trusted deterministic judge, never from Worker prose."""

    result: ValidationResult
    rationale_code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    evidence_refs: tuple[Digest, ...] = ()

    @model_validator(mode="after")
    def reproduced_requires_evidence(self) -> Self:
        if self.result is ValidationResult.REPRODUCED and not self.evidence_refs:
            raise ValueError("a reproduced verdict requires evidence")
        return self


class ValidationOutcome(DomainModel):
    plan_id: Digest
    candidate: Candidate
    validation_run: ValidationRun
    evidence_bundle: EvidenceBundle | None
    runner_result: SandboxRunResult
    broker_results: tuple[BrokerResult, ...]
    verdict: ValidationVerdict
    completed_at: AwareDatetime
