"""Typed contracts for source-to-live Hybrid evidence admission."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, EvidenceBundle, ValidationResult

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class HybridCheckKind(StrEnum):
    INITIAL = "initial"
    REMEDIATION_RETEST = "remediation_retest"


class HybridRunState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class HybridConclusion(StrEnum):
    CONFIRMED = "confirmed"
    REMEDIATED = "remediated"


class DeploymentProof(DomainModel):
    """Redacted proof that one source version is deployed at one exact endpoint."""

    proof_id: Digest
    source_target_id: UUID
    source_target_version: str = Field(min_length=1, max_length=256)
    source_manifest_digest: Digest
    live_target_id: UUID
    endpoint_url_digest: Digest
    deployed_artifact_digest: Digest
    attestation_evidence_ref: Digest
    attested_by: str = Field(pattern=r"^operator:[a-zA-Z0-9._-]{1,200}$")
    attested_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.expires_at <= self.attested_at:
            raise ValueError("Deployment proof validity window is invalid")
        if self.proof_id != canonical_digest(
            self.model_dump(mode="python", exclude={"proof_id"})
        ):
            raise ValueError("Deployment proof content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> DeploymentProof:
        expanded = cls.model_construct(proof_id="0" * 64, **values).model_dump(
            mode="python", exclude={"proof_id"}
        )
        return cls(proof_id=canonical_digest(expanded), **expanded)


class HybridValidationLimits(DomainModel):
    max_source_evidence_refs: int = Field(default=64, ge=1, le=256)
    max_http_evidence_refs: int = Field(default=64, ge=1, le=256)
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    max_attempts: int = Field(default=3, ge=1, le=3)


class HybridValidationPlan(DomainModel):
    plan_id: Digest
    check_kind: HybridCheckKind
    candidate_id: UUID
    candidate_digest: Digest
    source_target_id: UUID
    source_target_version: str = Field(min_length=1, max_length=256)
    source_manifest_digest: Digest
    live_target_id: UUID
    endpoint_url_digest: Digest
    deployment_proof_id: Digest
    deployment_proof_digest: Digest
    validation_plan_id: Digest
    source_evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=256)]
    expected_result: ValidationResult
    prior_chain_id: Digest | None = None
    scope_id: UUID
    scope_version: int = Field(ge=1)
    limits: HybridValidationLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.deadline <= self.created_at:
            raise ValueError("Hybrid validation window is invalid")
        if self.source_evidence_refs != tuple(sorted(set(self.source_evidence_refs))):
            raise ValueError("Hybrid source Evidence references must be sorted and unique")
        if len(self.source_evidence_refs) > self.limits.max_source_evidence_refs:
            raise ValueError("Hybrid source Evidence budget exceeded")
        initial = self.check_kind is HybridCheckKind.INITIAL
        if initial != (self.prior_chain_id is None):
            raise ValueError("Hybrid retest must bind exactly one prior chain")
        expected = (
            ValidationResult.REPRODUCED
            if initial
            else ValidationResult.NOT_REPRODUCED
        )
        if self.expected_result is not expected:
            raise ValueError("Hybrid check kind and expected result disagree")
        if self.plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"plan_id"})
        ):
            raise ValueError("Hybrid validation plan content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> HybridValidationPlan:
        expanded = cls.model_construct(plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


class HybridEvidenceChain(DomainModel):
    chain_id: Digest
    plan_id: Digest
    check_kind: HybridCheckKind
    conclusion: HybridConclusion
    candidate_id: UUID
    candidate_digest: Digest
    source_target_id: UUID
    source_target_version: str = Field(min_length=1, max_length=256)
    source_manifest_digest: Digest
    live_target_id: UUID
    endpoint_url_digest: Digest
    deployment_proof_id: Digest
    validation_plan_id: Digest
    validation_run_id: UUID
    prior_chain_id: Digest | None = None
    source_evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=256)]
    deployment_evidence_ref: Digest
    http_evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=256)]
    evidence_bundle: EvidenceBundle
    scope_id: UUID
    scope_version: int = Field(ge=1)
    sealed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected = (
            HybridConclusion.CONFIRMED
            if self.check_kind is HybridCheckKind.INITIAL
            else HybridConclusion.REMEDIATED
        )
        refs = tuple(
            sorted(
                {
                    *self.source_evidence_refs,
                    self.deployment_evidence_ref,
                    *self.http_evidence_refs,
                }
            )
        )
        if (
            self.conclusion is not expected
            or (self.check_kind is HybridCheckKind.INITIAL) != (self.prior_chain_id is None)
            or self.source_evidence_refs != tuple(sorted(set(self.source_evidence_refs)))
            or self.http_evidence_refs != tuple(sorted(set(self.http_evidence_refs)))
            or self.evidence_bundle.candidate_id != self.candidate_id
            or self.evidence_bundle.evidence_refs != refs
        ):
            raise ValueError("Hybrid Evidence Chain bindings are inconsistent")
        if self.chain_id != canonical_digest(
            self.model_dump(mode="python", exclude={"chain_id"})
        ):
            raise ValueError("Hybrid Evidence Chain content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> HybridEvidenceChain:
        expanded = cls.model_construct(chain_id="0" * 64, **values).model_dump(
            mode="python", exclude={"chain_id"}
        )
        return cls(chain_id=canonical_digest(expanded), **expanded)


class HybridValidationOutcome(DomainModel):
    plan_id: Digest
    state: HybridRunState
    attempt: int = Field(ge=1, le=3)
    chain: HybridEvidenceChain | None = None
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    cleanup_complete: bool
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def terminal_shape(self) -> Self:
        if self.state is HybridRunState.STARTED:
            raise ValueError("Hybrid outcome must be terminal")
        if (self.state is HybridRunState.COMPLETED) != (self.chain is not None):
            raise ValueError("Only completed Hybrid outcomes contain an Evidence Chain")
        if not self.cleanup_complete:
            raise ValueError("Hybrid outcome requires proven cleanup")
        return self
