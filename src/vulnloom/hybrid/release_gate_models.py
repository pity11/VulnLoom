"""Typed, redacted contracts for the Hybrid CI/CD release gate."""

from __future__ import annotations

from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel, Scope

from .models import DeploymentProof, HybridConclusion, HybridEvidenceChain


class HybridReleaseGateState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class HybridReleaseDecision(StrEnum):
    PASSED = "passed"
    BLOCKED = "blocked"


class HybridCiGateStatus(StrEnum):
    PASS = "pass"
    BLOCK = "block"
    ERROR = "error"


class HybridReleaseGatePolicy(DomainModel):
    required_conclusion: HybridConclusion = HybridConclusion.REMEDIATED
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=3, le=3)

    @model_validator(mode="after")
    def non_weakenable(self) -> Self:
        if self.required_conclusion is not HybridConclusion.REMEDIATED:
            raise ValueError("Hybrid release gate policy cannot accept an unremediated chain")
        return self


class HybridReleaseGatePlan(DomainModel):
    plan_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    hybrid_chain_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    hybrid_chain_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    deployment_proof_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    deployment_proof_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_target_id: UUID
    source_target_version: str = Field(min_length=1, max_length=256)
    source_manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    live_target_id: UUID
    endpoint_url_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope_id: UUID
    scope_version: int = Field(ge=1)
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy: HybridReleaseGatePolicy
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.deadline <= self.created_at:
            raise ValueError("Hybrid release gate window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Hybrid release gate key contains NUL")
        if self.plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"plan_id"})
        ):
            raise ValueError("Hybrid release gate plan content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        chain: HybridEvidenceChain,
        deployment_proof: DeploymentProof,
        scope: Scope,
        policy: HybridReleaseGatePolicy,
        created_at,
        deadline,
        idempotency_key: str,
    ) -> HybridReleaseGatePlan:
        values = {
            "hybrid_chain_id": chain.chain_id,
            "hybrid_chain_digest": canonical_digest(chain.model_dump(mode="python")),
            "deployment_proof_id": deployment_proof.proof_id,
            "deployment_proof_digest": canonical_digest(
                deployment_proof.model_dump(mode="python")
            ),
            "source_target_id": chain.source_target_id,
            "source_target_version": chain.source_target_version,
            "source_manifest_digest": chain.source_manifest_digest,
            "live_target_id": chain.live_target_id,
            "endpoint_url_digest": chain.endpoint_url_digest,
            "scope_id": scope.scope_id,
            "scope_version": scope.version,
            "scope_digest": canonical_digest(scope.model_dump(mode="python")),
            "policy": policy,
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {**values, "policy": policy.model_dump(mode="python")}
        return cls(plan_id=canonical_digest(digest_values), **values)


class HybridReleaseGateResult(DomainModel):
    result_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    hybrid_chain_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: HybridReleaseDecision
    reason_codes: tuple[str, ...]
    source_remediation_proof_id: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    evaluated_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("Hybrid release gate reasons must be sorted and unique")
        if (self.decision is HybridReleaseDecision.PASSED) != (not self.reason_codes):
            raise ValueError("Hybrid release gate decision and reasons disagree")
        if (self.decision is HybridReleaseDecision.PASSED) != (
            self.source_remediation_proof_id is not None
        ):
            raise ValueError("passing Hybrid release gate requires remediation proof")
        if self.result_id != canonical_digest(
            self.model_dump(mode="python", exclude={"result_id"})
        ):
            raise ValueError("Hybrid release gate result content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> HybridReleaseGateResult:
        expanded = cls.model_construct(result_id="0" * 64, **values).model_dump(
            mode="python", exclude={"result_id"}
        )
        return cls(result_id=canonical_digest(expanded), **expanded)


class HybridReleaseGateOutcome(DomainModel):
    plan_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: HybridReleaseGateState
    attempt: int = Field(ge=1, le=3)
    result: HybridReleaseGateResult | None = None
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    cleanup_complete: bool
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def terminal_shape(self) -> Self:
        if self.state is HybridReleaseGateState.STARTED:
            raise ValueError("Hybrid release gate outcome must be terminal")
        if (self.state is HybridReleaseGateState.COMPLETED) != (self.result is not None):
            raise ValueError("Only completed Hybrid release gates contain a result")
        if self.result is not None and self.result.plan_id != self.plan_id:
            raise ValueError("Hybrid release gate result binding is inconsistent")
        if not self.cleanup_complete:
            raise ValueError("Hybrid release gate outcome requires proven cleanup")
        return self


class HybridCiGateResponse(DomainModel):
    contract_version: str = Field(default="v1", pattern=r"^v1$")
    status: HybridCiGateStatus
    exit_code: int = Field(ge=0, le=2)
    plan_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    result_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    reason_codes: tuple[str, ...]

    @model_validator(mode="after")
    def stable_exit_contract(self) -> Self:
        expected = {
            HybridCiGateStatus.PASS: 0,
            HybridCiGateStatus.BLOCK: 1,
            HybridCiGateStatus.ERROR: 2,
        }[self.status]
        if self.exit_code != expected:
            raise ValueError("Hybrid CI gate status and exit code disagree")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("Hybrid CI gate reasons must be sorted and unique")
        if self.status is HybridCiGateStatus.PASS and self.reason_codes:
            raise ValueError("passing Hybrid CI gate cannot contain failure reasons")
        if self.status is not HybridCiGateStatus.PASS and not self.reason_codes:
            raise ValueError("non-passing Hybrid CI gate requires a stable reason")
        if (self.status is HybridCiGateStatus.ERROR) != (self.result_id is None):
            raise ValueError("Hybrid CI gate result identity is inconsistent")
        return self
