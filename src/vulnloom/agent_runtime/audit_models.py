"""Digest-only contracts for deterministic Agent session auditing."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

from .session_models import AgentSessionBudgetLedger, AgentSessionCleanup


class AgentSessionRecommendationDisposition(StrEnum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class AgentSessionRecommendationReason(StrEnum):
    SESSION_COMPLETED = "session_completed"
    AGENT_BLOCKED = "agent_blocked"
    BROKER_DENIED = "broker_denied"
    SESSION_FAILED = "session_failed"
    SESSION_TIMED_OUT = "session_timed_out"


class AgentSessionAuditLimits(DomainModel):
    timeout_seconds: float = Field(default=60.0, gt=0, le=300)
    max_evidence_refs: int = Field(default=128, ge=1, le=512)
    max_artifact_bytes: int = Field(default=2 * 1024 * 1024, ge=1024, le=8 * 1024 * 1024)


class AgentSessionAuditPlan(DomainModel):
    audit_plan_id: Digest
    session_id: Digest
    session_plan_digest: Digest
    session_outcome_id: Digest
    session_outcome_digest: Digest
    target_id: UUID
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    limits: AgentSessionAuditLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_plan(self) -> Self:
        if not self.created_at < self.deadline:
            raise ValueError("Agent session audit validity window is invalid")
        if (self.deadline - self.created_at).total_seconds() > self.limits.timeout_seconds:
            raise ValueError("Agent session audit deadline exceeds its wall budget")
        if "\x00" in self.idempotency_key:
            raise ValueError("Agent session audit idempotency key contains NUL")
        if self.audit_plan_id != agent_session_audit_plan_digest(self):
            raise ValueError("Agent session audit plan content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        session_id: str,
        session_plan_digest: str,
        session_outcome_id: str,
        session_outcome_digest: str,
        target_id: UUID,
        target_version_digest: str,
        scope_id: UUID,
        scope_version: int,
        limits: AgentSessionAuditLimits,
        created_at: AwareDatetime,
        deadline: AwareDatetime,
        idempotency_key: str,
    ) -> AgentSessionAuditPlan:
        values = {
            "session_id": session_id,
            "session_plan_digest": session_plan_digest,
            "session_outcome_id": session_outcome_id,
            "session_outcome_digest": session_outcome_digest,
            "target_id": target_id,
            "target_version_digest": target_version_digest,
            "scope_id": scope_id,
            "scope_version": scope_version,
            "limits": limits,
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {
            **values,
            "limits": limits.model_dump(mode="python"),
        }
        return cls(audit_plan_id=canonical_digest(digest_values), **values)


def agent_session_audit_plan_digest(plan: AgentSessionAuditPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"audit_plan_id"}))


class AgentSessionRecommendation(DomainModel):
    recommendation_id: Digest
    session_id: Digest
    disposition: AgentSessionRecommendationDisposition
    reason_code: AgentSessionRecommendationReason
    evidence_refs: Annotated[tuple[Digest, ...], Field(max_length=128)] = ()
    budget_digest: Digest
    projected_at: AwareDatetime

    @model_validator(mode="after")
    def deterministic_shape(self) -> Self:
        expected = {
            AgentSessionRecommendationReason.SESSION_COMPLETED:
                AgentSessionRecommendationDisposition.COMPLETED,
            AgentSessionRecommendationReason.AGENT_BLOCKED:
                AgentSessionRecommendationDisposition.BLOCKED,
            AgentSessionRecommendationReason.BROKER_DENIED:
                AgentSessionRecommendationDisposition.BLOCKED,
            AgentSessionRecommendationReason.SESSION_FAILED:
                AgentSessionRecommendationDisposition.FAILED,
            AgentSessionRecommendationReason.SESSION_TIMED_OUT:
                AgentSessionRecommendationDisposition.TIMED_OUT,
        }[self.reason_code]
        if self.disposition is not expected:
            raise ValueError("Agent session recommendation reason does not match disposition")
        if self.evidence_refs != tuple(sorted(set(self.evidence_refs))):
            raise ValueError("Agent session recommendation Evidence refs must be unique and sorted")
        if self.recommendation_id != agent_session_recommendation_digest(self):
            raise ValueError("Agent session recommendation content digest mismatch")
        return self


def agent_session_recommendation_digest(recommendation: AgentSessionRecommendation) -> str:
    return canonical_digest(
        recommendation.model_dump(mode="python", exclude={"recommendation_id"})
    )


class AgentSessionAuditBundle(DomainModel):
    bundle_id: Digest
    audit_plan_id: Digest
    session_id: Digest
    session_plan_digest: Digest
    session_outcome_id: Digest
    session_outcome_digest: Digest
    target_id: UUID
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    root_plan_id: Digest
    root_outcome_digest: Digest
    first_handoff_id: Digest
    first_handoff_outcome_digest: Digest
    round_plan_id: Digest
    round_outcome_digest: Digest
    authorized_call_set_id: Digest
    selected_call_commitment: Digest | None = None
    approval_digests: Annotated[tuple[Digest, ...], Field(max_length=32)] = ()
    second_handoff_id: Digest | None = None
    second_handoff_outcome_digest: Digest | None = None
    continuation_id: Digest | None = None
    continuation_outcome_digest: Digest | None = None
    observation_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=2)]
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=128)]
    budget: AgentSessionBudgetLedger
    cleanup: AgentSessionCleanup
    recommendation: AgentSessionRecommendation
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed_bundle(self) -> Self:
        if self.observation_ids != tuple(dict.fromkeys(self.observation_ids)):
            raise ValueError("Agent session audit Observations must be unique and ordered")
        if self.evidence_refs != tuple(sorted(set(self.evidence_refs))):
            raise ValueError("Agent session audit Evidence refs must be unique and sorted")
        if self.approval_digests != tuple(sorted(set(self.approval_digests))):
            raise ValueError("Agent session audit Approval digests must be unique and sorted")
        if (self.second_handoff_id is None) != (
            self.second_handoff_outcome_digest is None
        ) or (self.continuation_id is None) != (
            self.continuation_outcome_digest is None
        ):
            raise ValueError("Agent session audit chain digest is incomplete")
        if self.recommendation.session_id != self.session_id:
            raise ValueError("Agent session audit recommendation binding mismatch")
        if self.recommendation.evidence_refs != self.evidence_refs:
            raise ValueError("Agent session audit recommendation Evidence binding mismatch")
        if self.recommendation.budget_digest != canonical_digest(
            self.budget.model_dump(mode="python")
        ):
            raise ValueError("Agent session audit recommendation budget binding mismatch")
        if not self.cleanup.complete:
            raise ValueError("Agent session audit cleanup is incomplete")
        if self.bundle_id != agent_session_audit_bundle_digest(self):
            raise ValueError("Agent session audit bundle content digest mismatch")
        return self


def agent_session_audit_bundle_digest(bundle: AgentSessionAuditBundle) -> str:
    return canonical_digest(bundle.model_dump(mode="python", exclude={"bundle_id"}))


class AgentSessionAuditArtifact(DomainModel):
    bundle_id: Digest
    json_sha256: Digest
    markdown_sha256: Digest
    json_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/audit\.json$")
    markdown_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/audit\.md$")


class AgentSessionAuditOutcome(DomainModel):
    outcome_id: Digest
    audit_plan_id: Digest
    session_id: Digest
    bundle: AgentSessionAuditBundle
    artifact: AgentSessionAuditArtifact
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed_outcome(self) -> Self:
        if (
            self.bundle.audit_plan_id != self.audit_plan_id
            or self.bundle.session_id != self.session_id
            or self.artifact.bundle_id != self.bundle.bundle_id
            or self.completed_at != self.bundle.completed_at
        ):
            raise ValueError("Agent session audit outcome binding mismatch")
        if self.outcome_id != agent_session_audit_outcome_digest(self):
            raise ValueError("Agent session audit outcome content digest mismatch")
        return self


def agent_session_audit_outcome_digest(outcome: AgentSessionAuditOutcome) -> str:
    return canonical_digest(outcome.model_dump(mode="python", exclude={"outcome_id"}))
