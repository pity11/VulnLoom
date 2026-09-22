"""Contracts for offline validation of independent sealed-GET replays."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .evidence_requirement_models import (
    EvidenceAssertion,
    EvidenceFactKind,
    EvidenceFactVerdict,
    EvidenceRequirementStage,
)
from .models import Digest


class EvidenceReplayValidationState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


REPLAY_VALIDATION_RULESET_DIGEST = canonical_digest(
    {
        "ruleset": "sealed-get-independent-replay-v1",
        "comparison": "exact-response-body-sha256",
        "mismatch_verdict": EvidenceFactVerdict.INCONCLUSIVE,
        "request_execution_authorized": False,
    }
)


class EvidenceReplayValidationLimits(DomainModel):
    max_evidence_refs: int = Field(default=2, ge=2, le=2)
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class EvidenceReplayValidationPlan(DomainModel):
    plan_id: Digest
    requirement_id: Digest
    baseline_materialization_plan_id: Digest
    baseline_materialization_id: Digest
    baseline_flow_plan_id: Digest
    baseline_observation_id: Digest
    baseline_snapshot_id: Digest
    current_materialization_plan_id: Digest
    current_materialization_id: Digest
    current_flow_plan_id: Digest
    current_observation_id: Digest
    current_snapshot_id: Digest
    requested_url_digest: Digest
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=2, max_length=2)]
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    ruleset_digest: Literal[REPLAY_VALIDATION_RULESET_DIGEST] = (
        REPLAY_VALIDATION_RULESET_DIGEST
    )
    limits: EvidenceReplayValidationLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        independent_pairs = (
            (
                self.baseline_materialization_plan_id,
                self.current_materialization_plan_id,
            ),
            (self.baseline_materialization_id, self.current_materialization_id),
            (self.baseline_flow_plan_id, self.current_flow_plan_id),
            (self.baseline_observation_id, self.current_observation_id),
            (self.baseline_snapshot_id, self.current_snapshot_id),
        )
        if (
            self.deadline <= self.created_at
            or any(left == right for left, right in independent_pairs)
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or self.ruleset_digest != REPLAY_VALIDATION_RULESET_DIGEST
            or self.plan_id
            != canonical_digest(self.model_dump(mode="python", exclude={"plan_id"}))
        ):
            raise ValueError("Evidence Replay Validation Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> EvidenceReplayValidationPlan:
        expanded = cls.model_construct(plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


class EvidenceReplayValidation(DomainModel):
    validation_id: Digest
    plan_id: Digest
    requirement_id: Digest
    baseline_materialization_id: Digest
    current_materialization_id: Digest
    requested_url_digest: Digest
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=2, max_length=2)]
    assertions: Annotated[tuple[EvidenceAssertion, ...], Field(min_length=2, max_length=2)]
    content_match: bool
    replay_verdict: EvidenceFactVerdict
    ruleset_digest: Literal[REPLAY_VALIDATION_RULESET_DIGEST]
    request_execution_authorized: Literal[False] = False
    candidate_proposal_eligible: Literal[False] = False
    finding_authorized: Literal[False] = False
    validated_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        assertions = {item.fact: item for item in self.assertions}
        required = {
            EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED,
            EvidenceFactKind.REDACTION_BOUNDARY_PROVEN,
        }
        expected_replay = (
            EvidenceFactVerdict.SUPPORTED
            if self.content_match
            else EvidenceFactVerdict.INCONCLUSIVE
        )
        if (
            tuple(item.assertion_id for item in self.assertions)
            != tuple(sorted({item.assertion_id for item in self.assertions}))
            or set(assertions) != required
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or self.replay_verdict is not expected_replay
            or assertions[EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED].verdict
            is not self.replay_verdict
            or assertions[EvidenceFactKind.REDACTION_BOUNDARY_PROVEN].verdict
            is not EvidenceFactVerdict.SUPPORTED
            or any(
                item.requirement_id != self.requirement_id
                or item.stage is not EvidenceRequirementStage.VALIDATION
                or item.evidence_refs != self.evidence_refs
                or item.context_id != self.plan_id
                or item.producer_ref != "validator:sealed-get-replay-v1"
                for item in self.assertions
            )
            or self.ruleset_digest != REPLAY_VALIDATION_RULESET_DIGEST
            or self.request_execution_authorized
            or self.candidate_proposal_eligible
            or self.finding_authorized
            or self.validation_id
            != canonical_digest(
                self.model_dump(mode="python", exclude={"validation_id"})
            )
        ):
            raise ValueError("Evidence Replay Validation binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> EvidenceReplayValidation:
        expanded = cls.model_construct(validation_id="0" * 64, **values).model_dump(
            mode="python", exclude={"validation_id"}
        )
        return cls(validation_id=canonical_digest(expanded), **expanded)


class EvidenceReplayValidationOutcome(DomainModel):
    plan_id: Digest
    validation: EvidenceReplayValidation
    attempt: int = Field(ge=1, le=3)
    cleanup_complete: Literal[True] = True

    @model_validator(mode="after")
    def bound(self) -> Self:
        if self.validation.plan_id != self.plan_id:
            raise ValueError("Evidence Replay Validation Outcome binding is invalid")
        return self
