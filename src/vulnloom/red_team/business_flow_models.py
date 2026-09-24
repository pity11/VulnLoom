"""Secret-free contracts for one compensated local business-flow mutation."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .models import Digest
from .test_identity_models import RoleReference


class BusinessInvariantState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class PublicationState(StrEnum):
    DRAFT = "draft"
    PUBLISHED = "published"


class BusinessInvariantVerdict(StrEnum):
    UPHELD = "upheld"
    VIOLATED = "violated"


class OfflinePublicationFixture(DomainModel):
    fixture_id: Digest
    resource_ref: Digest
    publisher_roles: Annotated[tuple[RoleReference, ...], Field(min_length=1, max_length=8)]
    enforces_role_policy: bool
    initial_state: Literal[PublicationState.DRAFT] = PublicationState.DRAFT
    environment: Literal["local_offline_fixture"] = "local_offline_fixture"
    network_enabled: Literal[False] = False
    external_state_present: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.publisher_roles != tuple(sorted(set(self.publisher_roles)))
            or self.network_enabled
            or self.external_state_present
            or self.fixture_id
            != canonical_digest(self.model_dump(mode="python", exclude={"fixture_id"}))
        ):
            raise ValueError("Offline Publication Fixture binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> OfflinePublicationFixture:
        normalized = dict(values)
        normalized["publisher_roles"] = tuple(sorted(set(values["publisher_roles"])))
        expanded = cls.model_construct(fixture_id="0" * 64, **normalized).model_dump(
            mode="python", exclude={"fixture_id"}
        )
        return cls(fixture_id=canonical_digest(expanded), **expanded)


class BusinessStateSnapshot(DomainModel):
    snapshot_id: Digest
    fixture_id: Digest
    resource_ref: Digest
    state: PublicationState
    revision: int = Field(ge=1)
    semantic_digest: Digest
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        semantic = canonical_digest(
            {
                "fixture_id": self.fixture_id,
                "resource_ref": self.resource_ref,
                "state": self.state,
            }
        )
        if (
            self.semantic_digest != semantic
            or self.snapshot_id
            != canonical_digest(self.model_dump(mode="python", exclude={"snapshot_id"}))
        ):
            raise ValueError("Business State Snapshot binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> BusinessStateSnapshot:
        normalized = dict(values)
        normalized["semantic_digest"] = canonical_digest(
            {
                "fixture_id": values["fixture_id"],
                "resource_ref": values["resource_ref"],
                "state": values["state"],
            }
        )
        expanded = cls.model_construct(snapshot_id="0" * 64, **normalized).model_dump(
            mode="python", exclude={"snapshot_id"}
        )
        return cls(snapshot_id=canonical_digest(expanded), **expanded)


class BusinessMutationObservation(DomainModel):
    observation_id: Digest
    session_plan_id: Digest
    fixture_id: Digest
    resource_ref: Digest
    actor_identity_ref: Digest
    actor_role_ref: RoleReference
    action_intent_digest: Digest
    before_snapshot_id: Digest
    mutated_snapshot_id: Digest
    expected_authorized: bool
    mutation_applied: Literal[True] = True
    verdict: BusinessInvariantVerdict
    observed_at: AwareDatetime
    candidate_created: Literal[False] = False
    finding_created: Literal[False] = False
    vulnerability_claimed: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected_verdict = (
            BusinessInvariantVerdict.UPHELD
            if self.expected_authorized
            else BusinessInvariantVerdict.VIOLATED
        )
        if (
            not self.mutation_applied
            or self.verdict is not expected_verdict
            or self.candidate_created
            or self.finding_created
            or self.vulnerability_claimed
            or self.observation_id
            != canonical_digest(self.model_dump(mode="python", exclude={"observation_id"}))
        ):
            raise ValueError("Business Mutation Observation binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> BusinessMutationObservation:
        expanded = cls.model_construct(observation_id="0" * 64, **values).model_dump(
            mode="python", exclude={"observation_id"}
        )
        return cls(observation_id=canonical_digest(expanded), **expanded)


class StateRestorationProof(DomainModel):
    proof_id: Digest
    session_plan_id: Digest
    before_snapshot_id: Digest
    mutated_snapshot_id: Digest
    restored_snapshot_id: Digest
    before_semantic_digest: Digest
    restored_semantic_digest: Digest
    before_revision: int = Field(ge=1)
    mutated_revision: int = Field(ge=2)
    restored_revision: int = Field(ge=3)
    restored_at: AwareDatetime
    restoration_verified: Literal[True] = True
    network_performed: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.before_semantic_digest != self.restored_semantic_digest
            or not self.before_revision < self.mutated_revision < self.restored_revision
            or not self.restoration_verified
            or self.network_performed
            or self.proof_id
            != canonical_digest(self.model_dump(mode="python", exclude={"proof_id"}))
        ):
            raise ValueError("State Restoration Proof binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> StateRestorationProof:
        expanded = cls.model_construct(proof_id="0" * 64, **values).model_dump(
            mode="python", exclude={"proof_id"}
        )
        return cls(proof_id=canonical_digest(expanded), **expanded)


class LocalBusinessFlowExecution(DomainModel):
    execution_id: Digest
    before: BusinessStateSnapshot
    mutated: BusinessStateSnapshot
    restored: BusinessStateSnapshot
    observation: BusinessMutationObservation
    restoration: StateRestorationProof
    cleanup_complete: Literal[True] = True

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.before.snapshot_id != self.observation.before_snapshot_id
            or self.mutated.snapshot_id != self.observation.mutated_snapshot_id
            or self.restoration.before_snapshot_id != self.before.snapshot_id
            or self.restoration.mutated_snapshot_id != self.mutated.snapshot_id
            or self.restoration.restored_snapshot_id != self.restored.snapshot_id
            or self.restoration.before_semantic_digest != self.before.semantic_digest
            or self.restoration.restored_semantic_digest != self.restored.semantic_digest
            or not self.cleanup_complete
            or self.execution_id
            != canonical_digest(self.model_dump(mode="python", exclude={"execution_id"}))
        ):
            raise ValueError("Local Business Flow Execution binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> LocalBusinessFlowExecution:
        expanded = cls.model_construct(execution_id="0" * 64, **values).model_dump(
            mode="python", exclude={"execution_id"}
        )
        return cls(execution_id=canonical_digest(expanded), **expanded)


class BusinessInvariantLimits(DomainModel):
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class BusinessInvariantPlan(DomainModel):
    plan_id: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    target_id: UUID
    target_digest: Digest
    session_plan_id: Digest
    fixture_id: Digest
    resource_ref: Digest
    actor_identity_ref: Digest
    actor_role_ref: RoleReference
    action_intent_digest: Digest
    limits: BusinessInvariantLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    candidate_authorized: Literal[False] = False
    finding_authorized: Literal[False] = False
    submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            not self.created_at < self.deadline
            or self.candidate_authorized
            or self.finding_authorized
            or self.submission_authorized
            or self.plan_id != canonical_digest(self.model_dump(mode="python", exclude={"plan_id"}))
        ):
            raise ValueError("Business Invariant Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> BusinessInvariantPlan:
        expanded = cls.model_construct(plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


class BusinessInvariantOutcome(DomainModel):
    outcome_id: Digest
    plan_id: Digest
    session_outcome_id: Digest
    execution: LocalBusinessFlowExecution
    attempt: int = Field(ge=1, le=3)
    completed_at: AwareDatetime
    restoration_verified: Literal[True] = True
    candidate_created: Literal[False] = False
    finding_created: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            not self.restoration_verified
            or self.candidate_created
            or self.finding_created
            or self.outcome_id
            != canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        ):
            raise ValueError("Business Invariant Outcome binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> BusinessInvariantOutcome:
        expanded = cls.model_construct(outcome_id="0" * 64, **values).model_dump(
            mode="python", exclude={"outcome_id"}
        )
        return cls(outcome_id=canonical_digest(expanded), **expanded)
