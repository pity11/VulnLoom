"""Secret-free local authentication and role-differential contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .models import Digest
from .test_identity_models import RoleReference


class RoleDifferentialState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class RoleAccessDecision(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"


class RoleDifferentialVerdict(StrEnum):
    SAME = "same"
    DIFFERENT = "different"


class RoleFixtureDecision(DomainModel):
    role_ref: RoleReference
    decision: RoleAccessDecision


class OfflineRoleFixture(DomainModel):
    fixture_id: Digest
    decisions: Annotated[tuple[RoleFixtureDecision, ...], Field(min_length=2, max_length=16)]
    environment: Literal["local_offline_fixture"] = "local_offline_fixture"
    network_enabled: Literal[False] = False
    target_state_mutable: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        roles = tuple(item.role_ref for item in self.decisions)
        if (
            roles != tuple(sorted(set(roles)))
            or self.network_enabled
            or self.target_state_mutable
            or self.fixture_id
            != canonical_digest(self.model_dump(mode="python", exclude={"fixture_id"}))
        ):
            raise ValueError("Offline Role Fixture binding is invalid")
        return self

    @classmethod
    def create(cls, *, decisions: tuple[RoleFixtureDecision, ...]) -> OfflineRoleFixture:
        normalized = tuple(sorted(decisions, key=lambda item: item.role_ref))
        expanded = cls.model_construct(fixture_id="0" * 64, decisions=normalized).model_dump(
            mode="python", exclude={"fixture_id"}
        )
        return cls(fixture_id=canonical_digest(expanded), **expanded)


class LocalAuthenticationObservation(DomainModel):
    observation_id: Digest
    fixture_id: Digest
    session_plan_id: Digest
    identity_ref: Digest
    role_ref: RoleReference
    action_intent_digest: Digest
    access_decision: RoleAccessDecision
    observed_at: AwareDatetime
    authentication_accepted: Literal[True] = True
    network_performed: Literal[False] = False
    raw_response_present: Literal[False] = False
    credential_material_present: Literal[False] = False
    session_material_present: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            not self.authentication_accepted
            or self.network_performed
            or self.raw_response_present
            or self.credential_material_present
            or self.session_material_present
            or self.observation_id
            != canonical_digest(self.model_dump(mode="python", exclude={"observation_id"}))
        ):
            raise ValueError("Local Authentication Observation binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> LocalAuthenticationObservation:
        expanded = cls.model_construct(observation_id="0" * 64, **values).model_dump(
            mode="python", exclude={"observation_id"}
        )
        return cls(observation_id=canonical_digest(expanded), **expanded)


class SessionLogoutProof(DomainModel):
    proof_id: Digest
    session_plan_id: Digest
    session_binding: Digest
    logged_out_at: AwareDatetime
    session_released: Literal[True] = True
    session_zeroed: Literal[True] = True
    post_logout_reuse_rejected: Literal[True] = True
    credential_material_present: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            not self.session_released
            or not self.session_zeroed
            or not self.post_logout_reuse_rejected
            or self.credential_material_present
            or self.proof_id
            != canonical_digest(self.model_dump(mode="python", exclude={"proof_id"}))
        ):
            raise ValueError("Session Logout Proof binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> SessionLogoutProof:
        expanded = cls.model_construct(proof_id="0" * 64, **values).model_dump(
            mode="python", exclude={"proof_id"}
        )
        return cls(proof_id=canonical_digest(expanded), **expanded)


class LocalAuthenticationExecution(DomainModel):
    execution_id: Digest
    observation: LocalAuthenticationObservation
    logout: SessionLogoutProof
    cleanup_complete: Literal[True] = True

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.observation.session_plan_id != self.logout.session_plan_id
            or not self.cleanup_complete
            or self.execution_id
            != canonical_digest(self.model_dump(mode="python", exclude={"execution_id"}))
        ):
            raise ValueError("Local Authentication Execution binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> LocalAuthenticationExecution:
        expanded = cls.model_construct(execution_id="0" * 64, **values).model_dump(
            mode="python", exclude={"execution_id"}
        )
        return cls(execution_id=canonical_digest(expanded), **expanded)


class RoleDifferentialLimits(DomainModel):
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class RoleDifferentialPlan(DomainModel):
    plan_id: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    target_id: UUID
    target_digest: Digest
    fixture_id: Digest
    action_intent_digest: Digest
    baseline_session_plan_id: Digest
    baseline_session_outcome_id: Digest
    baseline_execution_id: Digest
    baseline_identity_ref: Digest
    baseline_role_ref: RoleReference
    comparison_session_plan_id: Digest
    comparison_session_outcome_id: Digest
    comparison_execution_id: Digest
    comparison_identity_ref: Digest
    comparison_role_ref: RoleReference
    limits: RoleDifferentialLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    candidate_authorized: Literal[False] = False
    finding_authorized: Literal[False] = False
    state_change_authorized: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.baseline_session_plan_id == self.comparison_session_plan_id
            or self.baseline_identity_ref == self.comparison_identity_ref
            or self.baseline_role_ref == self.comparison_role_ref
            or not self.created_at < self.deadline
            or self.candidate_authorized
            or self.finding_authorized
            or self.state_change_authorized
            or self.plan_id != canonical_digest(self.model_dump(mode="python", exclude={"plan_id"}))
        ):
            raise ValueError("Role Differential Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> RoleDifferentialPlan:
        expanded = cls.model_construct(plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


class RoleDifferentialObservation(DomainModel):
    observation_id: Digest
    plan_id: Digest
    action_intent_digest: Digest
    baseline_authentication_observation_id: Digest
    baseline_role_ref: RoleReference
    baseline_decision: RoleAccessDecision
    comparison_authentication_observation_id: Digest
    comparison_role_ref: RoleReference
    comparison_decision: RoleAccessDecision
    verdict: RoleDifferentialVerdict
    observed_at: AwareDatetime
    candidate_created: Literal[False] = False
    finding_created: Literal[False] = False
    vulnerability_claimed: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected = (
            RoleDifferentialVerdict.SAME
            if self.baseline_decision is self.comparison_decision
            else RoleDifferentialVerdict.DIFFERENT
        )
        if (
            self.baseline_role_ref == self.comparison_role_ref
            or self.verdict is not expected
            or self.candidate_created
            or self.finding_created
            or self.vulnerability_claimed
            or self.observation_id
            != canonical_digest(self.model_dump(mode="python", exclude={"observation_id"}))
        ):
            raise ValueError("Role Differential Observation binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> RoleDifferentialObservation:
        expanded = cls.model_construct(observation_id="0" * 64, **values).model_dump(
            mode="python", exclude={"observation_id"}
        )
        return cls(observation_id=canonical_digest(expanded), **expanded)


class RoleDifferentialOutcome(DomainModel):
    outcome_id: Digest
    plan_id: Digest
    observation: RoleDifferentialObservation
    baseline_logout_proof_id: Digest
    comparison_logout_proof_id: Digest
    attempt: int = Field(ge=1, le=3)
    completed_at: AwareDatetime
    cleanup_complete: Literal[True] = True
    secret_material_persisted: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.observation.plan_id != self.plan_id
            or not self.cleanup_complete
            or self.secret_material_persisted
            or self.outcome_id
            != canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        ):
            raise ValueError("Role Differential Outcome binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> RoleDifferentialOutcome:
        expanded = cls.model_construct(outcome_id="0" * 64, **values).model_dump(
            mode="python", exclude={"outcome_id"}
        )
        return cls(outcome_id=canonical_digest(expanded), **expanded)
