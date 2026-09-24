"""Secret-free contracts for one isolated Test Identity session."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, DomainModel

from .models import Digest
from .test_identity_models import RoleReference, TestIdentityPurpose


def credential_authorization_context_digest(
    *,
    admission_id: str,
    identity_ref: str,
    purpose: TestIdentityPurpose,
    role_ref: str,
) -> str:
    return canonical_digest(
        {
            "admission_id": admission_id,
            "identity_ref": identity_ref,
            "purpose": purpose,
            "role_ref": role_ref,
        }
    )


class CredentialSessionState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


class CredentialSessionLimits(DomainModel):
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    lease_ttl_seconds: int = Field(default=60, ge=1, le=300)
    max_attempts: int = Field(default=3, ge=1, le=3)
    max_session_uses: Literal[1] = 1


class CredentialSessionPlan(DomainModel):
    plan_id: Digest
    admission_plan_id: Digest
    admission_id: Digest
    record_id: Digest
    identity_ref: Digest
    credential_ref: Digest
    engagement_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    target_id: UUID
    target_digest: Digest
    purpose: TestIdentityPurpose
    role_ref: RoleReference
    action_digest: Digest
    action_intent_digest: Digest
    action_name: str = Field(min_length=1, max_length=200)
    mutates_state: bool
    required_approvals: Annotated[tuple[ApprovalAction, ...], Field(min_length=1, max_length=2)]
    limits: CredentialSessionLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    lease_expires_at: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    network_execution_authorized: Literal[False] = False
    third_party_account_authorized: Literal[False] = False
    secret_material_present: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.required_approvals
            != tuple(sorted(set(self.required_approvals), key=lambda item: item.value))
            or not self.created_at < self.deadline <= self.lease_expires_at
            or self.network_execution_authorized
            or self.third_party_account_authorized
            or self.secret_material_present
            or self.plan_id != canonical_digest(self.model_dump(mode="python", exclude={"plan_id"}))
        ):
            raise ValueError("Credential Session Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CredentialSessionPlan:
        normalized = dict(values)
        normalized["required_approvals"] = tuple(
            sorted(set(values["required_approvals"]), key=lambda item: item.value)
        )
        expanded = cls.model_construct(plan_id="0" * 64, **normalized).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


class CredentialLeaseReceipt(DomainModel):
    lease_id: Digest
    plan_id: Digest
    credential_ref: Digest
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    released: Literal[True] = True
    zeroed: Literal[True] = True
    secret_material_persisted: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            not self.issued_at < self.expires_at
            or not self.released
            or not self.zeroed
            or self.secret_material_persisted
            or self.lease_id
            != canonical_digest(self.model_dump(mode="python", exclude={"lease_id"}))
        ):
            raise ValueError("Credential Lease Receipt binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CredentialLeaseReceipt:
        expanded = cls.model_construct(lease_id="0" * 64, **values).model_dump(
            mode="python", exclude={"lease_id"}
        )
        return cls(lease_id=canonical_digest(expanded), **expanded)


class IsolatedSessionReceipt(DomainModel):
    session_id: Digest
    plan_id: Digest
    lease_id: Digest
    target_id: UUID
    identity_ref: Digest
    role_ref: RoleReference
    opened_at: AwareDatetime
    closed_at: AwareDatetime
    max_uses: Literal[1] = 1
    uses: Literal[1] = 1
    isolated: Literal[True] = True
    released: Literal[True] = True
    zeroed: Literal[True] = True
    network_performed: Literal[False] = False
    authentication_performed: bool = False
    state_changed: bool = False
    state_restored: Literal[True] = True

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.closed_at < self.opened_at
            or not self.isolated
            or not self.released
            or not self.zeroed
            or self.network_performed
            or not self.state_restored
            or self.session_id
            != canonical_digest(self.model_dump(mode="python", exclude={"session_id"}))
        ):
            raise ValueError("Isolated Session Receipt binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> IsolatedSessionReceipt:
        expanded = cls.model_construct(session_id="0" * 64, **values).model_dump(
            mode="python", exclude={"session_id"}
        )
        return cls(session_id=canonical_digest(expanded), **expanded)


class CredentialSessionOutcome(DomainModel):
    outcome_id: Digest
    plan_id: Digest
    attempt: int = Field(ge=1, le=3)
    approval_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=2)]
    lease: CredentialLeaseReceipt
    session: IsolatedSessionReceipt
    completed_at: AwareDatetime
    cleanup_complete: Literal[True] = True
    secret_material_persisted: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.approval_ids != tuple(sorted(set(self.approval_ids), key=str))
            or self.lease.plan_id != self.plan_id
            or self.session.plan_id != self.plan_id
            or self.session.lease_id != self.lease.lease_id
            or not self.cleanup_complete
            or self.secret_material_persisted
            or self.outcome_id
            != canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        ):
            raise ValueError("Credential Session Outcome binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> CredentialSessionOutcome:
        normalized = dict(values)
        normalized["approval_ids"] = tuple(sorted(set(values["approval_ids"]), key=str))
        expanded = cls.model_construct(outcome_id="0" * 64, **normalized).model_dump(
            mode="python", exclude={"outcome_id"}
        )
        return cls(outcome_id=canonical_digest(expanded), **expanded)
