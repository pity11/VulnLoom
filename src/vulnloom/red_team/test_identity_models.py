"""Opaque, non-secret contracts for controlled test-identity admission."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, DomainModel

from .models import Digest


class TestIdentityPurpose(StrEnum):
    AUTHENTICATION = "authentication"
    READ_ONLY_ROLE_OBSERVATION = "read_only_role_observation"
    STATE_CHANGE_VALIDATION = "state_change_validation"


class TestIdentityRecordState(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class TestIdentityAdmissionState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


RoleReference = Annotated[
    str, Field(pattern=r"^role:[a-zA-Z0-9._-]{1,200}$")
]


class TestIdentityReference(DomainModel):
    """Opaque identity and credential locators; neither field is secret material."""

    identity_ref: Digest
    credential_ref: Digest


class TestIdentityRecord(DomainModel):
    record_id: Digest
    record_version: Literal[1] = 1
    reference: TestIdentityReference
    custody_proof_digest: Digest
    issuer_ref: str = Field(pattern=r"^operator:[a-zA-Z0-9._-]{1,200}$")
    scope_id: UUID
    scope_version: int = Field(ge=1)
    target_id: UUID
    target_digest: Digest
    allowed_purposes: Annotated[
        tuple[TestIdentityPurpose, ...], Field(min_length=1, max_length=3)
    ]
    role_refs: Annotated[tuple[RoleReference, ...], Field(min_length=1, max_length=32)]
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    issued_at: AwareDatetime
    account_class: Literal["controlled_test_identity"] = "controlled_test_identity"
    third_party_account: Literal[False] = False
    secret_material_absent: Literal[True] = True

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            not self.valid_from <= self.issued_at < self.valid_until
            or self.allowed_purposes
            != tuple(sorted(set(self.allowed_purposes), key=lambda item: item.value))
            or self.role_refs != tuple(sorted(set(self.role_refs)))
            or self.third_party_account
            or not self.secret_material_absent
            or self.record_id
            != canonical_digest(self.model_dump(mode="python", exclude={"record_id"}))
        ):
            raise ValueError("Test Identity Record binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> TestIdentityRecord:
        normalized = dict(values)
        normalized["allowed_purposes"] = tuple(
            sorted(set(values["allowed_purposes"]), key=lambda item: item.value)
        )
        normalized["role_refs"] = tuple(sorted(set(values["role_refs"])))
        expanded = cls.model_construct(record_id="0" * 64, **normalized).model_dump(
            mode="python", exclude={"record_id"}
        )
        return cls(record_id=canonical_digest(expanded), **expanded)


class TestIdentityRevocation(DomainModel):
    revocation_id: Digest
    record_id: Digest
    identity_ref: Digest
    reason_digest: Digest
    revoked_at: AwareDatetime
    credential_material_accessed: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.credential_material_accessed
            or self.revocation_id
            != canonical_digest(self.model_dump(mode="python", exclude={"revocation_id"}))
        ):
            raise ValueError("Test Identity Revocation binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> TestIdentityRevocation:
        expanded = cls.model_construct(revocation_id="0" * 64, **values).model_dump(
            mode="python", exclude={"revocation_id"}
        )
        return cls(revocation_id=canonical_digest(expanded), **expanded)


class TestIdentityAdmissionLimits(DomainModel):
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)
    max_session_uses: Literal[1] = 1


class TestIdentityAdmissionPlan(DomainModel):
    plan_id: Digest
    record_id: Digest
    identity_ref: Digest
    credential_ref: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    target_id: UUID
    target_digest: Digest
    purposes: Annotated[
        tuple[TestIdentityPurpose, ...], Field(min_length=1, max_length=3)
    ]
    role_refs: Annotated[tuple[RoleReference, ...], Field(min_length=1, max_length=32)]
    limits: TestIdentityAdmissionLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    admission_expires_at: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    credential_material_present: Literal[False] = False
    authentication_authorized: Literal[False] = False
    session_authorized: Literal[False] = False
    state_change_authorized: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.purposes
            != tuple(sorted(set(self.purposes), key=lambda item: item.value))
            or self.role_refs != tuple(sorted(set(self.role_refs)))
            or not self.created_at < self.deadline <= self.admission_expires_at
            or self.credential_material_present
            or self.authentication_authorized
            or self.session_authorized
            or self.state_change_authorized
            or self.plan_id
            != canonical_digest(self.model_dump(mode="python", exclude={"plan_id"}))
        ):
            raise ValueError("Test Identity Admission Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> TestIdentityAdmissionPlan:
        normalized = dict(values)
        normalized["purposes"] = tuple(
            sorted(set(values["purposes"]), key=lambda item: item.value)
        )
        normalized["role_refs"] = tuple(sorted(set(values["role_refs"])))
        expanded = cls.model_construct(plan_id="0" * 64, **normalized).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


class TestIdentityAdmission(DomainModel):
    admission_id: Digest
    plan_id: Digest
    record_id: Digest
    identity_ref: Digest
    credential_ref: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    target_id: UUID
    target_digest: Digest
    purposes: Annotated[
        tuple[TestIdentityPurpose, ...], Field(min_length=1, max_length=3)
    ]
    role_refs: Annotated[tuple[RoleReference, ...], Field(min_length=1, max_length=32)]
    required_approvals: Annotated[
        tuple[ApprovalAction, ...], Field(min_length=1, max_length=2)
    ]
    admitted_at: AwareDatetime
    expires_at: AwareDatetime
    max_session_uses: Literal[1] = 1
    credential_access_authorized: Literal[False] = False
    authentication_authorized: Literal[False] = False
    session_authorized: Literal[False] = False
    state_change_authorized: Literal[False] = False
    third_party_account_authorized: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.purposes
            != tuple(sorted(set(self.purposes), key=lambda item: item.value))
            or self.role_refs != tuple(sorted(set(self.role_refs)))
            or self.required_approvals
            != tuple(sorted(set(self.required_approvals), key=lambda item: item.value))
            or not self.admitted_at < self.expires_at
            or self.credential_access_authorized
            or self.authentication_authorized
            or self.session_authorized
            or self.state_change_authorized
            or self.third_party_account_authorized
            or self.admission_id
            != canonical_digest(self.model_dump(mode="python", exclude={"admission_id"}))
        ):
            raise ValueError("Test Identity Admission binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> TestIdentityAdmission:
        normalized = dict(values)
        for name in ("purposes", "required_approvals"):
            normalized[name] = tuple(
                sorted(set(values[name]), key=lambda item: item.value)
            )
        normalized["role_refs"] = tuple(sorted(set(values["role_refs"])))
        expanded = cls.model_construct(
            admission_id="0" * 64, **normalized
        ).model_dump(mode="python", exclude={"admission_id"})
        return cls(admission_id=canonical_digest(expanded), **expanded)


class TestIdentityAdmissionOutcome(DomainModel):
    outcome_id: Digest
    plan_id: Digest
    admission_id: Digest
    attempt: int = Field(ge=1, le=3)
    completed_at: AwareDatetime
    credential_material_acquired: Literal[False] = False
    secret_material_persisted: Literal[False] = False
    session_created: Literal[False] = False
    cleanup_complete: Literal[True] = True

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.credential_material_acquired
            or self.secret_material_persisted
            or self.session_created
            or not self.cleanup_complete
            or self.outcome_id
            != canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        ):
            raise ValueError("Test Identity Admission Outcome binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> TestIdentityAdmissionOutcome:
        expanded = cls.model_construct(outcome_id="0" * 64, **values).model_dump(
            mode="python", exclude={"outcome_id"}
        )
        return cls(outcome_id=canonical_digest(expanded), **expanded)
