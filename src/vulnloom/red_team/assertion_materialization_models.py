"""Contracts for materializing bounded Assertions from a sealed GET."""

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
)
from .models import Digest


class EvidenceAssertionMaterializationState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


SENSITIVE_FIELD_NAMES = (
    "bank_account",
    "credit_card_number",
    "date_of_birth",
    "dob",
    "email",
    "email_address",
    "home_address",
    "national_id",
    "passport_number",
    "phone",
    "phone_number",
    "social_security_number",
    "ssn",
)
REDACTION_SENTINEL = "[REDACTED]"
SENSITIVE_ASSERTION_CLASSIFIER_DIGEST = canonical_digest(
    {
        "classifier": "sensitive-json-field-redaction-v1",
        "field_names": SENSITIVE_FIELD_NAMES,
        "redaction_sentinel": REDACTION_SENTINEL,
        "absence_verdict": EvidenceFactVerdict.INCONCLUSIVE,
    }
)


class EvidenceAssertionMaterializationLimits(DomainModel):
    max_document_bytes: int = Field(default=64 * 1024, ge=1, le=64 * 1024)
    max_nodes: int = Field(default=10_000, ge=1, le=20_000)
    max_depth: int = Field(default=32, ge=1, le=64)
    max_object_keys: int = Field(default=5_000, ge=1, le=10_000)
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class EvidenceAssertionMaterializationPlan(DomainModel):
    plan_id: Digest
    requirement_id: Digest
    endpoint_recon_plan_id: Digest
    flow_plan_id: Digest
    source_checkpoint_id: Digest
    source_observation_id: Digest
    web_response_snapshot_id: Digest
    evidence_ref: Digest
    response_body_sha256: Digest
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    classifier_digest: Literal[SENSITIVE_ASSERTION_CLASSIFIER_DIGEST] = (
        SENSITIVE_ASSERTION_CLASSIFIER_DIGEST
    )
    limits: EvidenceAssertionMaterializationLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.deadline <= self.created_at
            or self.classifier_digest != SENSITIVE_ASSERTION_CLASSIFIER_DIGEST
            or self.plan_id
            != canonical_digest(self.model_dump(mode="python", exclude={"plan_id"}))
        ):
            raise ValueError("Evidence Assertion materialization plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> EvidenceAssertionMaterializationPlan:
        expanded = cls.model_construct(plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


class EvidenceAssertionMaterialization(DomainModel):
    materialization_id: Digest
    plan_id: Digest
    requirement_id: Digest
    source_observation_id: Digest
    web_response_snapshot_id: Digest
    evidence_ref: Digest
    response_body_sha256: Digest
    classifier_digest: Literal[SENSITIVE_ASSERTION_CLASSIFIER_DIGEST]
    assertions: Annotated[tuple[EvidenceAssertion, ...], Field(min_length=6, max_length=6)]
    inspected_node_count: int = Field(ge=1, le=20_000)
    matched_field_count: int = Field(ge=0, le=10_000)
    sensitive_data_presence: EvidenceFactVerdict
    raw_values_retained: Literal[False] = False
    field_names_retained: Literal[False] = False
    request_execution_authorized: Literal[False] = False
    candidate_proposal_eligible: Literal[False] = False
    finding_authorized: Literal[False] = False
    materialized_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        assertions = {item.fact: item for item in self.assertions}
        required = {
            EvidenceFactKind.SEALED_GET_SUCCEEDED,
            EvidenceFactKind.UNAUTHENTICATED_REQUEST_PROVEN,
            EvidenceFactKind.SENSITIVE_DATA_CLASS_PRESENT,
            EvidenceFactKind.REDACTION_BOUNDARY_PROVEN,
            EvidenceFactKind.NO_STATE_CHANGE_PROVEN,
            EvidenceFactKind.NO_TEST_ARTIFACTS_REMAIN,
        }
        fixed_supported = required - {EvidenceFactKind.SENSITIVE_DATA_CLASS_PRESENT}
        producers = {
            EvidenceFactKind.SEALED_GET_SUCCEEDED: "control-plane:sealed-get-v1",
            EvidenceFactKind.UNAUTHENTICATED_REQUEST_PROVEN: (
                "control-plane:sealed-get-v1"
            ),
            EvidenceFactKind.SENSITIVE_DATA_CLASS_PRESENT: (
                "control-plane:sealed-get-v1"
            ),
            EvidenceFactKind.REDACTION_BOUNDARY_PROVEN: (
                "validator:sealed-get-materializer-v1"
            ),
            EvidenceFactKind.NO_STATE_CHANGE_PROVEN: "control-plane:sealed-get-v1",
            EvidenceFactKind.NO_TEST_ARTIFACTS_REMAIN: (
                "control-plane:sealed-get-v1"
            ),
        }
        if (
            tuple(item.assertion_id for item in self.assertions)
            != tuple(sorted({item.assertion_id for item in self.assertions}))
            or set(assertions) != required
            or any(
                assertions[fact].verdict is not EvidenceFactVerdict.SUPPORTED
                for fact in fixed_supported
            )
            or assertions[
                EvidenceFactKind.SENSITIVE_DATA_CLASS_PRESENT
            ].verdict
            is not self.sensitive_data_presence
            or self.sensitive_data_presence
            not in {
                EvidenceFactVerdict.SUPPORTED,
                EvidenceFactVerdict.INCONCLUSIVE,
            }
            or (self.matched_field_count > 0)
            != (self.sensitive_data_presence is EvidenceFactVerdict.SUPPORTED)
            or self.matched_field_count > self.inspected_node_count
            or any(
                item.requirement_id != self.requirement_id
                or item.evidence_refs != (self.evidence_ref,)
                or item.context_id != self.plan_id
                or item.producer_ref != producers[item.fact]
                for item in self.assertions
            )
            or self.raw_values_retained
            or self.field_names_retained
            or self.request_execution_authorized
            or self.candidate_proposal_eligible
            or self.finding_authorized
            or self.materialization_id
            != canonical_digest(
                self.model_dump(mode="python", exclude={"materialization_id"})
            )
        ):
            raise ValueError("Evidence Assertion materialization binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> EvidenceAssertionMaterialization:
        expanded = cls.model_construct(
            materialization_id="0" * 64, **values
        ).model_dump(mode="python", exclude={"materialization_id"})
        return cls(materialization_id=canonical_digest(expanded), **expanded)


class EvidenceAssertionMaterializationOutcome(DomainModel):
    plan_id: Digest
    materialization: EvidenceAssertionMaterialization
    attempt: int = Field(ge=1, le=3)
    cleanup_complete: Literal[True] = True

    @model_validator(mode="after")
    def bound(self) -> Self:
        if self.materialization.plan_id != self.plan_id:
            raise ValueError("Evidence Assertion materialization outcome binding is invalid")
        return self
