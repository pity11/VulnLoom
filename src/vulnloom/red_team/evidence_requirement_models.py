"""Versioned evidence contracts for bounded Web/API vulnerability classes."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .models import Digest


class VulnerabilityClass(StrEnum):
    UNAUTHENTICATED_SENSITIVE_DATA_EXPOSURE = (
        "unauthenticated_sensitive_data_exposure"
    )


class EvidenceRequirementStage(StrEnum):
    OBSERVATION = "observation"
    VALIDATION = "validation"
    CRITIC = "critic"
    CLEANUP = "cleanup"


class EvidenceFactKind(StrEnum):
    SEALED_GET_SUCCEEDED = "sealed_get_succeeded"
    UNAUTHENTICATED_REQUEST_PROVEN = "unauthenticated_request_proven"
    SENSITIVE_DATA_CLASS_PRESENT = "sensitive_data_class_present"
    INDEPENDENT_REPLAY_MATCHED = "independent_replay_matched"
    REDACTION_BOUNDARY_PROVEN = "redaction_boundary_proven"
    ACCESS_CONTROL_ENFORCED = "access_control_enforced"
    PUBLIC_BY_DESIGN = "public_by_design"
    SYNTHETIC_OR_PLACEHOLDER_DATA = "synthetic_or_placeholder_data"
    ENVIRONMENT_OR_VERSION_MISMATCH = "environment_or_version_mismatch"
    NO_STATE_CHANGE_PROVEN = "no_state_change_proven"
    NO_TEST_ARTIFACTS_REMAIN = "no_test_artifacts_remain"


class EvidenceFactVerdict(StrEnum):
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class EvidenceAssessmentVerdict(StrEnum):
    CANDIDATE_ELIGIBLE = "candidate_eligible"
    NEGATIVE = "negative"
    INCONCLUSIVE = "inconclusive"


class EvidenceAssessmentState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


_OBSERVATION_FACTS = (
    EvidenceFactKind.SEALED_GET_SUCCEEDED,
    EvidenceFactKind.UNAUTHENTICATED_REQUEST_PROVEN,
    EvidenceFactKind.SENSITIVE_DATA_CLASS_PRESENT,
)
_VALIDATION_FACTS = (
    EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED,
    EvidenceFactKind.REDACTION_BOUNDARY_PROVEN,
)
_CRITIC_FACTS = (
    EvidenceFactKind.ACCESS_CONTROL_ENFORCED,
    EvidenceFactKind.PUBLIC_BY_DESIGN,
    EvidenceFactKind.SYNTHETIC_OR_PLACEHOLDER_DATA,
    EvidenceFactKind.ENVIRONMENT_OR_VERSION_MISMATCH,
)
_CLEANUP_FACTS = (
    EvidenceFactKind.NO_STATE_CHANGE_PROVEN,
    EvidenceFactKind.NO_TEST_ARTIFACTS_REMAIN,
)
_FACT_STAGE = {
    **{item: EvidenceRequirementStage.OBSERVATION for item in _OBSERVATION_FACTS},
    **{item: EvidenceRequirementStage.VALIDATION for item in _VALIDATION_FACTS},
    **{item: EvidenceRequirementStage.CRITIC for item in _CRITIC_FACTS},
    **{item: EvidenceRequirementStage.CLEANUP for item in _CLEANUP_FACTS},
}


class VulnerabilityEvidenceRequirement(DomainModel):
    requirement_id: Digest
    requirement_version: Literal[1] = 1
    vulnerability_class: Literal[
        VulnerabilityClass.UNAUTHENTICATED_SENSITIVE_DATA_EXPOSURE
    ]
    cwe: Literal["CWE-200"] = "CWE-200"
    impact_class: Literal["read_only"] = "read_only"
    observation_facts: tuple[EvidenceFactKind, ...]
    validation_facts: tuple[EvidenceFactKind, ...]
    counterevidence_facts: tuple[EvidenceFactKind, ...]
    cleanup_facts: tuple[EvidenceFactKind, ...]
    candidate_only: Literal[True] = True
    finding_authorized: Literal[False] = False
    test_execution_authorized: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.observation_facts != _OBSERVATION_FACTS
            or self.validation_facts != _VALIDATION_FACTS
            or self.counterevidence_facts != _CRITIC_FACTS
            or self.cleanup_facts != _CLEANUP_FACTS
            or not self.candidate_only
            or self.finding_authorized
            or self.test_execution_authorized
            or self.requirement_id
            != canonical_digest(
                self.model_dump(mode="python", exclude={"requirement_id"})
            )
        ):
            raise ValueError("vulnerability Evidence Requirement binding is invalid")
        return self

    @classmethod
    def create(cls) -> VulnerabilityEvidenceRequirement:
        values = {
            "requirement_version": 1,
            "vulnerability_class": (
                VulnerabilityClass.UNAUTHENTICATED_SENSITIVE_DATA_EXPOSURE
            ),
            "cwe": "CWE-200",
            "impact_class": "read_only",
            "observation_facts": _OBSERVATION_FACTS,
            "validation_facts": _VALIDATION_FACTS,
            "counterevidence_facts": _CRITIC_FACTS,
            "cleanup_facts": _CLEANUP_FACTS,
            "candidate_only": True,
            "finding_authorized": False,
            "test_execution_authorized": False,
        }
        return cls(requirement_id=canonical_digest(values), **values)


class EvidenceAssertion(DomainModel):
    assertion_id: Digest
    requirement_id: Digest
    stage: EvidenceRequirementStage
    fact: EvidenceFactKind
    verdict: EvidenceFactVerdict
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=16)]
    producer_ref: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9:._-]{0,127}$",
    )
    context_id: Digest
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            _FACT_STAGE[self.fact] is not self.stage
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or self.assertion_id
            != canonical_digest(
                self.model_dump(mode="python", exclude={"assertion_id"})
            )
        ):
            raise ValueError("Evidence Assertion binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> EvidenceAssertion:
        expanded = cls.model_construct(assertion_id="0" * 64, **values).model_dump(
            mode="python", exclude={"assertion_id"}
        )
        return cls(assertion_id=canonical_digest(expanded), **expanded)


class EvidenceAssessmentLimits(DomainModel):
    max_assertions: int = Field(default=11, ge=1, le=32)
    max_evidence_refs: int = Field(default=64, ge=1, le=256)
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class EvidenceAssessmentPlan(DomainModel):
    plan_id: Digest
    requirement: VulnerabilityEvidenceRequirement
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    assertions: Annotated[tuple[EvidenceAssertion, ...], Field(min_length=1, max_length=32)]
    limits: EvidenceAssessmentLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        assertion_ids = tuple(item.assertion_id for item in self.assertions)
        if (
            self.deadline <= self.created_at
            or assertion_ids != tuple(sorted(set(assertion_ids)))
            or any(
                item.requirement_id != self.requirement.requirement_id
                for item in self.assertions
            )
            or self.plan_id
            != canonical_digest(self.model_dump(mode="python", exclude={"plan_id"}))
        ):
            raise ValueError("Evidence Assessment Plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> EvidenceAssessmentPlan:
        expanded = cls.model_construct(plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


class EvidenceAssessment(DomainModel):
    assessment_id: Digest
    plan_id: Digest
    requirement_id: Digest
    verdict: EvidenceAssessmentVerdict
    satisfied_facts: tuple[EvidenceFactKind, ...]
    counterevidence_facts: tuple[EvidenceFactKind, ...]
    unresolved_facts: tuple[EvidenceFactKind, ...]
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=256)]
    cleanup_requirement_satisfied: bool
    candidate_proposal_eligible: bool
    finding_authorized: Literal[False] = False
    test_execution_authorized: Literal[False] = False
    assessed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        collections = (
            self.satisfied_facts,
            self.counterevidence_facts,
            self.unresolved_facts,
        )
        all_facts = tuple(item for collection in collections for item in collection)
        eligible = self.verdict is EvidenceAssessmentVerdict.CANDIDATE_ELIGIBLE
        negative = self.verdict is EvidenceAssessmentVerdict.NEGATIVE
        all_required = {
            *_OBSERVATION_FACTS,
            *_VALIDATION_FACTS,
            *_CRITIC_FACTS,
            *_CLEANUP_FACTS,
        }
        cleanup_satisfied = set(_CLEANUP_FACTS) <= set(self.satisfied_facts)
        if (
            any(
                collection
                != tuple(sorted(set(collection), key=lambda item: item.value))
                for collection in collections
            )
            or len(all_facts) != len(set(all_facts))
            or not set(all_facts) <= all_required
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or eligible != self.candidate_proposal_eligible
            or cleanup_satisfied != self.cleanup_requirement_satisfied
            or (
                eligible
                and (
                    set(self.satisfied_facts) != all_required
                    or self.counterevidence_facts
                    or self.unresolved_facts
                )
            )
            or (negative != bool(self.counterevidence_facts))
            or (
                self.verdict is EvidenceAssessmentVerdict.INCONCLUSIVE
                and not self.unresolved_facts
            )
            or self.finding_authorized
            or self.test_execution_authorized
            or self.assessment_id
            != canonical_digest(
                self.model_dump(mode="python", exclude={"assessment_id"})
            )
        ):
            raise ValueError("Evidence Assessment binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> EvidenceAssessment:
        expanded = cls.model_construct(assessment_id="0" * 64, **values).model_dump(
            mode="python", exclude={"assessment_id"}
        )
        return cls(assessment_id=canonical_digest(expanded), **expanded)


class EvidenceAssessmentOutcome(DomainModel):
    plan_id: Digest
    assessment: EvidenceAssessment
    attempt: int = Field(ge=1, le=3)
    cleanup_complete: Literal[True] = True

    @model_validator(mode="after")
    def bound(self) -> Self:
        if self.assessment.plan_id != self.plan_id:
            raise ValueError("Evidence Assessment Outcome binding is invalid")
        return self
