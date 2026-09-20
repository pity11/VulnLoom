"""Typed R11 contracts for deterministic, Evidence-backed attack-path reports."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .attack_models import (
    AttackActionKind,
    AttackActionOutcome,
    AttackChainStatus,
    AttackImpact,
    Digest,
)
from .models import RedTeamPhase


class AttackDetectionKind(StrEnum):
    SESSION_CREATION = "session_creation"
    SESSION_USE = "session_use"
    PROTECTED_RESOURCE_ACCESS = "protected_resource_access"
    SESSION_REVOCATION = "session_revocation"


class AttackDefensiveControl(StrEnum):
    SESSION_ISSUANCE_POLICY = "session_issuance_policy"
    SESSION_ACTIVITY_MONITORING = "session_activity_monitoring"
    OBJECT_LEVEL_AUTHORIZATION = "object_level_authorization"
    SESSION_REVOCATION_ASSURANCE = "session_revocation_assurance"


class AttackReportState(StrEnum):
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


DETECTION_FOR_ACTION = {
    AttackActionKind.INITIAL_ACCESS_ATTEMPT: AttackDetectionKind.SESSION_CREATION,
    AttackActionKind.VERIFY_TEST_SESSION: AttackDetectionKind.SESSION_USE,
    AttackActionKind.VERIFY_OBJECTIVE: AttackDetectionKind.PROTECTED_RESOURCE_ACCESS,
    AttackActionKind.CLEANUP_TEST_SESSION: AttackDetectionKind.SESSION_REVOCATION,
}

CONTROL_FOR_DETECTION = {
    AttackDetectionKind.SESSION_CREATION: AttackDefensiveControl.SESSION_ISSUANCE_POLICY,
    AttackDetectionKind.SESSION_USE: AttackDefensiveControl.SESSION_ACTIVITY_MONITORING,
    AttackDetectionKind.PROTECTED_RESOURCE_ACCESS: (
        AttackDefensiveControl.OBJECT_LEVEL_AUTHORIZATION
    ),
    AttackDetectionKind.SESSION_REVOCATION: (AttackDefensiveControl.SESSION_REVOCATION_ASSURANCE),
}


class AttackPathStep(DomainModel):
    step_id: Digest
    ordinal: int = Field(ge=1, le=32)
    action_id: Digest
    kind: AttackActionKind
    phase: RedTeamPhase
    impact: AttackImpact
    outcome: AttackActionOutcome
    observation_id: Digest
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.outcome is not AttackActionOutcome.SUCCEEDED:
            raise ValueError("Attack Path Report only accepts successful path steps")
        if self.step_id != canonical_digest(self.model_dump(mode="python", exclude={"step_id"})):
            raise ValueError("Attack Path step digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackPathStep:
        expanded = cls.model_construct(step_id="0" * 64, **values).model_dump(
            mode="python", exclude={"step_id"}
        )
        return cls(step_id=canonical_digest(expanded), **expanded)


class AttackDetectionOpportunity(DomainModel):
    opportunity_id: Digest
    action_id: Digest
    kind: AttackDetectionKind
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.opportunity_id != canonical_digest(
            self.model_dump(mode="python", exclude={"opportunity_id"})
        ):
            raise ValueError("Detection Opportunity digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackDetectionOpportunity:
        expanded = cls.model_construct(opportunity_id="0" * 64, **values).model_dump(
            mode="python", exclude={"opportunity_id"}
        )
        return cls(opportunity_id=canonical_digest(expanded), **expanded)


class AttackDefensiveImprovement(DomainModel):
    improvement_id: Digest
    control: AttackDefensiveControl
    opportunity_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.improvement_id != canonical_digest(
            self.model_dump(mode="python", exclude={"improvement_id"})
        ):
            raise ValueError("Defensive Improvement digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackDefensiveImprovement:
        expanded = cls.model_construct(improvement_id="0" * 64, **values).model_dump(
            mode="python", exclude={"improvement_id"}
        )
        return cls(improvement_id=canonical_digest(expanded), **expanded)


class AttackChainReportPlan(DomainModel):
    report_plan_id: Digest
    chain_plan_id: Digest
    graph_id: Digest
    source_checkpoint_id: Digest
    target_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    prepared_by: str = Field(pattern=r"^operator:[a-zA-Z0-9._-]{1,200}$")
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    max_attempts: int = Field(default=3, ge=1, le=3)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.deadline <= self.created_at:
            raise ValueError("Attack Path Report window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Attack Path Report idempotency key contains NUL")
        if self.report_plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"report_plan_id"})
        ):
            raise ValueError("Attack Path Report plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackChainReportPlan:
        expanded = cls.model_construct(report_plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"report_plan_id"}
        )
        return cls(report_plan_id=canonical_digest(expanded), **expanded)


class AttackChainReport(DomainModel):
    report_id: Digest
    report_plan_id: Digest
    chain_plan_id: Digest
    graph_id: Digest
    source_checkpoint_id: Digest
    target_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    chain_status: AttackChainStatus
    objective_observation_id: Digest
    steps: Annotated[tuple[AttackPathStep, ...], Field(min_length=3, max_length=32)]
    detection_opportunities: Annotated[
        tuple[AttackDetectionOpportunity, ...], Field(min_length=3, max_length=32)
    ]
    defensive_improvements: Annotated[
        tuple[AttackDefensiveImprovement, ...], Field(min_length=1, max_length=16)
    ]
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=256)]
    generated_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.chain_status is not AttackChainStatus.GOAL_REACHED:
            raise ValueError("Attack Path Report requires a successful cleaned chain")
        if tuple(step.ordinal for step in self.steps) != tuple(range(1, len(self.steps) + 1)):
            raise ValueError("Attack Path Report steps must be contiguous")
        if self.steps[-1].kind is not AttackActionKind.CLEANUP_TEST_SESSION:
            raise ValueError("Attack Path Report must end with Cleanup")
        objective_steps = tuple(
            step for step in self.steps if step.kind is AttackActionKind.VERIFY_OBJECTIVE
        )
        if (
            len(objective_steps) != 1
            or objective_steps[0].observation_id != self.objective_observation_id
        ):
            raise ValueError("Attack Path Report objective Evidence is inconsistent")
        step_by_action = {step.action_id: step for step in self.steps}
        if len(step_by_action) != len(self.steps):
            raise ValueError("Attack Path Report actions must be unique")
        opportunity_ids = {item.opportunity_id for item in self.detection_opportunities}
        if len(opportunity_ids) != len(self.detection_opportunities):
            raise ValueError("Detection Opportunities must be unique")
        if {item.action_id for item in self.detection_opportunities} != set(step_by_action):
            raise ValueError("Detection Opportunities must cover every path step")
        for item in self.detection_opportunities:
            step = step_by_action.get(item.action_id)
            if (
                step is None
                or item.kind is not DETECTION_FOR_ACTION[step.kind]
                or item.evidence_refs != step.evidence_refs
            ):
                raise ValueError("Detection Opportunity Evidence is not on its path step")
        opportunity_by_id = {item.opportunity_id: item for item in self.detection_opportunities}
        covered_opportunities = {
            opportunity_id
            for item in self.defensive_improvements
            for opportunity_id in item.opportunity_ids
        }
        if (
            len(self.defensive_improvements) != len(opportunity_ids)
            or len({item.improvement_id for item in self.defensive_improvements})
            != len(self.defensive_improvements)
            or covered_opportunities != opportunity_ids
            or any(
                len(item.opportunity_ids) != 1
                or CONTROL_FOR_DETECTION[opportunity_by_id[item.opportunity_ids[0]].kind]
                is not item.control
                for item in self.defensive_improvements
            )
        ):
            raise ValueError("Defensive Improvement references an unknown opportunity")
        expected_evidence = tuple(
            sorted({ref for step in self.steps for ref in step.evidence_refs})
        )
        if self.evidence_refs != expected_evidence:
            raise ValueError("Attack Path Report Evidence index is incomplete")
        if self.report_id != canonical_digest(
            self.model_dump(mode="python", exclude={"report_id"})
        ):
            raise ValueError("Attack Path Report digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackChainReport:
        expanded = cls.model_construct(report_id="0" * 64, **values).model_dump(
            mode="python", exclude={"report_id"}
        )
        return cls(report_id=canonical_digest(expanded), **expanded)


class AttackChainReportArtifact(DomainModel):
    report_id: Digest
    json_sha256: Digest
    markdown_sha256: Digest
    json_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/attack-report\.json$")
    markdown_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/attack-report\.md$")

    @model_validator(mode="after")
    def bound(self) -> Self:
        prefix = f"objects/{self.report_id}/attack-report"
        if self.json_ref != f"{prefix}.json" or self.markdown_ref != f"{prefix}.md":
            raise ValueError("Attack Path Report artifact references are invalid")
        return self


class AttackChainReportOutcome(DomainModel):
    report_plan_id: Digest
    state: AttackReportState
    attempt: int = Field(ge=1, le=3)
    chain_plan_id: Digest
    report: AttackChainReport | None = None
    artifact: AttackChainReportArtifact | None = None
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    cleanup_complete: bool
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def terminal_shape(self) -> Self:
        completed = self.state is AttackReportState.COMPLETED
        if completed != (self.report is not None and self.artifact is not None):
            raise ValueError("Only completed Attack Path Report outcomes contain artifacts")
        if self.report is not None and (
            self.report.report_plan_id != self.report_plan_id
            or self.artifact is None
            or self.artifact.report_id != self.report.report_id
        ):
            raise ValueError("Attack Path Report outcome binding is invalid")
        if not self.cleanup_complete:
            raise ValueError("Attack Path Report outcome requires cleanup proof")
        return self
