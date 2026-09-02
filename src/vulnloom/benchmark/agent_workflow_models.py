"""Typed contracts for the closed Agent workflow regression gate."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    CandidateState,
    CriticVerdict,
    DomainModel,
    ReportReviewStatus,
    ValidationResult,
)

from .models import BenchmarkGateStatus, Code, Digest, Ratio


class AgentWorkflowStage(StrEnum):
    SESSION_AUDIT = "session_audit"
    VALIDATION_INTAKE = "validation_intake"
    VALIDATION_OUTCOME = "validation_outcome"
    CRITIC_INTAKE = "critic_intake"
    CRITIC_OUTCOME = "critic_outcome"
    FINDING_INTAKE = "finding_intake"
    FINDING_PROMOTION = "finding_promotion"
    REPORT_INTAKE = "report_intake"
    REPORT_DRAFT = "report_draft"
    REPORT_REVIEW_INTAKE = "report_review_intake"
    REPORT_REVIEW = "report_review"
    REPORT_EXPORT_INTAKE = "report_export_intake"
    REPORT_EXPORT = "report_export"


REQUIRED_AGENT_WORKFLOW_STAGES = tuple(AgentWorkflowStage)


class AgentWorkflowCheckpoint(DomainModel):
    stage: AgentWorkflowStage
    object_id: Digest
    object_digest: Digest


class AgentWorkflowEffectCounters(DomainModel):
    provider_attempts: int = Field(ge=0)
    broker_calls: int = Field(ge=0)
    runner_calls: int = Field(ge=0)
    target_requests: int = Field(ge=0)


class AgentWorkflowRegressionObservation(DomainModel):
    observation_id: Digest
    checkpoints: Annotated[
        tuple[AgentWorkflowCheckpoint, ...], Field(min_length=1, max_length=64)
    ]
    proposed_candidate_state: CandidateState
    critic_candidate_state: CandidateState
    promoted_candidate_state: CandidateState
    validation_result: ValidationResult
    critic_verdict: CriticVerdict
    draft_report_status: ReportReviewStatus
    reviewed_report_status: ReportReviewStatus
    exported_report_status: ReportReviewStatus
    evidence_refs: Annotated[tuple[Digest, ...], Field(max_length=256)] = ()
    human_decision_digests: Annotated[tuple[Digest, ...], Field(max_length=32)] = ()
    approval_digests: Annotated[tuple[Digest, ...], Field(max_length=32)] = ()
    validation_effects: AgentWorkflowEffectCounters
    export_effects: AgentWorkflowEffectCounters
    public_network_calls: int = Field(default=0, ge=0)
    target_builds: int = Field(default=0, ge=0)
    automatic_approvals: int = Field(default=0, ge=0)
    submission_calls: int = Field(default=0, ge=0)
    exported_artifact_digest: Digest

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.observation_id != agent_workflow_observation_digest(self):
            raise ValueError("Agent workflow observation digest mismatch")
        if self.evidence_refs != tuple(sorted(set(self.evidence_refs))):
            raise ValueError("Agent workflow Evidence refs must be unique and sorted")
        if self.human_decision_digests != tuple(sorted(set(self.human_decision_digests))):
            raise ValueError("Agent workflow human decisions must be unique and sorted")
        if self.approval_digests != tuple(sorted(set(self.approval_digests))):
            raise ValueError("Agent workflow Approvals must be unique and sorted")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentWorkflowRegressionObservation:
        partial = cls.model_construct(observation_id="0" * 64, **values)
        digest_values = partial.model_dump(mode="python", exclude={"observation_id"})
        return cls(observation_id=canonical_digest(digest_values), **values)


def agent_workflow_observation_digest(
    observation: AgentWorkflowRegressionObservation,
) -> str:
    return canonical_digest(observation.model_dump(mode="python", exclude={"observation_id"}))


class AgentWorkflowRegressionPolicy(DomainModel):
    required_stages: tuple[AgentWorkflowStage, ...] = REQUIRED_AGENT_WORKFLOW_STAGES
    required_human_decisions: int = Field(default=6, ge=0, le=32)
    required_approvals: int = Field(default=3, ge=0, le=32)
    min_evidence_refs: int = Field(default=1, ge=0, le=256)
    max_control_plane_provider_delta: int = Field(default=0, ge=0)
    max_control_plane_broker_delta: int = Field(default=0, ge=0)
    max_control_plane_runner_delta: int = Field(default=0, ge=0)
    max_control_plane_target_delta: int = Field(default=0, ge=0)
    max_public_network_calls: int = Field(default=0, ge=0)
    max_target_builds: int = Field(default=0, ge=0)
    max_automatic_approvals: int = Field(default=0, ge=0)
    max_submission_calls: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def fixed_stage_contract(self) -> Self:
        if self.required_stages != REQUIRED_AGENT_WORKFLOW_STAGES:
            raise ValueError("Agent workflow stage policy cannot weaken the closed path")
        if self.required_human_decisions != 6 or self.required_approvals != 3:
            raise ValueError("Agent workflow human gates cannot be weakened")
        if self.min_evidence_refs < 1:
            raise ValueError("Agent workflow requires Evidence")
        if any(
            value != 0
            for value in (
                self.max_control_plane_provider_delta,
                self.max_control_plane_broker_delta,
                self.max_control_plane_runner_delta,
                self.max_control_plane_target_delta,
                self.max_public_network_calls,
                self.max_target_builds,
                self.max_automatic_approvals,
                self.max_submission_calls,
            )
        ):
            raise ValueError("Agent workflow forbidden-effect limits cannot be weakened")
        return self


class AgentWorkflowRegressionPlan(DomainModel):
    plan_id: Digest
    observation_id: Digest
    observation_digest: Digest
    policy: AgentWorkflowRegressionPolicy
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.deadline:
            raise ValueError("Agent workflow regression window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Agent workflow regression key contains NUL")
        if self.plan_id != agent_workflow_regression_plan_digest(self):
            raise ValueError("Agent workflow regression plan digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        observation: AgentWorkflowRegressionObservation,
        policy: AgentWorkflowRegressionPolicy,
        created_at: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AgentWorkflowRegressionPlan:
        values = {
            "observation_id": observation.observation_id,
            "observation_digest": canonical_digest(observation.model_dump(mode="python")),
            "policy": policy,
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {**values, "policy": policy.model_dump(mode="python")}
        return cls(plan_id=canonical_digest(digest_values), **values)


def agent_workflow_regression_plan_digest(plan: AgentWorkflowRegressionPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"plan_id"}))


class AgentWorkflowRegressionMetrics(DomainModel):
    stage_completeness: Ratio
    evidence_ref_count: int = Field(ge=0)
    human_decision_count: int = Field(ge=0)
    approval_count: int = Field(ge=0)
    provider_delta: int = Field(ge=0)
    broker_delta: int = Field(ge=0)
    runner_delta: int = Field(ge=0)
    target_delta: int = Field(ge=0)
    forbidden_effect_count: int = Field(ge=0)


class AgentWorkflowRegressionViolation(DomainModel):
    code: Code
    actual: float = Field(allow_inf_nan=False)
    limit: float = Field(allow_inf_nan=False)


class AgentWorkflowRegressionResult(DomainModel):
    result_id: UUID
    plan_id: Digest
    observation_id: Digest
    metrics: AgentWorkflowRegressionMetrics
    gate_status: BenchmarkGateStatus
    violations: tuple[AgentWorkflowRegressionViolation, ...]
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def deterministic(self) -> Self:
        expected = uuid5(NAMESPACE_URL, f"vulnloom:agent-workflow-regression:{self.plan_id}")
        if self.result_id != expected:
            raise ValueError("Agent workflow regression result identity mismatch")
        if bool(self.violations) != (self.gate_status is BenchmarkGateStatus.FAILED):
            raise ValueError("Agent workflow regression status mismatch")
        return self


class AgentWorkflowRegressionArtifact(DomainModel):
    result_digest: Digest
    json_sha256: Digest
    markdown_sha256: Digest
    json_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/result\.json$")
    markdown_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/result\.md$")

    @model_validator(mode="after")
    def references_match_identity(self) -> Self:
        prefix = f"objects/{self.result_digest}"
        if self.json_ref != f"{prefix}/result.json" or self.markdown_ref != (
            f"{prefix}/result.md"
        ):
            raise ValueError("Agent workflow artifact references do not match identity")
        return self


class AgentWorkflowRegressionOutcome(DomainModel):
    plan_id: Digest
    result: AgentWorkflowRegressionResult
    artifact: AgentWorkflowRegressionArtifact

    @model_validator(mode="after")
    def bound(self) -> Self:
        if self.plan_id != self.result.plan_id:
            raise ValueError("Agent workflow regression outcome plan mismatch")
        if self.artifact.result_digest != canonical_digest(
            self.result.model_dump(mode="python")
        ):
            raise ValueError("Agent workflow regression artifact mismatch")
        return self
