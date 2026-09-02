"""Typed contracts for an authorized local-project pilot readiness gate."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.analyzers.models import SourceGraph, source_graph_digest
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, DomainModel, Scope, TargetSnapshot
from vulnloom.hypotheses.models import CandidateSet, candidate_set_digest

from .local_source import LocalSourceEffectCounters
from .local_source_robustness import (
    LocalSourceRobustnessProfile,
    LocalSourceRobustnessResult,
)
from .models import BenchmarkGateStatus, Code, Digest


class PilotHumanGate(StrEnum):
    CANDIDATE_SELECTION = "candidate_selection"
    VALIDATION_INTAKE = "validation_intake"
    CRITIC_INTAKE = "critic_intake"
    FINDING_PROMOTION_INTAKE = "finding_promotion_intake"
    FINDING_PROMOTION_APPROVAL = "finding_promotion_approval"
    REPORT_INTAKE = "report_intake"
    REPORT_REVIEW_INTAKE = "report_review_intake"
    REPORT_REVIEW_APPROVAL = "report_review_approval"
    REPORT_EXPORT_INTAKE = "report_export_intake"
    REPORT_EXPORT_APPROVAL = "report_export_approval"


REQUIRED_PILOT_HUMAN_GATES = tuple(PilotHumanGate)


class PilotForbiddenCapability(StrEnum):
    AGENT_RUNNER_PARAMETERS = "agent_runner_parameters"
    AGENT_BROKER_PARAMETERS = "agent_broker_parameters"
    AUTOMATIC_VALIDATION = "automatic_validation"
    AUTOMATIC_CANDIDATE_MUTATION = "automatic_candidate_mutation"
    AUTOMATIC_APPROVAL = "automatic_approval"
    TARGET_BUILD = "target_build"
    PUBLIC_NETWORK = "public_network"
    SUBMISSION = "submission"


REQUIRED_PILOT_FORBIDDEN_CAPABILITIES = tuple(PilotForbiddenCapability)


class AuthorizedPilotManifest(DomainModel):
    pilot_manifest_id: Digest
    engagement_id: UUID
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    target_manifest_id: Digest
    artifact_id: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    scope_digest: Digest
    source_graph_id: Digest
    source_graph_digest: Digest
    analyzer_version: str = Field(min_length=1, max_length=128)
    candidate_set_id: Digest
    candidate_set_digest: Digest
    generator_version: str = Field(min_length=1, max_length=128)
    candidate_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=2_000)]
    source_file_count: int = Field(gt=0, le=1_000_000)
    source_total_bytes: int = Field(gt=0, le=10_737_418_240)
    required_human_gates: tuple[PilotHumanGate, ...] = REQUIRED_PILOT_HUMAN_GATES
    forbidden_capabilities: tuple[PilotForbiddenCapability, ...] = (
        REQUIRED_PILOT_FORBIDDEN_CAPABILITIES
    )
    selected_candidate_ids: Annotated[tuple[UUID, ...], Field(max_length=0)] = ()

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.pilot_manifest_id != authorized_pilot_manifest_digest(self):
            raise ValueError("AuthorizedPilotManifest content digest mismatch")
        if self.required_human_gates != REQUIRED_PILOT_HUMAN_GATES:
            raise ValueError("authorized pilot human gates cannot be changed")
        if self.forbidden_capabilities != REQUIRED_PILOT_FORBIDDEN_CAPABILITIES:
            raise ValueError("authorized pilot forbidden capabilities cannot be changed")
        if self.candidate_ids != tuple(sorted(set(self.candidate_ids), key=str)):
            raise ValueError("authorized pilot Candidate identities must be unique and sorted")
        return self

    @classmethod
    def create(
        cls,
        *,
        scope: Scope,
        snapshot: TargetSnapshot,
        graph: SourceGraph,
        candidate_set: CandidateSet,
    ) -> AuthorizedPilotManifest:
        if source_graph_digest(graph) != graph.graph_id:
            raise ValueError("pilot SourceGraph content digest mismatch")
        if candidate_set_digest(candidate_set) != candidate_set.candidate_set_id:
            raise ValueError("pilot CandidateSet content digest mismatch")
        if (
            snapshot.target.engagement_id != scope.engagement_id
            or snapshot.target.target_id != graph.target_id
            or snapshot.target.target_id != candidate_set.target_id
            or snapshot.target.version != graph.target_version
            or snapshot.target.version != candidate_set.target_version
            or snapshot.manifest.manifest_id != graph.manifest_id
            or graph.scope_id != scope.scope_id
            or graph.scope_version != scope.version
            or candidate_set.scope_id != scope.scope_id
            or candidate_set.scope_version != scope.version
            or candidate_set.source_graph_id != graph.graph_id
        ):
            raise ValueError("pilot manifest provenance mismatch")
        candidate_ids = tuple(
            sorted((item.candidate_id for item in candidate_set.candidates), key=str)
        )
        values = {
            "engagement_id": scope.engagement_id,
            "target_id": snapshot.target.target_id,
            "target_version": snapshot.target.version,
            "target_manifest_id": snapshot.manifest.manifest_id,
            "artifact_id": snapshot.artifact.artifact_id,
            "scope_id": scope.scope_id,
            "scope_version": scope.version,
            "scope_digest": canonical_digest(scope.model_dump(mode="python")),
            "source_graph_id": graph.graph_id,
            "source_graph_digest": canonical_digest(graph.model_dump(mode="python")),
            "analyzer_version": graph.analyzer_version,
            "candidate_set_id": candidate_set.candidate_set_id,
            "candidate_set_digest": canonical_digest(candidate_set.model_dump(mode="python")),
            "generator_version": candidate_set.generator_version,
            "candidate_ids": candidate_ids,
            "source_file_count": len(snapshot.manifest.files),
            "source_total_bytes": snapshot.manifest.total_size,
            "required_human_gates": REQUIRED_PILOT_HUMAN_GATES,
            "forbidden_capabilities": REQUIRED_PILOT_FORBIDDEN_CAPABILITIES,
            "selected_candidate_ids": (),
        }
        return cls(pilot_manifest_id=canonical_digest(values), **values)


def authorized_pilot_manifest_digest(value: AuthorizedPilotManifest) -> str:
    return canonical_digest(value.model_dump(mode="python", exclude={"pilot_manifest_id"}))


class AuthorizedPilotReadinessPolicy(DomainModel):
    required_human_gates: tuple[PilotHumanGate, ...] = REQUIRED_PILOT_HUMAN_GATES
    forbidden_capabilities: tuple[PilotForbiddenCapability, ...] = (
        REQUIRED_PILOT_FORBIDDEN_CAPABILITIES
    )
    max_source_files: int = Field(default=10_000, ge=10_000, le=10_000)
    max_source_bytes: int = Field(default=209_715_200, ge=209_715_200, le=209_715_200)
    max_candidates: int = Field(default=2_000, ge=2_000, le=2_000)
    require_quality_pass: bool = True
    require_proposed_candidates: bool = True
    max_forbidden_effects: int = Field(default=0, ge=0, le=0)

    @model_validator(mode="after")
    def non_weakenable(self) -> Self:
        if (
            self.required_human_gates != REQUIRED_PILOT_HUMAN_GATES
            or self.forbidden_capabilities != REQUIRED_PILOT_FORBIDDEN_CAPABILITIES
            or not self.require_quality_pass
            or not self.require_proposed_candidates
        ):
            raise ValueError("authorized pilot readiness policy cannot be weakened")
        return self


class AuthorizedPilotReadinessPlan(DomainModel):
    plan_id: Digest
    pilot_manifest_id: Digest
    pilot_manifest_digest: Digest
    quality_profile_id: Digest
    quality_profile_digest: Digest
    quality_result_id: Digest
    quality_result_digest: Digest
    policy: AuthorizedPilotReadinessPolicy
    effects: LocalSourceEffectCounters
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.deadline <= self.created_at:
            raise ValueError("authorized pilot readiness window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("authorized pilot readiness key contains NUL")
        if self.plan_id != authorized_pilot_readiness_plan_digest(self):
            raise ValueError("AuthorizedPilotReadinessPlan content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        manifest: AuthorizedPilotManifest,
        quality_profile: LocalSourceRobustnessProfile,
        quality_result: LocalSourceRobustnessResult,
        policy: AuthorizedPilotReadinessPolicy,
        effects: LocalSourceEffectCounters,
        created_at: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AuthorizedPilotReadinessPlan:
        values = {
            "pilot_manifest_id": manifest.pilot_manifest_id,
            "pilot_manifest_digest": canonical_digest(manifest.model_dump(mode="python")),
            "quality_profile_id": quality_profile.profile_id,
            "quality_profile_digest": canonical_digest(quality_profile.model_dump(mode="python")),
            "quality_result_id": quality_result.result_id,
            "quality_result_digest": canonical_digest(quality_result.model_dump(mode="python")),
            "policy": policy,
            "effects": effects,
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {
            **values,
            "policy": policy.model_dump(mode="python"),
            "effects": effects.model_dump(mode="python"),
        }
        return cls(plan_id=canonical_digest(digest_values), **values)


def authorized_pilot_readiness_plan_digest(value: AuthorizedPilotReadinessPlan) -> str:
    return canonical_digest(value.model_dump(mode="python", exclude={"plan_id"}))


class AuthorizedPilotReadinessMetrics(DomainModel):
    source_file_count: int = Field(ge=0)
    source_total_bytes: int = Field(ge=0)
    candidate_count: int = Field(ge=0)
    proposed_candidate_count: int = Field(ge=0)
    human_gate_count: int = Field(ge=0)
    forbidden_capability_count: int = Field(ge=0)
    forbidden_effect_count: int = Field(ge=0)


class AuthorizedPilotReadinessViolation(DomainModel):
    code: Code
    actual: int = Field(ge=0)
    limit: int = Field(ge=0)


class AuthorizedPilotReadinessResult(DomainModel):
    result_id: Digest
    plan_id: Digest
    pilot_manifest_id: Digest
    metrics: AuthorizedPilotReadinessMetrics
    gate_status: BenchmarkGateStatus
    violations: tuple[AuthorizedPilotReadinessViolation, ...]
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.result_id != authorized_pilot_readiness_result_digest(self):
            raise ValueError("AuthorizedPilotReadinessResult content digest mismatch")
        if bool(self.violations) != (self.gate_status is BenchmarkGateStatus.FAILED):
            raise ValueError("authorized pilot readiness status mismatch")
        return self


def authorized_pilot_readiness_result_digest(value: AuthorizedPilotReadinessResult) -> str:
    return canonical_digest(value.model_dump(mode="python", exclude={"result_id"}))


class AuthorizedPilotReadinessArtifact(DomainModel):
    result_digest: Digest
    json_sha256: Digest
    markdown_sha256: Digest
    json_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/result\.json$")
    markdown_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/result\.md$")

    @model_validator(mode="after")
    def references_match(self) -> Self:
        prefix = f"objects/{self.result_digest}"
        if self.json_ref != f"{prefix}/result.json" or self.markdown_ref != (f"{prefix}/result.md"):
            raise ValueError("authorized pilot artifact references do not match identity")
        return self


class AuthorizedPilotReadinessOutcome(DomainModel):
    plan_id: Digest
    result: AuthorizedPilotReadinessResult
    artifact: AuthorizedPilotReadinessArtifact

    @model_validator(mode="after")
    def bound(self) -> Self:
        if self.plan_id != self.result.plan_id:
            raise ValueError("authorized pilot outcome plan mismatch")
        if self.artifact.result_digest != canonical_digest(self.result.model_dump(mode="python")):
            raise ValueError("authorized pilot outcome artifact mismatch")
        return self


def pilot_effect_count(effects: LocalSourceEffectCounters) -> int:
    return sum(effects.model_dump(mode="python").values())


def proposed_candidate_count(candidate_set: CandidateSet) -> int:
    return sum(item.state is CandidateState.PROPOSED for item in candidate_set.candidates)
