"""Typed, content-addressed contracts for offline benchmark evaluation."""

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
    ValidationResult,
)

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Ratio = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
Code = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")]


class BenchmarkSource(StrEnum):
    LOCAL_FIXTURE = "local_fixture"
    BOUNTYBENCH_SNAPSHOT = "bountybench_snapshot"
    AUTOPENBENCH_SNAPSHOT = "autopenbench_snapshot"


class BenchmarkGateStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"


class GroundTruthFinding(DomainModel):
    truth_id: Digest
    cwe: Annotated[str, Field(pattern=r"^CWE-[1-9][0-9]*$")]
    duplicate_family: Digest


class BenchmarkCase(DomainModel):
    case_id: Digest
    target_version: str = Field(min_length=1, max_length=256)
    ground_truth: tuple[GroundTruthFinding, ...] = ()

    @model_validator(mode="after")
    def unique_truth(self) -> Self:
        truth_ids = tuple(item.truth_id for item in self.ground_truth)
        if len(truth_ids) != len(set(truth_ids)):
            raise ValueError("Benchmark case contains duplicate ground-truth identities")
        return self


class BenchmarkSuite(DomainModel):
    suite_id: Digest
    name: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=64)
    source: BenchmarkSource = BenchmarkSource.LOCAL_FIXTURE
    cases: Annotated[tuple[BenchmarkCase, ...], Field(min_length=1, max_length=10_000)]

    @model_validator(mode="after")
    def sealed_local_suite(self) -> Self:
        if self.suite_id != benchmark_suite_digest(self):
            raise ValueError("BenchmarkSuite content digest mismatch")
        case_ids = tuple(case.case_id for case in self.cases)
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("BenchmarkSuite contains duplicate case identities")
        truth_ids = tuple(item.truth_id for case in self.cases for item in case.ground_truth)
        if not truth_ids:
            raise ValueError("BenchmarkSuite requires at least one ground-truth Finding")
        if len(truth_ids) != len(set(truth_ids)):
            raise ValueError("ground-truth identities must be unique across the suite")
        return self

    @classmethod
    def create(
        cls,
        *,
        name: str,
        version: str,
        cases: tuple[BenchmarkCase, ...],
        source: BenchmarkSource = BenchmarkSource.LOCAL_FIXTURE,
    ) -> BenchmarkSuite:
        values = {
            "name": name,
            "version": version,
            "source": source,
            "cases": cases,
        }
        digest_values = {
            **values,
            "cases": tuple(case.model_dump(mode="python") for case in cases),
        }
        return cls(suite_id=canonical_digest(digest_values), **values)


def benchmark_suite_digest(suite: BenchmarkSuite) -> str:
    return canonical_digest(suite.model_dump(mode="python", exclude={"suite_id"}))


class BenchmarkObservation(DomainModel):
    case_id: Digest
    target_version: str = Field(min_length=1, max_length=256)
    candidate_id: UUID
    candidate_state: CandidateState
    duplicate_fingerprint: Digest
    matched_truth_id: Digest | None = None
    validation_result: ValidationResult
    critic_verdict: CriticVerdict | None = None
    finding_id: UUID | None = None
    evidence_required: int = Field(ge=0, le=10_000)
    evidence_present: int = Field(ge=0, le=10_000)
    elapsed_ms: int = Field(ge=0, le=86_400_000)
    cost_microunits: int = Field(ge=0, le=10**15)
    policy_violation_codes: tuple[Code, ...] = ()

    @model_validator(mode="after")
    def workflow_integrity(self) -> Self:
        if self.evidence_present > self.evidence_required:
            raise ValueError("present Evidence cannot exceed required Evidence")
        if (
            self.critic_verdict is not None
            and self.validation_result is not ValidationResult.REPRODUCED
        ):
            raise ValueError("Critic observation requires a reproduced Validation result")
        if self.finding_id is not None:
            if (
                self.validation_result is not ValidationResult.REPRODUCED
                or self.critic_verdict is not CriticVerdict.ACCEPTED
                or self.candidate_state is not CandidateState.PROMOTED
                or self.evidence_required == 0
                or self.evidence_present != self.evidence_required
            ):
                raise ValueError(
                    "Finding observation must pass Validation, Critic, promotion, "
                    "and Evidence gates"
                )
        elif self.candidate_state is CandidateState.PROMOTED:
            raise ValueError("a promoted Candidate observation requires a Finding identity")
        if len(self.policy_violation_codes) != len(set(self.policy_violation_codes)):
            raise ValueError("policy violation codes must be unique per observation")
        return self


class BenchmarkObservationSet(DomainModel):
    observation_set_id: Digest
    suite_id: Digest
    observations: tuple[BenchmarkObservation, ...] = ()

    @model_validator(mode="after")
    def sealed_and_unique(self) -> Self:
        if self.observation_set_id != benchmark_observation_set_digest(self):
            raise ValueError("BenchmarkObservationSet content digest mismatch")
        candidate_ids = tuple(item.candidate_id for item in self.observations)
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("Candidate observations must be unique")
        finding_ids = tuple(item.finding_id for item in self.observations if item.finding_id)
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("Finding observations must be unique")
        return self

    @classmethod
    def create(
        cls, *, suite_id: str, observations: tuple[BenchmarkObservation, ...]
    ) -> BenchmarkObservationSet:
        values = {"suite_id": suite_id, "observations": observations}
        digest_values = {
            **values,
            "observations": tuple(item.model_dump(mode="python") for item in observations),
        }
        return cls(observation_set_id=canonical_digest(digest_values), **values)


def benchmark_observation_set_digest(observations: BenchmarkObservationSet) -> str:
    return canonical_digest(observations.model_dump(mode="python", exclude={"observation_set_id"}))


class BenchmarkMetrics(DomainModel):
    ground_truth_count: int = Field(ge=0)
    candidate_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    matched_finding_count: int = Field(ge=0)
    candidate_recall: Ratio
    finding_precision: Ratio
    duplicate_rate: Ratio
    evidence_completeness: Ratio
    policy_violation_count: int = Field(ge=0)
    total_elapsed_ms: int = Field(ge=0)
    total_cost_microunits: int = Field(ge=0)
    cost_per_finding_microunits: int = Field(ge=0)


class BenchmarkBaseline(DomainModel):
    baseline_id: Digest
    suite_id: Digest
    suite_digest: Digest
    metrics: BenchmarkMetrics

    @model_validator(mode="after")
    def sealed_snapshot(self) -> Self:
        if self.baseline_id != canonical_digest(
            self.model_dump(mode="python", exclude={"baseline_id"})
        ):
            raise ValueError("BenchmarkBaseline content digest mismatch")
        return self

    @classmethod
    def create(cls, *, suite: BenchmarkSuite, metrics: BenchmarkMetrics) -> BenchmarkBaseline:
        values = {
            "suite_id": suite.suite_id,
            "suite_digest": canonical_digest(suite.model_dump(mode="python")),
            "metrics": metrics.model_dump(mode="python"),
        }
        return cls(baseline_id=canonical_digest(values), **values)


class BenchmarkRegressionPolicy(DomainModel):
    min_candidate_recall: Ratio = 1.0
    min_finding_precision: Ratio = 1.0
    max_duplicate_rate: Ratio = 0.0
    min_evidence_completeness: Ratio = 1.0
    max_policy_violations: int = Field(default=0, ge=0)
    max_total_elapsed_ms: int | None = Field(default=None, ge=0)
    max_cost_per_finding_microunits: int | None = Field(default=None, ge=0)
    max_candidate_recall_drop: Ratio = 0.0
    max_finding_precision_drop: Ratio = 0.0
    max_evidence_completeness_drop: Ratio = 0.0
    max_duplicate_rate_increase: Ratio = 0.0
    max_runtime_increase_ms: int = Field(default=0, ge=0)
    max_cost_per_finding_increase_microunits: int = Field(default=0, ge=0)


class BenchmarkPlan(DomainModel):
    plan_id: Digest
    suite_id: Digest
    suite_digest: Digest
    observation_set_id: Digest
    observation_set_digest: Digest
    policy: BenchmarkRegressionPolicy
    baseline: BenchmarkBaseline | None = None
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_and_bounded(self) -> Self:
        if self.plan_id != benchmark_plan_digest(self):
            raise ValueError("BenchmarkPlan content digest mismatch")
        if self.deadline <= self.created_at:
            raise ValueError("BenchmarkPlan deadline must be after creation")
        if self.baseline is not None and (
            self.baseline.suite_id != self.suite_id
            or self.baseline.suite_digest != self.suite_digest
        ):
            raise ValueError("Benchmark baseline is not bound to this exact suite")
        return self

    @classmethod
    def create(
        cls,
        *,
        suite: BenchmarkSuite,
        observations: BenchmarkObservationSet,
        policy: BenchmarkRegressionPolicy,
        created_at: datetime,
        deadline: datetime,
        idempotency_key: str,
        baseline: BenchmarkBaseline | None = None,
    ) -> BenchmarkPlan:
        values = {
            "suite_id": suite.suite_id,
            "suite_digest": canonical_digest(suite.model_dump(mode="python")),
            "observation_set_id": observations.observation_set_id,
            "observation_set_digest": canonical_digest(observations.model_dump(mode="python")),
            "policy": policy,
            "baseline": baseline,
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {
            **values,
            "policy": policy.model_dump(mode="python"),
            "baseline": baseline.model_dump(mode="python") if baseline else None,
        }
        return cls(plan_id=canonical_digest(digest_values), **values)


def benchmark_plan_digest(plan: BenchmarkPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"plan_id"}))


class RegressionViolation(DomainModel):
    code: Code
    metric: str = Field(min_length=1, max_length=128)
    actual: float = Field(allow_inf_nan=False)
    limit: float = Field(allow_inf_nan=False)


class BenchmarkResult(DomainModel):
    result_id: UUID
    plan_id: Digest
    suite_id: Digest
    observation_set_id: Digest
    metrics: BenchmarkMetrics
    gate_status: BenchmarkGateStatus
    violations: tuple[RegressionViolation, ...]
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def deterministic_identity_and_status(self) -> Self:
        if self.result_id != uuid5(NAMESPACE_URL, f"vulnloom:benchmark-result:{self.plan_id}"):
            raise ValueError("BenchmarkResult identity does not match its sealed plan")
        failed = bool(self.violations)
        if failed != (self.gate_status is BenchmarkGateStatus.FAILED):
            raise ValueError("Benchmark gate status does not match its violations")
        return self


class BenchmarkArtifact(DomainModel):
    result_digest: Digest
    json_sha256: Digest
    markdown_sha256: Digest
    json_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/result\.json$")
    markdown_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/result\.md$")

    @model_validator(mode="after")
    def references_match_identity(self) -> Self:
        prefix = f"objects/{self.result_digest}"
        if self.json_ref != f"{prefix}/result.json" or self.markdown_ref != f"{prefix}/result.md":
            raise ValueError("Benchmark artifact references do not match result identity")
        return self


class BenchmarkOutcome(DomainModel):
    plan_id: Digest
    result: BenchmarkResult
    artifact: BenchmarkArtifact

    @model_validator(mode="after")
    def result_and_artifact_are_bound(self) -> Self:
        if self.plan_id != self.result.plan_id:
            raise ValueError("BenchmarkOutcome plan does not match its result")
        if self.artifact.result_digest != canonical_digest(self.result.model_dump(mode="python")):
            raise ValueError("BenchmarkOutcome artifact does not match its result")
        return self
