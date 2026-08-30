"""Typed contracts for explicit, offline analyzer-to-ground-truth evaluation."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .analyzer_models import AnalyzerKind, AnalyzerObservationSet
from .models import (
    BenchmarkGateStatus,
    BenchmarkSuite,
    Digest,
    Ratio,
    RegressionViolation,
)

ANALYZER_ALIGNMENT_RULESET_DIGEST = canonical_digest(
    {
        "contract": "vulnloom.explicit-analyzer-truth-alignment",
        "version": 1,
        "automatic_cwe_only_matching": False,
    }
)


class AlignmentProvenance(StrEnum):
    FIXTURE = "fixture"
    HUMAN_REVIEW = "human_review"


class AnalyzerCaseBinding(DomainModel):
    case_id: Digest
    observation_set_id: Digest
    observation_set_digest: Digest
    analyzer: AnalyzerKind
    target_version: str = Field(min_length=1, max_length=256)

    @classmethod
    def create(cls, *, case_id: str, observations: AnalyzerObservationSet) -> AnalyzerCaseBinding:
        return cls(
            case_id=case_id,
            observation_set_id=observations.observation_set_id,
            observation_set_digest=canonical_digest(observations.model_dump(mode="python")),
            analyzer=observations.analyzer,
            target_version=observations.target_version,
        )


class AnalyzerTruthMatch(DomainModel):
    case_id: Digest
    observation_set_id: Digest
    observation_id: Digest
    truth_id: Digest
    matched_cwe: Annotated[str, Field(pattern=r"^CWE-[1-9][0-9]*$")]


class AnalyzerTruthAlignment(DomainModel):
    alignment_id: Digest
    suite_id: Digest
    suite_digest: Digest
    ruleset_digest: Digest = ANALYZER_ALIGNMENT_RULESET_DIGEST
    provenance: AlignmentProvenance
    producer_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    bindings: Annotated[tuple[AnalyzerCaseBinding, ...], Field(min_length=1, max_length=100_000)]
    matches: tuple[AnalyzerTruthMatch, ...] = ()

    @model_validator(mode="after")
    def sealed_and_unique(self) -> Self:
        if self.alignment_id != analyzer_truth_alignment_digest(self):
            raise ValueError("analyzer truth alignment content digest mismatch")
        if self.ruleset_digest != ANALYZER_ALIGNMENT_RULESET_DIGEST:
            raise ValueError("analyzer truth alignment ruleset is not trusted")
        binding_keys = tuple(
            (item.case_id, item.analyzer.value, item.observation_set_id) for item in self.bindings
        )
        if binding_keys != tuple(sorted(binding_keys)) or len(binding_keys) != len(
            set(binding_keys)
        ):
            raise ValueError("analyzer case bindings must be unique and sorted")
        case_analyzers = tuple((item.case_id, item.analyzer) for item in self.bindings)
        if len(case_analyzers) != len(set(case_analyzers)):
            raise ValueError("a benchmark case may bind only one set per analyzer")
        observation_set_ids = tuple(item.observation_set_id for item in self.bindings)
        if len(observation_set_ids) != len(set(observation_set_ids)):
            raise ValueError("an analyzer ObservationSet may be bound only once")
        match_keys = tuple(
            (
                item.case_id,
                item.observation_set_id,
                item.observation_id,
                item.truth_id,
            )
            for item in self.matches
        )
        if match_keys != tuple(sorted(match_keys)) or len(match_keys) != len(set(match_keys)):
            raise ValueError("analyzer truth matches must be unique and sorted")
        observation_keys = tuple(
            (item.observation_set_id, item.observation_id) for item in self.matches
        )
        if len(observation_keys) != len(set(observation_keys)):
            raise ValueError("one analyzer Observation cannot match multiple ground truths")
        return self

    @classmethod
    def create(
        cls,
        *,
        suite: BenchmarkSuite,
        provenance: AlignmentProvenance,
        producer_id: str,
        bindings: tuple[AnalyzerCaseBinding, ...],
        matches: tuple[AnalyzerTruthMatch, ...] = (),
    ) -> AnalyzerTruthAlignment:
        ordered_bindings = tuple(
            sorted(
                bindings,
                key=lambda item: (item.case_id, item.analyzer.value, item.observation_set_id),
            )
        )
        ordered_matches = tuple(
            sorted(
                matches,
                key=lambda item: (
                    item.case_id,
                    item.observation_set_id,
                    item.observation_id,
                    item.truth_id,
                ),
            )
        )
        values = {
            "suite_id": suite.suite_id,
            "suite_digest": canonical_digest(suite.model_dump(mode="python")),
            "ruleset_digest": ANALYZER_ALIGNMENT_RULESET_DIGEST,
            "provenance": provenance,
            "producer_id": producer_id,
            "bindings": ordered_bindings,
            "matches": ordered_matches,
        }
        digest_values = {
            **values,
            "bindings": tuple(item.model_dump(mode="python") for item in ordered_bindings),
            "matches": tuple(item.model_dump(mode="python") for item in ordered_matches),
        }
        return cls(alignment_id=canonical_digest(digest_values), **values)


def analyzer_truth_alignment_digest(alignment: AnalyzerTruthAlignment) -> str:
    return canonical_digest(alignment.model_dump(mode="python", exclude={"alignment_id"}))


class AnalyzerEvaluationLimits(DomainModel):
    max_observation_sets: int = Field(default=10_000, gt=0, le=100_000)
    max_observations: int = Field(default=1_000_000, gt=0, le=10_000_000)
    max_matches: int = Field(default=1_000_000, ge=0, le=10_000_000)
    timeout_seconds: float = Field(default=60.0, gt=0, le=3600)


class AnalyzerEvaluationPolicy(DomainModel):
    min_truth_recall: Ratio = 1.0
    min_observation_precision: Ratio = 0.0
    max_duplicate_rate: Ratio = 1.0
    max_exclusion_rate: Ratio = 1.0
    required_analyzers: tuple[AnalyzerKind, ...] = ()
    require_full_case_matrix: bool = True
    apply_thresholds_per_analyzer: bool = True
    max_truth_recall_drop: Ratio = 0.0
    max_observation_precision_drop: Ratio = 0.0
    max_duplicate_rate_increase: Ratio = 0.0
    max_exclusion_rate_increase: Ratio = 0.0

    @model_validator(mode="after")
    def normalized_required_analyzers(self) -> Self:
        if self.required_analyzers != tuple(
            sorted(set(self.required_analyzers), key=lambda item: item.value)
        ):
            raise ValueError("required analyzers must be unique and sorted")
        return self


class AnalyzerMetricSlice(DomainModel):
    analyzer: AnalyzerKind
    case_count: int = Field(ge=0)
    ground_truth_count: int = Field(ge=0)
    observation_count: int = Field(ge=0)
    matched_truth_count: int = Field(ge=0)
    matched_observation_count: int = Field(ge=0)
    false_positive_count: int = Field(ge=0)
    duplicate_match_count: int = Field(ge=0)
    exclusion_count: int = Field(ge=0)
    truth_recall: Ratio
    observation_precision: Ratio
    duplicate_rate: Ratio
    exclusion_rate: Ratio

    @model_validator(mode="after")
    def internally_consistent(self) -> Self:
        if (
            self.matched_truth_count > self.ground_truth_count
            or self.matched_observation_count > self.observation_count
            or self.false_positive_count != self.observation_count - self.matched_observation_count
            or self.duplicate_match_count > self.matched_observation_count
            or self.truth_recall
            != _ratio(self.matched_truth_count, self.ground_truth_count, empty=1.0)
            or self.observation_precision
            != _ratio(self.matched_observation_count, self.observation_count, empty=1.0)
            or self.duplicate_rate
            != _ratio(self.duplicate_match_count, self.observation_count, empty=0.0)
            or self.exclusion_rate
            != _ratio(
                self.exclusion_count,
                self.observation_count + self.exclusion_count,
                empty=0.0,
            )
        ):
            raise ValueError("per-analyzer metrics are internally inconsistent")
        return self


class AnalyzerEvaluationMetrics(DomainModel):
    case_count: int = Field(ge=0)
    analyzer_count: int = Field(ge=0)
    ground_truth_count: int = Field(ge=0)
    observation_count: int = Field(ge=0)
    matched_truth_count: int = Field(ge=0)
    matched_observation_count: int = Field(ge=0)
    false_positive_count: int = Field(ge=0)
    duplicate_match_count: int = Field(ge=0)
    exclusion_count: int = Field(ge=0)
    truth_recall: Ratio
    observation_precision: Ratio
    duplicate_rate: Ratio
    exclusion_rate: Ratio
    by_analyzer: tuple[AnalyzerMetricSlice, ...]

    @model_validator(mode="after")
    def sorted_analyzers(self) -> Self:
        kinds = tuple(item.analyzer.value for item in self.by_analyzer)
        if kinds != tuple(sorted(kinds)) or len(kinds) != len(set(kinds)):
            raise ValueError("per-analyzer metric slices must be unique and sorted")
        if self.analyzer_count != len(self.by_analyzer):
            raise ValueError("analyzer metric count does not match its slices")
        if (
            self.matched_truth_count > self.ground_truth_count
            or self.matched_observation_count > self.observation_count
            or self.false_positive_count != self.observation_count - self.matched_observation_count
            or self.duplicate_match_count > self.matched_observation_count
            or self.observation_count != sum(item.observation_count for item in self.by_analyzer)
            or self.matched_observation_count
            != sum(item.matched_observation_count for item in self.by_analyzer)
            or self.false_positive_count
            != sum(item.false_positive_count for item in self.by_analyzer)
            or self.exclusion_count != sum(item.exclusion_count for item in self.by_analyzer)
            or self.truth_recall
            != _ratio(self.matched_truth_count, self.ground_truth_count, empty=1.0)
            or self.observation_precision
            != _ratio(self.matched_observation_count, self.observation_count, empty=1.0)
            or self.duplicate_rate
            != _ratio(self.duplicate_match_count, self.observation_count, empty=0.0)
            or self.exclusion_rate
            != _ratio(
                self.exclusion_count,
                self.observation_count + self.exclusion_count,
                empty=0.0,
            )
        ):
            raise ValueError("aggregate analyzer metrics are internally inconsistent")
        return self


class AnalyzerEvaluationBaseline(DomainModel):
    baseline_id: Digest
    suite_id: Digest
    suite_digest: Digest
    metrics: AnalyzerEvaluationMetrics

    @model_validator(mode="after")
    def sealed_baseline(self) -> Self:
        if self.baseline_id != canonical_digest(
            self.model_dump(mode="python", exclude={"baseline_id"})
        ):
            raise ValueError("analyzer evaluation baseline content digest mismatch")
        return self

    @classmethod
    def create(
        cls, *, suite: BenchmarkSuite, metrics: AnalyzerEvaluationMetrics
    ) -> AnalyzerEvaluationBaseline:
        values = {
            "suite_id": suite.suite_id,
            "suite_digest": canonical_digest(suite.model_dump(mode="python")),
            "metrics": metrics.model_dump(mode="python"),
        }
        return cls(baseline_id=canonical_digest(values), **values)


class AnalyzerEvaluationPlan(DomainModel):
    plan_id: Digest
    suite_id: Digest
    suite_digest: Digest
    alignment_id: Digest
    alignment_digest: Digest
    policy: AnalyzerEvaluationPolicy
    limits: AnalyzerEvaluationLimits
    baseline: AnalyzerEvaluationBaseline | None = None
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_and_bounded(self) -> Self:
        if self.plan_id != analyzer_evaluation_plan_digest(self):
            raise ValueError("analyzer evaluation plan content digest mismatch")
        if self.deadline <= self.created_at:
            raise ValueError("analyzer evaluation deadline must be after creation")
        if self.baseline is not None and (
            self.baseline.suite_id != self.suite_id
            or self.baseline.suite_digest != self.suite_digest
        ):
            raise ValueError("analyzer baseline is not bound to this exact suite")
        return self

    @classmethod
    def create(
        cls,
        *,
        suite: BenchmarkSuite,
        alignment: AnalyzerTruthAlignment,
        policy: AnalyzerEvaluationPolicy,
        limits: AnalyzerEvaluationLimits,
        created_at: datetime,
        deadline: datetime,
        idempotency_key: str,
        baseline: AnalyzerEvaluationBaseline | None = None,
    ) -> AnalyzerEvaluationPlan:
        values = {
            "suite_id": suite.suite_id,
            "suite_digest": canonical_digest(suite.model_dump(mode="python")),
            "alignment_id": alignment.alignment_id,
            "alignment_digest": canonical_digest(alignment.model_dump(mode="python")),
            "policy": policy,
            "limits": limits,
            "baseline": baseline,
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {
            **values,
            "policy": policy.model_dump(mode="python"),
            "limits": limits.model_dump(mode="python"),
            "baseline": baseline.model_dump(mode="python") if baseline else None,
        }
        return cls(plan_id=canonical_digest(digest_values), **values)


def analyzer_evaluation_plan_digest(plan: AnalyzerEvaluationPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"plan_id"}))


class AnalyzerEvaluationResult(DomainModel):
    result_id: UUID
    plan_id: Digest
    suite_id: Digest
    alignment_id: Digest
    metrics: AnalyzerEvaluationMetrics
    gate_status: BenchmarkGateStatus
    violations: tuple[RegressionViolation, ...]
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def deterministic_identity_and_status(self) -> Self:
        if self.result_id != uuid5(
            NAMESPACE_URL, f"vulnloom:analyzer-evaluation-result:{self.plan_id}"
        ):
            raise ValueError("analyzer evaluation result identity does not match its plan")
        if bool(self.violations) != (self.gate_status is BenchmarkGateStatus.FAILED):
            raise ValueError("analyzer evaluation gate status does not match violations")
        return self


class AnalyzerEvaluationArtifact(DomainModel):
    result_digest: Digest
    json_sha256: Digest
    markdown_sha256: Digest
    json_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/result\.json$")
    markdown_ref: str = Field(pattern=r"^objects/[0-9a-f]{64}/result\.md$")

    @model_validator(mode="after")
    def references_match_identity(self) -> Self:
        prefix = f"objects/{self.result_digest}"
        if self.json_ref != f"{prefix}/result.json" or self.markdown_ref != (f"{prefix}/result.md"):
            raise ValueError("analyzer evaluation artifact references do not match result")
        return self


class AnalyzerEvaluationOutcome(DomainModel):
    plan_id: Digest
    result: AnalyzerEvaluationResult
    artifact: AnalyzerEvaluationArtifact

    @model_validator(mode="after")
    def bound_result(self) -> Self:
        if self.plan_id != self.result.plan_id:
            raise ValueError("analyzer evaluation outcome plan does not match result")
        if self.artifact.result_digest != canonical_digest(self.result.model_dump(mode="python")):
            raise ValueError("analyzer evaluation artifact does not match result")
        return self


def _ratio(numerator: int, denominator: int, *, empty: float) -> float:
    return round(numerator / denominator, 9) if denominator else empty
