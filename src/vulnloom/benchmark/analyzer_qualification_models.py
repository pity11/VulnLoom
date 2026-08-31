"""Sealed execution-to-evaluation qualification contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

from .analyzer_evaluation_models import (
    AnalyzerEvaluationOutcome,
    AnalyzerEvaluationPlan,
    AnalyzerTruthAlignment,
)
from .analyzer_execution_models import (
    AnalyzerExecutionPlan,
    AnalyzerToolRegistration,
    DockerAnalyzerExecutionOutcome,
    DockerAnalyzerExecutionStatus,
)
from .analyzer_models import AnalyzerKind
from .models import BenchmarkGateStatus, BenchmarkSuite


class AnalyzerExecutionEvidenceBinding(DomainModel):
    case_id: Digest
    analyzer: AnalyzerKind
    target_id: UUID
    target_version: str = Field(min_length=1, max_length=256)
    manifest_id: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    execution_plan_id: Digest
    execution_plan_digest: Digest
    registration_id: Digest
    registration_digest: Digest
    execution_outcome_digest: Digest
    observation_set_id: Digest
    observation_set_digest: Digest

    @classmethod
    def create(
        cls,
        *,
        case_id: str,
        execution_plan: AnalyzerExecutionPlan,
        registration: AnalyzerToolRegistration,
        outcome: DockerAnalyzerExecutionOutcome,
    ) -> AnalyzerExecutionEvidenceBinding:
        if (
            outcome.status is not DockerAnalyzerExecutionStatus.COMPLETED
            or outcome.import_outcome is None
            or not outcome.runner_result.cleanup.complete
            or outcome.plan_id != execution_plan.plan_id
            or outcome.registration_id != registration.registration_id
            or execution_plan.registration_id != registration.registration_id
            or execution_plan.registration_digest
            != canonical_digest(registration.model_dump(mode="python"))
        ):
            raise ValueError("qualification binding requires one completed bound execution")
        observations = outcome.import_outcome.observation_set
        if (
            outcome.target_id != execution_plan.target_id
            or outcome.target_version != execution_plan.target_version
            or observations.analyzer is not registration.analyzer
        ):
            raise ValueError("qualification execution provenance mismatch")
        return cls(
            case_id=case_id,
            analyzer=registration.analyzer,
            target_id=execution_plan.target_id,
            target_version=execution_plan.target_version,
            manifest_id=execution_plan.manifest_id,
            scope_id=execution_plan.scope_id,
            scope_version=execution_plan.scope_version,
            execution_plan_id=execution_plan.plan_id,
            execution_plan_digest=canonical_digest(execution_plan.model_dump(mode="python")),
            registration_id=registration.registration_id,
            registration_digest=canonical_digest(registration.model_dump(mode="python")),
            execution_outcome_digest=canonical_digest(outcome.model_dump(mode="python")),
            observation_set_id=observations.observation_set_id,
            observation_set_digest=canonical_digest(observations.model_dump(mode="python")),
        )


class AnalyzerQualificationPlan(DomainModel):
    plan_id: Digest
    suite_id: Digest
    suite_digest: Digest
    alignment_id: Digest
    alignment_digest: Digest
    evaluation_plan_id: Digest
    evaluation_plan_digest: Digest
    required_analyzers: Annotated[tuple[AnalyzerKind, ...], Field(min_length=1)]
    execution_bindings: Annotated[
        tuple[AnalyzerExecutionEvidenceBinding, ...], Field(min_length=1, max_length=100_000)
    ]
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_unique_matrix(self) -> Self:
        if self.deadline <= self.created_at:
            raise ValueError("analyzer qualification deadline must be after creation")
        if self.required_analyzers != tuple(
            sorted(set(self.required_analyzers), key=lambda item: item.value)
        ):
            raise ValueError("qualification analyzers must be unique and sorted")
        keys = tuple(
            (item.case_id, item.analyzer.value, item.execution_plan_id)
            for item in self.execution_bindings
        )
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("qualification execution bindings must be unique and sorted")
        if len({(item.case_id, item.analyzer) for item in self.execution_bindings}) != len(
            self.execution_bindings
        ):
            raise ValueError("qualification permits one execution per case and analyzer")
        for attribute in (
            "execution_plan_id",
            "observation_set_id",
        ):
            values = tuple(getattr(item, attribute) for item in self.execution_bindings)
            if len(values) != len(set(values)):
                raise ValueError(f"qualification {attribute} values must be unique")
        if self.plan_id != analyzer_qualification_plan_digest(self):
            raise ValueError("analyzer qualification plan content digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        suite: BenchmarkSuite,
        alignment: AnalyzerTruthAlignment,
        evaluation_plan: AnalyzerEvaluationPlan,
        execution_bindings: tuple[AnalyzerExecutionEvidenceBinding, ...],
        created_at: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AnalyzerQualificationPlan:
        if created_at < evaluation_plan.created_at or deadline > evaluation_plan.deadline:
            raise ValueError("qualification lifetime must fit inside its evaluation plan")
        required = evaluation_plan.policy.required_analyzers
        if not required:
            raise ValueError("qualification requires an explicit analyzer matrix")
        ordered = tuple(
            sorted(
                execution_bindings,
                key=lambda item: (item.case_id, item.analyzer.value, item.execution_plan_id),
            )
        )
        values = {
            "suite_id": suite.suite_id,
            "suite_digest": canonical_digest(suite.model_dump(mode="python")),
            "alignment_id": alignment.alignment_id,
            "alignment_digest": canonical_digest(alignment.model_dump(mode="python")),
            "evaluation_plan_id": evaluation_plan.plan_id,
            "evaluation_plan_digest": canonical_digest(
                evaluation_plan.model_dump(mode="python")
            ),
            "required_analyzers": required,
            "execution_bindings": ordered,
            "created_at": created_at,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        digest_values = {
            **values,
            "execution_bindings": tuple(item.model_dump(mode="python") for item in ordered),
        }
        return cls(plan_id=canonical_digest(digest_values), **values)


def analyzer_qualification_plan_digest(plan: AnalyzerQualificationPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"plan_id"}))


class AnalyzerQualificationOutcome(DomainModel):
    plan_id: Digest
    evaluation_plan_id: Digest
    evaluation_outcome: AnalyzerEvaluationOutcome
    execution_count: int = Field(gt=0, le=100_000)
    gate_status: BenchmarkGateStatus
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def evaluation_is_bound(self) -> Self:
        if (
            self.evaluation_plan_id != self.evaluation_outcome.plan_id
            or self.gate_status is not self.evaluation_outcome.result.gate_status
        ):
            raise ValueError("qualification evaluation outcome binding mismatch")
        return self
