"""M9.4 sealed cross-framework and safe-negative static robustness gate."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self

from pydantic import Field, model_validator

from vulnloom.analyzers.models import WebFramework
from vulnloom.benchmark.local_source import (
    Digest,
    LocalSourceBenchmarkRejected,
    LocalSourceObservationSet,
    LocalSourceQualityPolicy,
    LocalSourceQualityResult,
    LocalSourceSuite,
    evaluate_local_source_quality,
)
from vulnloom.benchmark.models import BenchmarkBaseline, BenchmarkGateStatus
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel


class RobustnessDisposition(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"


# This contract is code-owned rather than fixture-owned: regenerating JSON cannot
# remove a case, change its expected framework, or relabel a negative as positive.
M9_4_CASE_CONTRACT = (
    (
        "flask_cross_file_idor",
        WebFramework.FLASK,
        RobustnessDisposition.POSITIVE,
        True,
        2,
        2,
        ("CWE-639",),
    ),
    (
        "fastapi_cross_file_ssrf",
        WebFramework.FASTAPI,
        RobustnessDisposition.POSITIVE,
        True,
        2,
        2,
        ("CWE-918",),
    ),
    (
        "django_cross_file_idor",
        WebFramework.DJANGO,
        RobustnessDisposition.POSITIVE,
        True,
        2,
        1,
        ("CWE-639",),
    ),
    (
        "flask_cross_file_sql",
        WebFramework.FLASK,
        RobustnessDisposition.POSITIVE,
        True,
        2,
        2,
        ("CWE-89",),
    ),
    (
        "fastapi_dependency_idor",
        WebFramework.FASTAPI,
        RobustnessDisposition.POSITIVE,
        False,
        1,
        1,
        ("CWE-639",),
    ),
    ("django_guarded_idor", WebFramework.DJANGO, RobustnessDisposition.NEGATIVE, True, 2, 1, ()),
    ("constant_sql", WebFramework.FLASK, RobustnessDisposition.NEGATIVE, False, 1, 1, ()),
    ("constant_command", WebFramework.FLASK, RobustnessDisposition.NEGATIVE, False, 1, 1, ()),
    ("constant_file", WebFramework.FLASK, RobustnessDisposition.NEGATIVE, False, 1, 1, ()),
    ("constant_network", WebFramework.FLASK, RobustnessDisposition.NEGATIVE, False, 1, 1, ()),
    ("constant_template", WebFramework.FLASK, RobustnessDisposition.NEGATIVE, False, 1, 1, ()),
    (
        "constant_deserialization",
        WebFramework.FLASK,
        RobustnessDisposition.NEGATIVE,
        False,
        1,
        1,
        (),
    ),
    ("constant_redirect", WebFramework.FLASK, RobustnessDisposition.NEGATIVE, False, 1, 1, ()),
)


class LocalSourceRobustnessRequirement(DomainModel):
    case_id: Digest
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    framework: WebFramework
    disposition: RobustnessDisposition
    cross_file: bool
    min_file_count: int = Field(ge=1, le=16)
    min_call_chain_length: int = Field(ge=1, le=16)
    expected_cwes: tuple[str, ...]


class LocalSourceRobustnessProfile(DomainModel):
    profile_id: Digest
    suite_id: Digest
    workflow_baseline_id: Digest
    requirements: Annotated[
        tuple[LocalSourceRobustnessRequirement, ...],
        Field(min_length=len(M9_4_CASE_CONTRACT), max_length=len(M9_4_CASE_CONTRACT)),
    ]

    @model_validator(mode="after")
    def sealed_contract(self) -> Self:
        if self.profile_id != local_source_robustness_profile_digest(self):
            raise ValueError("LocalSourceRobustnessProfile content digest mismatch")
        semantic = tuple(
            (
                item.name,
                item.framework,
                item.disposition,
                item.cross_file,
                item.min_file_count,
                item.min_call_chain_length,
                item.expected_cwes,
            )
            for item in self.requirements
        )
        if semantic != M9_4_CASE_CONTRACT:
            raise ValueError("M9.4 robustness case contract cannot be changed")
        case_ids = tuple(item.case_id for item in self.requirements)
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("M9.4 robustness case identities must be unique")
        return self

    @classmethod
    def create(
        cls, *, suite: LocalSourceSuite, workflow_baseline: BenchmarkBaseline
    ) -> LocalSourceRobustnessProfile:
        cases = {item.name: item for item in suite.cases}
        if tuple(item.name for item in suite.cases) != tuple(
            item[0] for item in M9_4_CASE_CONTRACT
        ):
            raise LocalSourceBenchmarkRejected("M9.4 suite does not match the sealed case order")
        requirements = tuple(
            LocalSourceRobustnessRequirement(
                case_id=cases[name].case_id,
                name=name,
                framework=framework,
                disposition=disposition,
                cross_file=cross_file,
                min_file_count=min_file_count,
                min_call_chain_length=min_call_chain_length,
                expected_cwes=expected_cwes,
            )
            for (
                name,
                framework,
                disposition,
                cross_file,
                min_file_count,
                min_call_chain_length,
                expected_cwes,
            ) in M9_4_CASE_CONTRACT
        )
        values = {
            "suite_id": suite.suite_id,
            "workflow_baseline_id": workflow_baseline.baseline_id,
            "requirements": requirements,
        }
        digest_values = {
            **values,
            "requirements": tuple(item.model_dump(mode="python") for item in requirements),
        }
        return cls(profile_id=canonical_digest(digest_values), **values)


def local_source_robustness_profile_digest(value: LocalSourceRobustnessProfile) -> str:
    return canonical_digest(value.model_dump(mode="python", exclude={"profile_id"}))


class LocalSourceRobustnessMetrics(DomainModel):
    positive_case_count: int = Field(ge=0)
    negative_case_count: int = Field(ge=0)
    cross_file_case_count: int = Field(ge=0)
    framework_count: int = Field(ge=0)
    parse_failure_count: int = Field(ge=0)
    framework_mismatch_count: int = Field(ge=0)
    cross_file_trace_failure_count: int = Field(ge=0)
    negative_candidate_count: int = Field(ge=0)


class LocalSourceRobustnessResult(DomainModel):
    result_id: Digest
    suite_id: Digest
    observation_set_id: Digest
    profile_id: Digest
    base_quality_result_id: Digest
    metrics: LocalSourceRobustnessMetrics
    violations: tuple[str, ...]
    gate_status: BenchmarkGateStatus

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.result_id != canonical_digest(
            self.model_dump(mode="python", exclude={"result_id"})
        ):
            raise ValueError("LocalSourceRobustnessResult content digest mismatch")
        return self


def evaluate_local_source_robustness(
    suite: LocalSourceSuite,
    observations: LocalSourceObservationSet,
    workflow_baseline: BenchmarkBaseline,
    profile: LocalSourceRobustnessProfile,
) -> tuple[LocalSourceQualityResult, LocalSourceRobustnessResult]:
    try:
        LocalSourceSuite.model_validate(suite.model_dump(mode="python"))
        LocalSourceObservationSet.model_validate(observations.model_dump(mode="python"))
        LocalSourceRobustnessProfile.model_validate(profile.model_dump(mode="python"))
        BenchmarkBaseline.model_validate(workflow_baseline.model_dump(mode="python"))
    except ValueError as exc:
        raise LocalSourceBenchmarkRejected(
            "M9.4 input failed content-integrity validation"
        ) from exc
    if suite.suite_id != profile.suite_id:
        raise LocalSourceBenchmarkRejected("robustness profile belongs to another suite")
    if workflow_baseline.baseline_id != profile.workflow_baseline_id:
        raise LocalSourceBenchmarkRejected("robustness profile binds another workflow baseline")
    if suite.name != "vulnloom-m9.4-local-source-robustness" or suite.version != "1":
        raise LocalSourceBenchmarkRejected("M9.4 suite identity is not admitted")
    case_by_id = {item.case_id: item for item in suite.cases}
    observation_by_id = {item.case_id: item for item in observations.observations}
    if set(case_by_id) != {item.case_id for item in profile.requirements}:
        raise LocalSourceBenchmarkRejected("M9.4 profile does not bind the exact suite cases")
    for requirement in profile.requirements:
        case = case_by_id[requirement.case_id]
        if case.name != requirement.name or case.expected_cwes != requirement.expected_cwes:
            raise LocalSourceBenchmarkRejected("M9.4 case truth differs from the sealed contract")

    base_policy = LocalSourceQualityPolicy(
        required_workflow_baseline_id=workflow_baseline.baseline_id
    )
    base_result = evaluate_local_source_quality(suite, observations, workflow_baseline, base_policy)
    framework_mismatches = cross_file_failures = negative_candidates = parse_failures = 0
    observed_frameworks = set()
    for requirement in profile.requirements:
        observation = observation_by_id[requirement.case_id]
        parse_failures += observation.parse_failure_count
        candidates = observation.candidates
        if requirement.disposition is RobustnessDisposition.NEGATIVE:
            negative_candidates += len(candidates)
            continue
        candidate_frameworks = {item.framework for item in candidates}
        observed_frameworks.update(candidate_frameworks)
        if candidate_frameworks != {requirement.framework}:
            framework_mismatches += 1
        if requirement.cross_file and (
            len(observation.files_analyzed) < requirement.min_file_count
            or any(
                item.entry_path == item.sink_path
                or item.call_chain_length < requirement.min_call_chain_length
                for item in candidates
            )
        ):
            cross_file_failures += 1

    metrics = LocalSourceRobustnessMetrics(
        positive_case_count=sum(
            item.disposition is RobustnessDisposition.POSITIVE for item in profile.requirements
        ),
        negative_case_count=sum(
            item.disposition is RobustnessDisposition.NEGATIVE for item in profile.requirements
        ),
        cross_file_case_count=sum(item.cross_file for item in profile.requirements),
        framework_count=len(observed_frameworks),
        parse_failure_count=parse_failures,
        framework_mismatch_count=framework_mismatches,
        cross_file_trace_failure_count=cross_file_failures,
        negative_candidate_count=negative_candidates,
    )
    checks = (
        ("base_quality_gate_failed", base_result.gate_status is BenchmarkGateStatus.FAILED),
        (
            "framework_coverage_incomplete",
            observed_frameworks != {WebFramework.FLASK, WebFramework.FASTAPI, WebFramework.DJANGO},
        ),
        ("framework_mismatch", framework_mismatches > 0),
        ("cross_file_trace_missing", cross_file_failures > 0),
        ("parse_failure_observed", parse_failures > 0),
        ("negative_candidate_observed", negative_candidates > 0),
    )
    violations = tuple(code for code, failed in checks if failed)
    values = {
        "suite_id": suite.suite_id,
        "observation_set_id": observations.observation_set_id,
        "profile_id": profile.profile_id,
        "base_quality_result_id": base_result.result_id,
        "metrics": metrics,
        "violations": violations,
        "gate_status": BenchmarkGateStatus.FAILED if violations else BenchmarkGateStatus.PASSED,
    }
    digest_values = {**values, "metrics": metrics.model_dump(mode="python")}
    result = LocalSourceRobustnessResult(result_id=canonical_digest(digest_values), **values)
    return base_result, result
