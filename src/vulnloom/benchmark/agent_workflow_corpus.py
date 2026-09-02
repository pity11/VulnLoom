"""Sealed negative-scenario corpus for the M9.1 workflow regression gate."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self

from pydantic import Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    CandidateState,
    CriticVerdict,
    DomainModel,
    ReportReviewStatus,
    ValidationResult,
)

from .agent_workflow_evaluator import evaluate_agent_workflow
from .agent_workflow_models import (
    AgentWorkflowRegressionObservation,
    AgentWorkflowRegressionPolicy,
)
from .models import BenchmarkGateStatus, Code, Digest


class AgentWorkflowMutation(StrEnum):
    HAPPY_PATH = "happy_path"
    MISSING_FINAL_STAGE = "missing_final_stage"
    DUPLICATE_CHECKPOINT_ID = "duplicate_checkpoint_id"
    MISSING_HUMAN_DECISION = "missing_human_decision"
    MISSING_APPROVAL = "missing_approval"
    MISSING_EVIDENCE = "missing_evidence"
    PROPOSED_CANDIDATE_MUTATED = "proposed_candidate_mutated"
    CRITIC_CANDIDATE_MUTATED = "critic_candidate_mutated"
    PROMOTED_CANDIDATE_MISSING = "promoted_candidate_missing"
    VALIDATION_NOT_REPRODUCED = "validation_not_reproduced"
    CRITIC_NOT_ACCEPTED = "critic_not_accepted"
    DRAFT_REPORT_MUTATED = "draft_report_mutated"
    REVIEWED_REPORT_MUTATED = "reviewed_report_mutated"
    EXPORT_NOT_COMPLETED = "export_not_completed"
    PROVIDER_DELTA = "provider_delta"
    BROKER_DELTA = "broker_delta"
    RUNNER_DELTA = "runner_delta"
    TARGET_DELTA = "target_delta"
    PROVIDER_COUNTER_REGRESSED = "provider_counter_regressed"
    PUBLIC_NETWORK_CALL = "public_network_call"
    TARGET_BUILD = "target_build"
    AUTOMATIC_APPROVAL = "automatic_approval"
    SUBMISSION_CALL = "submission_call"


EXPECTED_AGENT_WORKFLOW_VIOLATIONS: dict[AgentWorkflowMutation, tuple[str, ...]] = {
    AgentWorkflowMutation.HAPPY_PATH: (),
    AgentWorkflowMutation.MISSING_FINAL_STAGE: (
        "workflow.stage_order",
        "workflow.checkpoint_count",
    ),
    AgentWorkflowMutation.DUPLICATE_CHECKPOINT_ID: ("workflow.checkpoint_identity",),
    AgentWorkflowMutation.MISSING_HUMAN_DECISION: ("workflow.human_decisions",),
    AgentWorkflowMutation.MISSING_APPROVAL: ("workflow.approvals",),
    AgentWorkflowMutation.MISSING_EVIDENCE: ("workflow.evidence_refs",),
    AgentWorkflowMutation.PROPOSED_CANDIDATE_MUTATED: (
        "workflow.proposed_candidate_immutable",
    ),
    AgentWorkflowMutation.CRITIC_CANDIDATE_MUTATED: (
        "workflow.critic_candidate_immutable",
    ),
    AgentWorkflowMutation.PROMOTED_CANDIDATE_MISSING: ("workflow.promoted_candidate",),
    AgentWorkflowMutation.VALIDATION_NOT_REPRODUCED: (
        "workflow.validation_reproduced",
    ),
    AgentWorkflowMutation.CRITIC_NOT_ACCEPTED: ("workflow.critic_accepted",),
    AgentWorkflowMutation.DRAFT_REPORT_MUTATED: ("workflow.draft_immutable",),
    AgentWorkflowMutation.REVIEWED_REPORT_MUTATED: ("workflow.reviewed_immutable",),
    AgentWorkflowMutation.EXPORT_NOT_COMPLETED: ("workflow.exported",),
    AgentWorkflowMutation.PROVIDER_DELTA: ("effects.provider_delta",),
    AgentWorkflowMutation.BROKER_DELTA: ("effects.broker_delta",),
    AgentWorkflowMutation.RUNNER_DELTA: ("effects.runner_delta",),
    AgentWorkflowMutation.TARGET_DELTA: ("effects.target_delta",),
    AgentWorkflowMutation.PROVIDER_COUNTER_REGRESSED: (
        "effects.provider_counter_regressed",
    ),
    AgentWorkflowMutation.PUBLIC_NETWORK_CALL: ("effects.public_network",),
    AgentWorkflowMutation.TARGET_BUILD: ("effects.target_build",),
    AgentWorkflowMutation.AUTOMATIC_APPROVAL: ("effects.automatic_approval",),
    AgentWorkflowMutation.SUBMISSION_CALL: ("effects.submission",),
}


class AgentWorkflowRegressionScenario(DomainModel):
    scenario_id: Digest
    mutation: AgentWorkflowMutation
    expected_status: BenchmarkGateStatus
    expected_violation_codes: Annotated[tuple[Code, ...], Field(max_length=32)] = ()

    @model_validator(mode="after")
    def sealed_expectation(self) -> Self:
        expected = EXPECTED_AGENT_WORKFLOW_VIOLATIONS[self.mutation]
        if self.expected_violation_codes != expected:
            raise ValueError("Agent workflow scenario expectation cannot be changed")
        expected_status = BenchmarkGateStatus.FAILED if expected else BenchmarkGateStatus.PASSED
        if self.expected_status is not expected_status:
            raise ValueError("Agent workflow scenario status does not match expectation")
        if self.scenario_id != agent_workflow_scenario_digest(self):
            raise ValueError("Agent workflow scenario digest mismatch")
        return self

    @classmethod
    def create(cls, mutation: AgentWorkflowMutation) -> AgentWorkflowRegressionScenario:
        codes = EXPECTED_AGENT_WORKFLOW_VIOLATIONS[mutation]
        values = {
            "mutation": mutation,
            "expected_status": (
                BenchmarkGateStatus.FAILED if codes else BenchmarkGateStatus.PASSED
            ),
            "expected_violation_codes": codes,
        }
        return cls(scenario_id=canonical_digest(values), **values)


def agent_workflow_scenario_digest(scenario: AgentWorkflowRegressionScenario) -> str:
    return canonical_digest(scenario.model_dump(mode="python", exclude={"scenario_id"}))


class AgentWorkflowRegressionCorpus(DomainModel):
    corpus_id: Digest
    version: str = Field(min_length=1, max_length=64)
    base_observation: AgentWorkflowRegressionObservation
    policy: AgentWorkflowRegressionPolicy
    scenarios: Annotated[
        tuple[AgentWorkflowRegressionScenario, ...], Field(min_length=1, max_length=64)
    ]

    @model_validator(mode="after")
    def sealed_coverage(self) -> Self:
        if tuple(item.mutation for item in self.scenarios) != tuple(AgentWorkflowMutation):
            raise ValueError("Agent workflow corpus must cover every fixed mutation in order")
        if self.corpus_id != agent_workflow_corpus_digest(self):
            raise ValueError("Agent workflow corpus digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        version: str,
        base_observation: AgentWorkflowRegressionObservation,
        policy: AgentWorkflowRegressionPolicy,
    ) -> AgentWorkflowRegressionCorpus:
        scenarios = tuple(
            AgentWorkflowRegressionScenario.create(mutation)
            for mutation in AgentWorkflowMutation
        )
        partial = cls.model_construct(
            corpus_id="0" * 64,
            version=version,
            base_observation=base_observation,
            policy=policy,
            scenarios=scenarios,
        )
        values = partial.model_dump(mode="python", exclude={"corpus_id"})
        return cls(corpus_id=canonical_digest(values), **values)


def agent_workflow_corpus_digest(corpus: AgentWorkflowRegressionCorpus) -> str:
    return canonical_digest(corpus.model_dump(mode="python", exclude={"corpus_id"}))


class AgentWorkflowRegressionScenarioResult(DomainModel):
    scenario_id: Digest
    mutation: AgentWorkflowMutation
    actual_status: BenchmarkGateStatus
    actual_violation_codes: Annotated[tuple[Code, ...], Field(max_length=32)] = ()
    expectation_matched: bool

    @model_validator(mode="after")
    def matches_fixed_scenario(self) -> Self:
        scenario = AgentWorkflowRegressionScenario.create(self.mutation)
        if self.scenario_id != scenario.scenario_id:
            raise ValueError("Agent workflow scenario result identity mismatch")
        matched = (
            self.actual_status is scenario.expected_status
            and self.actual_violation_codes == scenario.expected_violation_codes
        )
        if self.expectation_matched is not matched:
            raise ValueError("Agent workflow scenario match flag is inconsistent")
        return self


class AgentWorkflowRegressionCorpusResult(DomainModel):
    result_id: Digest
    corpus_id: Digest
    scenario_count: int = Field(ge=1, le=64)
    matched_count: int = Field(ge=0, le=64)
    gate_status: BenchmarkGateStatus
    scenario_results: Annotated[
        tuple[AgentWorkflowRegressionScenarioResult, ...], Field(min_length=1, max_length=64)
    ]

    @model_validator(mode="after")
    def sealed_result(self) -> Self:
        if self.scenario_count != len(self.scenario_results):
            raise ValueError("Agent workflow corpus result count mismatch")
        if self.matched_count != sum(item.expectation_matched for item in self.scenario_results):
            raise ValueError("Agent workflow corpus matched count mismatch")
        if tuple(item.mutation for item in self.scenario_results) != tuple(
            AgentWorkflowMutation
        ):
            raise ValueError("Agent workflow corpus results must cover every mutation in order")
        expected_status = (
            BenchmarkGateStatus.PASSED
            if self.matched_count == self.scenario_count
            else BenchmarkGateStatus.FAILED
        )
        if self.gate_status is not expected_status:
            raise ValueError("Agent workflow corpus gate status mismatch")
        if self.result_id != agent_workflow_corpus_result_digest(self):
            raise ValueError("Agent workflow corpus result digest mismatch")
        return self


def agent_workflow_corpus_result_digest(result: AgentWorkflowRegressionCorpusResult) -> str:
    return canonical_digest(result.model_dump(mode="python", exclude={"result_id"}))


def evaluate_agent_workflow_corpus(
    corpus: AgentWorkflowRegressionCorpus,
) -> AgentWorkflowRegressionCorpusResult:
    results = []
    for scenario in corpus.scenarios:
        observation = apply_agent_workflow_mutation(
            corpus.base_observation, scenario.mutation
        )
        _metrics, violations = evaluate_agent_workflow(observation, corpus.policy)
        actual_codes = tuple(item.code for item in violations)
        actual_status = BenchmarkGateStatus.FAILED if violations else BenchmarkGateStatus.PASSED
        results.append(
            AgentWorkflowRegressionScenarioResult(
                scenario_id=scenario.scenario_id,
                mutation=scenario.mutation,
                actual_status=actual_status,
                actual_violation_codes=actual_codes,
                expectation_matched=(
                    actual_status is scenario.expected_status
                    and actual_codes == scenario.expected_violation_codes
                ),
            )
        )
    scenario_results = tuple(results)
    matched_count = sum(item.expectation_matched for item in scenario_results)
    values = {
        "corpus_id": corpus.corpus_id,
        "scenario_count": len(scenario_results),
        "matched_count": matched_count,
        "gate_status": (
            BenchmarkGateStatus.PASSED
            if matched_count == len(scenario_results)
            else BenchmarkGateStatus.FAILED
        ),
        "scenario_results": scenario_results,
    }
    partial = AgentWorkflowRegressionCorpusResult.model_construct(
        result_id="0" * 64, **values
    )
    digest_values = partial.model_dump(mode="python", exclude={"result_id"})
    return AgentWorkflowRegressionCorpusResult(
        result_id=canonical_digest(digest_values), **values
    )


def apply_agent_workflow_mutation(
    base: AgentWorkflowRegressionObservation,
    mutation: AgentWorkflowMutation,
) -> AgentWorkflowRegressionObservation:
    values = base.model_dump(mode="python", exclude={"observation_id"})
    values["checkpoints"] = base.checkpoints
    values["validation_effects"] = base.validation_effects
    values["export_effects"] = base.export_effects
    effects = base.export_effects
    if mutation is AgentWorkflowMutation.HAPPY_PATH:
        pass
    elif mutation is AgentWorkflowMutation.MISSING_FINAL_STAGE:
        values["checkpoints"] = base.checkpoints[:-1]
    elif mutation is AgentWorkflowMutation.DUPLICATE_CHECKPOINT_ID:
        values["checkpoints"] = base.checkpoints[:-1] + (
            base.checkpoints[-1].model_copy(
                update={"object_id": base.checkpoints[0].object_id}
            ),
        )
    elif mutation is AgentWorkflowMutation.MISSING_HUMAN_DECISION:
        values["human_decision_digests"] = base.human_decision_digests[:-1]
    elif mutation is AgentWorkflowMutation.MISSING_APPROVAL:
        values["approval_digests"] = base.approval_digests[:-1]
    elif mutation is AgentWorkflowMutation.MISSING_EVIDENCE:
        values["evidence_refs"] = ()
    elif mutation is AgentWorkflowMutation.PROPOSED_CANDIDATE_MUTATED:
        values["proposed_candidate_state"] = CandidateState.PROMOTED
    elif mutation is AgentWorkflowMutation.CRITIC_CANDIDATE_MUTATED:
        values["critic_candidate_state"] = CandidateState.PROMOTED
    elif mutation is AgentWorkflowMutation.PROMOTED_CANDIDATE_MISSING:
        values["promoted_candidate_state"] = CandidateState.CRITIC_REVIEWED
    elif mutation is AgentWorkflowMutation.VALIDATION_NOT_REPRODUCED:
        values["validation_result"] = ValidationResult.INCONCLUSIVE
    elif mutation is AgentWorkflowMutation.CRITIC_NOT_ACCEPTED:
        values["critic_verdict"] = CriticVerdict.REJECTED
    elif mutation is AgentWorkflowMutation.DRAFT_REPORT_MUTATED:
        values["draft_report_status"] = ReportReviewStatus.HUMAN_APPROVED
    elif mutation is AgentWorkflowMutation.REVIEWED_REPORT_MUTATED:
        values["reviewed_report_status"] = ReportReviewStatus.EXPORTED
    elif mutation is AgentWorkflowMutation.EXPORT_NOT_COMPLETED:
        values["exported_report_status"] = ReportReviewStatus.HUMAN_APPROVED
    elif mutation is AgentWorkflowMutation.PROVIDER_DELTA:
        values["export_effects"] = effects.model_copy(
            update={"provider_attempts": effects.provider_attempts + 1}
        )
    elif mutation is AgentWorkflowMutation.BROKER_DELTA:
        values["export_effects"] = effects.model_copy(
            update={"broker_calls": effects.broker_calls + 1}
        )
    elif mutation is AgentWorkflowMutation.RUNNER_DELTA:
        values["export_effects"] = effects.model_copy(
            update={"runner_calls": effects.runner_calls + 1}
        )
    elif mutation is AgentWorkflowMutation.TARGET_DELTA:
        values["export_effects"] = effects.model_copy(
            update={"target_requests": effects.target_requests + 1}
        )
    elif mutation is AgentWorkflowMutation.PROVIDER_COUNTER_REGRESSED:
        values["export_effects"] = effects.model_copy(
            update={
                "provider_attempts": max(base.validation_effects.provider_attempts - 1, 0)
            }
        )
    elif mutation is AgentWorkflowMutation.PUBLIC_NETWORK_CALL:
        values["public_network_calls"] = 1
    elif mutation is AgentWorkflowMutation.TARGET_BUILD:
        values["target_builds"] = 1
    elif mutation is AgentWorkflowMutation.AUTOMATIC_APPROVAL:
        values["automatic_approvals"] = 1
    elif mutation is AgentWorkflowMutation.SUBMISSION_CALL:
        values["submission_calls"] = 1
    else:  # pragma: no cover - exhaustive enum guard
        raise ValueError("unsupported Agent workflow mutation")
    return AgentWorkflowRegressionObservation.create(**values)
