"""Trusted fan-in from admitted analyzer executions to the evaluation gate."""

from __future__ import annotations

from datetime import datetime

from vulnloom.domain.digests import canonical_digest

from .analyzer_docker_execution_store import (
    AnalyzerDockerExecutionRecoveryRequired,
    AnalyzerDockerExecutionStore,
)
from .analyzer_evaluation_models import AnalyzerEvaluationPlan, AnalyzerTruthAlignment
from .analyzer_evaluation_service import AnalyzerEvaluationService
from .analyzer_execution_models import (
    AnalyzerExecutionPlan,
    AnalyzerToolRegistration,
    DockerAnalyzerExecutionOutcome,
    DockerAnalyzerExecutionStatus,
)
from .analyzer_models import AnalyzerObservationSet
from .analyzer_qualification_models import (
    AnalyzerQualificationOutcome,
    AnalyzerQualificationPlan,
)
from .analyzer_qualification_store import AnalyzerQualificationStore
from .models import BenchmarkSuite


class AnalyzerQualificationRejected(ValueError):
    pass


class AnalyzerQualificationService:
    def __init__(
        self,
        *,
        store: AnalyzerQualificationStore,
        execution_store: AnalyzerDockerExecutionStore,
        evaluation_service: AnalyzerEvaluationService,
    ):
        self.store = store
        self.execution_store = execution_store
        self.evaluation_service = evaluation_service

    def qualify(
        self,
        suite: BenchmarkSuite,
        execution_plans: tuple[AnalyzerExecutionPlan, ...],
        registrations: tuple[AnalyzerToolRegistration, ...],
        outcomes: tuple[DockerAnalyzerExecutionOutcome, ...],
        alignment: AnalyzerTruthAlignment,
        evaluation_plan: AnalyzerEvaluationPlan,
        plan: AnalyzerQualificationPlan,
        *,
        now: datetime,
    ) -> AnalyzerQualificationOutcome:
        if now < plan.created_at or now >= plan.deadline:
            raise AnalyzerQualificationRejected("analyzer qualification plan is not active")
        if (
            plan.suite_id != suite.suite_id
            or plan.suite_digest != canonical_digest(suite.model_dump(mode="python"))
            or plan.alignment_id != alignment.alignment_id
            or plan.alignment_digest != canonical_digest(alignment.model_dump(mode="python"))
            or plan.evaluation_plan_id != evaluation_plan.plan_id
            or plan.evaluation_plan_digest
            != canonical_digest(evaluation_plan.model_dump(mode="python"))
            or plan.required_analyzers != evaluation_plan.policy.required_analyzers
        ):
            raise AnalyzerQualificationRejected("qualification sealed input binding mismatch")

        plans = _unique(execution_plans, "plan_id", "execution plans")
        tools = _unique(registrations, "registration_id", "registrations")
        results = _unique(outcomes, "plan_id", "execution outcomes")
        if (
            len(plans) != len(plan.execution_bindings)
            or len(results) != len(plan.execution_bindings)
            or set(tools) != {item.registration_id for item in plan.execution_bindings}
        ):
            raise AnalyzerQualificationRejected("qualification requires the exact execution set")

        cases = {item.case_id: item for item in suite.cases}
        alignment_bindings = {
            (item.case_id, item.analyzer): item for item in alignment.bindings
        }
        expected_matrix = {
            (case.case_id, analyzer)
            for case in suite.cases
            for analyzer in plan.required_analyzers
        }
        supplied_matrix = {(item.case_id, item.analyzer) for item in plan.execution_bindings}
        if supplied_matrix != expected_matrix or set(alignment_bindings) != expected_matrix:
            raise AnalyzerQualificationRejected("qualification case/analyzer matrix is incomplete")

        observation_sets: list[AnalyzerObservationSet] = []
        for binding in plan.execution_bindings:
            execution = plans.get(binding.execution_plan_id)
            registration = tools.get(binding.registration_id)
            outcome = results.get(binding.execution_plan_id)
            case = cases.get(binding.case_id)
            aligned = alignment_bindings.get((binding.case_id, binding.analyzer))
            if any(
                item is None for item in (execution, registration, outcome, case, aligned)
            ):
                raise AnalyzerQualificationRejected("qualification references an unknown input")
            assert execution is not None
            assert registration is not None
            assert outcome is not None
            assert case is not None
            assert aligned is not None
            try:
                recorded = self.execution_store.read_completed(binding.execution_plan_id)
            except AnalyzerDockerExecutionRecoveryRequired as exc:
                raise AnalyzerQualificationRejected(
                    "qualification requires an authoritative completed execution checkpoint"
                ) from exc
            if (
                binding.execution_plan_digest
                != canonical_digest(execution.model_dump(mode="python"))
                or binding.registration_digest
                != canonical_digest(registration.model_dump(mode="python"))
                or binding.execution_outcome_digest
                != canonical_digest(outcome.model_dump(mode="python"))
                or recorded != outcome
                or execution.registration_id != registration.registration_id
                or execution.registration_digest != binding.registration_digest
                or outcome.plan_id != execution.plan_id
                or outcome.registration_id != registration.registration_id
                or outcome.status is not DockerAnalyzerExecutionStatus.COMPLETED
                or outcome.import_outcome is None
                or not outcome.runner_result.cleanup.complete
                or execution.target_id != binding.target_id
                or execution.target_version != binding.target_version
                or execution.manifest_id != binding.manifest_id
                or execution.scope_id != binding.scope_id
                or execution.scope_version != binding.scope_version
                or outcome.target_id != binding.target_id
                or outcome.target_version != binding.target_version
                or registration.analyzer is not binding.analyzer
                or case.target_version != binding.target_version
            ):
                raise AnalyzerQualificationRejected("qualification execution provenance mismatch")
            observations = outcome.import_outcome.observation_set
            if (
                binding.observation_set_id != observations.observation_set_id
                or binding.observation_set_digest
                != canonical_digest(observations.model_dump(mode="python"))
                or observations.analyzer is not binding.analyzer
                or observations.target_id != binding.target_id
                or observations.target_version != binding.target_version
                or aligned.observation_set_id != binding.observation_set_id
                or aligned.observation_set_digest != binding.observation_set_digest
            ):
                raise AnalyzerQualificationRejected("qualification Observation binding mismatch")
            observation_sets.append(observations)

        evaluation_outcome = self.evaluation_service.evaluate(
            suite,
            tuple(observation_sets),
            alignment,
            evaluation_plan,
            now=now,
        )
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            if claim.outcome is None:
                raise RuntimeError("completed analyzer qualification has no outcome")
            return claim.outcome
        outcome = AnalyzerQualificationOutcome(
            plan_id=plan.plan_id,
            evaluation_plan_id=evaluation_plan.plan_id,
            evaluation_outcome=evaluation_outcome,
            execution_count=len(plan.execution_bindings),
            gate_status=evaluation_outcome.result.gate_status,
            completed_at=now,
        )
        self.store.complete(outcome)
        return outcome


def _unique(items: tuple[object, ...], attribute: str, label: str) -> dict[str, object]:
    values = {getattr(item, attribute): item for item in items}
    if len(values) != len(items):
        raise AnalyzerQualificationRejected(f"qualification {label} must be unique")
    return values
