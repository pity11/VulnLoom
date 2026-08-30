"""Trusted orchestration for offline analyzer benchmark evaluation."""

from __future__ import annotations

from datetime import datetime
from uuid import NAMESPACE_URL, uuid5

from vulnloom.domain.digests import canonical_digest

from .analyzer_evaluation_models import (
    AnalyzerEvaluationOutcome,
    AnalyzerEvaluationPlan,
    AnalyzerEvaluationResult,
    AnalyzerTruthAlignment,
)
from .analyzer_evaluation_store import (
    AnalyzerEvaluationArtifactStore,
    AnalyzerEvaluationStore,
)
from .analyzer_evaluator import (
    AnalyzerEvaluationRejected,
    EvaluationDeadline,
    evaluate_analyzer_metrics,
    evaluate_analyzer_regressions,
)
from .analyzer_models import AnalyzerObservationSet
from .models import BenchmarkGateStatus, BenchmarkSuite


class AnalyzerEvaluationService:
    def __init__(
        self,
        *,
        store: AnalyzerEvaluationStore,
        artifact_store: AnalyzerEvaluationArtifactStore,
    ):
        self.store = store
        self.artifact_store = artifact_store

    def evaluate(
        self,
        suite: BenchmarkSuite,
        observation_sets: tuple[AnalyzerObservationSet, ...],
        alignment: AnalyzerTruthAlignment,
        plan: AnalyzerEvaluationPlan,
        *,
        now: datetime,
    ) -> AnalyzerEvaluationOutcome:
        if now < plan.created_at or now >= plan.deadline:
            raise AnalyzerEvaluationRejected("analyzer evaluation plan is not active")
        if (
            plan.suite_id != suite.suite_id
            or plan.suite_digest != canonical_digest(suite.model_dump(mode="python"))
            or plan.alignment_id != alignment.alignment_id
            or plan.alignment_digest != canonical_digest(alignment.model_dump(mode="python"))
        ):
            raise AnalyzerEvaluationRejected("analyzer evaluation plan input binding mismatch")
        available_seconds = min(
            plan.limits.timeout_seconds,
            max(0.001, (plan.deadline - now).total_seconds()),
        )
        deadline = EvaluationDeadline(available_seconds)
        metrics = evaluate_analyzer_metrics(
            suite,
            observation_sets,
            alignment,
            limits=plan.limits,
            deadline=deadline,
        )
        violations = evaluate_analyzer_regressions(metrics, alignment, plan.policy, plan.baseline)
        deadline.check()

        claim = self.store.claim(plan, now=now)
        if not claim.created:
            if claim.outcome is None:
                raise RuntimeError("completed analyzer evaluation checkpoint has no outcome")
            self.artifact_store.read_result(claim.outcome.artifact)
            return claim.outcome

        result = AnalyzerEvaluationResult(
            result_id=uuid5(NAMESPACE_URL, f"vulnloom:analyzer-evaluation-result:{plan.plan_id}"),
            plan_id=plan.plan_id,
            suite_id=suite.suite_id,
            alignment_id=alignment.alignment_id,
            metrics=metrics,
            gate_status=(BenchmarkGateStatus.FAILED if violations else BenchmarkGateStatus.PASSED),
            violations=violations,
            completed_at=now,
        )
        artifact = self.artifact_store.put(result)
        outcome = AnalyzerEvaluationOutcome(
            plan_id=plan.plan_id,
            result=result,
            artifact=artifact,
        )
        self.store.complete(outcome, completed_at=now)
        return outcome
