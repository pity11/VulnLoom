"""Trusted offline benchmark orchestration."""

from __future__ import annotations

from datetime import datetime
from uuid import NAMESPACE_URL, uuid5

from vulnloom.domain.digests import canonical_digest

from .evaluator import BenchmarkRejected, evaluate_metrics, evaluate_regressions
from .models import (
    BenchmarkGateStatus,
    BenchmarkObservationSet,
    BenchmarkOutcome,
    BenchmarkPlan,
    BenchmarkResult,
    BenchmarkSuite,
)
from .store import BenchmarkArtifactStore, BenchmarkStore


class BenchmarkService:
    def __init__(self, *, store: BenchmarkStore, artifact_store: BenchmarkArtifactStore):
        self.store = store
        self.artifact_store = artifact_store

    def evaluate(
        self,
        suite: BenchmarkSuite,
        observations: BenchmarkObservationSet,
        plan: BenchmarkPlan,
        *,
        now: datetime,
    ) -> BenchmarkOutcome:
        if now < plan.created_at or now >= plan.deadline:
            raise BenchmarkRejected("BenchmarkPlan is not active at evaluation time")
        if (
            plan.suite_id != suite.suite_id
            or plan.suite_digest != canonical_digest(suite.model_dump(mode="python"))
            or observations.suite_id != suite.suite_id
            or plan.observation_set_id != observations.observation_set_id
            or plan.observation_set_digest
            != canonical_digest(observations.model_dump(mode="python"))
        ):
            raise BenchmarkRejected("Benchmark plan input binding mismatch")

        # Validate all sealed semantic references before creating a durable checkpoint.
        metrics = evaluate_metrics(suite, observations)
        violations = evaluate_regressions(metrics, plan.policy, plan.baseline)

        claim = self.store.claim(plan, now=now)
        if not claim.created:
            if claim.outcome is None:
                raise RuntimeError("completed benchmark checkpoint has no outcome")
            self.artifact_store.read_result(claim.outcome.artifact)
            return claim.outcome

        result = BenchmarkResult(
            result_id=uuid5(NAMESPACE_URL, f"vulnloom:benchmark-result:{plan.plan_id}"),
            plan_id=plan.plan_id,
            suite_id=suite.suite_id,
            observation_set_id=observations.observation_set_id,
            metrics=metrics,
            gate_status=(BenchmarkGateStatus.FAILED if violations else BenchmarkGateStatus.PASSED),
            violations=violations,
            completed_at=now,
        )
        artifact = self.artifact_store.put(result)
        outcome = BenchmarkOutcome(plan_id=plan.plan_id, result=result, artifact=artifact)
        self.store.complete(outcome, completed_at=now)
        return outcome
