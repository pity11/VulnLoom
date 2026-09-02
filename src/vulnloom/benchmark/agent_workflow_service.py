"""Trusted offline orchestration for Agent workflow regression qualification."""

from __future__ import annotations

from datetime import datetime
from uuid import NAMESPACE_URL, uuid5

from vulnloom.domain.digests import canonical_digest

from .agent_workflow_evaluator import evaluate_agent_workflow
from .agent_workflow_models import (
    AgentWorkflowRegressionObservation,
    AgentWorkflowRegressionOutcome,
    AgentWorkflowRegressionPlan,
    AgentWorkflowRegressionResult,
)
from .agent_workflow_store import (
    AgentWorkflowRegressionArtifactStore,
    AgentWorkflowRegressionStore,
)
from .models import BenchmarkGateStatus


class AgentWorkflowRegressionRejected(ValueError):
    pass


class AgentWorkflowRegressionTimedOut(TimeoutError):
    pass


class AgentWorkflowRegressionService:
    def __init__(
        self,
        *,
        store: AgentWorkflowRegressionStore,
        artifact_store: AgentWorkflowRegressionArtifactStore,
    ):
        self.store = store
        self.artifact_store = artifact_store

    def evaluate(
        self,
        plan: AgentWorkflowRegressionPlan,
        observation: AgentWorkflowRegressionObservation,
        *,
        now: datetime,
    ) -> AgentWorkflowRegressionOutcome:
        if now < plan.created_at or now >= plan.deadline:
            raise AgentWorkflowRegressionTimedOut(
                "Agent workflow regression is outside its window"
            )
        if (
            plan.observation_id != observation.observation_id
            or plan.observation_digest
            != canonical_digest(observation.model_dump(mode="python"))
        ):
            raise AgentWorkflowRegressionRejected(
                "Agent workflow regression observation drifted"
            )
        metrics, violations = evaluate_agent_workflow(observation, plan.policy)
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.outcome is not None
            self.artifact_store.read_result(claim.outcome.artifact)
            return claim.outcome
        result = AgentWorkflowRegressionResult(
            result_id=uuid5(
                NAMESPACE_URL, f"vulnloom:agent-workflow-regression:{plan.plan_id}"
            ),
            plan_id=plan.plan_id,
            observation_id=observation.observation_id,
            metrics=metrics,
            gate_status=(BenchmarkGateStatus.FAILED if violations else BenchmarkGateStatus.PASSED),
            violations=violations,
            completed_at=now,
        )
        artifact = self.artifact_store.put(result)
        outcome = AgentWorkflowRegressionOutcome(
            plan_id=plan.plan_id, result=result, artifact=artifact
        )
        self.store.complete(outcome, now=now)
        return outcome
