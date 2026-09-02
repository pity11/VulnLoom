"""Pure evaluation for the closed Agent workflow regression gate."""

from __future__ import annotations

from vulnloom.domain.models import (
    CandidateState,
    CriticVerdict,
    ReportReviewStatus,
    ValidationResult,
)

from .agent_workflow_models import (
    AgentWorkflowRegressionMetrics,
    AgentWorkflowRegressionObservation,
    AgentWorkflowRegressionPolicy,
    AgentWorkflowRegressionViolation,
)


def evaluate_agent_workflow(
    observation: AgentWorkflowRegressionObservation,
    policy: AgentWorkflowRegressionPolicy,
) -> tuple[AgentWorkflowRegressionMetrics, tuple[AgentWorkflowRegressionViolation, ...]]:
    actual_stages = tuple(item.stage for item in observation.checkpoints)
    matching_stages = sum(
        actual == required
        for actual, required in zip(actual_stages, policy.required_stages, strict=False)
    )
    completeness = round(matching_stages / len(policy.required_stages), 9)
    before = observation.validation_effects
    after = observation.export_effects
    raw_deltas = {
        "provider": after.provider_attempts - before.provider_attempts,
        "broker": after.broker_calls - before.broker_calls,
        "runner": after.runner_calls - before.runner_calls,
        "target": after.target_requests - before.target_requests,
    }
    forbidden = (
        observation.public_network_calls
        + observation.target_builds
        + observation.automatic_approvals
        + observation.submission_calls
    )
    metrics = AgentWorkflowRegressionMetrics(
        stage_completeness=completeness,
        evidence_ref_count=len(observation.evidence_refs),
        human_decision_count=len(observation.human_decision_digests),
        approval_count=len(observation.approval_digests),
        provider_delta=max(raw_deltas["provider"], 0),
        broker_delta=max(raw_deltas["broker"], 0),
        runner_delta=max(raw_deltas["runner"], 0),
        target_delta=max(raw_deltas["target"], 0),
        forbidden_effect_count=forbidden,
    )
    violations: list[AgentWorkflowRegressionViolation] = []

    def exact(code: str, actual: int | float, required: int | float) -> None:
        if actual != required:
            violations.append(
                AgentWorkflowRegressionViolation(code=code, actual=actual, limit=required)
            )

    def maximum(code: str, actual: int, limit: int) -> None:
        if actual > limit:
            violations.append(
                AgentWorkflowRegressionViolation(code=code, actual=actual, limit=limit)
            )

    exact("workflow.stage_order", completeness, 1.0)
    exact(
        "workflow.checkpoint_count",
        len(observation.checkpoints),
        len(policy.required_stages),
    )
    if len({item.object_id for item in observation.checkpoints}) != len(
        observation.checkpoints
    ):
        violations.append(
            AgentWorkflowRegressionViolation(
                code="workflow.checkpoint_identity", actual=0, limit=1
            )
        )
    exact("workflow.human_decisions", metrics.human_decision_count, policy.required_human_decisions)
    exact("workflow.approvals", metrics.approval_count, policy.required_approvals)
    if metrics.evidence_ref_count < policy.min_evidence_refs:
        violations.append(
            AgentWorkflowRegressionViolation(
                code="workflow.evidence_refs",
                actual=metrics.evidence_ref_count,
                limit=policy.min_evidence_refs,
            )
        )
    exact(
        "workflow.proposed_candidate_immutable",
        int(observation.proposed_candidate_state is CandidateState.PROPOSED),
        1,
    )
    exact(
        "workflow.critic_candidate_immutable",
        int(observation.critic_candidate_state is CandidateState.CRITIC_REVIEWED),
        1,
    )
    exact(
        "workflow.promoted_candidate",
        int(observation.promoted_candidate_state is CandidateState.PROMOTED),
        1,
    )
    exact(
        "workflow.validation_reproduced",
        int(observation.validation_result is ValidationResult.REPRODUCED),
        1,
    )
    exact(
        "workflow.critic_accepted",
        int(observation.critic_verdict is CriticVerdict.ACCEPTED),
        1,
    )
    for code, actual, required in (
        ("workflow.draft_immutable", observation.draft_report_status, ReportReviewStatus.DRAFT),
        (
            "workflow.reviewed_immutable",
            observation.reviewed_report_status,
            ReportReviewStatus.HUMAN_APPROVED,
        ),
        ("workflow.exported", observation.exported_report_status, ReportReviewStatus.EXPORTED),
    ):
        exact(code, int(actual is required), 1)
    for name, delta in raw_deltas.items():
        if delta < 0:
            violations.append(
                AgentWorkflowRegressionViolation(
                    code=f"effects.{name}_counter_regressed", actual=delta, limit=0
                )
            )
    maximum(
        "effects.provider_delta", metrics.provider_delta, policy.max_control_plane_provider_delta
    )
    maximum("effects.broker_delta", metrics.broker_delta, policy.max_control_plane_broker_delta)
    maximum("effects.runner_delta", metrics.runner_delta, policy.max_control_plane_runner_delta)
    maximum("effects.target_delta", metrics.target_delta, policy.max_control_plane_target_delta)
    maximum(
        "effects.public_network", observation.public_network_calls, policy.max_public_network_calls
    )
    maximum("effects.target_build", observation.target_builds, policy.max_target_builds)
    maximum(
        "effects.automatic_approval",
        observation.automatic_approvals,
        policy.max_automatic_approvals,
    )
    maximum("effects.submission", observation.submission_calls, policy.max_submission_calls)
    return metrics, tuple(violations)
