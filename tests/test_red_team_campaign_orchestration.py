from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    ScopeState,
)
from vulnloom.red_team import (
    CampaignBudget,
    CampaignEvidenceClosure,
    CampaignEvidenceClosureDisposition,
    CampaignFlowQualificationBinding,
    CampaignGoal,
    CampaignGoalKind,
    CampaignOrchestrationLimits,
    CampaignOrchestrationOutcome,
    CampaignOrchestrationRecoveryRequired,
    CampaignOrchestrationRejected,
    CampaignOrchestrationService,
    CampaignOrchestrationState,
    CampaignOrchestrationStore,
    CampaignOrchestrationTimedOut,
    CampaignPhase,
    CampaignPhaseCheckpoint,
    CampaignPhaseKind,
    CampaignQualificationLimits,
    CampaignRuntimeQualificationLimits,
    CampaignRuntimeQualificationOutcome,
    CampaignRuntimeQualificationPlan,
    CampaignStopConditions,
    EvidenceAssertion,
    EvidenceAssessment,
    EvidenceAssessmentLimits,
    EvidenceAssessmentOutcome,
    EvidenceAssessmentPlan,
    EvidenceAssessmentVerdict,
    EvidenceFactVerdict,
    EvidenceRequirementStage,
    GoalDrivenCampaignPlan,
    GoalDrivenCampaignQualificationOutcome,
    RuntimeAssuranceLevel,
    VulnerabilityEvidenceRequirement,
    campaign_phase_admission_digest,
)


def _digest(number: int) -> str:
    return f"{number:064x}"


class _Source:
    def __init__(self, plan, outcome):
        self._plan = plan
        self._outcome = outcome

    def plan(self, plan_id):
        if plan_id not in {
            getattr(self._plan, "campaign_plan_id", None),
            getattr(self._plan, "runtime_plan_id", None),
            getattr(self._plan, "plan_id", None),
        }:
            raise KeyError(plan_id)
        return self._plan

    def outcome(self, plan_id):
        self.plan(plan_id)
        return self._outcome


def _campaign(scope, now):
    bindings = tuple(
        CampaignFlowQualificationBinding.create(
            flow_plan_id=_digest(10 + index),
            target_id=uuid4(),
            scope_id=scope.scope_id,
            scope_version=scope.version,
            adaptive_plan_id=_digest(20 + index),
            adaptive_outcome_id=_digest(30 + index),
            coverage_ledger_id=_digest(40 + index),
            runtime_plan_id=_digest(50 + index),
            runtime_outcome_id=_digest(60 + index),
            runtime_outcome_digest=_digest(70 + index),
            assurance_level=RuntimeAssuranceLevel.LOCAL_DOCKER,
        )
        for index in (1, 2)
    )
    phases = []
    previous = None
    for ordinal, kind in enumerate(CampaignPhaseKind, start=1):
        phase = CampaignPhase.create(
            ordinal=ordinal,
            kind=kind,
            prerequisite_phase_ids=(() if previous is None else (previous.phase_id,)),
            max_flow_materializations=1,
            max_actions=1,
            wall_seconds=60,
        )
        phases.append(phase)
        previous = phase
    goal = CampaignGoal.create(
        kind=CampaignGoalKind.EVIDENCE_REQUIREMENT_SATISFACTION,
        statement_digest=_digest(80),
        required_evidence_classes=("critic_review", "independent_validation"),
    )
    plan = GoalDrivenCampaignPlan.create(
        goal=goal,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        target_ids=tuple(sorted((item.target_id for item in bindings), key=str)),
        flow_bindings=tuple(sorted(bindings, key=lambda item: item.flow_plan_id)),
        phases=tuple(phases),
        budget=CampaignBudget(
            max_flow_materializations=12,
            max_actions=12,
            wall_seconds=600,
            max_consecutive_failures=2,
        ),
        stop_conditions=CampaignStopConditions(),
        limits=CampaignQualificationLimits(),
        created_at=now - timedelta(minutes=5),
        deadline=now + timedelta(minutes=20),
        idempotency_key="b5.5:campaign",
    )
    outcome = GoalDrivenCampaignQualificationOutcome.create(
        campaign_plan_id=plan.campaign_plan_id,
        goal_id=plan.goal.goal_id,
        flow_binding_ids=tuple(item.binding_id for item in plan.flow_bindings),
        target_ids=plan.target_ids,
        minimum_assurance_level=RuntimeAssuranceLevel.LOCAL_DOCKER,
        attempt=1,
        completed_at=now - timedelta(minutes=4),
    )
    return plan, outcome


def _runtime(campaign_plan, campaign_outcome, scope, now):
    plan = CampaignRuntimeQualificationPlan.create(
        campaign_plan_id=campaign_plan.campaign_plan_id,
        campaign_plan_digest=canonical_digest(campaign_plan.model_dump(mode="python")),
        campaign_outcome_id=campaign_outcome.outcome_id,
        campaign_outcome_digest=canonical_digest(campaign_outcome.model_dump(mode="python")),
        goal_id=campaign_plan.goal.goal_id,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        target_set_digest=canonical_digest(campaign_plan.target_ids),
        phase_graph_digest=canonical_digest(
            tuple(item.model_dump(mode="python") for item in campaign_plan.phases)
        ),
        required_phase_ids=tuple(item.phase_id for item in campaign_plan.phases),
        image_digest="sha256:" + "1" * 64,
        sandbox_profile_digest=_digest(90),
        hostile_worker_plan_id=_digest(91),
        hostile_worker_outcome_id=_digest(92),
        hostile_worker_outcome_digest=_digest(93),
        resource_pressure_plan_id=_digest(94),
        resource_pressure_outcome_id=_digest(95),
        resource_pressure_outcome_digest=_digest(96),
        limits=CampaignRuntimeQualificationLimits(),
        created_at=now - timedelta(minutes=3),
        deadline=now + timedelta(minutes=15),
        idempotency_key="b5.5:runtime",
    )
    outcome = CampaignRuntimeQualificationOutcome.create(
        runtime_plan_id=plan.runtime_plan_id,
        campaign_plan_id=campaign_plan.campaign_plan_id,
        campaign_outcome_id=campaign_outcome.outcome_id,
        phase_observation_ids=tuple(_digest(100 + item) for item in range(6)),
        stop_observation_ids=(_digest(110), _digest(111)),
        assurance_level=RuntimeAssuranceLevel.LOCAL_DOCKER,
        attempt=1,
        completed_at=now - timedelta(minutes=2),
        production_campaign_runtime_admitted=False,
    )
    return plan, outcome


def _assessment(campaign_plan, scope, now, *, cleanup=True):
    requirement = VulnerabilityEvidenceRequirement.create()
    facts = (
        *requirement.observation_facts,
        *requirement.validation_facts,
        *requirement.counterevidence_facts,
        *requirement.cleanup_facts,
    )
    assertions = tuple(
        sorted(
            (
                EvidenceAssertion.create(
                    requirement_id=requirement.requirement_id,
                    stage=(
                        EvidenceRequirementStage.OBSERVATION
                        if fact in requirement.observation_facts
                        else EvidenceRequirementStage.VALIDATION
                        if fact in requirement.validation_facts
                        else EvidenceRequirementStage.CRITIC
                        if fact in requirement.counterevidence_facts
                        else EvidenceRequirementStage.CLEANUP
                    ),
                    fact=fact,
                    verdict=(
                        EvidenceFactVerdict.REFUTED
                        if fact in requirement.counterevidence_facts
                        else EvidenceFactVerdict.SUPPORTED
                    ),
                    evidence_refs=(_digest(200 + index),),
                    producer_ref=(
                        "critic:counterevidence-review-v1"
                        if fact in requirement.counterevidence_facts
                        else "validator:sealed-get-replay-v1"
                        if fact in requirement.validation_facts
                        else "control-plane:sealed-get-v1"
                    ),
                    context_id=(
                        _digest(301)
                        if fact in requirement.counterevidence_facts
                        else _digest(302)
                        if fact in requirement.validation_facts
                        else _digest(303)
                    ),
                    observed_at=now - timedelta(minutes=2),
                )
                for index, fact in enumerate(facts)
                if cleanup or fact not in requirement.cleanup_facts
            ),
            key=lambda item: item.assertion_id,
        )
    )
    plan = EvidenceAssessmentPlan.create(
        requirement=requirement,
        target_id=campaign_plan.target_ids[0],
        target_version=_digest(310),
        scope_id=scope.scope_id,
        scope_version=scope.version,
        assertions=assertions,
        limits=EvidenceAssessmentLimits(),
        created_at=now - timedelta(minutes=2),
        deadline=now + timedelta(minutes=10),
        idempotency_key="b5.5:assessment",
    )
    included_facts = tuple(item.fact for item in assertions)
    verdict = (
        EvidenceAssessmentVerdict.CANDIDATE_ELIGIBLE
        if cleanup
        else EvidenceAssessmentVerdict.INCONCLUSIVE
    )
    assessment = EvidenceAssessment.create(
        plan_id=plan.plan_id,
        requirement_id=requirement.requirement_id,
        verdict=verdict,
        satisfied_facts=tuple(sorted(included_facts, key=lambda item: item.value)),
        counterevidence_facts=(),
        unresolved_facts=(
            () if cleanup else tuple(sorted(requirement.cleanup_facts, key=lambda item: item.value))
        ),
        evidence_refs=tuple(sorted({ref for item in assertions for ref in item.evidence_refs})),
        cleanup_requirement_satisfied=cleanup,
        candidate_proposal_eligible=cleanup,
        assessed_at=now - timedelta(minutes=1),
    )
    return plan, EvidenceAssessmentOutcome(
        plan_id=plan.plan_id,
        assessment=assessment,
        attempt=1,
    )


def _runtime_bundle(scope, now, *, cleanup=True, after_phase=None, monotonic=None):
    campaign_plan, campaign_outcome = _campaign(scope, now)
    runtime_plan, runtime_outcome = _runtime(campaign_plan, campaign_outcome, scope, now)
    assessment_plan, assessment_outcome = _assessment(campaign_plan, scope, now, cleanup=cleanup)
    connection = sqlite3.connect(":memory:")
    store = CampaignOrchestrationStore(connection)
    service = CampaignOrchestrationService(
        campaign_source=_Source(campaign_plan, campaign_outcome),
        runtime_source=_Source(runtime_plan, runtime_outcome),
        assessment_source=_Source(assessment_plan, assessment_outcome),
        store=store,
        after_phase=after_phase,
        **({"monotonic": monotonic} if monotonic is not None else {}),
    )
    return (
        service,
        store,
        connection,
        campaign_plan,
        runtime_plan,
        assessment_plan,
    )


def _prepare(service, campaign_plan, runtime_plan, assessment_plan, scope, now):
    return service.prepare(
        campaign_plan_id=campaign_plan.campaign_plan_id,
        runtime_plan_id=runtime_plan.runtime_plan_id,
        evidence_assessment_plan_id=assessment_plan.plan_id,
        scope=scope,
        limits=CampaignOrchestrationLimits(),
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="b5.5:orchestration",
    )


def _approvals(plan, scope, now):
    return tuple(
        ApprovalRequest(
            engagement_id=scope.engagement_id,
            target_id=plan.evidence_target_id,
            action=ApprovalAction.ADVANCE_CAMPAIGN_PHASE,
            action_digest=campaign_phase_admission_digest(
                plan.orchestration_plan_id, phase_id, ordinal
            ),
            expected_side_effects=(),
            evidence_summary=f"phase {ordinal} control-plane admission",
            policy_version=scope.version,
            expires_at=now + timedelta(minutes=5),
            status=ApprovalStatus.GRANTED,
            decided_by="operator",
            decided_at=now - timedelta(seconds=7 - ordinal),
        )
        for ordinal, phase_id in enumerate(plan.phase_ids, start=1)
    )


def test_campaign_orchestration_closes_as_unresolved_without_authority(approved_scope, now):
    service, store, connection, campaign_plan, runtime_plan, assessment_plan = _runtime_bundle(
        approved_scope, now
    )
    plan = _prepare(service, campaign_plan, runtime_plan, assessment_plan, approved_scope, now)
    outcome = service.execute(
        plan,
        approvals=_approvals(plan, approved_scope, now),
        scope=approved_scope,
        now=now,
    )
    assert outcome.closure.disposition is CampaignEvidenceClosureDisposition.UNRESOLVED_CANDIDATE
    assert outcome.closure.unresolved_candidate_recorded is True
    assert outcome.closure.candidate_created is False
    assert outcome.closure.finding_created is False
    assert outcome.closure.action_execution_authority_granted is False
    assert outcome.closure.submission_granted is False
    assert store.state(plan.orchestration_plan_id) == (
        CampaignOrchestrationState.COMPLETED,
        1,
        6,
    )
    assert (
        service.execute(
            plan,
            approvals=_approvals(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
        == outcome
    )
    connection.close()


def test_phase_approval_is_exact_and_cannot_reuse_runtime_qualification_approval(
    approved_scope, now
):
    service, store, connection, campaign_plan, runtime_plan, assessment_plan = _runtime_bundle(
        approved_scope, now
    )
    plan = _prepare(service, campaign_plan, runtime_plan, assessment_plan, approved_scope, now)
    approvals = list(_approvals(plan, approved_scope, now))
    approvals[2] = approvals[2].model_copy(update={"action_digest": plan.phase_ids[2]})
    with pytest.raises(CampaignOrchestrationRejected, match="six distinct|invalid"):
        service.execute(
            plan,
            approvals=tuple(approvals),
            scope=approved_scope,
            now=now,
        )
    assert store.state(plan.orchestration_plan_id) is None
    connection.close()


def test_scope_plan_source_and_approval_drift_fail_before_checkpoint(
    approved_scope, now
):
    service, store, connection, campaign_plan, runtime_plan, assessment_plan = (
        _runtime_bundle(approved_scope, now)
    )
    plan = _prepare(
        service, campaign_plan, runtime_plan, assessment_plan, approved_scope, now
    )
    approvals = _approvals(plan, approved_scope, now)

    revoked = approved_scope.model_copy(update={"state": ScopeState.REVOKED})
    with pytest.raises(CampaignOrchestrationRejected, match="approved Scope"):
        service.execute(plan, approvals=approvals, scope=revoked, now=now)

    with pytest.raises(CampaignOrchestrationRejected, match="not active"):
        service.execute(
            plan,
            approvals=approvals,
            scope=approved_scope,
            now=plan.deadline,
        )

    disordered = list(approvals)
    disordered[1] = disordered[1].model_copy(
        update={"decided_at": disordered[0].decided_at}
    )
    with pytest.raises(CampaignOrchestrationRejected, match="temporally ordered"):
        service.execute(
            plan,
            approvals=tuple(disordered),
            scope=approved_scope,
            now=now,
        )

    runtime_outcome = service.runtime_source._outcome
    service.runtime_source._outcome = runtime_outcome.model_copy(
        update={"completed_at": now}
    )
    with pytest.raises(CampaignOrchestrationRejected, match="source binding drifted"):
        service.execute(plan, approvals=approvals, scope=approved_scope, now=now)
    assert store.state(plan.orchestration_plan_id) is None
    connection.close()


def test_checkpoint_resume_is_bounded_and_does_not_repeat_completed_phases(approved_scope, now):
    seen = []

    def interrupt(checkpoint):
        seen.append(checkpoint.ordinal)
        if checkpoint.ordinal == 3:
            raise RuntimeError("fixture interruption")

    service, store, connection, campaign_plan, runtime_plan, assessment_plan = _runtime_bundle(
        approved_scope, now, after_phase=interrupt
    )
    plan = _prepare(service, campaign_plan, runtime_plan, assessment_plan, approved_scope, now)
    approvals = _approvals(plan, approved_scope, now)
    with pytest.raises(RuntimeError, match="fixture interruption"):
        service.execute(plan, approvals=approvals, scope=approved_scope, now=now)
    assert store.state(plan.orchestration_plan_id) == (
        CampaignOrchestrationState.STARTED,
        1,
        3,
    )
    service.after_phase = None
    outcome = service.execute(plan, approvals=approvals, scope=approved_scope, now=now)
    assert outcome.attempt == 2
    assert store.state(plan.orchestration_plan_id) == (
        CampaignOrchestrationState.COMPLETED,
        2,
        6,
    )
    connection.close()


def test_timeout_and_cleanup_unknown_fail_closed(approved_scope, now):
    ticks = iter((0.0, 11.0))
    service, store, connection, campaign_plan, runtime_plan, assessment_plan = _runtime_bundle(
        approved_scope, now, monotonic=lambda: next(ticks)
    )
    plan = _prepare(service, campaign_plan, runtime_plan, assessment_plan, approved_scope, now)
    with pytest.raises(CampaignOrchestrationTimedOut):
        service.execute(
            plan,
            approvals=_approvals(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    assert store.state(plan.orchestration_plan_id) is None
    connection.close()

    service, store, connection, campaign_plan, runtime_plan, assessment_plan = _runtime_bundle(
        approved_scope, now, cleanup=False
    )
    with pytest.raises(CampaignOrchestrationRejected, match="source binding"):
        _prepare(service, campaign_plan, runtime_plan, assessment_plan, approved_scope, now)
    connection.close()


def test_recovery_exhaustion_and_schema_authority_regression(approved_scope, now):
    def interrupt(_checkpoint):
        raise RuntimeError("fixture interruption")

    service, store, connection, campaign_plan, runtime_plan, assessment_plan = _runtime_bundle(
        approved_scope, now, after_phase=interrupt
    )
    plan = _prepare(service, campaign_plan, runtime_plan, assessment_plan, approved_scope, now)
    approvals = _approvals(plan, approved_scope, now)
    for _ in range(3):
        with pytest.raises(RuntimeError, match="fixture interruption"):
            service.execute(plan, approvals=approvals, scope=approved_scope, now=now)
    with pytest.raises(CampaignOrchestrationRecoveryRequired, match="exhausted"):
        service.execute(plan, approvals=approvals, scope=approved_scope, now=now)

    schemas = json.dumps(
        {
            model.__name__: model.model_json_schema()
            for model in (
                type(plan),
                CampaignPhaseCheckpoint,
                CampaignEvidenceClosure,
                CampaignOrchestrationOutcome,
            )
        },
    ).lower()
    for forbidden in (
        "target_url",
        "cookie",
        "password",
        "model_token",
        "docker_socket",
        "raw_response",
        "payload",
    ):
        assert forbidden not in schemas
    with pytest.raises(ValidationError):
        type(plan).model_validate(
            plan.model_dump(mode="python")
            | {
                "action_execution_requested": True,
                "candidate_creation_requested": True,
                "finding_creation_requested": True,
            }
        )
    connection.close()
