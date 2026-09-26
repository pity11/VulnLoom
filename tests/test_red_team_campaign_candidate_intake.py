from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from uuid import NAMESPACE_URL, uuid4, uuid5

import pytest
from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    CandidateState,
    ScopeState,
)
from vulnloom.red_team.campaign_candidate_models import (
    CampaignCandidate,
    CampaignCandidateIntakeLimits,
    CampaignCandidateIntakeOutcome,
    CampaignCandidateIntakePlan,
    CampaignCandidateIntakeState,
)
from vulnloom.red_team.campaign_candidate_service import (
    CampaignCandidateIntakeRejected,
    CampaignCandidateIntakeService,
    CampaignCandidateIntakeTimedOut,
)
from vulnloom.red_team.campaign_candidate_store import (
    CampaignCandidateIntakeRecoveryRequired,
    CampaignCandidateIntakeStore,
    CampaignCandidateIntakeStoreRejected,
)
from vulnloom.red_team.campaign_orchestration_models import (
    CampaignEvidenceClosure,
    CampaignEvidenceClosureDisposition,
    CampaignOrchestrationLimits,
    CampaignOrchestrationOutcome,
    CampaignOrchestrationPlan,
)
from vulnloom.red_team.evidence_requirement_models import (
    EvidenceAssertion,
    EvidenceAssessment,
    EvidenceAssessmentLimits,
    EvidenceAssessmentOutcome,
    EvidenceAssessmentPlan,
    EvidenceAssessmentVerdict,
    EvidenceFactVerdict,
    EvidenceRequirementStage,
    VulnerabilityEvidenceRequirement,
)


def _digest(number: int) -> str:
    return f"{number:064x}"


class _Source:
    def __init__(self, plan, outcome):
        self._plan = plan
        self._outcome = outcome

    def plan(self, plan_id):
        identity = getattr(
            self._plan,
            "orchestration_plan_id",
            getattr(self._plan, "plan_id", None),
        )
        if plan_id != identity:
            raise KeyError(plan_id)
        return self._plan

    def outcome(self, plan_id):
        self.plan(plan_id)
        return self._outcome


def _assessment(scope, target_id, now):
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
                    evidence_refs=(_digest(100 + index),),
                    producer_ref=(
                        "critic:counterevidence-review-v1"
                        if fact in requirement.counterevidence_facts
                        else "validator:sealed-get-replay-v1"
                        if fact in requirement.validation_facts
                        else "control-plane:sealed-get-v1"
                    ),
                    context_id=(
                        _digest(201)
                        if fact in requirement.counterevidence_facts
                        else _digest(202)
                        if fact in requirement.validation_facts
                        else _digest(203)
                    ),
                    observed_at=now - timedelta(minutes=3),
                )
                for index, fact in enumerate(facts)
            ),
            key=lambda item: item.assertion_id,
        )
    )
    plan = EvidenceAssessmentPlan.create(
        requirement=requirement,
        target_id=target_id,
        target_version=_digest(210),
        scope_id=scope.scope_id,
        scope_version=scope.version,
        assertions=assertions,
        limits=EvidenceAssessmentLimits(),
        created_at=now - timedelta(minutes=3),
        deadline=now + timedelta(minutes=10),
        idempotency_key="b5.6:assessment",
    )
    assessment = EvidenceAssessment.create(
        plan_id=plan.plan_id,
        requirement_id=requirement.requirement_id,
        verdict=EvidenceAssessmentVerdict.CANDIDATE_ELIGIBLE,
        satisfied_facts=tuple(sorted(facts, key=lambda item: item.value)),
        counterevidence_facts=(),
        unresolved_facts=(),
        evidence_refs=tuple(sorted({ref for item in assertions for ref in item.evidence_refs})),
        cleanup_requirement_satisfied=True,
        candidate_proposal_eligible=True,
        assessed_at=now - timedelta(minutes=2),
    )
    return plan, EvidenceAssessmentOutcome(
        plan_id=plan.plan_id,
        assessment=assessment,
        attempt=1,
    )


def _orchestration(scope, assessment_plan, assessment_outcome, now):
    target_ids = tuple(sorted((assessment_plan.target_id, uuid4()), key=str))
    plan = CampaignOrchestrationPlan.create(
        campaign_plan_id=_digest(1),
        campaign_plan_digest=_digest(2),
        campaign_outcome_id=_digest(3),
        campaign_outcome_digest=_digest(4),
        runtime_plan_id=_digest(5),
        runtime_plan_digest=_digest(6),
        runtime_outcome_id=_digest(7),
        runtime_outcome_digest=_digest(8),
        goal_id=_digest(9),
        scope_id=scope.scope_id,
        scope_version=scope.version,
        target_ids=target_ids,
        target_set_digest=canonical_digest(target_ids),
        phase_ids=tuple(_digest(20 + index) for index in range(6)),
        phase_graph_digest=_digest(30),
        evidence_assessment_plan_id=assessment_plan.plan_id,
        evidence_assessment_plan_digest=canonical_digest(assessment_plan.model_dump(mode="python")),
        evidence_assessment_id=assessment_outcome.assessment.assessment_id,
        evidence_assessment_outcome_digest=canonical_digest(
            assessment_outcome.model_dump(mode="python")
        ),
        evidence_requirement_id=assessment_plan.requirement.requirement_id,
        evidence_target_id=assessment_plan.target_id,
        evidence_target_version=assessment_plan.target_version,
        limits=CampaignOrchestrationLimits(),
        created_at=now - timedelta(minutes=2),
        deadline=now + timedelta(minutes=5),
        idempotency_key="b5.6:orchestration",
    )
    closure = CampaignEvidenceClosure.create(
        orchestration_plan_id=plan.orchestration_plan_id,
        campaign_plan_id=plan.campaign_plan_id,
        runtime_outcome_id=plan.runtime_outcome_id,
        evidence_assessment_id=assessment_outcome.assessment.assessment_id,
        evidence_requirement_id=assessment_outcome.assessment.requirement_id,
        disposition=CampaignEvidenceClosureDisposition.UNRESOLVED_CANDIDATE,
        assessment_verdict=EvidenceAssessmentVerdict.CANDIDATE_ELIGIBLE,
        phase_checkpoint_ids=tuple(_digest(40 + index) for index in range(6)),
        evidence_refs=assessment_outcome.assessment.evidence_refs,
        unresolved_candidate_recorded=True,
        closed_at=now - timedelta(minutes=1),
    )
    return plan, CampaignOrchestrationOutcome(
        orchestration_plan_id=plan.orchestration_plan_id,
        closure=closure,
        attempt=1,
    )


def _bundle(scope, now, *, monotonic=None, after_claim=None):
    target_id = uuid4()
    assessment_plan, assessment_outcome = _assessment(scope, target_id, now)
    orchestration_plan, orchestration_outcome = _orchestration(
        scope, assessment_plan, assessment_outcome, now
    )
    connection = sqlite3.connect(":memory:")
    store = CampaignCandidateIntakeStore(connection)
    service = CampaignCandidateIntakeService(
        orchestration_source=_Source(orchestration_plan, orchestration_outcome),
        evidence_source=_Source(assessment_plan, assessment_outcome),
        store=store,
        after_claim=after_claim,
        **({"monotonic": monotonic} if monotonic is not None else {}),
    )
    return service, store, connection, orchestration_plan


def _prepare(service, orchestration_plan, scope, now):
    return service.prepare(
        orchestration_plan_id=orchestration_plan.orchestration_plan_id,
        scope=scope,
        limits=CampaignCandidateIntakeLimits(),
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="b5.6:intake",
    )


def _approval(plan, scope, now, *, status=ApprovalStatus.GRANTED):
    return ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=plan.target_id,
        action=ApprovalAction.CREATE_CAMPAIGN_CANDIDATE,
        action_digest=plan.intake_plan_id,
        expected_side_effects=("create proposed campaign candidate",),
        evidence_summary="reviewed unresolved campaign evidence closure",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=5),
        status=status,
        decided_by="operator",
        decided_at=now,
    )


def test_human_approval_materializes_only_a_proposed_campaign_candidate(approved_scope, now):
    service, store, connection, orchestration_plan = _bundle(approved_scope, now)
    plan = _prepare(service, orchestration_plan, approved_scope, now)
    approval = _approval(plan, approved_scope, now)
    outcome = service.execute(plan, approval=approval, scope=approved_scope, now=now)
    candidate = outcome.candidate
    assert candidate.state is CandidateState.PROPOSED
    assert candidate.validation_required is True
    assert candidate.independent_critic_required is True
    assert candidate.prior_campaign_evidence_is_validation_run is False
    assert candidate.finding_authorized is False
    assert outcome.validation_started is False
    assert outcome.finding_created is False
    assert store.candidate(candidate.candidate_id) == candidate
    assert store.plan(plan.intake_plan_id) == plan
    assert store.outcome(plan.intake_plan_id) == outcome
    assert store.state(plan.intake_plan_id) == (
        CampaignCandidateIntakeState.COMPLETED,
        1,
    )
    assert service.execute(plan, approval=approval, scope=approved_scope, now=now) == outcome

    second_closure = _digest(888)
    values = plan.model_dump(mode="python", exclude={"intake_plan_id"})
    values["limits"] = plan.limits
    values.update(
        {
            "closure_id": second_closure,
            "candidate_id": uuid5(
                NAMESPACE_URL,
                f"vulnloom:campaign-candidate:{second_closure}",
            ),
            "idempotency_key": "b5.6:duplicate-fingerprint",
        }
    )
    duplicate = CampaignCandidateIntakePlan.create(**values)
    with pytest.raises(CampaignCandidateIntakeStoreRejected, match="identity"):
        store.claim(duplicate, now=now)
    connection.close()


def test_denied_or_wrong_approval_cannot_create_candidate(approved_scope, now):
    service, store, connection, orchestration_plan = _bundle(approved_scope, now)
    plan = _prepare(service, orchestration_plan, approved_scope, now)
    denied = _approval(plan, approved_scope, now, status=ApprovalStatus.DENIED)
    with pytest.raises(CampaignCandidateIntakeRejected, match="Approval"):
        service.execute(plan, approval=denied, scope=approved_scope, now=now)
    wrong = _approval(plan, approved_scope, now).model_copy(update={"action_digest": _digest(999)})
    with pytest.raises(CampaignCandidateIntakeRejected, match="Approval"):
        service.execute(plan, approval=wrong, scope=approved_scope, now=now)
    assert store.state(plan.intake_plan_id) is None
    with pytest.raises(KeyError):
        store.candidate(plan.candidate_id)
    connection.close()


def test_scope_cleanup_and_source_drift_fail_before_candidate(approved_scope, now):
    service, store, connection, orchestration_plan = _bundle(approved_scope, now)
    plan = _prepare(service, orchestration_plan, approved_scope, now)
    approval = _approval(plan, approved_scope, now)

    revoked = approved_scope.model_copy(update={"state": ScopeState.REVOKED})
    with pytest.raises(CampaignCandidateIntakeRejected, match="approved Scope"):
        service.execute(plan, approval=approval, scope=revoked, now=now)

    closure = service.orchestration_source._outcome.closure.model_copy(
        update={"cleanup_complete": False}
    )
    service.orchestration_source._outcome = service.orchestration_source._outcome.model_copy(
        update={"closure": closure}
    )
    with pytest.raises(CampaignCandidateIntakeRejected, match="source binding"):
        service.execute(plan, approval=approval, scope=approved_scope, now=now)
    assert store.state(plan.intake_plan_id) is None
    connection.close()

    service, store, connection, orchestration_plan = _bundle(approved_scope, now)
    plan = _prepare(service, orchestration_plan, approved_scope, now)
    values = plan.model_dump(mode="python", exclude={"intake_plan_id"})
    values["limits"] = plan.limits
    values["hypothesis_digest"] = _digest(777)
    drifted = CampaignCandidateIntakePlan.create(**values)
    with pytest.raises(CampaignCandidateIntakeRejected, match="source binding drifted"):
        service.execute(
            drifted,
            approval=_approval(drifted, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    assert store.state(drifted.intake_plan_id) is None
    connection.close()


def test_timeout_has_no_partial_candidate(approved_scope, now):
    ticks = iter((0.0, 11.0))
    service, store, connection, orchestration_plan = _bundle(
        approved_scope, now, monotonic=lambda: next(ticks)
    )
    plan = _prepare(service, orchestration_plan, approved_scope, now)
    with pytest.raises(CampaignCandidateIntakeTimedOut):
        service.execute(
            plan,
            approval=_approval(plan, approved_scope, now),
            scope=approved_scope,
            now=now,
        )
    assert store.state(plan.intake_plan_id) is None
    with pytest.raises(KeyError):
        store.candidate(plan.candidate_id)
    connection.close()


def test_interrupted_intake_recovers_without_duplicate_candidate(approved_scope, now):
    def interrupt():
        raise RuntimeError("fixture interruption")

    service, store, connection, orchestration_plan = _bundle(
        approved_scope, now, after_claim=interrupt
    )
    plan = _prepare(service, orchestration_plan, approved_scope, now)
    approval = _approval(plan, approved_scope, now)
    with pytest.raises(RuntimeError, match="fixture interruption"):
        service.execute(plan, approval=approval, scope=approved_scope, now=now)
    assert store.state(plan.intake_plan_id) == (
        CampaignCandidateIntakeState.STARTED,
        1,
    )
    with pytest.raises(KeyError):
        store.candidate(plan.candidate_id)
    service.after_claim = None
    outcome = service.execute(plan, approval=approval, scope=approved_scope, now=now)
    assert outcome.attempt == 2
    assert store.candidate(plan.candidate_id) == outcome.candidate
    connection.close()


def test_recovery_limit_and_schema_prevent_authority_escalation(approved_scope, now):
    def interrupt():
        raise RuntimeError("fixture interruption")

    service, store, connection, orchestration_plan = _bundle(
        approved_scope, now, after_claim=interrupt
    )
    plan = _prepare(service, orchestration_plan, approved_scope, now)
    approval = _approval(plan, approved_scope, now)
    for _ in range(3):
        with pytest.raises(RuntimeError, match="fixture interruption"):
            service.execute(plan, approval=approval, scope=approved_scope, now=now)
    with pytest.raises(CampaignCandidateIntakeRecoveryRequired, match="exhausted"):
        service.execute(plan, approval=approval, scope=approved_scope, now=now)

    schemas = json.dumps(
        {
            model.__name__: model.model_json_schema()
            for model in (
                CampaignCandidateIntakePlan,
                CampaignCandidate,
                CampaignCandidateIntakeOutcome,
            )
        }
    ).lower()
    assert "entry_point" not in schemas
    assert "sink" not in schemas
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
        CampaignCandidate.model_validate(
            CampaignCandidate.create(
                candidate_id=plan.candidate_id,
                target_id=plan.target_id,
                target_version=plan.target_version,
                scope_id=plan.scope_id,
                scope_version=plan.scope_version,
                vulnerability_class=plan.vulnerability_class,
                cwe=plan.cwe,
                hypothesis_digest=plan.hypothesis_digest,
                duplicate_fingerprint=plan.duplicate_fingerprint,
                orchestration_plan_id=plan.orchestration_plan_id,
                closure_id=plan.closure_id,
                assessment_id=plan.assessment_id,
                evidence_refs=plan.evidence_refs,
                created_at=now,
            ).model_dump(mode="python")
            | {
                "state": CandidateState.PROMOTED,
                "finding_authorized": True,
                "prior_campaign_evidence_is_validation_run": True,
            }
        )
    connection.close()
