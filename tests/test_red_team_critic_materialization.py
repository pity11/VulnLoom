from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.domain.models import EvidenceKind
from vulnloom.evidence import EvidenceStore
from vulnloom.red_team import (
    CRITIC_FACTS,
    CriticAssertionMaterializationLimits,
    CriticAssertionMaterializationRecoveryRequired,
    CriticAssertionMaterializationRejected,
    CriticAssertionMaterializationService,
    CriticAssertionMaterializationState,
    CriticAssertionMaterializationStore,
    CriticAssertionMaterializationTimedOut,
    CriticEvidenceConclusion,
    CriticEvidenceReview,
    EvidenceAssertion,
    EvidenceAssessmentLimits,
    EvidenceAssessmentService,
    EvidenceAssessmentStore,
    EvidenceAssessmentVerdict,
    EvidenceFactKind,
    EvidenceFactVerdict,
    EvidenceReplayValidation,
    EvidenceReplayValidationLimits,
    EvidenceReplayValidationOutcome,
    EvidenceReplayValidationPlan,
    EvidenceRequirementStage,
    VulnerabilityEvidenceRequirement,
)


def _digest(character):
    return character * 64


class _ReplaySource:
    def __init__(self, plan, outcome):
        self._plan = plan
        self._outcome = outcome

    def plan(self, plan_id):
        if plan_id != self._plan.plan_id:
            raise KeyError(plan_id)
        return self._plan

    def outcome(self, plan_id):
        if plan_id != self._plan.plan_id:
            raise KeyError(plan_id)
        return self._outcome


def _capture(evidence_store, content, *, target_version):
    return evidence_store.capture_text(
        content,
        kind=EvidenceKind.POLICY,
        source_ref="fixture:counterevidence",
        producer="critic-fixture",
        target_version=target_version,
        summary="redacted counterevidence fixture",
    ).evidence_id


def _replay_source(evidence_store, approved_scope, now):
    requirement = VulnerabilityEvidenceRequirement.create()
    target_id = uuid4()
    target_version = _digest("a")
    validation_refs = tuple(
        sorted(
            (
                _capture(evidence_store, "validation fixture one", target_version=target_version),
                _capture(evidence_store, "validation fixture two", target_version=target_version),
            )
        )
    )
    plan = EvidenceReplayValidationPlan.create(
        requirement_id=requirement.requirement_id,
        baseline_materialization_plan_id=_digest("1"),
        baseline_materialization_id=_digest("2"),
        baseline_flow_plan_id=_digest("3"),
        baseline_observation_id=_digest("4"),
        baseline_snapshot_id=_digest("5"),
        current_materialization_plan_id=_digest("6"),
        current_materialization_id=_digest("7"),
        current_flow_plan_id=_digest("8"),
        current_observation_id=_digest("9"),
        current_snapshot_id=_digest("b"),
        requested_url_digest=_digest("c"),
        evidence_refs=validation_refs,
        target_id=target_id,
        target_version=target_version,
        scope_id=approved_scope.scope_id,
        scope_version=approved_scope.version,
        limits=EvidenceReplayValidationLimits(),
        created_at=now,
        deadline=now + timedelta(minutes=10),
        idempotency_key="b3.3:fixture",
    )
    assertions = tuple(
        sorted(
            (
                EvidenceAssertion.create(
                    requirement_id=requirement.requirement_id,
                    stage=EvidenceRequirementStage.VALIDATION,
                    fact=EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED,
                    verdict=EvidenceFactVerdict.SUPPORTED,
                    evidence_refs=validation_refs,
                    producer_ref="validator:sealed-get-replay-v1",
                    context_id=plan.plan_id,
                    observed_at=now,
                ),
                EvidenceAssertion.create(
                    requirement_id=requirement.requirement_id,
                    stage=EvidenceRequirementStage.VALIDATION,
                    fact=EvidenceFactKind.REDACTION_BOUNDARY_PROVEN,
                    verdict=EvidenceFactVerdict.SUPPORTED,
                    evidence_refs=validation_refs,
                    producer_ref="validator:sealed-get-replay-v1",
                    context_id=plan.plan_id,
                    observed_at=now,
                ),
            ),
            key=lambda item: item.assertion_id,
        )
    )
    validation = EvidenceReplayValidation.create(
        plan_id=plan.plan_id,
        requirement_id=requirement.requirement_id,
        baseline_materialization_id=plan.baseline_materialization_id,
        current_materialization_id=plan.current_materialization_id,
        requested_url_digest=plan.requested_url_digest,
        evidence_refs=validation_refs,
        assertions=assertions,
        content_match=True,
        replay_verdict=EvidenceFactVerdict.SUPPORTED,
        ruleset_digest=plan.ruleset_digest,
        validated_at=now,
    )
    outcome = EvidenceReplayValidationOutcome(
        plan_id=plan.plan_id,
        validation=validation,
        attempt=1,
    )
    return _ReplaySource(plan, outcome), plan, outcome


def _review(
    evidence_store,
    replay_plan,
    now,
    *,
    verdicts=None,
    context_id=None,
    override_ref=None,
):
    verdicts = verdicts or {}
    conclusions = []
    for index, fact in enumerate(CRITIC_FACTS):
        evidence_ref = override_ref if index == 0 and override_ref else _capture(
            evidence_store,
            f"critic fixture {fact.value}",
            target_version=replay_plan.target_version,
        )
        conclusions.append(
            CriticEvidenceConclusion(
                fact=fact,
                verdict=verdicts.get(fact, EvidenceFactVerdict.REFUTED),
                evidence_refs=(evidence_ref,),
            )
        )
    return CriticEvidenceReview.create(
        requirement_id=replay_plan.requirement_id,
        target_id=replay_plan.target_id,
        target_version=replay_plan.target_version,
        scope_id=replay_plan.scope_id,
        scope_version=replay_plan.scope_version,
        review_context_id=context_id or _digest("d"),
        conclusions=tuple(conclusions),
        reviewed_at=now + timedelta(seconds=2),
    )


def _runtime(tmp_path, approved_scope, now, *, verdicts=None, monotonic=None):
    evidence_store = EvidenceStore(tmp_path / "evidence")
    source, replay_plan, replay_outcome = _replay_source(
        evidence_store, approved_scope, now
    )
    review = _review(
        evidence_store,
        replay_plan,
        now,
        verdicts=verdicts,
    )
    store = CriticAssertionMaterializationStore(tmp_path / "critic.sqlite3")
    service = CriticAssertionMaterializationService(
        replay_validation_source=source,
        store=store,
        evidence_store=evidence_store,
        **({"monotonic": monotonic} if monotonic is not None else {}),
    )
    return service, store, evidence_store, replay_plan, replay_outcome, review


def _prepare(service, replay_plan, review, approved_scope, now):
    return service.prepare(
        replay_validation_plan_id=replay_plan.plan_id,
        review=review,
        scope=approved_scope,
        limits=CriticAssertionMaterializationLimits(),
        now=now + timedelta(seconds=3),
        deadline=now + timedelta(minutes=5),
        idempotency_key="b3.4:materialize",
    )


def _source_assertions(replay_plan, replay_outcome, now):
    facts = (
        (EvidenceRequirementStage.OBSERVATION, EvidenceFactKind.SEALED_GET_SUCCEEDED),
        (
            EvidenceRequirementStage.OBSERVATION,
            EvidenceFactKind.UNAUTHENTICATED_REQUEST_PROVEN,
        ),
        (
            EvidenceRequirementStage.OBSERVATION,
            EvidenceFactKind.SENSITIVE_DATA_CLASS_PRESENT,
        ),
        (EvidenceRequirementStage.CLEANUP, EvidenceFactKind.NO_STATE_CHANGE_PROVEN),
        (
            EvidenceRequirementStage.CLEANUP,
            EvidenceFactKind.NO_TEST_ARTIFACTS_REMAIN,
        ),
    )
    return tuple(
        EvidenceAssertion.create(
            requirement_id=replay_plan.requirement_id,
            stage=stage,
            fact=fact,
            verdict=EvidenceFactVerdict.SUPPORTED,
            evidence_refs=(replay_outcome.validation.evidence_refs[0],),
            producer_ref="control-plane:sealed-get-v1",
            context_id=_digest("e"),
            observed_at=now,
        )
        for stage, fact in facts
    )


def test_critic_assertions_complete_candidate_eligibility_without_promotion(
    tmp_path, approved_scope, now
):
    service, store, evidence_store, replay_plan, replay_outcome, review = _runtime(
        tmp_path, approved_scope, now
    )
    plan = _prepare(service, replay_plan, review, approved_scope, now)
    outcome = service.execute(
        plan,
        scope=approved_scope,
        now=now + timedelta(seconds=3),
    )
    materialization = outcome.materialization
    assert {item.fact for item in materialization.assertions} == set(CRITIC_FACTS)
    assert all(
        item.verdict is EvidenceFactVerdict.REFUTED
        and item.context_id == plan.plan_id
        and item.producer_ref == "critic:counterevidence-review-v1"
        for item in materialization.assertions
    )
    assert set(materialization.evidence_refs).isdisjoint(
        replay_outcome.validation.evidence_refs
    )
    assert materialization.review_executed is False
    assert materialization.request_execution_authorized is False
    assert materialization.candidate_proposal_eligible is False
    assert materialization.finding_authorized is False
    assert service.execute(
        plan,
        scope=approved_scope,
        now=now + timedelta(seconds=4),
    ) == outcome
    assert store.state(plan.plan_id) == (
        CriticAssertionMaterializationState.COMPLETED,
        1,
    )

    assessment_store = EvidenceAssessmentStore(tmp_path / "assessment.sqlite3")
    assessment_service = EvidenceAssessmentService(
        store=assessment_store,
        evidence_store=evidence_store,
    )
    assertions = tuple(
        sorted(
            _source_assertions(replay_plan, replay_outcome, now)
            + replay_outcome.validation.assertions
            + materialization.assertions,
            key=lambda item: item.assertion_id,
        )
    )
    assessment_plan = assessment_service.prepare(
        target_id=replay_plan.target_id,
        target_version=replay_plan.target_version,
        scope=approved_scope,
        assertions=assertions,
        limits=EvidenceAssessmentLimits(),
        now=now + timedelta(seconds=4),
        deadline=now + timedelta(minutes=5),
        idempotency_key="b3.4:assessment",
    )
    assessment = assessment_service.execute(
        assessment_plan,
        scope=approved_scope,
        now=now + timedelta(seconds=5),
    ).assessment
    assert assessment.verdict is EvidenceAssessmentVerdict.CANDIDATE_ELIGIBLE
    assert assessment.candidate_proposal_eligible is True
    assert assessment.finding_authorized is False
    assert assessment.test_execution_authorized is False
    assessment_store.close()
    store.close()


def test_supported_or_inconclusive_counterevidence_is_preserved(
    tmp_path, approved_scope, now
):
    verdicts = {
        EvidenceFactKind.ACCESS_CONTROL_ENFORCED: EvidenceFactVerdict.SUPPORTED,
        EvidenceFactKind.PUBLIC_BY_DESIGN: EvidenceFactVerdict.INCONCLUSIVE,
    }
    service, store, _, replay_plan, _, review = _runtime(
        tmp_path,
        approved_scope,
        now,
        verdicts=verdicts,
    )
    plan = _prepare(service, replay_plan, review, approved_scope, now)
    materialization = service.execute(
        plan,
        scope=approved_scope,
        now=now + timedelta(seconds=3),
    ).materialization
    by_fact = {item.fact: item.verdict for item in materialization.assertions}
    assert by_fact[EvidenceFactKind.ACCESS_CONTROL_ENFORCED] is EvidenceFactVerdict.SUPPORTED
    assert by_fact[EvidenceFactKind.PUBLIC_BY_DESIGN] is EvidenceFactVerdict.INCONCLUSIVE
    store.close()


def test_critic_materialization_rejects_nonindependent_or_missing_evidence(
    tmp_path, approved_scope, now
):
    service, store, evidence_store, replay_plan, replay_outcome, _ = _runtime(
        tmp_path, approved_scope, now
    )
    overlapping = _review(
        evidence_store,
        replay_plan,
        now,
        override_ref=replay_outcome.validation.evidence_refs[0],
    )
    with pytest.raises(CriticAssertionMaterializationRejected, match="independent"):
        _prepare(service, replay_plan, overlapping, approved_scope, now)

    same_context = _review(
        evidence_store,
        replay_plan,
        now,
        context_id=replay_plan.plan_id,
    )
    with pytest.raises(CriticAssertionMaterializationRejected, match="independent"):
        _prepare(service, replay_plan, same_context, approved_scope, now)

    missing = _review(
        evidence_store,
        replay_plan,
        now,
        override_ref=_digest("f"),
    )
    with pytest.raises(CriticAssertionMaterializationRejected, match="integrity"):
        _prepare(service, replay_plan, missing, approved_scope, now)

    conclusions = tuple(
        item for item in missing.conclusions if item.fact is not CRITIC_FACTS[0]
    )
    with pytest.raises(ValidationError):
        CriticEvidenceReview.model_validate(
            missing.model_dump(mode="python")
            | {"conclusions": conclusions}
        )
    assert store.state(_digest("0")) is None
    store.close()


def test_critic_materialization_timeout_binding_recovery_and_authority_schema(
    tmp_path, approved_scope, now
):
    ticks = iter((0.0, 11.0))
    service, store, _, replay_plan, _, review = _runtime(
        tmp_path / "timeout",
        approved_scope,
        now,
        monotonic=lambda: next(ticks),
    )
    plan = _prepare(service, replay_plan, review, approved_scope, now)
    with pytest.raises(CriticAssertionMaterializationTimedOut):
        service.execute(
            plan,
            scope=approved_scope,
            now=now + timedelta(seconds=3),
        )
    assert store.state(plan.plan_id) is None
    store.close()

    service, store, _, replay_plan, _, review = _runtime(
        tmp_path / "recovery", approved_scope, now
    )
    plan = _prepare(service, replay_plan, review, approved_scope, now)
    values = plan.model_dump(mode="python", exclude={"plan_id"})
    values["limits"] = plan.limits
    values["review"] = plan.review
    values["replay_validation_id"] = _digest("f")
    drifted = type(plan).create(**values)
    with pytest.raises(CriticAssertionMaterializationRejected, match="binding drifted"):
        service.execute(
            drifted,
            scope=approved_scope,
            now=now + timedelta(seconds=3),
        )
    assert store.state(drifted.plan_id) is None

    store.claim(plan, now=now + timedelta(seconds=3))
    with pytest.raises(
        CriticAssertionMaterializationRecoveryRequired, match="unfinished"
    ):
        service.execute(
            plan,
            scope=approved_scope,
            now=now + timedelta(seconds=3),
        )
    outcome = service.recover(
        plan,
        scope=approved_scope,
        now=now + timedelta(seconds=4),
    )
    assert outcome.attempt == 2
    assert outcome.cleanup_complete is True
    assert store.state(plan.plan_id) == (
        CriticAssertionMaterializationState.COMPLETED,
        2,
    )
    with pytest.raises(ValidationError):
        type(outcome.materialization).model_validate(
            outcome.materialization.model_dump(mode="python")
            | {
                "review_executed": True,
                "request_execution_authorized": True,
                "candidate_proposal_eligible": True,
                "finding_authorized": True,
                "raw_values": ["forbidden"],
            }
        )
    encoded = outcome.materialization.model_dump_json()
    assert "critic fixture" not in encoded
    assert "validation fixture" not in encoded
    store.close()
