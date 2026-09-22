from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.domain.models import EvidenceKind
from vulnloom.evidence import EvidenceStore
from vulnloom.red_team import (
    EvidenceAssertion,
    EvidenceAssessmentLimits,
    EvidenceAssessmentRecoveryRequired,
    EvidenceAssessmentRejected,
    EvidenceAssessmentService,
    EvidenceAssessmentState,
    EvidenceAssessmentStore,
    EvidenceAssessmentStoreRejected,
    EvidenceAssessmentTimedOut,
    EvidenceAssessmentVerdict,
    EvidenceFactKind,
    EvidenceFactVerdict,
    EvidenceRequirementStage,
    VulnerabilityEvidenceRequirement,
)

_STAGES = {
    EvidenceFactKind.SEALED_GET_SUCCEEDED: EvidenceRequirementStage.OBSERVATION,
    EvidenceFactKind.UNAUTHENTICATED_REQUEST_PROVEN: (
        EvidenceRequirementStage.OBSERVATION
    ),
    EvidenceFactKind.SENSITIVE_DATA_CLASS_PRESENT: (
        EvidenceRequirementStage.OBSERVATION
    ),
    EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED: EvidenceRequirementStage.VALIDATION,
    EvidenceFactKind.REDACTION_BOUNDARY_PROVEN: EvidenceRequirementStage.VALIDATION,
    EvidenceFactKind.ACCESS_CONTROL_ENFORCED: EvidenceRequirementStage.CRITIC,
    EvidenceFactKind.PUBLIC_BY_DESIGN: EvidenceRequirementStage.CRITIC,
    EvidenceFactKind.SYNTHETIC_OR_PLACEHOLDER_DATA: EvidenceRequirementStage.CRITIC,
    EvidenceFactKind.ENVIRONMENT_OR_VERSION_MISMATCH: EvidenceRequirementStage.CRITIC,
    EvidenceFactKind.NO_STATE_CHANGE_PROVEN: EvidenceRequirementStage.CLEANUP,
    EvidenceFactKind.NO_TEST_ARTIFACTS_REMAIN: EvidenceRequirementStage.CLEANUP,
}


def _runtime(tmp_path, *, monotonic=None):
    evidence_store = EvidenceStore(tmp_path / "evidence")
    store = EvidenceAssessmentStore(tmp_path / "assessments.sqlite3")
    service = EvidenceAssessmentService(
        store=store,
        evidence_store=evidence_store,
        **({"monotonic": monotonic} if monotonic is not None else {}),
    )
    return service, store, evidence_store


def _assertions(
    evidence_store,
    requirement,
    now,
    *,
    overrides=None,
    omit=frozenset(),
    shared_validation_critic_ref=False,
):
    overrides = overrides or {}
    assertions = []
    shared_ref = None
    for fact, stage in _STAGES.items():
        if fact in omit:
            continue
        if (
            shared_validation_critic_ref
            and stage in {
                EvidenceRequirementStage.VALIDATION,
                EvidenceRequirementStage.CRITIC,
            }
        ):
            if shared_ref is None:
                shared_ref = evidence_store.capture_text(
                    "shared independent-boundary fixture",
                    kind=EvidenceKind.TEST,
                    source_ref="fixture:b3.1:shared",
                    producer="test.b3.1",
                    target_version="fixture-v1",
                    summary="shared fixture",
                ).evidence_id
            evidence_ref = shared_ref
        else:
            evidence_ref = evidence_store.capture_text(
                f"bounded fact: {fact.value}",
                kind=EvidenceKind.TEST,
                source_ref=f"fixture:b3.1:{fact.value}",
                producer="test.b3.1",
                target_version="fixture-v1",
                summary=f"bounded {fact.value} fixture",
            ).evidence_id
        default_verdict = (
            EvidenceFactVerdict.REFUTED
            if stage is EvidenceRequirementStage.CRITIC
            else EvidenceFactVerdict.SUPPORTED
        )
        assertions.append(
            EvidenceAssertion.create(
                requirement_id=requirement.requirement_id,
                stage=stage,
                fact=fact,
                verdict=overrides.get(fact, default_verdict),
                evidence_refs=(evidence_ref,),
                producer_ref=(
                    "critic:independent-v1"
                    if stage is EvidenceRequirementStage.CRITIC
                    else "validator:deterministic-v1"
                    if stage is EvidenceRequirementStage.VALIDATION
                    else "control-plane:b3.1"
                ),
                context_id=(
                    "c" * 64
                    if stage is EvidenceRequirementStage.CRITIC
                    else "b" * 64
                    if stage is EvidenceRequirementStage.VALIDATION
                    else "a" * 64
                    if stage is EvidenceRequirementStage.OBSERVATION
                    else "f" * 64
                ),
                observed_at=now,
            )
        )
    return tuple(assertions)


def _prepare(service, scope, assertions, now, *, limits=None, key="b3.1:assessment"):
    return service.prepare(
        target_id=uuid4(),
        target_version="fixture-v1",
        scope=scope,
        assertions=assertions,
        limits=limits or EvidenceAssessmentLimits(),
        now=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key=key,
    )


def test_complete_evidence_contract_grants_candidate_eligibility_only(
    tmp_path, approved_scope, now
):
    service, store, evidence_store = _runtime(tmp_path)
    requirement = service.requirement()
    assertions = _assertions(evidence_store, requirement, now)
    plan = _prepare(service, approved_scope, assertions, now)

    outcome = service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=1)
    )
    assessment = outcome.assessment
    assert assessment.verdict is EvidenceAssessmentVerdict.CANDIDATE_ELIGIBLE
    assert assessment.candidate_proposal_eligible is True
    assert assessment.cleanup_requirement_satisfied is True
    assert assessment.counterevidence_facts == ()
    assert assessment.unresolved_facts == ()
    assert assessment.finding_authorized is False
    assert assessment.test_execution_authorized is False
    assert len(assessment.satisfied_facts) == 11
    assert service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=2)
    ) == outcome
    assert store.state(plan.plan_id) == (EvidenceAssessmentState.COMPLETED, 1)
    store.close()


def test_confirmed_counterevidence_produces_negative_not_candidate(
    tmp_path, approved_scope, now
):
    service, store, evidence_store = _runtime(tmp_path)
    requirement = service.requirement()
    assertions = _assertions(
        evidence_store,
        requirement,
        now,
        overrides={
            EvidenceFactKind.ACCESS_CONTROL_ENFORCED: EvidenceFactVerdict.SUPPORTED
        },
    )
    plan = _prepare(service, approved_scope, assertions, now)
    assessment = service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=1)
    ).assessment

    assert assessment.verdict is EvidenceAssessmentVerdict.NEGATIVE
    assert assessment.candidate_proposal_eligible is False
    assert assessment.counterevidence_facts == (
        EvidenceFactKind.ACCESS_CONTROL_ENFORCED,
    )
    assert assessment.finding_authorized is False
    store.close()


def test_missing_or_uncertain_validation_and_cleanup_are_inconclusive(
    tmp_path, approved_scope, now
):
    service, store, evidence_store = _runtime(tmp_path)
    requirement = service.requirement()
    assertions = _assertions(
        evidence_store,
        requirement,
        now,
        overrides={
            EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED: (
                EvidenceFactVerdict.INCONCLUSIVE
            )
        },
        omit=frozenset({EvidenceFactKind.NO_TEST_ARTIFACTS_REMAIN}),
    )
    plan = _prepare(service, approved_scope, assertions, now)
    assessment = service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=1)
    ).assessment

    assert assessment.verdict is EvidenceAssessmentVerdict.INCONCLUSIVE
    assert assessment.candidate_proposal_eligible is False
    assert assessment.cleanup_requirement_satisfied is False
    assert set(assessment.unresolved_facts) == {
        EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED,
        EvidenceFactKind.NO_TEST_ARTIFACTS_REMAIN,
    }
    store.close()


def test_critic_must_be_independent_and_evidence_must_exist(
    tmp_path, approved_scope, now
):
    service, store, evidence_store = _runtime(tmp_path)
    requirement = service.requirement()
    assertions = _assertions(
        evidence_store,
        requirement,
        now,
        shared_validation_critic_ref=True,
    )
    with pytest.raises(EvidenceAssessmentRejected, match="independent"):
        _prepare(service, approved_scope, assertions, now)

    good = list(_assertions(evidence_store, requirement, now))
    missing = good[0].model_dump(mode="python", exclude={"assertion_id"})
    missing["evidence_refs"] = ("f" * 64,)
    good[0] = EvidenceAssertion.create(**missing)
    with pytest.raises(EvidenceAssessmentRejected, match="integrity"):
        _prepare(service, approved_scope, tuple(good), now, key="b3.1:missing")
    store.close()


def test_timeout_has_no_partial_assessment_and_started_state_recovers(
    tmp_path, approved_scope, now
):
    ticks = iter((0.0, 11.0))
    service, store, evidence_store = _runtime(
        tmp_path / "timeout", monotonic=lambda: next(ticks)
    )
    requirement = service.requirement()
    assertions = _assertions(evidence_store, requirement, now)
    plan = _prepare(service, approved_scope, assertions, now)
    with pytest.raises(EvidenceAssessmentTimedOut):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    assert store.state(plan.plan_id) is None
    store.close()

    service, store, evidence_store = _runtime(tmp_path / "recovery")
    assertions = _assertions(evidence_store, service.requirement(), now)
    plan = _prepare(service, approved_scope, assertions, now)
    store.claim(plan, now=now)
    with pytest.raises(EvidenceAssessmentRecoveryRequired, match="unfinished"):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    outcome = service.recover(
        plan, scope=approved_scope, now=now + timedelta(seconds=2)
    )
    assert outcome.attempt == 2
    assert outcome.cleanup_complete is True
    assert store.state(plan.plan_id) == (EvidenceAssessmentState.COMPLETED, 2)
    store.close()


def test_requirement_and_assessment_schemas_cannot_grant_stronger_authority(
    tmp_path, approved_scope, now
):
    service, store, evidence_store = _runtime(tmp_path)
    requirement = service.requirement()
    with pytest.raises(ValidationError):
        VulnerabilityEvidenceRequirement.model_validate(
            requirement.model_dump(mode="python")
            | {"finding_authorized": True, "test_execution_authorized": True}
        )

    assertions = _assertions(evidence_store, requirement, now)
    plan = _prepare(service, approved_scope, assertions, now)
    assessment = service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=1)
    ).assessment
    with pytest.raises(ValidationError):
        type(assessment).model_validate(
            assessment.model_dump(mode="python")
            | {"finding_authorized": True, "test_execution_authorized": True}
        )
    forged = assessment.model_dump(mode="python", exclude={"assessment_id"})
    forged["satisfied_facts"] = assessment.satisfied_facts[:-1]
    forged["unresolved_facts"] = (EvidenceFactKind.NO_TEST_ARTIFACTS_REMAIN,)
    with pytest.raises(ValidationError):
        type(assessment).create(**forged)
    encoded = assessment.model_dump_json()
    assert "response_body" not in encoded
    assert "field_name" not in encoded
    assert "sample_value" not in encoded
    store.close()


def test_scope_binding_and_idempotency_identity_fail_closed(
    tmp_path, approved_scope, now
):
    service, store, evidence_store = _runtime(tmp_path)
    assertions = _assertions(evidence_store, service.requirement(), now)
    plan = _prepare(service, approved_scope, assertions, now)
    values = plan.model_dump(mode="python", exclude={"plan_id"})
    values["requirement"] = plan.requirement
    values["assertions"] = plan.assertions
    values["limits"] = plan.limits
    values["scope_version"] = plan.scope_version + 1
    drifted = type(plan).create(**values)
    with pytest.raises(EvidenceAssessmentRejected, match="binding drifted"):
        service.execute(
            drifted, scope=approved_scope, now=now + timedelta(seconds=1)
        )
    assert store.state(drifted.plan_id) is None

    service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    conflicting = service.prepare(
        target_id=uuid4(),
        target_version="fixture-v2",
        scope=approved_scope,
        assertions=assertions,
        limits=EvidenceAssessmentLimits(),
        now=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key=plan.idempotency_key,
    )
    with pytest.raises(EvidenceAssessmentStoreRejected, match="different content"):
        service.execute(
            conflicting, scope=approved_scope, now=now + timedelta(seconds=1)
        )
    store.close()
