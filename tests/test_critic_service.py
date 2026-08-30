from __future__ import annotations

import sqlite3
from datetime import timedelta

import pytest
from pydantic import ValidationError

from vulnloom.critic import (
    REQUIRED_ANGLES,
    CounterevidenceAssessment,
    CounterevidenceDisposition,
    CriticIdempotencyConflict,
    CriticPlan,
    CriticRecoveryRequired,
    CriticRejected,
    CriticStore,
    DeterministicCritic,
    domain_object_digest,
)
from vulnloom.domain.models import (
    CandidateState,
    CriticVerdict,
    EvidenceBundle,
    EvidenceKind,
    ValidationResult,
    ValidationRun,
)
from vulnloom.domain.state_machine import (
    TransitionRejected,
    complete_validation,
    promote_candidate,
    queue_validation,
    transition_candidate,
)
from vulnloom.evidence import EvidenceStore


def _inputs(tmp_path, candidate, approved_scope, now):
    evidence_store = EvidenceStore(tmp_path / "evidence")
    evidence = evidence_store.capture_text(
        "deterministic authorized counterexample transcript",
        kind=EvidenceKind.TEST,
        source_ref="critic-fixture:validation",
        producer="test.validator",
        target_version=candidate.target_version,
        summary="Redacted deterministic validation observation",
    )
    run = ValidationRun(
        candidate_id=candidate.candidate_id,
        target_version=candidate.target_version,
        scope_version=candidate.scope_version,
        sandbox_image_digest="sha256:" + "a" * 64,
        policy_digest="b" * 64,
        plan=("sealed-validation-plan",),
        started_at=now,
        finished_at=now + timedelta(seconds=1),
        result=ValidationResult.REPRODUCED,
        evidence_refs=(evidence.evidence_id,),
    )
    queued = queue_validation(candidate, approved_scope, now=now)
    running = transition_candidate(queued, CandidateState.VALIDATION_RUNNING)
    validated = complete_validation(running, run)
    bundle = EvidenceBundle(
        candidate_id=candidate.candidate_id,
        evidence_refs=run.evidence_refs,
        sealed_at=now + timedelta(seconds=1),
    )
    return evidence_store, evidence, run, validated, bundle


def _assessments(evidence_ref, *, disposition=CounterevidenceDisposition.RULED_OUT):
    return tuple(
        CounterevidenceAssessment(
            angle=angle,
            disposition=disposition,
            evidence_refs=(
                (evidence_ref,)
                if disposition is not CounterevidenceDisposition.INCONCLUSIVE
                else ()
            ),
            rationale_code=f"{angle.value}_{disposition.value}",
        )
        for angle in sorted(REQUIRED_ANGLES, key=lambda item: item.value)
    )


def _plan(
    now, validated, run, bundle, evidence_ref, *, assessments=None, key="critic:1", **updates
):
    values = {
        "candidate_id": validated.candidate_id,
        "candidate_digest": domain_object_digest(validated),
        "validation_run_id": run.run_id,
        "validation_run_digest": domain_object_digest(run),
        "evidence_bundle_id": bundle.bundle_id,
        "evidence_bundle_digest": domain_object_digest(bundle),
        "scope_id": validated.scope_id,
        "scope_version": validated.scope_version,
        "validation_context_id": "1" * 64,
        "review_context_id": "2" * 64,
        "validation_producer": "deterministic-http-judge/v1",
        "review_producer": "deterministic-critic/v1",
        "assessments": assessments or _assessments(evidence_ref),
        "created_at": now,
        "deadline": now + timedelta(minutes=1),
        "idempotency_key": key,
    }
    values.update(updates)
    return CriticPlan.create(**values)


def _service(tmp_path, approved_scope, evidence_store):
    store = CriticStore(tmp_path / "critic.db")
    service = DeterministicCritic(
        scope=approved_scope,
        evidence_store=evidence_store,
        store=store,
    )
    return service, store


def test_deterministic_critic_accepts_only_after_all_disproof_angles_are_ruled_out(
    tmp_path, candidate, approved_scope, now
):
    evidence_store, evidence, run, validated, bundle = _inputs(
        tmp_path, candidate, approved_scope, now
    )
    plan = _plan(now, validated, run, bundle, evidence.evidence_id)
    service, store = _service(tmp_path, approved_scope, evidence_store)

    first = service.review(validated, run, bundle, (evidence,), plan, now=now)
    second = service.review(validated, run, bundle, (evidence,), plan, now=now)
    store.close()

    assert first == second
    assert first.review.verdict is CriticVerdict.ACCEPTED
    assert first.review.accepted is True
    assert first.candidate.state is CandidateState.CRITIC_REVIEWED
    assert first.review.counterevidence_refs == ()
    promoted, finding = promote_candidate(
        first.candidate,
        scope=approved_scope,
        now=now,
        root_cause="Missing ownership predicate",
        affected_versions=(candidate.target_version,),
        impact="Cross-tenant object disclosure",
        severity_assessment={"cvss": 6.5},
        validation_runs=(run,),
        evidence_bundle=bundle,
        critic_review=first.review,
        duplicate_checked=True,
    )
    assert promoted.state is CandidateState.PROMOTED
    assert finding.validation_run_ids == (run.run_id,)
    with pytest.raises(TransitionRejected, match="currently approved Scope"):
        promote_candidate(
            first.candidate,
            scope=approved_scope,
            now=approved_scope.valid_until,
            root_cause="Missing ownership predicate",
            affected_versions=(candidate.target_version,),
            impact="Cross-tenant object disclosure",
            severity_assessment={"cvss": 6.5},
            validation_runs=(run,),
            evidence_bundle=bundle,
            critic_review=first.review,
            duplicate_checked=True,
        )


def test_confirmed_counterevidence_deterministically_rejects_candidate(
    tmp_path, candidate, approved_scope, now
):
    evidence_store, evidence, run, validated, bundle = _inputs(
        tmp_path, candidate, approved_scope, now
    )
    assessments = list(_assessments(evidence.evidence_id))
    assessments[0] = assessments[0].model_copy(
        update={"disposition": CounterevidenceDisposition.CONFIRMED}
    )
    plan = _plan(
        now, validated, run, bundle, evidence.evidence_id, assessments=tuple(assessments)
    )
    service, store = _service(tmp_path, approved_scope, evidence_store)

    outcome = service.review(validated, run, bundle, (evidence,), plan, now=now)
    store.close()

    assert outcome.review.verdict is CriticVerdict.REJECTED
    assert outcome.review.counterevidence_refs == (evidence.evidence_id,)
    assert outcome.candidate.state is CandidateState.REJECTED


def test_inconclusive_counterevidence_fails_closed_without_advancing_candidate(
    tmp_path, candidate, approved_scope, now
):
    evidence_store, evidence, run, validated, bundle = _inputs(
        tmp_path, candidate, approved_scope, now
    )
    assessments = list(_assessments(evidence.evidence_id))
    assessments[0] = CounterevidenceAssessment(
        angle=assessments[0].angle,
        disposition=CounterevidenceDisposition.INCONCLUSIVE,
        rationale_code="reachability_not_proven",
    )
    plan = _plan(
        now, validated, run, bundle, evidence.evidence_id, assessments=tuple(assessments)
    )
    service, store = _service(tmp_path, approved_scope, evidence_store)

    outcome = service.review(validated, run, bundle, (evidence,), plan, now=now)
    store.close()

    assert outcome.review.verdict is CriticVerdict.INCONCLUSIVE
    assert outcome.candidate.state is CandidateState.VALIDATED


def test_critic_plan_rejects_shared_context_or_missing_review_angle(
    tmp_path, candidate, approved_scope, now
):
    _, evidence, run, validated, bundle = _inputs(tmp_path, candidate, approved_scope, now)
    with pytest.raises(ValidationError, match="independent"):
        _plan(
            now,
            validated,
            run,
            bundle,
            evidence.evidence_id,
            review_context_id="1" * 64,
        )
    with pytest.raises(ValidationError, match="every required"):
        _plan(
            now,
            validated,
            run,
            bundle,
            evidence.evidence_id,
            assessments=_assessments(evidence.evidence_id)[:-1],
        )


@pytest.mark.parametrize("failure", ["scope", "provenance", "bundle", "target", "corrupt"])
def test_critic_rejects_invalid_scope_provenance_or_evidence(
    tmp_path, candidate, approved_scope, now, failure
):
    evidence_store, evidence, run, validated, bundle = _inputs(
        tmp_path, candidate, approved_scope, now
    )
    plan = _plan(now, validated, run, bundle, evidence.evidence_id)
    scope = approved_scope
    supplied_evidence = evidence
    if failure == "scope":
        scope = approved_scope.model_copy(update={"valid_until": now})
    elif failure == "provenance":
        plan = _plan(
            now,
            validated,
            run.model_copy(update={"policy_digest": "c" * 64}),
            bundle,
            evidence.evidence_id,
        )
    elif failure == "bundle":
        bundle = bundle.model_copy(update={"evidence_refs": ()})
    elif failure == "target":
        supplied_evidence = evidence.model_copy(update={"target_version": "other"})
    else:
        (tmp_path / "evidence" / evidence.content_ref).write_text("tampered", encoding="utf-8")
    service, store = _service(tmp_path, scope, evidence_store)

    with pytest.raises(CriticRejected):
        service.review(validated, run, bundle, (supplied_evidence,), plan, now=now)
    count = store.connection.execute("SELECT COUNT(*) FROM critic_executions").fetchone()[0]
    store.close()
    assert count == 0


def test_expired_plan_times_out_before_checkpoint_or_state_change(
    tmp_path, candidate, approved_scope, now
):
    evidence_store, evidence, run, validated, bundle = _inputs(
        tmp_path, candidate, approved_scope, now
    )
    plan = _plan(now, validated, run, bundle, evidence.evidence_id)
    service, store = _service(tmp_path, approved_scope, evidence_store)

    with pytest.raises(CriticRejected, match="not currently valid"):
        service.review(
            validated,
            run,
            bundle,
            (evidence,),
            plan,
            now=plan.deadline,
        )
    count = store.connection.execute("SELECT COUNT(*) FROM critic_executions").fetchone()[0]
    store.close()
    assert count == 0
    assert validated.state is CandidateState.VALIDATED


def test_critic_store_rejects_conflicts_and_unfinished_replay(
    tmp_path, candidate, approved_scope, now
):
    evidence_store, evidence, run, validated, bundle = _inputs(
        tmp_path, candidate, approved_scope, now
    )
    plan = _plan(now, validated, run, bundle, evidence.evidence_id)
    service, store = _service(tmp_path, approved_scope, evidence_store)
    service.review(validated, run, bundle, (evidence,), plan, now=now)
    changed = _plan(
        now,
        validated,
        run,
        bundle,
        evidence.evidence_id,
        key=plan.idempotency_key,
        review_context_id="3" * 64,
    )
    with pytest.raises(CriticIdempotencyConflict):
        service.review(validated, run, bundle, (evidence,), changed, now=now)
    store.close()

    recovery_store = CriticStore(tmp_path / "recovery.db")
    recovery_store.claim(plan, now=now)
    recovery_service = DeterministicCritic(
        scope=approved_scope,
        evidence_store=evidence_store,
        store=recovery_store,
    )
    with pytest.raises(CriticRecoveryRequired):
        recovery_service.review(validated, run, bundle, (evidence,), plan, now=now)
    recovery_store.close()


def test_critic_store_context_manager_closes_connection(tmp_path):
    store = CriticStore(tmp_path / "critic.db")
    with pytest.raises(RuntimeError), store:
        raise RuntimeError("boom")
    with pytest.raises(sqlite3.ProgrammingError):
        store.connection.execute("SELECT 1")
