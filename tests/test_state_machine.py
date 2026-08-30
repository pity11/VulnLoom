from __future__ import annotations

from datetime import timedelta

import pytest

from vulnloom.domain.models import (
    CandidateState,
    CriticReview,
    EvidenceBundle,
    ScopeState,
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


def _run(candidate, now, result=ValidationResult.REPRODUCED, evidence=("a" * 64,)):
    return ValidationRun(
        candidate_id=candidate.candidate_id,
        target_version="a" * 40,
        scope_version=1,
        sandbox_image_digest="sha256:" + "b" * 64,
        policy_digest="c" * 64,
        plan=("GET /invoice/42 as tenant B",),
        started_at=now,
        finished_at=now + timedelta(seconds=1),
        result=result,
        evidence_refs=evidence,
    )


def test_candidate_happy_path_requires_validation_and_critic(candidate, approved_scope, now):
    candidate = queue_validation(candidate, approved_scope, now=now)
    candidate = transition_candidate(candidate, CandidateState.VALIDATION_RUNNING)
    run = _run(candidate, now)
    candidate = complete_validation(candidate, run)
    candidate = transition_candidate(candidate, CandidateState.CRITIC_REVIEWED)
    bundle = EvidenceBundle(candidate_id=candidate.candidate_id, evidence_refs=("a" * 64,))
    critic = CriticReview(
        candidate_id=candidate.candidate_id,
        accepted=True,
        rationale="Ownership check is absent on the reachable path",
    )

    promoted, finding = promote_candidate(
        candidate,
        root_cause="Missing tenant predicate",
        affected_versions=("1.2.0",),
        impact="Cross-tenant invoice disclosure",
        severity_assessment={"cvss": 6.5},
        validation_runs=(run,),
        evidence_bundle=bundle,
        critic_review=critic,
        duplicate_checked=True,
    )

    assert promoted.state is CandidateState.PROMOTED
    assert finding.validation_run_ids == (run.run_id,)


def test_draft_scope_cannot_queue_validation(candidate, approved_scope, now):
    draft = approved_scope.model_copy(update={"state": ScopeState.DRAFT})
    with pytest.raises(TransitionRejected, match="approved Scope"):
        queue_validation(candidate, draft, now=now)


def test_expired_scope_cannot_queue_validation(candidate, approved_scope):
    with pytest.raises(TransitionRejected, match="validity window"):
        queue_validation(candidate, approved_scope, now=approved_scope.valid_until)


def test_illegal_shortcut_to_finding_is_rejected(candidate):
    with pytest.raises(TransitionRejected, match="illegal candidate transition"):
        transition_candidate(candidate, CandidateState.PROMOTED)


def test_non_reproduction_becomes_inconclusive(candidate, approved_scope, now):
    candidate = queue_validation(candidate, approved_scope, now=now)
    candidate = transition_candidate(candidate, CandidateState.VALIDATION_RUNNING)
    candidate = complete_validation(candidate, _run(candidate, now, ValidationResult.TIMED_OUT, ()))
    assert candidate.state is CandidateState.INCONCLUSIVE


def test_validation_run_for_another_candidate_is_rejected(candidate, approved_scope, now):
    candidate = queue_validation(candidate, approved_scope, now=now)
    candidate = transition_candidate(candidate, CandidateState.VALIDATION_RUNNING)
    other = candidate.model_copy(update={"candidate_id": __import__("uuid").uuid4()})
    with pytest.raises(TransitionRejected, match="another Candidate"):
        complete_validation(candidate, _run(other, now))


@pytest.mark.parametrize("failure", ["evidence", "critic", "duplicate"])
def test_finding_gate_rejects_missing_invariants(candidate, approved_scope, now, failure):
    candidate = queue_validation(candidate, approved_scope, now=now)
    candidate = transition_candidate(candidate, CandidateState.VALIDATION_RUNNING)
    run = _run(candidate, now, evidence=() if failure == "evidence" else ("a" * 64,))
    if failure == "evidence":
        candidate = transition_candidate(candidate, CandidateState.VALIDATED)
    else:
        candidate = complete_validation(candidate, run)
    candidate = transition_candidate(candidate, CandidateState.CRITIC_REVIEWED)
    bundle = EvidenceBundle(
        candidate_id=candidate.candidate_id,
        evidence_refs=("a" * 64,),
    )
    critic = CriticReview(
        candidate_id=candidate.candidate_id,
        accepted=failure != "critic",
        rationale="Independent review",
    )
    with pytest.raises(TransitionRejected):
        promote_candidate(
            candidate,
            root_cause="Missing authorization predicate",
            affected_versions=("1.0",),
            impact="Cross-tenant read",
            severity_assessment={"cvss": 6.5},
            validation_runs=(run,),
            evidence_bundle=bundle,
            critic_review=critic,
            duplicate_checked=failure != "duplicate",
        )
