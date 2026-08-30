"""Pure, explicit Candidate and Finding lifecycle rules."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from uuid import UUID

from .models import (
    Candidate,
    CandidateState,
    CriticReview,
    EvidenceBundle,
    Finding,
    Scope,
    ScopeState,
    ValidationResult,
    ValidationRun,
)


class TransitionRejected(ValueError):
    """A requested domain transition violated an invariant."""


_CANDIDATE_TRANSITIONS: dict[CandidateState, frozenset[CandidateState]] = {
    CandidateState.PROPOSED: frozenset(
        {CandidateState.REJECTED, CandidateState.DUPLICATE, CandidateState.VALIDATION_PENDING}
    ),
    CandidateState.VALIDATION_PENDING: frozenset({CandidateState.VALIDATION_RUNNING}),
    CandidateState.VALIDATION_RUNNING: frozenset(
        {CandidateState.VALIDATED, CandidateState.INCONCLUSIVE}
    ),
    CandidateState.VALIDATED: frozenset({CandidateState.CRITIC_REVIEWED}),
    CandidateState.CRITIC_REVIEWED: frozenset({CandidateState.REJECTED, CandidateState.PROMOTED}),
}


def transition_candidate(candidate: Candidate, target: CandidateState) -> Candidate:
    allowed = _CANDIDATE_TRANSITIONS.get(candidate.state, frozenset())
    if target not in allowed:
        raise TransitionRejected(f"illegal candidate transition: {candidate.state} -> {target}")
    return candidate.model_copy(update={"state": target})


def queue_validation(candidate: Candidate, scope: Scope, *, now: datetime) -> Candidate:
    if scope.state is not ScopeState.APPROVED:
        raise TransitionRejected("validation requires an approved Scope")
    if not scope.valid_from <= now < scope.valid_until:
        raise TransitionRejected("validation is outside the Scope validity window")
    if candidate.scope_id != scope.scope_id or candidate.scope_version != scope.version:
        raise TransitionRejected("Candidate is bound to another Scope version")
    return transition_candidate(candidate, CandidateState.VALIDATION_PENDING)


def complete_validation(candidate: Candidate, run: ValidationRun) -> Candidate:
    if run.candidate_id != candidate.candidate_id:
        raise TransitionRejected("ValidationRun belongs to another Candidate")
    if (
        run.target_version != candidate.target_version
        or run.scope_version != candidate.scope_version
    ):
        raise TransitionRejected("ValidationRun is bound to another Target or Scope version")
    target = (
        CandidateState.VALIDATED
        if run.result is ValidationResult.REPRODUCED
        else CandidateState.INCONCLUSIVE
    )
    return transition_candidate(candidate, target)


def promote_candidate(
    candidate: Candidate,
    *,
    root_cause: str,
    affected_versions: tuple[str, ...],
    impact: str,
    severity_assessment: dict[str, str | float],
    validation_runs: Iterable[ValidationRun],
    evidence_bundle: EvidenceBundle,
    critic_review: CriticReview,
    duplicate_checked: bool,
    finding_id: UUID | None = None,
) -> tuple[Candidate, Finding]:
    if candidate.state is not CandidateState.CRITIC_REVIEWED:
        raise TransitionRejected("only a critic-reviewed Candidate can become a Finding")
    runs = tuple(validation_runs)
    reproduced = tuple(
        run
        for run in runs
        if run.candidate_id == candidate.candidate_id
        and run.target_version == candidate.target_version
        and run.scope_version == candidate.scope_version
        and run.result is ValidationResult.REPRODUCED
        and run.evidence_refs
    )
    if not reproduced:
        raise TransitionRejected("Finding requires a reproduced ValidationRun with evidence")
    if evidence_bundle.candidate_id != candidate.candidate_id or not evidence_bundle.evidence_refs:
        raise TransitionRejected("Finding requires a non-empty EvidenceBundle for this Candidate")
    if critic_review.candidate_id != candidate.candidate_id or not critic_review.accepted:
        raise TransitionRejected("Critic rejected or did not review this Candidate")
    if not duplicate_checked:
        raise TransitionRejected("duplicate-family check is required")

    promoted = transition_candidate(candidate, CandidateState.PROMOTED)
    values = {
        "candidate_id": candidate.candidate_id,
        "root_cause": root_cause,
        "affected_versions": affected_versions,
        "preconditions": candidate.preconditions,
        "impact": impact,
        "severity_assessment": severity_assessment,
        "validation_run_ids": tuple(run.run_id for run in reproduced),
        "evidence_bundle_id": evidence_bundle.bundle_id,
    }
    if finding_id is not None:
        values["finding_id"] = finding_id
    return promoted, Finding(**values)
