"""Trusted deterministic reducer for independent counterevidence review."""

from __future__ import annotations

from datetime import datetime
from uuid import NAMESPACE_URL, uuid5

from vulnloom.domain.models import (
    Candidate,
    CandidateState,
    CriticReview,
    CriticVerdict,
    Evidence,
    EvidenceBundle,
    Scope,
    ScopeState,
    ValidationResult,
    ValidationRun,
)
from vulnloom.domain.state_machine import transition_candidate
from vulnloom.evidence import EvidenceStore

from .models import (
    CRITIC_RULESET_DIGEST,
    CounterevidenceDisposition,
    CriticOutcome,
    CriticPlan,
    domain_object_digest,
)
from .store import CriticStore


class CriticRejected(ValueError):
    """The review request violated provenance, Scope, or Evidence invariants."""


class DeterministicCritic:
    def __init__(self, *, scope: Scope, evidence_store: EvidenceStore, store: CriticStore):
        self.scope = scope
        self.evidence_store = evidence_store
        self.store = store

    def review(
        self,
        candidate: Candidate,
        validation_run: ValidationRun,
        evidence_bundle: EvidenceBundle,
        evidence: tuple[Evidence, ...],
        plan: CriticPlan,
        *,
        now: datetime,
    ) -> CriticOutcome:
        catalog = self._preflight(
            candidate, validation_run, evidence_bundle, evidence, plan, now=now
        )
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome

        confirmed = tuple(
            dict.fromkeys(
                ref
                for assessment in plan.assessments
                if assessment.disposition is CounterevidenceDisposition.CONFIRMED
                for ref in assessment.evidence_refs
            )
        )
        if confirmed:
            verdict = CriticVerdict.REJECTED
            rationale_code = "counterevidence_confirmed"
        elif any(
            item.disposition is CounterevidenceDisposition.INCONCLUSIVE
            for item in plan.assessments
        ):
            verdict = CriticVerdict.INCONCLUSIVE
            rationale_code = "counterevidence_review_inconclusive"
        else:
            verdict = CriticVerdict.ACCEPTED
            rationale_code = "all_counterevidence_angles_ruled_out"

        # Force a final no-follow integrity read immediately before the state decision.
        for ref in dict.fromkeys(
            ref for item in plan.assessments for ref in item.evidence_refs
        ):
            self.evidence_store.read_text(catalog[ref])

        review = CriticReview(
            review_id=uuid5(NAMESPACE_URL, f"vulnloom:critic-review:{plan.plan_id}"),
            plan_id=plan.plan_id,
            candidate_id=candidate.candidate_id,
            validation_run_id=validation_run.run_id,
            evidence_bundle_id=evidence_bundle.bundle_id,
            validation_context_id=plan.validation_context_id,
            review_context_id=plan.review_context_id,
            ruleset_digest=CRITIC_RULESET_DIGEST,
            verdict=verdict,
            counterevidence_refs=confirmed,
            rationale_code=rationale_code,
            reviewed_at=now,
        )
        if verdict is CriticVerdict.INCONCLUSIVE:
            reviewed_candidate = candidate
        else:
            reviewed_candidate = transition_candidate(candidate, CandidateState.CRITIC_REVIEWED)
            if verdict is CriticVerdict.REJECTED:
                reviewed_candidate = transition_candidate(
                    reviewed_candidate, CandidateState.REJECTED
                )
        outcome = CriticOutcome(
            plan_id=plan.plan_id,
            candidate=reviewed_candidate,
            review=review,
            completed_at=now,
        )
        self.store.complete(outcome)
        return outcome

    def _preflight(
        self,
        candidate: Candidate,
        validation_run: ValidationRun,
        evidence_bundle: EvidenceBundle,
        evidence: tuple[Evidence, ...],
        plan: CriticPlan,
        *,
        now: datetime,
    ) -> dict[str, Evidence]:
        if candidate.state is not CandidateState.VALIDATED:
            raise CriticRejected("Critic requires a deterministically validated Candidate")
        if self.scope.state is not ScopeState.APPROVED:
            raise CriticRejected("Critic requires an approved Scope")
        if not self.scope.valid_from <= now < self.scope.valid_until:
            raise CriticRejected("Critic is outside the Scope validity window")
        if plan.created_at > now or now >= plan.deadline:
            raise CriticRejected("CriticPlan is not currently valid")
        if (
            candidate.scope_id != self.scope.scope_id
            or candidate.scope_version != self.scope.version
            or plan.scope_id != self.scope.scope_id
            or plan.scope_version != self.scope.version
        ):
            raise CriticRejected("Critic inputs are bound to another Scope version")
        if (
            plan.candidate_id != candidate.candidate_id
            or plan.candidate_digest != domain_object_digest(candidate)
            or plan.validation_run_id != validation_run.run_id
            or plan.validation_run_digest != domain_object_digest(validation_run)
            or plan.evidence_bundle_id != evidence_bundle.bundle_id
            or plan.evidence_bundle_digest != domain_object_digest(evidence_bundle)
        ):
            raise CriticRejected("CriticPlan provenance does not match its sealed inputs")
        if (
            validation_run.candidate_id != candidate.candidate_id
            or validation_run.target_version != candidate.target_version
            or validation_run.scope_version != candidate.scope_version
            or validation_run.result is not ValidationResult.REPRODUCED
            or not validation_run.evidence_refs
        ):
            raise CriticRejected("Critic requires a matching reproduced ValidationRun")
        if (
            evidence_bundle.candidate_id != candidate.candidate_id
            or not evidence_bundle.evidence_refs
            or not set(validation_run.evidence_refs) <= set(evidence_bundle.evidence_refs)
        ):
            raise CriticRejected("Critic EvidenceBundle does not cover Validation Evidence")

        catalog = {item.evidence_id: item for item in evidence}
        if len(catalog) != len(evidence):
            raise CriticRejected("Critic Evidence catalog contains duplicate identities")
        required = set(evidence_bundle.evidence_refs)
        required.update(ref for item in plan.assessments for ref in item.evidence_refs)
        if not required <= set(catalog):
            raise CriticRejected("Critic referenced Evidence missing from the supplied catalog")
        for ref in required:
            item = catalog[ref]
            if item.target_version != candidate.target_version:
                raise CriticRejected("Critic Evidence is bound to another Target version")
            try:
                self.evidence_store.read_text(item)
            except ValueError as exc:
                raise CriticRejected("Critic Evidence is unavailable or corrupt") from exc
        return catalog
