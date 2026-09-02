"""Digest-only binding of an accepted Critic Intake to a completed outcome."""

from __future__ import annotations

from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, CriticVerdict, DomainModel
from vulnloom.runners.models import Digest

_FINAL_STATES = {
    CriticVerdict.ACCEPTED: CandidateState.CRITIC_REVIEWED,
    CriticVerdict.REJECTED: CandidateState.REJECTED,
    CriticVerdict.INCONCLUSIVE: CandidateState.VALIDATED,
}


class AgentCriticOutcomeBindingPlan(DomainModel):
    binding_plan_id: Digest
    critic_intake_plan_id: Digest
    critic_intake_record_id: Digest
    critic_intake_record_digest: Digest
    outcome_binding_id: Digest
    outcome_binding_digest: Digest
    candidate_id: UUID
    validated_candidate_digest: Digest
    validation_run_id: UUID
    validation_run_digest: Digest
    evidence_bundle_id: UUID
    evidence_bundle_digest: Digest
    critic_plan_id: Digest
    critic_plan_digest: Digest
    critic_outcome_digest: Digest
    critic_review_id: UUID
    critic_review_digest: Digest
    verdict: CriticVerdict
    final_candidate_state: CandidateState
    final_candidate_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.deadline:
            raise ValueError("Critic outcome binding window is invalid")
        if "\x00" in self.idempotency_key:
            raise ValueError("Critic outcome binding idempotency key contains NUL")
        if self.final_candidate_state is not _FINAL_STATES[self.verdict]:
            raise ValueError("Critic outcome binding state does not match verdict")
        if self.binding_plan_id != agent_critic_outcome_binding_plan_digest(self):
            raise ValueError("Critic outcome binding plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AgentCriticOutcomeBindingPlan:
        return cls(binding_plan_id=canonical_digest(values), **values)


def agent_critic_outcome_binding_plan_digest(plan: AgentCriticOutcomeBindingPlan) -> str:
    return canonical_digest(plan.model_dump(mode="python", exclude={"binding_plan_id"}))


class AgentCriticOutcomeBinding(DomainModel):
    binding_id: Digest
    binding_plan_id: Digest
    critic_intake_record_id: Digest
    outcome_binding_id: Digest
    candidate_id: UUID
    validated_candidate_digest: Digest
    validation_run_id: UUID
    evidence_bundle_id: UUID
    critic_plan_id: Digest
    critic_outcome_digest: Digest
    critic_review_id: UUID
    critic_review_digest: Digest
    verdict: CriticVerdict
    final_candidate_state: CandidateState
    final_candidate_digest: Digest
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.final_candidate_state is not _FINAL_STATES[self.verdict]:
            raise ValueError("Critic binding state does not match verdict")
        if self.binding_id != agent_critic_outcome_binding_digest(self):
            raise ValueError("Critic outcome binding digest mismatch")
        return self


def agent_critic_outcome_binding_digest(binding: AgentCriticOutcomeBinding) -> str:
    return canonical_digest(binding.model_dump(mode="python", exclude={"binding_id"}))
