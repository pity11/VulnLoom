"""Digest-only Approval and outcome contracts for deterministic pilot Critic execution."""

from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, CriticVerdict, DomainModel
from vulnloom.runners.models import Digest

PILOT_CRITIC_EFFECTS = ("critic:review", "candidate:critic_result")


class PilotCriticApprovalAction(DomainModel):
    action_id: Digest
    engagement_id: UUID
    target_id: UUID
    pilot_intake_plan_id: Digest
    pilot_intake_binding_id: Digest
    pilot_intake_binding_digest: Digest
    intake_record_id: Digest
    intake_record_digest: Digest
    critic_plan_id: Digest
    critic_plan_digest: Digest
    evidence_catalog_digest: Digest
    candidate_id: UUID
    validated_candidate_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    expected_side_effects: tuple[str, ...]

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.expected_side_effects != PILOT_CRITIC_EFFECTS:
            raise ValueError("pilot Critic effects drifted")
        if self.action_id != canonical_digest(
            self.model_dump(mode="python", exclude={"action_id"})
        ):
            raise ValueError("pilot Critic action digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        return cls(action_id=canonical_digest(values), **values)


class PilotCriticExecutionPlan(DomainModel):
    execution_plan_id: Digest
    approval_action_id: Digest
    approval_id: UUID
    approval_digest: Digest
    pilot_intake_plan_id: Digest
    pilot_intake_binding_id: Digest
    pilot_intake_binding_digest: Digest
    intake_record_id: Digest
    critic_plan_id: Digest
    critic_plan_digest: Digest
    evidence_catalog_digest: Digest
    candidate_id: UUID
    validated_candidate_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.created_at < self.deadline or "\x00" in self.idempotency_key:
            raise ValueError("pilot Critic execution window or key is invalid")
        if self.execution_plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"execution_plan_id"})
        ):
            raise ValueError("pilot Critic execution plan digest mismatch")
        return self

    @classmethod
    def create(cls, **values):
        return cls(execution_plan_id=canonical_digest(values), **values)


class PilotCriticExecutionBinding(DomainModel):
    binding_id: Digest
    execution_plan_id: Digest
    approval_action_id: Digest
    approval_id: UUID
    approval_digest: Digest
    pilot_intake_binding_id: Digest
    intake_record_id: Digest
    critic_plan_id: Digest
    critic_outcome_digest: Digest
    critic_review_id: UUID
    critic_review_digest: Digest
    outcome_binding_plan_id: Digest
    outcome_binding_plan_digest: Digest
    outcome_binding_id: Digest
    outcome_binding_digest: Digest
    candidate_id: UUID
    validated_candidate_digest: Digest
    final_candidate_digest: Digest
    verdict: CriticVerdict
    final_candidate_state: CandidateState
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected = {
            CriticVerdict.ACCEPTED: CandidateState.CRITIC_REVIEWED,
            CriticVerdict.REJECTED: CandidateState.REJECTED,
            CriticVerdict.INCONCLUSIVE: CandidateState.VALIDATED,
        }[self.verdict]
        if self.final_candidate_state is not expected:
            raise ValueError("pilot Critic verdict/state mismatch")
        if self.binding_id != canonical_digest(
            self.model_dump(mode="python", exclude={"binding_id"})
        ):
            raise ValueError("pilot Critic execution binding digest mismatch")
        return self
