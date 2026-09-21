"""Typed contracts for observation-driven bounded Red Team replanning."""

from __future__ import annotations

from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, DomainModel

from .models import Digest, RedTeamActionKind, RedTeamReconCommand


class RedTeamReplanToolView(DomainModel):
    """Finite authority view exposed to a proposer; it contains no raw target."""

    tool_view_id: Digest
    flow_plan_id: Digest
    checkpoint_id: Digest
    target_id: UUID
    target_url_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    observation_ids: Annotated[tuple[Digest, ...], Field(min_length=1)]
    allowed_action_kinds: Annotated[
        tuple[RedTeamActionKind, ...], Field(min_length=1, max_length=3)
    ]
    allowed_test_classes: Annotated[tuple[str, ...], Field(min_length=1, max_length=128)]
    remaining_actions: int = Field(ge=1)
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("Red Team replan Tool View expiry is invalid")
        if tuple(sorted(set(self.observation_ids))) != self.observation_ids:
            raise ValueError("Red Team replan observations must be sorted and unique")
        if tuple(sorted(set(self.allowed_action_kinds), key=str)) != self.allowed_action_kinds:
            raise ValueError("Red Team replan action kinds must be sorted and unique")
        if tuple(sorted(set(self.allowed_test_classes))) != self.allowed_test_classes:
            raise ValueError("Red Team replan test classes must be sorted and unique")
        if self.tool_view_id != canonical_digest(
            self.model_dump(mode="python", exclude={"tool_view_id"})
        ):
            raise ValueError("Red Team replan Tool View digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> RedTeamReplanToolView:
        return cls(tool_view_id=canonical_digest(values), **values)


class RedTeamReplanProposal(DomainModel):
    """Untrusted next-step intent. Target URL and executable fields are absent."""

    proposal_id: Digest
    tool_view_id: Digest
    source_observation_ids: Annotated[tuple[Digest, ...], Field(min_length=1)]
    action_kind: RedTeamActionKind
    test_class: str = Field(min_length=1, max_length=128)
    rationale_digest: Digest
    ttl_seconds: int = Field(ge=1, le=300)
    proposed_at: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if tuple(sorted(set(self.source_observation_ids))) != self.source_observation_ids:
            raise ValueError("Red Team replan proposal observations must be sorted and unique")
        if self.proposal_id != canonical_digest(
            self.model_dump(mode="python", exclude={"proposal_id"})
        ):
            raise ValueError("Red Team replan proposal digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> RedTeamReplanProposal:
        return cls(proposal_id=canonical_digest(values), **values)


class RedTeamReplanAdmission(DomainModel):
    """Control-plane admission for exactly one re-sealed next action."""

    admission_id: Digest
    proposal_id: Digest
    tool_view_id: Digest
    flow_plan_id: Digest
    source_checkpoint_id: Digest
    source_observation_ids: tuple[Digest, ...]
    command: RedTeamReconCommand
    policy_request_digest: Digest
    required_approval_action: ApprovalAction = ApprovalAction.EXECUTE_RED_TEAM_ACTION
    required_approval_digest: Digest
    admitted_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.command.action.plan_id != self.flow_plan_id
            or self.command.action.expected_checkpoint_id != self.source_checkpoint_id
            or self.required_approval_action is not ApprovalAction.EXECUTE_RED_TEAM_ACTION
            or self.required_approval_digest != self.command.action.action_id
        ):
            raise ValueError("Red Team replan admission binding is invalid")
        if self.admission_id != canonical_digest(
            self.model_dump(mode="python", exclude={"admission_id"})
        ):
            raise ValueError("Red Team replan admission digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> RedTeamReplanAdmission:
        expanded = cls.model_construct(admission_id="0" * 64, **values).model_dump(
            mode="python", exclude={"admission_id"}
        )
        return cls(admission_id=canonical_digest(expanded), **expanded)
