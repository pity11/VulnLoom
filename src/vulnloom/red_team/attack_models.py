"""Typed R11 contracts for an approval-bound external Web attack chain."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, DomainModel

from .models import RedTeamPhase

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ReasonCode = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")]


class AttackObjectiveKind(StrEnum):
    ESTABLISH_TEST_SESSION = "establish_test_session"
    PROVE_PROTECTED_RESOURCE_ACCESS = "prove_protected_resource_access"


class AttackActionKind(StrEnum):
    INITIAL_ACCESS_ATTEMPT = "initial_access_attempt"
    VERIFY_TEST_SESSION = "verify_test_session"
    VERIFY_OBJECTIVE = "verify_objective"


class AttackImpact(StrEnum):
    READ_ONLY = "read_only"
    STATE_CHANGE = "state_change"


class AttackChainStatus(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    GOAL_REACHED = "goal_reached"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    KILLED = "killed"


class AttackNodeStatus(StrEnum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class AttackActionOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class AttackAuditDecision(StrEnum):
    ALLOWED = "allowed"
    REJECTED = "rejected"


class AttackObjective(DomainModel):
    objective_id: Digest
    kind: AttackObjectiveKind
    evidence_requirement: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.objective_id != canonical_digest(
            self.model_dump(mode="python", exclude={"objective_id"})
        ):
            raise ValueError("Attack Objective content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackObjective:
        return cls(objective_id=canonical_digest(values), **values)


class AttackAction(DomainModel):
    action_id: Digest
    flow_plan_id: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    ordinal: int = Field(ge=1, le=32)
    kind: AttackActionKind
    phase: RedTeamPhase
    target_id: UUID
    target_path: str = Field(min_length=1, max_length=1_024)
    test_class: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    impact: AttackImpact
    prerequisite_action_ids: Annotated[tuple[Digest, ...], Field(max_length=8)] = ()
    objective_id: Digest

    @field_validator("target_path")
    @classmethod
    def exact_safe_path(cls, value: str) -> str:
        if (
            not value.startswith("/")
            or "//" in value
            or "?" in value
            or "#" in value
            or "%" in value
            or "\\" in value
            or "\x00" in value
            or any(segment in {".", ".."} for segment in value.split("/"))
            or not value.isascii()
            or any(ord(character) <= 32 for character in value)
        ):
            raise ValueError("Attack Action requires an exact canonical path")
        return value

    @model_validator(mode="after")
    def sealed(self) -> Self:
        expected_phase = {
            AttackActionKind.INITIAL_ACCESS_ATTEMPT: RedTeamPhase.INITIAL_ACCESS,
            AttackActionKind.VERIFY_TEST_SESSION: RedTeamPhase.POST_EXPLOITATION,
            AttackActionKind.VERIFY_OBJECTIVE: RedTeamPhase.POST_EXPLOITATION,
        }[self.kind]
        if self.phase is not expected_phase:
            raise ValueError("Attack Action kind and phase do not match")
        if self.kind is AttackActionKind.INITIAL_ACCESS_ATTEMPT:
            if self.impact is not AttackImpact.STATE_CHANGE:
                raise ValueError("Initial Access must declare state-change impact")
        elif self.impact is not AttackImpact.READ_ONLY:
            raise ValueError("Post-exploitation verification must remain read-only")
        if len(set(self.prerequisite_action_ids)) != len(self.prerequisite_action_ids):
            raise ValueError("Attack Action prerequisites must be unique")
        if self.action_id != canonical_digest(
            self.model_dump(mode="python", exclude={"action_id"})
        ):
            raise ValueError("Attack Action content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackAction:
        expanded = cls.model_construct(action_id="0" * 64, **values).model_dump(
            mode="python", exclude={"action_id"}
        )
        return cls(action_id=canonical_digest(expanded), **expanded)


class AttackGraph(DomainModel):
    graph_id: Digest
    flow_plan_id: Digest
    target_id: UUID
    scope_id: UUID
    scope_version: int = Field(ge=1)
    objective: AttackObjective
    actions: Annotated[tuple[AttackAction, ...], Field(min_length=2, max_length=32)]

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if tuple(action.ordinal for action in self.actions) != tuple(
            range(1, len(self.actions) + 1)
        ):
            raise ValueError("Attack Graph actions must use contiguous ordinals")
        ids: set[str] = set()
        for action in self.actions:
            if (
                action.flow_plan_id != self.flow_plan_id
                or action.scope_id != self.scope_id
                or action.scope_version != self.scope_version
                or action.target_id != self.target_id
                or action.objective_id != self.objective.objective_id
                or not set(action.prerequisite_action_ids) <= ids
            ):
                raise ValueError("Attack Graph action binding or topology is invalid")
            ids.add(action.action_id)
        if self.actions[0].kind is not AttackActionKind.INITIAL_ACCESS_ATTEMPT:
            raise ValueError("Attack Graph must begin with Initial Access")
        if any(
            action.kind is AttackActionKind.INITIAL_ACCESS_ATTEMPT for action in self.actions[1:]
        ):
            raise ValueError("Attack Graph contains multiple Initial Access actions")
        if any(not action.prerequisite_action_ids for action in self.actions[1:]):
            raise ValueError("Every later Attack Action requires a prerequisite")
        if self.actions[-1].kind is not AttackActionKind.VERIFY_OBJECTIVE:
            raise ValueError("Attack Graph must end with objective verification")
        if self.graph_id != canonical_digest(self.model_dump(mode="python", exclude={"graph_id"})):
            raise ValueError("Attack Graph content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackGraph:
        expanded = cls.model_construct(graph_id="0" * 64, **values).model_dump(
            mode="python", exclude={"graph_id"}
        )
        return cls(graph_id=canonical_digest(expanded), **expanded)


class AttackChainPlan(DomainModel):
    chain_plan_id: Digest
    graph: AttackGraph
    expected_flow_checkpoint_id: Digest
    created_at: AwareDatetime
    deadline: AwareDatetime
    max_failures: int = Field(default=1, ge=1, le=3)
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.deadline <= self.created_at:
            raise ValueError("Attack Chain deadline must follow creation")
        if self.chain_plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"chain_plan_id"})
        ):
            raise ValueError("Attack Chain Plan content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackChainPlan:
        expanded = cls.model_construct(chain_plan_id="0" * 64, **values).model_dump(
            mode="python", exclude={"chain_plan_id"}
        )
        return cls(chain_plan_id=canonical_digest(expanded), **expanded)


class AttackNodeProgress(DomainModel):
    action_id: Digest
    status: AttackNodeStatus = AttackNodeStatus.PENDING
    observation_id: Digest | None = None

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if (self.status is AttackNodeStatus.PENDING) != (self.observation_id is None):
            raise ValueError("Attack node status and observation are inconsistent")
        return self


class AttackChainCheckpoint(DomainModel):
    checkpoint_id: Digest
    chain_plan_id: Digest
    revision: int = Field(ge=0)
    status: AttackChainStatus
    nodes: tuple[AttackNodeProgress, ...]
    failures: int = Field(ge=0)
    stop_reason: ReasonCode | None = None
    updated_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        terminal = self.status in {
            AttackChainStatus.GOAL_REACHED,
            AttackChainStatus.FAILED,
            AttackChainStatus.TIMED_OUT,
            AttackChainStatus.KILLED,
        }
        if terminal != (self.stop_reason is not None):
            raise ValueError("Attack Chain terminal state requires one stop reason")
        if len({node.action_id for node in self.nodes}) != len(self.nodes):
            raise ValueError("Attack Chain checkpoint nodes must be unique")
        if self.checkpoint_id != canonical_digest(
            self.model_dump(mode="python", exclude={"checkpoint_id"})
        ):
            raise ValueError("Attack Chain checkpoint digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackChainCheckpoint:
        expanded = cls.model_construct(checkpoint_id="0" * 64, **values).model_dump(
            mode="python", exclude={"checkpoint_id"}
        )
        return cls(checkpoint_id=canonical_digest(expanded), **expanded)


class AttackActionAuthorization(DomainModel):
    authorization_id: Digest
    chain_plan_id: Digest
    action_id: Digest
    execution_approval_action: ApprovalAction = ApprovalAction.EXECUTE_RED_TEAM_ACTION
    execution_approval_digest: Digest
    policy_action_digest: Digest
    required_policy_approvals: tuple[ApprovalAction, ...]

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.execution_approval_action is not ApprovalAction.EXECUTE_RED_TEAM_ACTION
            or self.execution_approval_digest != self.action_id
            or tuple(sorted(set(self.required_policy_approvals), key=str))
            != self.required_policy_approvals
        ):
            raise ValueError("Attack Action authorization binding is invalid")
        if self.authorization_id != canonical_digest(
            self.model_dump(mode="python", exclude={"authorization_id"})
        ):
            raise ValueError("Attack Action authorization digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackActionAuthorization:
        expanded = cls.model_construct(authorization_id="0" * 64, **values).model_dump(
            mode="python", exclude={"authorization_id"}
        )
        return cls(authorization_id=canonical_digest(expanded), **expanded)


class AttackActionCommand(DomainModel):
    command_id: Digest
    chain_plan_id: Digest
    expected_checkpoint_id: Digest
    action_id: Digest
    attempt: int = Field(default=1, ge=1, le=2)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.command_id != canonical_digest(
            self.model_dump(mode="python", exclude={"command_id"})
        ):
            raise ValueError("Attack Action command digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackActionCommand:
        expanded = cls.model_construct(command_id="0" * 64, **values).model_dump(
            mode="python", exclude={"command_id"}
        )
        return cls(command_id=canonical_digest(expanded), **expanded)


class AttackActionObservation(DomainModel):
    observation_id: Digest
    command_id: Digest
    action_id: Digest
    outcome: AttackActionOutcome
    reason_code: ReasonCode
    evidence_refs: Annotated[tuple[Digest, ...], Field(max_length=8)] = ()
    goal_reached: bool = False
    cleanup_complete: bool
    sensitive_data_redacted: bool = True
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.sensitive_data_redacted:
            raise ValueError("Attack Action observation must be redacted")
        if self.outcome is AttackActionOutcome.SUCCEEDED and (
            not self.cleanup_complete or not self.evidence_refs
        ):
            raise ValueError("Successful Attack Action requires evidence and cleanup")
        if self.goal_reached and self.outcome is not AttackActionOutcome.SUCCEEDED:
            raise ValueError("Only a successful Attack Action may reach the goal")
        if self.observation_id != canonical_digest(
            self.model_dump(mode="python", exclude={"observation_id"})
        ):
            raise ValueError("Attack Action observation digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackActionObservation:
        expanded = cls.model_construct(observation_id="0" * 64, **values).model_dump(
            mode="python", exclude={"observation_id"}
        )
        return cls(observation_id=canonical_digest(expanded), **expanded)


class AttackActionAuditRecord(DomainModel):
    audit_id: Digest
    chain_plan_id: Digest
    action_id: Digest
    checkpoint_id: Digest
    decision: AttackAuditDecision
    reason_code: ReasonCode
    approval_ids: tuple[UUID, ...] = ()
    recorded_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.audit_id != canonical_digest(self.model_dump(mode="python", exclude={"audit_id"})):
            raise ValueError("Attack Action audit digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> AttackActionAuditRecord:
        expanded = cls.model_construct(audit_id="0" * 64, **values).model_dump(
            mode="python", exclude={"audit_id"}
        )
        return cls(audit_id=canonical_digest(expanded), **expanded)
