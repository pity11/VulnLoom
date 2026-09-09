"""Approval-gated adapter from Source Hunt validation/Critic to shared Finding."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.critic import CriticOutcome, CriticStore, domain_object_digest
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    Candidate,
    CriticVerdict,
    DomainModel,
    Finding,
    Scope,
    ScopeState,
)
from vulnloom.domain.state_machine import promote_candidate
from vulnloom.findings import DuplicateCheckResult, FindingDuplicateCheck

from .execution_models import SourceValidationBinding
from .execution_store import SourceExecutionStore
from .models import Digest

SOURCE_FINDING_SIDE_EFFECTS = ("create verified Finding",)


class SourceFindingPromotionPlan(DomainModel):
    plan_id: Digest
    validation_binding_id: Digest
    validation_binding_digest: Digest
    critic_plan_id: Digest
    critic_outcome_digest: Digest
    duplicate_check_id: Digest
    duplicate_check_digest: Digest
    candidate_id: UUID
    candidate_digest: Digest
    finding_id: UUID
    root_cause: str = Field(min_length=1, max_length=8_192)
    affected_versions: Annotated[tuple[str, ...], Field(min_length=1, max_length=128)]
    impact: str = Field(min_length=1, max_length=8_192)
    severity_assessment: Annotated[dict[str, str | float], Field(min_length=1, max_length=32)]
    scope_id: UUID
    scope_version: int = Field(ge=1)
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.deadline <= self.created_at:
            raise ValueError("Source Finding promotion window is invalid")
        if self.plan_id != canonical_digest(
            self.model_dump(mode="python", exclude={"plan_id"})
        ):
            raise ValueError("SourceFindingPromotionPlan content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> SourceFindingPromotionPlan:
        return cls(plan_id=canonical_digest(values), **values)


def source_finding_approval_digest(plan: SourceFindingPromotionPlan) -> str:
    return canonical_digest(
        {"action": ApprovalAction.MUTATE_TARGET_STATE, "plan_id": plan.plan_id}
    )


class SourceFindingPromotionOutcome(DomainModel):
    plan_id: Digest
    source_candidate_digest: Digest
    promoted_candidate: Candidate
    finding: Finding
    completed_at: AwareDatetime


class SourceFindingPromotionRejected(ValueError):
    pass


class SourceFindingPromotionStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS source_finding_promotions (
                plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                plan_payload TEXT NOT NULL,
                outcome_payload TEXT NOT NULL
            )
            """
        )

    def put(self, plan, outcome):
        with self.connection:
            row = self.connection.execute(
                "SELECT plan_payload, outcome_payload FROM source_finding_promotions "
                "WHERE idempotency_key = ?",
                (plan.idempotency_key,),
            ).fetchone()
            if row is not None:
                if SourceFindingPromotionPlan.model_validate_json(row[0]) != plan:
                    raise SourceFindingPromotionRejected(
                        "Source Finding promotion idempotency collision"
                    )
                return SourceFindingPromotionOutcome.model_validate_json(row[1])
            self.connection.execute(
                "INSERT INTO source_finding_promotions VALUES (?, ?, ?, ?)",
                (
                    plan.plan_id,
                    plan.idempotency_key,
                    plan.model_dump_json(),
                    outcome.model_dump_json(),
                ),
            )
        return outcome

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class SourceFindingPromotionService:
    def __init__(
        self,
        *,
        scope: Scope,
        execution_store: SourceExecutionStore,
        critic_store: CriticStore,
        store: SourceFindingPromotionStore,
    ):
        self.scope = scope
        self.execution_store = execution_store
        self.critic_store = critic_store
        self.store = store

    def execute(
        self,
        *,
        plan: SourceFindingPromotionPlan,
        validation: SourceValidationBinding,
        critic: CriticOutcome,
        duplicate_check: FindingDuplicateCheck,
        approval: ApprovalRequest,
        now,
    ) -> SourceFindingPromotionOutcome:
        try:
            authoritative_validation = self.execution_store.load_validation_binding(
                validation.execution_plan_id
            )
            authoritative_critic_plan, authoritative_critic = (
                self.critic_store.load_completed(critic.plan_id)
            )
        except (ValueError, RuntimeError) as exc:
            raise SourceFindingPromotionRejected(
                "Source Finding authoritative checkpoint is unavailable"
            ) from exc
        candidate = critic.candidate
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or not plan.created_at <= now < plan.deadline
            or plan.scope_id != self.scope.scope_id
            or plan.scope_version != self.scope.version
            or plan.validation_binding_id != validation.binding_id
            or authoritative_validation != validation
            or plan.validation_binding_digest != domain_object_digest(validation)
            or plan.critic_plan_id != critic.plan_id
            or authoritative_critic_plan.plan_id != critic.plan_id
            or authoritative_critic != critic
            or plan.critic_outcome_digest != domain_object_digest(critic)
            or plan.duplicate_check_id != duplicate_check.check_id
            or plan.duplicate_check_digest != domain_object_digest(duplicate_check)
            or plan.candidate_id != candidate.candidate_id
            or plan.candidate_digest != domain_object_digest(candidate)
            or validation.validated_candidate.candidate_id != candidate.candidate_id
            or validation.validation_run.candidate_id != candidate.candidate_id
            or critic.review.verdict is not CriticVerdict.ACCEPTED
            or duplicate_check.result is not DuplicateCheckResult.CLEAR
            or duplicate_check.candidate_id != candidate.candidate_id
            or duplicate_check.candidate_digest != domain_object_digest(candidate)
            or not duplicate_check.checked_at <= now < duplicate_check.expires_at
        ):
            raise SourceFindingPromotionRejected("Source Finding promotion provenance failed")
        if (
            approval.status is not ApprovalStatus.GRANTED
            or approval.action is not ApprovalAction.MUTATE_TARGET_STATE
            or approval.action_digest != source_finding_approval_digest(plan)
            or approval.engagement_id != self.scope.engagement_id
            or approval.target_id != candidate.target_id
            or approval.policy_version != self.scope.version
            or approval.expected_side_effects != SOURCE_FINDING_SIDE_EFFECTS
            or approval.decided_by is None
            or approval.decided_at is None
            or not plan.created_at <= approval.decided_at <= now < approval.expires_at
        ):
            raise SourceFindingPromotionRejected("Source Finding promotion Approval failed")
        promoted, finding = promote_candidate(
            candidate,
            scope=self.scope,
            now=now,
            root_cause=plan.root_cause,
            affected_versions=plan.affected_versions,
            impact=plan.impact,
            severity_assessment=plan.severity_assessment,
            validation_runs=(validation.validation_run,),
            evidence_bundle=validation.evidence_bundle,
            critic_review=critic.review,
            duplicate_checked=True,
            finding_id=plan.finding_id,
        )
        outcome = SourceFindingPromotionOutcome(
            plan_id=plan.plan_id,
            source_candidate_digest=domain_object_digest(candidate),
            promoted_candidate=promoted,
            finding=finding,
            completed_at=now,
        )
        return self.store.put(plan, outcome)
