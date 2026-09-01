"""Trusted human intake that binds, but never executes, a ValidationPlan."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from vulnloom.agent_runtime.audit_models import (
    AgentSessionAuditArtifact,
    AgentSessionRecommendationDisposition,
    agent_session_audit_bundle_digest,
    agent_session_recommendation_digest,
)
from vulnloom.agent_runtime.audit_store import AgentSessionAuditArtifactStore
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, Scope, ScopeState
from vulnloom.domain.protocol import WorkerRole
from vulnloom.hypotheses import CandidateSetStore
from vulnloom.hypotheses.models import candidate_set_digest
from vulnloom.policy import PolicyEngine
from vulnloom.runners import NetworkMode, SandboxProfileKind
from vulnloom.runners.models import sandbox_profile_digest

from .intake_models import (
    AgentValidationIntakeCommand,
    AgentValidationIntakeDecision,
    AgentValidationIntakePlan,
    AgentValidationIntakeRecord,
    agent_validation_intake_command_digest,
    agent_validation_intake_plan_digest,
)
from .intake_store import AgentValidationIntakeStore
from .models import ValidationPlan, candidate_content_digest, validation_plan_digest


class AgentValidationIntakeRejected(ValueError):
    pass


class AgentValidationIntakeTimedOut(TimeoutError):
    pass


class AgentValidationIntakeService:
    def __init__(
        self,
        *,
        scope: Scope,
        audit_artifact_store: AgentSessionAuditArtifactStore,
        candidate_set_store: CandidateSetStore,
        store: AgentValidationIntakeStore,
    ):
        self.scope = scope
        self.audit_artifact_store = audit_artifact_store
        self.candidate_set_store = candidate_set_store
        self.store = store

    def prepare(
        self,
        *,
        audit_artifact: AgentSessionAuditArtifact,
        candidate_set_id: str,
        candidate_id,
        validation_plan: ValidationPlan,
        now: datetime,
        decision_deadline: datetime,
        idempotency_key: str,
    ) -> AgentValidationIntakePlan:
        bundle, candidate_set, candidate = self._authoritative_inputs(
            audit_artifact, candidate_set_id, candidate_id
        )
        self._verify_bindings(bundle, candidate_set, candidate, validation_plan, now)
        task_deadline = min(
            item.task.deadline
            for item in (validation_plan.runner_request, *validation_plan.broker_calls)
        )
        if not now < decision_deadline <= min(self.scope.valid_until, task_deadline):
            raise AgentValidationIntakeRejected(
                "Agent Validation Intake decision deadline exceeds active Scope"
            )
        values = {
            "audit_bundle_id": bundle.bundle_id,
            "audit_bundle_digest": agent_session_audit_bundle_digest(bundle),
            "audit_artifact_digest": canonical_digest(
                audit_artifact.model_dump(mode="python")
            ),
            "recommendation_id": bundle.recommendation.recommendation_id,
            "recommendation_digest": agent_session_recommendation_digest(
                bundle.recommendation
            ),
            "candidate_set_id": candidate_set.candidate_set_id,
            "candidate_set_digest": candidate_set_digest(candidate_set),
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate_content_digest(candidate),
            "target_id": candidate.target_id,
            "target_version_digest": canonical_digest(candidate.target_version),
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "validation_plan_id": validation_plan.plan_id,
            "validation_plan_digest": validation_plan_digest(validation_plan),
            "created_at": now,
            "decision_deadline": decision_deadline,
            "idempotency_key": idempotency_key,
        }
        return AgentValidationIntakePlan.create(**values)

    def decide(
        self,
        plan: AgentValidationIntakePlan,
        command: AgentValidationIntakeCommand,
        *,
        audit_artifact: AgentSessionAuditArtifact,
        validation_plan: ValidationPlan,
        now: datetime,
    ) -> AgentValidationIntakeRecord:
        try:
            plan = AgentValidationIntakePlan.model_validate(plan)
            command = AgentValidationIntakeCommand.model_validate(command)
        except ValidationError as exc:
            raise AgentValidationIntakeRejected(
                "Agent Validation Intake boundary validation failed"
            ) from exc
        if now >= plan.decision_deadline or now < plan.created_at:
            raise AgentValidationIntakeTimedOut(
                "Agent Validation Intake decision is outside its validity window"
            )
        bundle, candidate_set, candidate = self._authoritative_inputs(
            audit_artifact, plan.candidate_set_id, plan.candidate_id
        )
        self._verify_bindings(bundle, candidate_set, candidate, validation_plan, now)
        self._verify_plan(plan, audit_artifact, bundle, candidate_set, candidate, validation_plan)
        self._verify_command(plan, command, now)
        if (
            command.decision is AgentValidationIntakeDecision.ACCEPT
            and bundle.recommendation.disposition
            is not AgentSessionRecommendationDisposition.COMPLETED
        ):
            raise AgentValidationIntakeRejected(
                "Only a completed Agent recommendation may be accepted"
            )
        claim = self.store.claim(plan, command, now=now)
        if not claim.created:
            assert claim.record is not None
            return claim.record
        values = {
            "intake_plan_id": plan.intake_plan_id,
            "command_id": command.command_id,
            "audit_bundle_id": plan.audit_bundle_id,
            "recommendation_id": plan.recommendation_id,
            "candidate_set_id": plan.candidate_set_id,
            "candidate_id": plan.candidate_id,
            "candidate_digest": plan.candidate_digest,
            "validation_plan_id": plan.validation_plan_id,
            "validation_plan_digest": plan.validation_plan_digest,
            "target_id": plan.target_id,
            "target_version_digest": plan.target_version_digest,
            "scope_id": plan.scope_id,
            "scope_version": plan.scope_version,
            "decision": command.decision,
            "reason_code": command.reason_code,
            "reviewer": command.reviewer,
            "decided_at": command.decided_at,
            "expires_at": plan.decision_deadline,
        }
        record = AgentValidationIntakeRecord(
            record_id=canonical_digest(values), **values
        )
        self.store.complete(record)
        return record

    def _authoritative_inputs(self, artifact, candidate_set_id, candidate_id):
        try:
            bundle = self.audit_artifact_store.read_bundle(artifact)
            candidate_set = self.candidate_set_store.load(candidate_set_id)
        except (OSError, ValueError, ValidationError) as exc:
            raise AgentValidationIntakeRejected(
                "Agent Validation Intake authoritative object verification failed"
            ) from exc
        matches = tuple(
            item for item in candidate_set.candidates if item.candidate_id == candidate_id
        )
        if len(matches) != 1:
            raise AgentValidationIntakeRejected(
                "Agent Validation Intake Candidate is absent or duplicated"
            )
        return bundle, candidate_set, matches[0]

    def _verify_bindings(self, bundle, candidate_set, candidate, validation_plan, now):
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
        ):
            raise AgentValidationIntakeRejected(
                "Agent Validation Intake requires a currently approved Scope"
            )
        if candidate.state is not CandidateState.PROPOSED:
            raise AgentValidationIntakeRejected(
                "Agent Validation Intake requires a proposed Candidate"
            )
        if (
            candidate_set.target_id != candidate.target_id
            or candidate_set.target_version != candidate.target_version
            or candidate_set.scope_id != self.scope.scope_id
            or candidate_set.scope_version != self.scope.version
            or bundle.target_id != candidate.target_id
            or bundle.target_version_digest != canonical_digest(candidate.target_version)
            or bundle.scope_id != self.scope.scope_id
            or bundle.scope_version != self.scope.version
            or validation_plan.candidate_id != candidate.candidate_id
            or validation_plan.candidate_digest != candidate_content_digest(candidate)
            or validation_plan.target_id != candidate.target_id
            or validation_plan.target_version != candidate.target_version
            or validation_plan.scope_id != self.scope.scope_id
            or validation_plan.scope_version != self.scope.version
            or validation_plan.selected_at > now
            or validation_plan.plan_id != validation_plan_digest(validation_plan)
            or bundle.completed_at > now
        ):
            raise AgentValidationIntakeRejected(
                "Agent Validation Intake Candidate, Audit, Scope, or ValidationPlan drifted"
            )
        expected_input = f"candidate:{candidate_content_digest(candidate)}"
        for request in (validation_plan.runner_request, *validation_plan.broker_calls):
            task = request.task
            if (
                task.engagement_id != self.scope.engagement_id
                or task.target_id != candidate.target_id
                or task.target_version != candidate.target_version
                or task.scope_id != self.scope.scope_id
                or task.scope_version != self.scope.version
                or task.worker_role is not WorkerRole.VALIDATOR
                or task.policy_digest != PolicyEngine(self.scope).policy_digest
                or expected_input not in task.input_refs
                or now >= task.deadline
                or task.deadline > self.scope.valid_until
            ):
                raise AgentValidationIntakeRejected(
                    "Agent Validation Intake ValidationPlan task provenance drifted"
                )
        request = validation_plan.runner_request
        if (
            request.profile.kind is not SandboxProfileKind.VALIDATION
            or request.profile.network_mode is not NetworkMode.NONE
            or request.task.sandbox_profile_digest
            != sandbox_profile_digest(request.profile)
            or any(
                call.profile.kind is not SandboxProfileKind.VALIDATION
                for call in validation_plan.broker_calls
            )
        ):
            raise AgentValidationIntakeRejected(
                "Agent Validation Intake Runner/Profile binding is unsafe"
            )

    @staticmethod
    def _verify_plan(plan, artifact, bundle, candidate_set, candidate, validation_plan):
        if (
            plan.intake_plan_id != agent_validation_intake_plan_digest(plan)
            or plan.audit_bundle_id != bundle.bundle_id
            or plan.audit_bundle_digest != agent_session_audit_bundle_digest(bundle)
            or plan.audit_artifact_digest
            != canonical_digest(artifact.model_dump(mode="python"))
            or plan.recommendation_id != bundle.recommendation.recommendation_id
            or plan.recommendation_digest
            != agent_session_recommendation_digest(bundle.recommendation)
            or plan.candidate_set_id != candidate_set.candidate_set_id
            or plan.candidate_set_digest != candidate_set_digest(candidate_set)
            or plan.candidate_id != candidate.candidate_id
            or plan.candidate_digest != candidate_content_digest(candidate)
            or plan.target_id != candidate.target_id
            or plan.target_version_digest != canonical_digest(candidate.target_version)
            or plan.scope_id != candidate.scope_id
            or plan.scope_version != candidate.scope_version
            or plan.validation_plan_id != validation_plan.plan_id
            or plan.validation_plan_digest != validation_plan_digest(validation_plan)
        ):
            raise AgentValidationIntakeRejected(
                "Agent Validation Intake plan binding drifted"
            )

    @staticmethod
    def _verify_command(plan, command, now):
        if (
            command.command_id != agent_validation_intake_command_digest(command)
            or command.intake_plan_id != plan.intake_plan_id
            or command.intake_plan_digest != agent_validation_intake_plan_digest(plan)
            or command.audit_bundle_id != plan.audit_bundle_id
            or command.candidate_id != plan.candidate_id
            or command.candidate_digest != plan.candidate_digest
            or command.validation_plan_id != plan.validation_plan_id
            or command.validation_plan_digest != plan.validation_plan_digest
            or not plan.created_at <= command.decided_at < plan.decision_deadline
            or command.decided_at > now
        ):
            raise AgentValidationIntakeRejected(
                "Agent Validation Intake command binding drifted"
            )
