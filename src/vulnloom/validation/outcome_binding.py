"""Read-only provenance binding for an already completed Validation outcome."""

from __future__ import annotations

from datetime import datetime, timedelta

from vulnloom.agent_runtime import AgentSessionAuditArtifact, AgentSessionAuditArtifactStore
from vulnloom.broker import BrokerStatus
from vulnloom.broker.models import broker_call_digest
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, Scope, ScopeState, ValidationResult
from vulnloom.evidence import EvidenceStore
from vulnloom.hypotheses import CandidateSetStore
from vulnloom.hypotheses.models import candidate_set_digest
from vulnloom.runners import SandboxRunStatus
from vulnloom.runners.models import invocation_digest, sandbox_profile_digest

from .intake_models import AgentValidationIntakeDecision, agent_validation_intake_record_digest
from .intake_store import AgentValidationIntakeStore
from .models import ValidationPlan, candidate_content_digest, validation_plan_digest
from .outcome_binding_models import (
    AgentValidationOutcomeBinding,
    AgentValidationOutcomeBindingPlan,
)
from .outcome_binding_store import AgentValidationOutcomeBindingStore
from .store import ValidationStore


class AgentValidationOutcomeBindingRejected(ValueError):
    pass


class AgentValidationOutcomeBindingService:
    def __init__(
        self,
        *,
        scope: Scope,
        audit_store: AgentSessionAuditArtifactStore,
        candidate_store: CandidateSetStore,
        intake_store: AgentValidationIntakeStore,
        validation_store: ValidationStore,
        evidence_store: EvidenceStore,
        binding_store: AgentValidationOutcomeBindingStore,
    ):
        self.scope = scope
        self.audit_store = audit_store
        self.candidate_store = candidate_store
        self.intake_store = intake_store
        self.validation_store = validation_store
        self.evidence_store = evidence_store
        self.binding_store = binding_store

    def prepare(
        self,
        *,
        intake_plan_id: str,
        audit_artifact: AgentSessionAuditArtifact,
        candidate_set_id: str,
        candidate_id,
        validation_plan: ValidationPlan,
        now: datetime,
        idempotency_key: str,
    ) -> AgentValidationOutcomeBindingPlan:
        record, bundle, candidate_set, candidate, stored_plan, outcome = self._load(
            intake_plan_id,
            audit_artifact,
            candidate_set_id,
            candidate_id,
            validation_plan,
            now,
        )
        values = {
            "intake_plan_id": record.intake_plan_id,
            "intake_record_id": record.record_id,
            "intake_record_digest": agent_validation_intake_record_digest(record),
            "audit_bundle_id": bundle.bundle_id,
            "candidate_set_id": candidate_set.candidate_set_id,
            "candidate_set_digest": candidate_set_digest(candidate_set),
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate_content_digest(candidate),
            "target_id": candidate.target_id,
            "target_version_digest": canonical_digest(candidate.target_version),
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "validation_plan_id": stored_plan.plan_id,
            "validation_plan_digest": validation_plan_digest(stored_plan),
            "validation_outcome_digest": canonical_digest(outcome.model_dump(mode="python")),
            "validation_run_id": outcome.validation_run.run_id,
            "result": outcome.verdict.result,
            "evidence_refs": tuple(sorted(outcome.verdict.evidence_refs)),
            "created_at": now,
            "deadline": now + timedelta(seconds=60),
            "idempotency_key": idempotency_key,
        }
        return AgentValidationOutcomeBindingPlan.create(**values)

    def execute(
        self,
        plan: AgentValidationOutcomeBindingPlan,
        *,
        audit_artifact: AgentSessionAuditArtifact,
        validation_plan: ValidationPlan,
        now: datetime,
    ) -> AgentValidationOutcomeBinding:
        if now >= plan.deadline:
            raise AgentValidationOutcomeBindingRejected("outcome binding deadline expired")
        record, _, _, candidate, stored_plan, outcome = self._load(
            plan.intake_plan_id,
            audit_artifact,
            plan.candidate_set_id,
            plan.candidate_id,
            validation_plan,
            now,
        )
        expected = self.prepare(
            intake_plan_id=plan.intake_plan_id,
            audit_artifact=audit_artifact,
            candidate_set_id=plan.candidate_set_id,
            candidate_id=plan.candidate_id,
            validation_plan=validation_plan,
            now=plan.created_at,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise AgentValidationOutcomeBindingRejected("outcome binding plan drifted")
        claim = self.binding_store.claim(plan, now=now)
        if not claim.created:
            assert claim.binding is not None
            return claim.binding
        evidence_bundle = outcome.evidence_bundle
        values = {
            "binding_plan_id": plan.binding_plan_id,
            "intake_record_id": record.record_id,
            "audit_bundle_id": plan.audit_bundle_id,
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate_content_digest(candidate),
            "validation_plan_id": stored_plan.plan_id,
            "validation_outcome_digest": plan.validation_outcome_digest,
            "validation_run_id": outcome.validation_run.run_id,
            "result": outcome.verdict.result,
            "final_candidate_state": outcome.candidate.state,
            "final_candidate_digest": candidate_content_digest(outcome.candidate),
            "evidence_bundle_id": None if evidence_bundle is None else evidence_bundle.bundle_id,
            "evidence_bundle_digest": None
            if evidence_bundle is None
            else canonical_digest(evidence_bundle.model_dump(mode="python")),
            "evidence_refs": tuple(sorted(outcome.verdict.evidence_refs)),
            "completed_at": now,
        }
        binding = AgentValidationOutcomeBinding(binding_id=canonical_digest(values), **values)
        self.binding_store.complete(binding)
        return binding

    def _load(self, intake_plan_id, artifact, candidate_set_id, candidate_id, validation_plan, now):
        try:
            record = self.intake_store.load_completed(intake_plan_id)
            bundle = self.audit_store.read_bundle(artifact)
            candidate_set = self.candidate_store.load(candidate_set_id)
            stored_plan, outcome = self.validation_store.load_completed(validation_plan.plan_id)
        except (ValueError, RuntimeError) as exc:
            raise AgentValidationOutcomeBindingRejected(
                "authoritative binding input unavailable"
            ) from exc
        candidates = tuple(
            item for item in candidate_set.candidates if item.candidate_id == candidate_id
        )
        if len(candidates) != 1:
            raise AgentValidationOutcomeBindingRejected("Candidate binding is unavailable")
        candidate = candidates[0]
        refs = tuple(sorted(outcome.verdict.evidence_refs))
        expected_state = (
            CandidateState.VALIDATED
            if outcome.verdict.result is ValidationResult.REPRODUCED
            else CandidateState.INCONCLUSIVE
        )
        evidence_bundle = outcome.evidence_bundle
        collected_refs = self._collected_evidence_refs(outcome)
        expected_forced_result = self._forced_result(outcome)
        expected_run_plan = (
            f"plan:{stored_plan.plan_id}",
            f"runner:{stored_plan.runner_request.invocation.tool_id}",
            *(
                f"broker:{call.tool_id}:{index}"
                for index, call in enumerate(stored_plan.broker_calls)
            ),
        )
        expected_side_effects = tuple(
            f"broker:{call.tool_id}:{call.http.method.value}"
            for call, result in zip(stored_plan.broker_calls, outcome.broker_results, strict=False)
            if result.status is BrokerStatus.COMPLETED and call.http.method.mutates_state
        )
        expected_resource_usage = {
            "wall_seconds": outcome.runner_result.usage.wall_seconds,
            "cpu_millis": outcome.runner_result.usage.cpu_millis,
            "peak_memory_bytes": outcome.runner_result.usage.peak_memory_bytes,
            "broker_calls": len(outcome.broker_results),
            "tool_calls": outcome.runner_result.budget_used.tool_calls
            + sum(item.tool_calls_used for item in outcome.broker_results),
        }
        broker_bindings_valid = all(
            result.call_id == call.call_id
            and result.task_id == call.task.task_id
            and result.tool_id == call.tool_id
            and result.registry_digest == call.task.tool_registry_digest
            and result.call_digest == broker_call_digest(call)
            and result.completed_at <= outcome.completed_at
            for call, result in zip(stored_plan.broker_calls, outcome.broker_results, strict=False)
        )
        broker_sequence_complete = (
            len(outcome.broker_results) == len(stored_plan.broker_calls)
            or (
                bool(outcome.broker_results)
                and outcome.broker_results[-1].status is not BrokerStatus.COMPLETED
            )
            or outcome.runner_result.status is not SandboxRunStatus.COMPLETED
        )
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or record.decision is not AgentValidationIntakeDecision.ACCEPT
            or now >= record.expires_at
            or record.audit_bundle_id != bundle.bundle_id
            or record.target_id != candidate.target_id
            or record.target_version_digest != canonical_digest(candidate.target_version)
            or record.scope_id != self.scope.scope_id
            or record.scope_version != self.scope.version
            or record.candidate_set_id != candidate_set.candidate_set_id
            or record.candidate_id != candidate.candidate_id
            or record.candidate_digest != candidate_content_digest(candidate)
            or record.validation_plan_id != validation_plan.plan_id
            or record.validation_plan_digest != validation_plan_digest(validation_plan)
            or stored_plan != validation_plan
            or candidate.state is not CandidateState.PROPOSED
            or candidate_set.target_id != candidate.target_id
            or candidate_set.target_version != candidate.target_version
            or candidate_set.scope_id != self.scope.scope_id
            or candidate_set.scope_version != self.scope.version
            or bundle.target_id != candidate.target_id
            or bundle.target_version_digest != canonical_digest(candidate.target_version)
            or bundle.scope_id != self.scope.scope_id
            or bundle.scope_version != self.scope.version
            or outcome.plan_id != stored_plan.plan_id
            or outcome.completed_at != outcome.validation_run.finished_at
            or outcome.validation_run.started_at != outcome.validation_run.finished_at
            or outcome.candidate.candidate_id != candidate.candidate_id
            or outcome.candidate.target_id != candidate.target_id
            or outcome.candidate.target_version != candidate.target_version
            or outcome.candidate.scope_id != self.scope.scope_id
            or outcome.candidate.scope_version != self.scope.version
            or outcome.candidate.state is not expected_state
            or outcome.candidate.model_copy(update={"state": CandidateState.PROPOSED}) != candidate
            or outcome.validation_run.candidate_id != candidate.candidate_id
            or outcome.validation_run.target_version != candidate.target_version
            or outcome.validation_run.scope_version != self.scope.version
            or outcome.validation_run.result is not outcome.verdict.result
            or tuple(sorted(outcome.validation_run.evidence_refs)) != refs
            or outcome.validation_run.sandbox_image_digest
            != stored_plan.runner_request.profile.image_digest
            or outcome.validation_run.policy_digest != stored_plan.runner_request.task.policy_digest
            or outcome.validation_run.plan != expected_run_plan
            or outcome.validation_run.side_effects != expected_side_effects
            or outcome.validation_run.resource_usage != expected_resource_usage
            or outcome.runner_result.run_id != stored_plan.runner_request.run_id
            or outcome.runner_result.task_id != stored_plan.runner_request.task.task_id
            or outcome.runner_result.sandbox_profile_digest
            != sandbox_profile_digest(stored_plan.runner_request.profile)
            or outcome.runner_result.invocation_digest
            != invocation_digest(stored_plan.runner_request.invocation)
            or (
                outcome.runner_result.status is not SandboxRunStatus.COMPLETED
                and outcome.broker_results
            )
            or len(outcome.broker_results) > len(stored_plan.broker_calls)
            or not broker_bindings_valid
            or not broker_sequence_complete
            or not set(refs) <= set(collected_refs)
            or (
                expected_forced_result is not None
                and outcome.verdict.result is not expected_forced_result
            )
            or (
                expected_forced_result is None
                and outcome.verdict.result
                in {ValidationResult.POLICY_STOPPED, ValidationResult.TIMED_OUT}
            )
            or (
                evidence_bundle is not None
                and (
                    evidence_bundle.candidate_id != candidate.candidate_id
                    or tuple(sorted(evidence_bundle.evidence_refs)) != refs
                    or evidence_bundle.sealed_at != outcome.completed_at
                )
            )
            or (refs and evidence_bundle is None)
            or (not refs and evidence_bundle is not None)
            or any(not self.evidence_store.contains(ref) for ref in collected_refs)
        ):
            raise AgentValidationOutcomeBindingRejected("Validation outcome provenance drifted")
        return record, bundle, candidate_set, candidate, stored_plan, outcome

    @staticmethod
    def _collected_evidence_refs(outcome) -> tuple[str, ...]:
        refs = list(outcome.runner_result.evidence_refs)
        for result in outcome.broker_results:
            if result.http is not None:
                refs.extend(result.http.evidence_refs)
        return tuple(dict.fromkeys(refs))

    @staticmethod
    def _forced_result(outcome) -> ValidationResult | None:
        if outcome.runner_result.status is SandboxRunStatus.TIMED_OUT or any(
            item.status is BrokerStatus.TIMED_OUT for item in outcome.broker_results
        ):
            return ValidationResult.TIMED_OUT
        if outcome.runner_result.status is not SandboxRunStatus.COMPLETED:
            return ValidationResult.INCONCLUSIVE
        if any(
            item.status in {BrokerStatus.DENIED, BrokerStatus.APPROVAL_REQUIRED}
            for item in outcome.broker_results
        ):
            return ValidationResult.POLICY_STOPPED
        if any(item.status is BrokerStatus.FAILED for item in outcome.broker_results):
            return ValidationResult.INCONCLUSIVE
        return None
