"""Fail-closed orchestration of one Candidate validation vertical slice."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from vulnloom.broker import BrokerRejected, BrokerResult, BrokerStatus, ToolBroker
from vulnloom.domain.models import (
    ApprovalRequest,
    Candidate,
    CandidateState,
    EvidenceBundle,
    Scope,
    ValidationResult,
    ValidationRun,
)
from vulnloom.domain.protocol import WorkerRole
from vulnloom.domain.state_machine import (
    complete_validation,
    queue_validation,
    transition_candidate,
)
from vulnloom.policy import PolicyEngine
from vulnloom.runners import (
    NetworkMode,
    SandboxProfileKind,
    SandboxRunner,
    SandboxRunResult,
    SandboxRunStatus,
)
from vulnloom.runners.models import invocation_digest, sandbox_profile_digest

from .models import (
    ValidationOutcome,
    ValidationPlan,
    ValidationVerdict,
    candidate_content_digest,
)
from .store import ValidationStore


class ValidationRejected(ValueError):
    """The selected Candidate or typed plan failed trusted preflight."""


class ValidationJudge(Protocol):
    def evaluate(
        self,
        *,
        plan: ValidationPlan,
        runner_result: SandboxRunResult,
        broker_results: tuple[BrokerResult, ...],
        evidence_refs: tuple[str, ...],
    ) -> ValidationVerdict: ...


class InconclusiveValidationJudge:
    """Safe production default until a deterministic assertion adapter is selected."""

    def evaluate(
        self,
        *,
        plan: ValidationPlan,
        runner_result: SandboxRunResult,
        broker_results: tuple[BrokerResult, ...],
        evidence_refs: tuple[str, ...],
    ) -> ValidationVerdict:
        return ValidationVerdict(
            result=ValidationResult.INCONCLUSIVE,
            rationale_code="evidence_requires_deterministic_assertion",
            evidence_refs=evidence_refs,
        )


class ValidationService:
    def __init__(
        self,
        *,
        scope: Scope,
        runner: SandboxRunner,
        broker: ToolBroker,
        store: ValidationStore,
        judge: ValidationJudge | None = None,
    ):
        self.scope = scope
        self.runner = runner
        self.broker = broker
        self.store = store
        self.judge = judge or InconclusiveValidationJudge()

    def execute(
        self,
        candidate: Candidate,
        plan: ValidationPlan,
        *,
        now: datetime,
        approvals: tuple[ApprovalRequest, ...] = (),
    ) -> ValidationOutcome:
        self._preflight(candidate, plan, now)
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome

        queued = queue_validation(candidate, self.scope, now=now)
        running = transition_candidate(queued, CandidateState.VALIDATION_RUNNING)
        runner_result = self.runner.execute(plan.runner_request, now=now)
        self._validate_runner_result(plan, runner_result)
        broker_results: list[BrokerResult] = []
        if runner_result.status is SandboxRunStatus.COMPLETED:
            for call in plan.broker_calls:
                result = self.broker.execute(call, now=now, approvals=approvals)
                broker_results.append(result)
                if result.status is not BrokerStatus.COMPLETED:
                    break

        collected = self._evidence_refs(runner_result, tuple(broker_results))
        forced = self._forced_result(runner_result, tuple(broker_results))
        if forced is None:
            verdict = self.judge.evaluate(
                plan=plan,
                runner_result=runner_result,
                broker_results=tuple(broker_results),
                evidence_refs=collected,
            )
        else:
            verdict = ValidationVerdict(
                result=forced,
                rationale_code=f"execution_{forced.value}",
                evidence_refs=collected,
            )
        if forced is None and verdict.result in {
            ValidationResult.POLICY_STOPPED,
            ValidationResult.TIMED_OUT,
        }:
            raise ValidationRejected("judge cannot manufacture an execution control result")
        if not set(verdict.evidence_refs) <= set(collected):
            raise ValidationRejected("judge referenced evidence not produced by this validation")

        run = ValidationRun(
            candidate_id=candidate.candidate_id,
            target_version=candidate.target_version,
            scope_version=candidate.scope_version,
            sandbox_image_digest=plan.runner_request.profile.image_digest,
            policy_digest=plan.runner_request.task.policy_digest,
            plan=(
                f"plan:{plan.plan_id}",
                f"runner:{plan.runner_request.invocation.tool_id}",
                *(f"broker:{call.tool_id}:{index}" for index, call in enumerate(plan.broker_calls)),
            ),
            started_at=now,
            finished_at=now,
            result=verdict.result,
            side_effects=self._side_effects(plan, tuple(broker_results)),
            evidence_refs=verdict.evidence_refs,
            resource_usage={
                "wall_seconds": runner_result.usage.wall_seconds,
                "cpu_millis": runner_result.usage.cpu_millis,
                "peak_memory_bytes": runner_result.usage.peak_memory_bytes,
                "broker_calls": len(broker_results),
                "tool_calls": runner_result.budget_used.tool_calls
                + sum(item.tool_calls_used for item in broker_results),
            },
        )
        final_candidate = complete_validation(running, run)
        bundle = (
            EvidenceBundle(
                candidate_id=candidate.candidate_id,
                evidence_refs=verdict.evidence_refs,
                sealed_at=now,
            )
            if verdict.evidence_refs
            else None
        )
        outcome = ValidationOutcome(
            plan_id=plan.plan_id,
            candidate=final_candidate,
            validation_run=run,
            evidence_bundle=bundle,
            runner_result=runner_result,
            broker_results=tuple(broker_results),
            verdict=verdict,
            completed_at=now,
        )
        self.store.complete(outcome)
        return outcome

    def _preflight(self, candidate: Candidate, plan: ValidationPlan, now: datetime) -> None:
        if candidate.state is not CandidateState.PROPOSED:
            raise ValidationRejected("only a proposed Candidate can be selected for validation")
        if plan.selected_at > now:
            raise ValidationRejected("Candidate selection timestamp cannot be in the future")
        if (
            plan.candidate_id != candidate.candidate_id
            or plan.candidate_digest != candidate_content_digest(candidate)
            or plan.target_id != candidate.target_id
            or plan.target_version != candidate.target_version
            or plan.scope_id != candidate.scope_id
            or plan.scope_version != candidate.scope_version
        ):
            raise ValidationRejected("ValidationPlan provenance does not match Candidate")
        queue_validation(candidate, self.scope, now=now)
        expected_input = f"candidate:{plan.candidate_digest}"
        requests = (plan.runner_request, *(call for call in plan.broker_calls))
        for item in requests:
            task = item.task
            if (
                task.engagement_id != self.scope.engagement_id
                or task.target_id != candidate.target_id
                or task.target_version != candidate.target_version
                or task.scope_id != self.scope.scope_id
                or task.scope_version != self.scope.version
                or task.worker_role is not WorkerRole.VALIDATOR
                or task.policy_digest != PolicyEngine(self.scope).policy_digest
                or expected_input not in task.input_refs
                or task.deadline > self.scope.valid_until
            ):
                raise ValidationRejected("validation task provenance or policy binding mismatch")
        request = plan.runner_request
        if (
            request.profile.kind is not SandboxProfileKind.VALIDATION
            or request.profile.network_mode is not NetworkMode.NONE
            or request.task.sandbox_profile_digest != sandbox_profile_digest(request.profile)
        ):
            raise ValidationRejected("Runner validation must be network-isolated and profile-bound")
        for call in plan.broker_calls:
            if call.profile.kind is not SandboxProfileKind.VALIDATION:
                raise ValidationRejected("Broker calls require a Validation profile")
            try:
                self.broker.validate_call(call)
            except BrokerRejected as exc:
                raise ValidationRejected("Broker call failed static preflight") from exc

    @staticmethod
    def _validate_runner_result(plan: ValidationPlan, result: SandboxRunResult) -> None:
        request = plan.runner_request
        if (
            result.run_id != request.run_id
            or result.task_id != request.task.task_id
            or result.sandbox_profile_digest != sandbox_profile_digest(request.profile)
            or result.invocation_digest != invocation_digest(request.invocation)
        ):
            raise ValidationRejected("Runner result does not match the selected request")

    @staticmethod
    def _evidence_refs(
        runner: SandboxRunResult, brokers: tuple[BrokerResult, ...]
    ) -> tuple[str, ...]:
        refs = list(runner.evidence_refs)
        for result in brokers:
            if result.http is not None:
                refs.extend(result.http.evidence_refs)
        return tuple(dict.fromkeys(refs))

    @staticmethod
    def _forced_result(
        runner: SandboxRunResult, brokers: tuple[BrokerResult, ...]
    ) -> ValidationResult | None:
        if runner.status is SandboxRunStatus.TIMED_OUT or any(
            item.status is BrokerStatus.TIMED_OUT for item in brokers
        ):
            return ValidationResult.TIMED_OUT
        if runner.status is not SandboxRunStatus.COMPLETED:
            return ValidationResult.INCONCLUSIVE
        if any(
            item.status in {BrokerStatus.DENIED, BrokerStatus.APPROVAL_REQUIRED}
            for item in brokers
        ):
            return ValidationResult.POLICY_STOPPED
        if any(item.status is BrokerStatus.FAILED for item in brokers):
            return ValidationResult.INCONCLUSIVE
        return None

    @staticmethod
    def _side_effects(
        plan: ValidationPlan, results: tuple[BrokerResult, ...]
    ) -> tuple[str, ...]:
        return tuple(
            f"broker:{call.tool_id}:{call.http.method.value}"
            for call, result in zip(plan.broker_calls, results, strict=False)
            if result.status is BrokerStatus.COMPLETED and call.http.method.mutates_state
        )
