"""Fail-closed B5.1 qualification of an authoritative two-round adaptive trace."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, Scope

from .adaptive_qualification_models import (
    AdaptiveCoverageLedger,
    AdaptiveFlowQualificationOutcome,
    AdaptiveFlowQualificationPlan,
    AdaptiveQualificationLimits,
    AdaptiveRoundCoverage,
)
from .adaptive_qualification_store import AdaptiveQualificationStore
from .models import ReconOutcome, RedTeamFlowStatus
from .service import RedTeamService
from .store import RedTeamStore


class AdaptiveQualificationRejected(ValueError):
    pass


class AdaptiveQualificationTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.started = clock()
        self.seconds = seconds
        self.clock = clock

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise AdaptiveQualificationTimedOut(
                "Adaptive Flow Qualification timed out"
            )


class AdaptiveFlowQualificationService:
    def __init__(
        self,
        *,
        red_team_store: RedTeamStore,
        store: AdaptiveQualificationStore,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.red_team_store = red_team_store
        self.store = store
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        flow_plan_id: str,
        replan_execution_receipt_ids: tuple[str, ...],
        scope: Scope,
        limits: AdaptiveQualificationLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AdaptiveFlowQualificationPlan:
        flow, checkpoint, _ = self._trace(
            flow_plan_id=flow_plan_id,
            receipt_ids=replan_execution_receipt_ids,
            scope=scope,
            limits=limits,
            now=now,
        )
        stop_at = min(deadline, flow.deadline, scope.valid_until)
        if not now < stop_at:
            raise AdaptiveQualificationRejected(
                "Adaptive Flow Qualification deadline is invalid"
            )
        try:
            return AdaptiveFlowQualificationPlan.create(
                flow_plan_id=flow.plan_id,
                scope_id=scope.scope_id,
                scope_version=scope.version,
                target_id=flow.target.target_id,
                target_url_digest=canonical_digest(flow.target.url),
                final_checkpoint_id=checkpoint.checkpoint_id,
                replan_execution_receipt_ids=replan_execution_receipt_ids,
                limits=limits,
                created_at=now,
                deadline=stop_at,
                idempotency_key=idempotency_key,
            )
        except ValueError as exc:
            raise AdaptiveQualificationRejected(
                "Adaptive Flow Qualification Plan could not be sealed"
            ) from exc

    def execute(
        self,
        plan: AdaptiveFlowQualificationPlan,
        *,
        scope: Scope,
        now: datetime,
    ) -> AdaptiveFlowQualificationOutcome:
        authoritative = AdaptiveFlowQualificationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        trace = self._binding(authoritative, scope=scope, now=now)
        claim = self.store.claim(authoritative, now=now)
        if not claim.created:
            assert claim.outcome is not None
            if claim.outcome.plan_id != authoritative.plan_id:
                raise AdaptiveQualificationRejected(
                    "completed Adaptive Flow Qualification binding drifted"
                )
            return claim.outcome
        return self._complete(
            authoritative,
            trace=trace,
            scope=scope,
            now=now,
            attempt=claim.attempt,
        )

    def recover(self, plan, *, scope, now):
        authoritative = AdaptiveFlowQualificationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        trace = self._binding(authoritative, scope=scope, now=now)
        claim = self.store.recover(authoritative, now=now)
        return self._complete(
            authoritative,
            trace=trace,
            scope=scope,
            now=now,
            attempt=claim.attempt,
        )

    def _complete(self, plan, *, trace, scope, now, attempt):
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        deadline.check()
        flow, checkpoint, rounds = trace
        coverage = tuple(
            AdaptiveRoundCoverage.create(
                ordinal=index,
                execution_receipt_id=receipt.receipt_id,
                admission_id=admission.admission_id,
                source_checkpoint_id=source.checkpoint_id,
                result_checkpoint_id=result.checkpoint_id,
                source_observation_ids=admission.source_observation_ids,
                produced_observation_id=observation.observation_id,
                action_id=action.action_id,
                action_kind=action.kind,
                test_class=action.test_class,
                outcome=observation.outcome,
            )
            for index, (
                receipt,
                admission,
                source,
                result,
                action,
                observation,
            ) in enumerate(rounds, start=1)
        )
        ledger = AdaptiveCoverageLedger.create(
            flow_plan_id=flow.plan_id,
            final_checkpoint_id=checkpoint.checkpoint_id,
            rounds=coverage,
            covered_action_kinds=tuple(
                sorted({item.action_kind for item in coverage}, key=str)
            ),
            covered_test_classes=tuple(
                sorted({item.test_class for item in coverage})
            ),
            source_observation_count=len(coverage[0].source_observation_ids),
            produced_observation_count=len(coverage),
        )
        outcome = AdaptiveFlowQualificationOutcome.create(
            plan_id=plan.plan_id,
            flow_plan_id=flow.plan_id,
            coverage_ledger=ledger,
            attempt=attempt,
            completed_at=now,
        )
        deadline.check()
        self._binding(plan, scope=scope, now=now)
        self.store.complete(plan, outcome)
        return outcome

    def _binding(self, plan, *, scope, now):
        if not plan.created_at <= now < plan.deadline:
            raise AdaptiveQualificationRejected(
                "Adaptive Flow Qualification Plan is not active"
            )
        trace = self._trace(
            flow_plan_id=plan.flow_plan_id,
            receipt_ids=plan.replan_execution_receipt_ids,
            scope=scope,
            limits=plan.limits,
            now=now,
        )
        flow, checkpoint, _ = trace
        if (
            plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
            or plan.target_id != flow.target.target_id
            or plan.target_url_digest != canonical_digest(flow.target.url)
            or plan.final_checkpoint_id != checkpoint.checkpoint_id
        ):
            raise AdaptiveQualificationRejected(
                "Adaptive Flow Qualification binding drifted"
            )
        return trace

    def _trace(self, *, flow_plan_id, receipt_ids, scope, limits, now):
        if (
            len(receipt_ids) < limits.minimum_replan_rounds
            or len(receipt_ids) > limits.maximum_replan_rounds
            or len(set(receipt_ids)) != len(receipt_ids)
        ):
            raise AdaptiveQualificationRejected(
                "Adaptive Flow Qualification requires a bounded unique trace"
            )
        try:
            flow = self.red_team_store.plan(flow_plan_id)
            checkpoint = self.red_team_store.latest(flow_plan_id)
            flow_service = RedTeamService(store=self.red_team_store)
            flow_service._scope(scope, now)
            flow_service._scope_binding(flow, scope)
            rounds = []
            previous_result = None
            for receipt_id in receipt_ids:
                receipt = self.red_team_store.replan_execution_receipt(receipt_id)
                admission = self.red_team_store.replan_admission(receipt.admission_id)
                source = self.red_team_store.checkpoint(receipt.source_checkpoint_id)
                result = self.red_team_store.checkpoint(receipt.result_checkpoint_id)
                action = self.red_team_store.action(receipt.action_id)
                observation = self.red_team_store.observation(receipt.observation_id)
                rounds.append(
                    (receipt, admission, source, result, action, observation)
                )
                if (
                    receipt.flow_plan_id != flow.plan_id
                    or admission.flow_plan_id != flow.plan_id
                    or self.red_team_store.replan_admission_state(admission.admission_id)
                    != "consumed"
                    or receipt.admission_id != admission.admission_id
                    or receipt.source_checkpoint_id != admission.source_checkpoint_id
                    or receipt.action_id != admission.command.action.action_id
                    or receipt.approval_action
                    is not ApprovalAction.EXECUTE_RED_TEAM_ACTION
                    or receipt.approval_digest != admission.required_approval_digest
                    or receipt.approval_digest != action.action_id
                    or action.plan_id != flow.plan_id
                    or action.expected_checkpoint_id != source.checkpoint_id
                    or action.target_url != flow.target.url
                    or observation.action_id != action.action_id
                    or observation.outcome is not ReconOutcome.SUCCEEDED
                    or not observation.cleanup_complete
                    or not observation.sensitive_data_redacted
                    or source.plan_id != flow.plan_id
                    or result.plan_id != flow.plan_id
                    or source.revision >= result.revision
                    or set(admission.source_observation_ids)
                    != set(source.observation_ids)
                    or observation.observation_id in source.observation_ids
                    or set(result.observation_ids)
                    != set(source.observation_ids) | {observation.observation_id}
                    or receipt.result_checkpoint_id != result.checkpoint_id
                    or (previous_result is not None and source != previous_result)
                ):
                    raise AdaptiveQualificationRejected(
                        "Adaptive Flow trace provenance or authority drifted"
                    )
                previous_result = result
            if (
                previous_result != checkpoint
                or checkpoint.status is not RedTeamFlowStatus.COMPLETED
                or checkpoint.actions_used < limits.minimum_replan_rounds + 1
                or self.red_team_store.has_unfinished_work(flow.plan_id)
            ):
                raise AdaptiveQualificationRejected(
                    "Adaptive Flow trace is not cleanly terminal"
                )
        except AdaptiveQualificationRejected:
            raise
        except (ValueError, RuntimeError, KeyError) as exc:
            raise AdaptiveQualificationRejected(
                "authoritative Adaptive Flow trace is unavailable"
            ) from exc
        return flow, checkpoint, tuple(rounds)
