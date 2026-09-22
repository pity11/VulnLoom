"""Offline validator for two independently materialized sealed GETs."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from vulnloom.domain.models import Scope, ScopeState
from vulnloom.evidence import EvidenceStore

from .assertion_materialization_models import (
    SENSITIVE_ASSERTION_CLASSIFIER_DIGEST,
    EvidenceAssertionMaterializationOutcome,
    EvidenceAssertionMaterializationPlan,
)
from .evidence_requirement_models import (
    EvidenceAssertion,
    EvidenceFactKind,
    EvidenceFactVerdict,
    EvidenceRequirementStage,
    VulnerabilityEvidenceRequirement,
)
from .replay_validation_models import (
    REPLAY_VALIDATION_RULESET_DIGEST,
    EvidenceReplayValidation,
    EvidenceReplayValidationLimits,
    EvidenceReplayValidationOutcome,
    EvidenceReplayValidationPlan,
)
from .replay_validation_store import EvidenceReplayValidationStore


class EvidenceMaterializationSource(Protocol):
    def plan(self, plan_id: str) -> EvidenceAssertionMaterializationPlan: ...

    def outcome(self, plan_id: str) -> EvidenceAssertionMaterializationOutcome: ...


class EvidenceReplayValidationRejected(ValueError):
    pass


class EvidenceReplayValidationTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.seconds = seconds
        self.clock = clock
        self.started = clock()

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise EvidenceReplayValidationTimedOut(
                "Evidence replay validation timed out"
            )


class EvidenceReplayValidationService:
    def __init__(
        self,
        *,
        materialization_source: EvidenceMaterializationSource,
        store: EvidenceReplayValidationStore,
        evidence_store: EvidenceStore,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.materialization_source = materialization_source
        self.store = store
        self.evidence_store = evidence_store
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        baseline_materialization_plan_id: str,
        current_materialization_plan_id: str,
        scope: Scope,
        limits: EvidenceReplayValidationLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> EvidenceReplayValidationPlan:
        baseline, current = self._sources(
            baseline_materialization_plan_id,
            current_materialization_plan_id,
            scope=scope,
            now=now,
        )
        baseline_plan, baseline_outcome = baseline
        current_plan, current_outcome = current
        stop_at = min(deadline, scope.valid_until)
        if stop_at <= now:
            raise EvidenceReplayValidationRejected(
                "Evidence replay validation deadline is invalid"
            )
        refs = tuple(
            sorted((baseline_plan.evidence_ref, current_plan.evidence_ref))
        )
        return EvidenceReplayValidationPlan.create(
            requirement_id=baseline_plan.requirement_id,
            baseline_materialization_plan_id=baseline_plan.plan_id,
            baseline_materialization_id=(
                baseline_outcome.materialization.materialization_id
            ),
            baseline_flow_plan_id=baseline_plan.flow_plan_id,
            baseline_observation_id=baseline_plan.source_observation_id,
            baseline_snapshot_id=baseline_plan.web_response_snapshot_id,
            current_materialization_plan_id=current_plan.plan_id,
            current_materialization_id=(
                current_outcome.materialization.materialization_id
            ),
            current_flow_plan_id=current_plan.flow_plan_id,
            current_observation_id=current_plan.source_observation_id,
            current_snapshot_id=current_plan.web_response_snapshot_id,
            requested_url_digest=current_plan.requested_url_digest,
            evidence_refs=refs,
            target_id=current_plan.target_id,
            target_version=current_plan.target_version,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            ruleset_digest=REPLAY_VALIDATION_RULESET_DIGEST,
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        plan: EvidenceReplayValidationPlan,
        *,
        scope: Scope,
        now: datetime,
    ) -> EvidenceReplayValidationOutcome:
        authoritative = EvidenceReplayValidationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        validation = self._validate(authoritative, scope=scope, now=now)
        claim = self.store.claim(authoritative, now=now)
        if not claim.created:
            if claim.outcome is None or claim.outcome.validation != validation:
                raise EvidenceReplayValidationRejected(
                    "completed Evidence replay validation outcome drifted"
                )
            return claim.outcome
        return self._complete(
            authoritative,
            validation,
            attempt=claim.attempt,
            scope=scope,
            now=now,
        )

    def recover(
        self,
        plan: EvidenceReplayValidationPlan,
        *,
        scope: Scope,
        now: datetime,
    ) -> EvidenceReplayValidationOutcome:
        authoritative = EvidenceReplayValidationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        validation = self._validate(authoritative, scope=scope, now=now)
        claim = self.store.recover(authoritative, now=now)
        return self._complete(
            authoritative,
            validation,
            attempt=claim.attempt,
            scope=scope,
            now=now,
        )

    def _complete(self, plan, validation, *, attempt, scope, now):
        self._binding(plan, scope=scope, now=now)
        self._verify_evidence(plan.evidence_refs)
        outcome = EvidenceReplayValidationOutcome(
            plan_id=plan.plan_id,
            validation=validation,
            attempt=attempt,
        )
        self.store.complete(outcome, completed_at=now)
        return outcome

    def _validate(self, plan, *, scope, now):
        baseline, current = self._binding(plan, scope=scope, now=now)
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        deadline.check()
        baseline_materialization = baseline[1].materialization
        current_materialization = current[1].materialization
        content_match = (
            baseline_materialization.response_body_sha256
            == current_materialization.response_body_sha256
            and baseline_materialization.sensitive_data_presence
            is EvidenceFactVerdict.SUPPORTED
            and current_materialization.sensitive_data_presence
            is EvidenceFactVerdict.SUPPORTED
        )
        replay_verdict = (
            EvidenceFactVerdict.SUPPORTED
            if content_match
            else EvidenceFactVerdict.INCONCLUSIVE
        )
        assertions = tuple(
            sorted(
                (
                    EvidenceAssertion.create(
                        requirement_id=plan.requirement_id,
                        stage=EvidenceRequirementStage.VALIDATION,
                        fact=EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED,
                        verdict=replay_verdict,
                        evidence_refs=plan.evidence_refs,
                        producer_ref="validator:sealed-get-replay-v1",
                        context_id=plan.plan_id,
                        observed_at=plan.created_at,
                    ),
                    EvidenceAssertion.create(
                        requirement_id=plan.requirement_id,
                        stage=EvidenceRequirementStage.VALIDATION,
                        fact=EvidenceFactKind.REDACTION_BOUNDARY_PROVEN,
                        verdict=EvidenceFactVerdict.SUPPORTED,
                        evidence_refs=plan.evidence_refs,
                        producer_ref="validator:sealed-get-replay-v1",
                        context_id=plan.plan_id,
                        observed_at=plan.created_at,
                    ),
                ),
                key=lambda item: item.assertion_id,
            )
        )
        deadline.check()
        return EvidenceReplayValidation.create(
            plan_id=plan.plan_id,
            requirement_id=plan.requirement_id,
            baseline_materialization_id=plan.baseline_materialization_id,
            current_materialization_id=plan.current_materialization_id,
            requested_url_digest=plan.requested_url_digest,
            evidence_refs=plan.evidence_refs,
            assertions=assertions,
            content_match=content_match,
            replay_verdict=replay_verdict,
            ruleset_digest=plan.ruleset_digest,
            validated_at=plan.created_at,
        )

    def _binding(self, plan, *, scope, now):
        if (
            not plan.created_at <= now < plan.deadline
            or plan.ruleset_digest != REPLAY_VALIDATION_RULESET_DIGEST
        ):
            raise EvidenceReplayValidationRejected(
                "Evidence replay validation plan is not active"
            )
        baseline, current = self._sources(
            plan.baseline_materialization_plan_id,
            plan.current_materialization_plan_id,
            scope=scope,
            now=now,
        )
        baseline_plan, baseline_outcome = baseline
        current_plan, current_outcome = current
        refs = tuple(sorted((baseline_plan.evidence_ref, current_plan.evidence_ref)))
        if (
            plan.requirement_id != baseline_plan.requirement_id
            or plan.baseline_materialization_id
            != baseline_outcome.materialization.materialization_id
            or plan.baseline_flow_plan_id != baseline_plan.flow_plan_id
            or plan.baseline_observation_id != baseline_plan.source_observation_id
            or plan.baseline_snapshot_id != baseline_plan.web_response_snapshot_id
            or plan.current_materialization_id
            != current_outcome.materialization.materialization_id
            or plan.current_flow_plan_id != current_plan.flow_plan_id
            or plan.current_observation_id != current_plan.source_observation_id
            or plan.current_snapshot_id != current_plan.web_response_snapshot_id
            or plan.requested_url_digest != current_plan.requested_url_digest
            or plan.evidence_refs != refs
            or plan.target_id != current_plan.target_id
            or plan.target_version != current_plan.target_version
            or plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
        ):
            raise EvidenceReplayValidationRejected(
                "Evidence replay validation binding drifted"
            )
        self._verify_evidence(plan.evidence_refs)
        return baseline, current

    def _sources(self, baseline_plan_id, current_plan_id, *, scope, now):
        self._scope(scope, now=now)
        if baseline_plan_id == current_plan_id:
            raise EvidenceReplayValidationRejected(
                "Evidence replay validation requires independent executions"
            )
        baseline = self._source(baseline_plan_id)
        current = self._source(current_plan_id)
        baseline_plan, baseline_outcome = baseline
        current_plan, current_outcome = current
        if (
            baseline_plan.flow_plan_id == current_plan.flow_plan_id
            or baseline_plan.source_observation_id
            == current_plan.source_observation_id
            or baseline_plan.web_response_snapshot_id
            == current_plan.web_response_snapshot_id
            or baseline_plan.evidence_ref == current_plan.evidence_ref
            or baseline_plan.created_at >= current_plan.created_at
            or baseline_plan.requirement_id != current_plan.requirement_id
            or baseline_plan.requirement_id
            != VulnerabilityEvidenceRequirement.create().requirement_id
            or baseline_plan.requested_url_digest
            != current_plan.requested_url_digest
            or baseline_plan.scope_id != current_plan.scope_id
            or baseline_plan.scope_version != current_plan.scope_version
            or baseline_plan.scope_id != scope.scope_id
            or baseline_plan.scope_version != scope.version
            or baseline_plan.classifier_digest
            != SENSITIVE_ASSERTION_CLASSIFIER_DIGEST
            or current_plan.classifier_digest
            != SENSITIVE_ASSERTION_CLASSIFIER_DIGEST
            or not baseline_outcome.cleanup_complete
            or not current_outcome.cleanup_complete
        ):
            raise EvidenceReplayValidationRejected(
                "Evidence replay validation sources are not independent and compatible"
            )
        self._verify_evidence(
            (baseline_plan.evidence_ref, current_plan.evidence_ref)
        )
        return baseline, current

    def _source(self, plan_id):
        try:
            plan = self.materialization_source.plan(plan_id)
            outcome = self.materialization_source.outcome(plan_id)
        except (KeyError, RuntimeError, ValueError) as exc:
            raise EvidenceReplayValidationRejected(
                "completed Evidence materialization source is unavailable"
            ) from exc
        materialization = outcome.materialization
        if (
            outcome.plan_id != plan.plan_id
            or materialization.plan_id != plan.plan_id
            or materialization.requirement_id != plan.requirement_id
            or materialization.source_observation_id != plan.source_observation_id
            or materialization.web_response_snapshot_id
            != plan.web_response_snapshot_id
            or materialization.evidence_ref != plan.evidence_ref
            or materialization.response_body_sha256 != plan.response_body_sha256
            or materialization.classifier_digest != plan.classifier_digest
        ):
            raise EvidenceReplayValidationRejected(
                "Evidence materialization source binding is invalid"
            )
        return plan, outcome

    @staticmethod
    def _scope(scope: Scope, *, now: datetime) -> None:
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or "read_only" not in scope.allowed_test_classes
        ):
            raise EvidenceReplayValidationRejected(
                "Evidence replay validation requires a current read-only approved Scope"
            )

    def _verify_evidence(self, refs) -> None:
        if len(refs) != 2 or not all(self.evidence_store.contains(ref) for ref in refs):
            raise EvidenceReplayValidationRejected(
                "Evidence replay validation integrity check failed"
            )
