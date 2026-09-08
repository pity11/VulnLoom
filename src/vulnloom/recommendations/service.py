"""Deterministically admit advisory output without allowing model-authored Candidates."""

import time
from datetime import datetime

from pydantic import ValidationError

from vulnloom.agent_runtime.provider_probe_models import ProviderProbeResult
from vulnloom.analyzers import SourceGraphStore
from vulnloom.analyzers.models import source_graph_digest
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, Scope, ScopeState
from vulnloom.hypotheses import CandidateSetStore
from vulnloom.hypotheses.models import candidate_set_digest
from vulnloom.validation.models import candidate_content_digest

from .generation_store import CandidateRecommendationGenerationStore
from .models import (
    CandidateRecommendation,
    CandidateRecommendationAdmissionPlan,
    CandidateRecommendationRecord,
)
from .store import CandidateRecommendationStore


class CandidateRecommendationRejected(ValueError):
    pass


class CandidateRecommendationTimedOut(TimeoutError):
    pass


class CandidateRecommendationAdmissionService:
    def __init__(
        self,
        *,
        scope: Scope,
        graph_store: SourceGraphStore,
        candidate_store: CandidateSetStore,
        store: CandidateRecommendationStore,
        generation_store: CandidateRecommendationGenerationStore | None = None,
        timeout_seconds: float = 2.0,
        clock=time.monotonic,
    ):
        if not 0 < timeout_seconds <= 30:
            raise ValueError("recommendation admission timeout is invalid")
        self.scope = scope
        self.graph_store = graph_store
        self.candidate_store = candidate_store
        self.store = store
        self.generation_store = generation_store
        self.timeout_seconds = timeout_seconds
        self.clock = clock

    def prepare(
        self,
        recommendation: CandidateRecommendation,
        provider_result: ProviderProbeResult,
        *,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> CandidateRecommendationAdmissionPlan:
        return self._prepare(
            recommendation,
            provider_result,
            now=now,
            deadline=deadline,
            idempotency_key=idempotency_key,
            generation_outcome=None,
        )

    def prepare_generated(
        self,
        *,
        generation_plan_id: str,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> CandidateRecommendationAdmissionPlan:
        outcome = self._generation_outcome(generation_plan_id)
        return self._prepare(
            outcome.recommendation,
            outcome.transport,
            now=now,
            deadline=deadline,
            idempotency_key=idempotency_key,
            generation_outcome=outcome,
        )

    def _prepare(
        self,
        recommendation,
        provider_result,
        *,
        now,
        deadline,
        idempotency_key,
        generation_outcome,
    ):
        started = self.clock()
        recommendation, provider_result, candidate_set, graph, candidate = self._inputs(
            recommendation, provider_result, now=now, started=started
        )
        values = {
            "recommendation_id": recommendation.recommendation_id,
            "recommendation_digest": canonical_digest(recommendation.model_dump(mode="python")),
            "producer_result_id": provider_result.result_id,
            "producer_result_digest": canonical_digest(provider_result.model_dump(mode="python")),
            "candidate_set_id": candidate_set.candidate_set_id,
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate_content_digest(candidate),
            "source_graph_id": graph.graph_id,
            "target_id": candidate.target_id,
            "target_version_digest": canonical_digest(candidate.target_version),
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "scope_digest": canonical_digest(self.scope.model_dump(mode="python")),
            "created_at": now,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
        }
        if generation_outcome is not None:
            values.update(
                {
                    "generation_plan_id": generation_outcome.plan_id,
                    "generation_outcome_id": generation_outcome.outcome_id,
                    "generation_outcome_digest": canonical_digest(
                        generation_outcome.model_dump(mode="python")
                    ),
                }
            )
        try:
            plan = CandidateRecommendationAdmissionPlan.create(**values)
        except ValidationError as exc:
            raise CandidateRecommendationRejected("recommendation admission plan rejected") from exc
        if deadline > self.scope.valid_until:
            raise CandidateRecommendationRejected("recommendation deadline exceeds Scope")
        return plan

    def admit(
        self,
        plan: CandidateRecommendationAdmissionPlan,
        recommendation: CandidateRecommendation,
        provider_result: ProviderProbeResult,
        *,
        now: datetime,
    ) -> CandidateRecommendationRecord:
        try:
            plan = CandidateRecommendationAdmissionPlan.model_validate(plan)
        except ValidationError as exc:
            raise CandidateRecommendationRejected("recommendation plan boundary rejected") from exc
        if plan.generation_outcome_id is not None:
            raise CandidateRecommendationRejected(
                "generated recommendation requires authoritative admission"
            )
        return self._admit(
            plan,
            recommendation,
            provider_result,
            now=now,
            generation_outcome=None,
        )

    def admit_generated(
        self,
        plan: CandidateRecommendationAdmissionPlan,
        *,
        now: datetime,
    ) -> CandidateRecommendationRecord:
        try:
            plan = CandidateRecommendationAdmissionPlan.model_validate(plan)
        except ValidationError as exc:
            raise CandidateRecommendationRejected("recommendation plan boundary rejected") from exc
        if plan.generation_plan_id is None:
            raise CandidateRecommendationRejected("recommendation generation binding is required")
        outcome = self._generation_outcome(plan.generation_plan_id)
        return self._admit(
            plan,
            outcome.recommendation,
            outcome.transport,
            now=now,
            generation_outcome=outcome,
        )

    def _admit(
        self,
        plan,
        recommendation,
        provider_result,
        *,
        now,
        generation_outcome,
    ):
        started = self.clock()
        try:
            plan = CandidateRecommendationAdmissionPlan.model_validate(plan)
        except ValidationError as exc:
            raise CandidateRecommendationRejected("recommendation plan boundary rejected") from exc
        if now < plan.created_at or now >= plan.deadline:
            raise CandidateRecommendationTimedOut("recommendation admission window expired")
        recommendation, provider_result, candidate_set, graph, candidate = self._inputs(
            recommendation, provider_result, now=now, started=started
        )
        expected = self._prepare(
            recommendation,
            provider_result,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
            generation_outcome=generation_outcome,
        )
        if plan != expected:
            raise CandidateRecommendationRejected("recommendation admission binding drifted")
        claim = self.store.claim(plan)
        if not claim.created:
            if claim.record is None:
                raise CandidateRecommendationRejected("completed recommendation has no record")
            self._verify_record(claim.record, plan, candidate)
            return claim.record
        self._check(started)
        record = CandidateRecommendationRecord.create(
            plan_id=plan.plan_id,
            recommendation_id=recommendation.recommendation_id,
            recommendation_digest=plan.recommendation_digest,
            producer_result_id=provider_result.result_id,
            producer_result_digest=plan.producer_result_digest,
            candidate_set_id=candidate_set.candidate_set_id,
            candidate_id=candidate.candidate_id,
            candidate_digest=candidate_content_digest(candidate),
            source_graph_id=graph.graph_id,
            target_id=candidate.target_id,
            target_version_digest=canonical_digest(candidate.target_version),
            scope_id=self.scope.scope_id,
            scope_version=self.scope.version,
            admitted_at=now,
            generation_plan_id=plan.generation_plan_id,
            generation_outcome_id=plan.generation_outcome_id,
            generation_outcome_digest=plan.generation_outcome_digest,
            producer_content_binding_verified=generation_outcome is not None,
        )
        self.store.complete(record)
        return record

    def _generation_outcome(self, generation_plan_id):
        if self.generation_store is None:
            raise CandidateRecommendationRejected(
                "authoritative recommendation generation store is required"
            )
        try:
            outcome = self.generation_store.load_completed(generation_plan_id)
        except (ValueError, ValidationError) as exc:
            raise CandidateRecommendationRejected(
                "authoritative recommendation generation outcome rejected"
            ) from exc
        if (
            outcome.status != "recommendation_ready"
            or outcome.recommendation is None
            or outcome.response is None
            or not outcome.producer_content_binding_verified
            or outcome.eligible_for_validation_intake
        ):
            raise CandidateRecommendationRejected(
                "completed recommendation generation outcome is not admissible"
            )
        return outcome

    def _inputs(self, recommendation, provider_result, *, now, started):
        try:
            recommendation = CandidateRecommendation.model_validate(recommendation.model_dump())
            provider_result = ProviderProbeResult.model_validate(provider_result.model_dump())
            candidate_set = self.candidate_store.load(recommendation.candidate_set_id)
            graph = self.graph_store.load(recommendation.source_graph_id)
        except (OSError, ValueError, ValidationError) as exc:
            raise CandidateRecommendationRejected(
                "recommendation authoritative inputs are unavailable"
            ) from exc
        self._check(started)
        if (
            self.scope.state is not ScopeState.APPROVED
            or not (
                self.scope.valid_from <= recommendation.created_at <= now < self.scope.valid_until
            )
            or candidate_set_digest(candidate_set) != candidate_set.candidate_set_id
            or source_graph_digest(graph) != graph.graph_id
            or candidate_set.source_graph_id != graph.graph_id
            or candidate_set.target_id != graph.target_id
            or candidate_set.target_version != graph.target_version
            or candidate_set.scope_id != self.scope.scope_id
            or candidate_set.scope_version != self.scope.version
            or graph.scope_id != self.scope.scope_id
            or graph.scope_version != self.scope.version
        ):
            raise CandidateRecommendationRejected("recommendation provenance rejected")
        matches = tuple(
            c for c in candidate_set.candidates if c.candidate_id == recommendation.candidate_id
        )
        if len(matches) != 1 or matches[0].state is not CandidateState.PROPOSED:
            raise CandidateRecommendationRejected("recommendation requires one proposed Candidate")
        candidate = matches[0]
        allowed_locations = {(item.path, item.line, item.symbol) for item in candidate.code_path}
        cited_locations = {
            (item.path, item.line, item.symbol) for item in recommendation.cited_locations
        }
        if (
            recommendation.candidate_digest != candidate_content_digest(candidate)
            or recommendation.source_graph_id != candidate.source_graph_id
            or recommendation.target_id != candidate.target_id
            or recommendation.target_version_digest != canonical_digest(candidate.target_version)
            or recommendation.scope_id != candidate.scope_id
            or recommendation.scope_version != candidate.scope_version
            or recommendation.supporting_signal_ids != candidate.signal_ids
            or not cited_locations <= allowed_locations
            or provider_result.status != "passed"
            or not provider_result.cleanup_verified
            or provider_result.receipt_digest is None
            or provider_result.response_model is None
            or recommendation.producer_result_id != provider_result.result_id
            or recommendation.producer_plan_id != provider_result.plan_id
            or recommendation.producer_receipt_digest != provider_result.receipt_digest
            or provider_result.completed_at > recommendation.created_at
        ):
            raise CandidateRecommendationRejected(
                "recommendation Candidate or provider binding rejected"
            )
        return recommendation, provider_result, candidate_set, graph, candidate

    def _verify_record(self, record, plan, candidate):
        generated = plan.generation_outcome_id is not None
        if (
            record.plan_id != plan.plan_id
            or record.recommendation_id != plan.recommendation_id
            or record.recommendation_digest != plan.recommendation_digest
            or record.producer_result_id != plan.producer_result_id
            or record.producer_result_digest != plan.producer_result_digest
            or record.candidate_digest != candidate_content_digest(candidate)
            or record.generation_plan_id != plan.generation_plan_id
            or record.generation_outcome_id != plan.generation_outcome_id
            or record.generation_outcome_digest != plan.generation_outcome_digest
            or not record.candidate_unchanged
            or not record.requires_human_selection
            or record.producer_content_binding_verified != generated
            or record.eligible_for_validation_intake
        ):
            raise CandidateRecommendationRejected("recommendation admission record drifted")

    def _check(self, started):
        if self.clock() - started >= self.timeout_seconds:
            raise CandidateRecommendationTimedOut("recommendation admission timed out")
