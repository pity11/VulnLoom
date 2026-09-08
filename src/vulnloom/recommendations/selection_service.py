"""Trusted human selection over an authoritative generated recommendation admission."""

import time

from pydantic import ValidationError

from vulnloom.analyzers.models import source_graph_digest
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, ScopeState
from vulnloom.hypotheses.models import candidate_set_digest
from vulnloom.validation.models import candidate_content_digest

from .selection_models import (
    CandidateRecommendationSelectionCommand,
    CandidateRecommendationSelectionDecision,
    CandidateRecommendationSelectionRecord,
)
from .selection_store import CandidateRecommendationSelectionRecoveryRequired
from .store import CandidateRecommendationRecoveryRequired


class CandidateRecommendationSelectionRejected(ValueError):
    pass


class CandidateRecommendationSelectionTimedOut(TimeoutError):
    pass


class CandidateRecommendationSelectionService:
    def __init__(
        self,
        *,
        scope,
        graph_store,
        candidate_store,
        recommendation_store,
        generation_store,
        selection_store,
        timeout_seconds=2.0,
        clock=time.monotonic,
    ):
        if not 0 < timeout_seconds <= 30:
            raise ValueError("recommendation selection timeout is invalid")
        self.scope = scope
        self.graph_store = graph_store
        self.candidate_store = candidate_store
        self.recommendation_store = recommendation_store
        self.generation_store = generation_store
        self.selection_store = selection_store
        self.timeout_seconds = timeout_seconds
        self.clock = clock

    def prepare(
        self,
        *,
        admission_record_id,
        decision,
        reviewer_id,
        decided_at,
        expires_at,
        idempotency_key,
    ):
        started = self.clock()
        admission, outcome, candidate_set, graph, candidate = self._inputs(
            admission_record_id, at=decided_at, started=started
        )
        values = {
            "admission_plan_id": admission.plan_id,
            "admission_record_id": admission.record_id,
            "admission_record_digest": canonical_digest(admission.model_dump(mode="python")),
            "recommendation_id": admission.recommendation_id,
            "recommendation_digest": admission.recommendation_digest,
            "generation_plan_id": outcome.plan_id,
            "generation_outcome_id": outcome.outcome_id,
            "generation_outcome_digest": canonical_digest(outcome.model_dump(mode="python")),
            "candidate_set_id": candidate_set.candidate_set_id,
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate_content_digest(candidate),
            "source_graph_id": graph.graph_id,
            "target_id": candidate.target_id,
            "target_version_digest": canonical_digest(candidate.target_version),
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "scope_digest": canonical_digest(self.scope.model_dump(mode="python")),
            "decision": decision,
            "reviewer_id": reviewer_id,
            "decided_at": decided_at,
            "expires_at": expires_at,
            "idempotency_key": idempotency_key,
        }
        try:
            command = CandidateRecommendationSelectionCommand.create(**values)
        except ValidationError as exc:
            raise CandidateRecommendationSelectionRejected(
                "recommendation selection command rejected"
            ) from exc
        if expires_at > self.scope.valid_until:
            raise CandidateRecommendationSelectionRejected(
                "recommendation selection deadline exceeds Scope"
            )
        return command

    def record(self, command, *, now):
        started = self.clock()
        try:
            command = CandidateRecommendationSelectionCommand.model_validate(command)
        except ValidationError as exc:
            raise CandidateRecommendationSelectionRejected(
                "recommendation selection boundary rejected"
            ) from exc
        if now < command.decided_at or now >= command.expires_at:
            raise CandidateRecommendationSelectionTimedOut(
                "recommendation selection window expired"
            )
        admission, _, _, _, candidate = self._inputs(
            command.admission_record_id, at=command.decided_at, started=started
        )
        expected = self.prepare(
            admission_record_id=admission.record_id,
            decision=command.decision,
            reviewer_id=command.reviewer_id,
            decided_at=command.decided_at,
            expires_at=command.expires_at,
            idempotency_key=command.idempotency_key,
        )
        if command != expected:
            raise CandidateRecommendationSelectionRejected(
                "recommendation selection binding drifted"
            )
        claim = self.selection_store.claim(command)
        if not claim.created:
            if claim.record is None:
                raise CandidateRecommendationSelectionRejected(
                    "completed recommendation selection has no record"
                )
            self._verify_record(claim.record, command, candidate)
            return claim.record
        self._check(started)
        record = CandidateRecommendationSelectionRecord.create(
            command_id=command.command_id,
            admission_plan_id=command.admission_plan_id,
            admission_record_id=command.admission_record_id,
            admission_record_digest=command.admission_record_digest,
            recommendation_id=command.recommendation_id,
            generation_plan_id=command.generation_plan_id,
            generation_outcome_id=command.generation_outcome_id,
            candidate_set_id=command.candidate_set_id,
            candidate_id=command.candidate_id,
            candidate_digest=command.candidate_digest,
            target_id=command.target_id,
            target_version_digest=command.target_version_digest,
            scope_id=command.scope_id,
            scope_version=command.scope_version,
            decision=command.decision,
            reviewer_id=command.reviewer_id,
            decided_at=command.decided_at,
            recorded_at=now,
        )
        self.selection_store.complete(record)
        return record

    def review_item(self, admission_record_id, *, at):
        admission, outcome, _, _, candidate = self._inputs(
            admission_record_id, at=at, started=self.clock()
        )
        return admission, outcome.recommendation, candidate

    def load_verified(self, record_id, *, at):
        """Reload one completed selection and every authoritative upstream object."""
        started = self.clock()
        try:
            record = self.selection_store.load_completed(record_id)
        except (
            ValueError,
            ValidationError,
            CandidateRecommendationSelectionRecoveryRequired,
        ) as exc:
            raise CandidateRecommendationSelectionRejected(
                "recommendation selection record is unavailable"
            ) from exc
        admission, outcome, candidate_set, graph, candidate = self._inputs(
            record.admission_record_id, at=at, started=started
        )
        if (
            record.admission_plan_id != admission.plan_id
            or record.admission_record_id != admission.record_id
            or record.admission_record_digest
            != canonical_digest(admission.model_dump(mode="python"))
            or record.recommendation_id != admission.recommendation_id
            or record.generation_plan_id != outcome.plan_id
            or record.generation_outcome_id != outcome.outcome_id
            or record.candidate_set_id != candidate_set.candidate_set_id
            or record.candidate_id != candidate.candidate_id
            or record.candidate_digest != candidate_content_digest(candidate)
            or record.target_id != candidate.target_id
            or record.target_version_digest != canonical_digest(candidate.target_version)
            or record.scope_id != self.scope.scope_id
            or record.scope_version != self.scope.version
            or record.decided_at > at
            or not record.candidate_unchanged
            or not record.requires_separate_validation_approval
            or record.eligible_for_validation_intake
            != (record.decision is CandidateRecommendationSelectionDecision.ACCEPT)
        ):
            raise CandidateRecommendationSelectionRejected(
                "recommendation selection completed record drifted"
            )
        self._check(started)
        return record, admission, outcome, candidate_set, graph, candidate

    def _inputs(self, admission_record_id, *, at, started):
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= at < self.scope.valid_until
        ):
            raise CandidateRecommendationSelectionRejected(
                "recommendation selection requires approved Scope"
            )
        try:
            admission = self.recommendation_store.load_completed(admission_record_id)
            outcome = self.generation_store.load_completed(admission.generation_plan_id)
            candidate_set = self.candidate_store.load(admission.candidate_set_id)
            graph = self.graph_store.load(admission.source_graph_id)
        except (
            OSError,
            ValueError,
            ValidationError,
            CandidateRecommendationRecoveryRequired,
        ) as exc:
            raise CandidateRecommendationSelectionRejected(
                "recommendation selection authoritative inputs rejected"
            ) from exc
        self._check(started)
        matches = tuple(
            item for item in candidate_set.candidates if item.candidate_id == admission.candidate_id
        )
        if len(matches) != 1 or matches[0].state is not CandidateState.PROPOSED:
            raise CandidateRecommendationSelectionRejected(
                "recommendation selection requires one proposed Candidate"
            )
        candidate = matches[0]
        recommendation = outcome.recommendation
        if (
            not admission.producer_content_binding_verified
            or not admission.requires_human_selection
            or admission.eligible_for_validation_intake
            or admission.generation_plan_id != outcome.plan_id
            or admission.generation_outcome_id != outcome.outcome_id
            or admission.generation_outcome_digest
            != canonical_digest(outcome.model_dump(mode="python"))
            or outcome.status != "recommendation_ready"
            or recommendation is None
            or admission.recommendation_id != recommendation.recommendation_id
            or admission.recommendation_digest
            != canonical_digest(recommendation.model_dump(mode="python"))
            or admission.producer_result_id != outcome.transport.result_id
            or admission.producer_result_digest
            != canonical_digest(outcome.transport.model_dump(mode="python"))
            or admission.candidate_digest != candidate_content_digest(candidate)
            or admission.target_id != candidate.target_id
            or admission.target_version_digest != canonical_digest(candidate.target_version)
            or admission.scope_id != self.scope.scope_id
            or admission.scope_version != self.scope.version
            or admission.admitted_at > at
            or candidate_set_digest(candidate_set) != candidate_set.candidate_set_id
            or source_graph_digest(graph) != graph.graph_id
            or candidate_set.source_graph_id != graph.graph_id
            or graph.scope_id != self.scope.scope_id
            or graph.scope_version != self.scope.version
        ):
            raise CandidateRecommendationSelectionRejected(
                "recommendation selection provenance rejected"
            )
        return admission, outcome, candidate_set, graph, candidate

    def _verify_record(self, record, command, candidate):
        if (
            record.command_id != command.command_id
            or record.admission_record_id != command.admission_record_id
            or record.admission_record_digest != command.admission_record_digest
            or record.recommendation_id != command.recommendation_id
            or record.generation_outcome_id != command.generation_outcome_id
            or record.candidate_digest != candidate_content_digest(candidate)
            or record.decision is not command.decision
            or record.reviewer_id != command.reviewer_id
            or not record.candidate_unchanged
            or not record.requires_separate_validation_approval
            or record.eligible_for_validation_intake
            != (record.decision is CandidateRecommendationSelectionDecision.ACCEPT)
        ):
            raise CandidateRecommendationSelectionRejected(
                "recommendation selection record drifted"
            )

    def _check(self, started):
        if self.clock() - started >= self.timeout_seconds:
            raise CandidateRecommendationSelectionTimedOut("recommendation selection timed out")
