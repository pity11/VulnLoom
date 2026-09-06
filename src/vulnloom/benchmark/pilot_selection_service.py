"""Trusted human Candidate selection after an admitted local shadow pilot."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import ValidationError

from vulnloom.analyzers import SourceGraphStore
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, Scope, ScopeState
from vulnloom.hypotheses import CandidateSetStore
from vulnloom.ingestion import IngestionError, IngestionService
from vulnloom.validation.models import candidate_content_digest

from .models import BenchmarkGateStatus
from .pilot_readiness_models import AuthorizedPilotManifest
from .pilot_readiness_store import (
    AuthorizedPilotReadinessArtifactStore,
    AuthorizedPilotReadinessRecoveryRequired,
    AuthorizedPilotReadinessStore,
)
from .pilot_selection_models import (
    PilotCandidateSelectionCommand,
    PilotCandidateSelectionRecord,
    pilot_candidate_selection_command_digest,
)
from .pilot_selection_store import PilotCandidateSelectionStore


class PilotCandidateSelectionRejected(ValueError):
    pass


class PilotCandidateSelectionTimedOut(TimeoutError):
    pass


class PilotCandidateSelectionService:
    def __init__(
        self,
        *,
        scope: Scope,
        ingestion: IngestionService,
        graph_store: SourceGraphStore,
        candidate_store: CandidateSetStore,
        readiness_store: AuthorizedPilotReadinessStore,
        readiness_artifact_store: AuthorizedPilotReadinessArtifactStore,
        selection_store: PilotCandidateSelectionStore,
    ):
        self.scope = scope
        self.ingestion = ingestion
        self.graph_store = graph_store
        self.candidate_store = candidate_store
        self.readiness_store = readiness_store
        self.readiness_artifact_store = readiness_artifact_store
        self.selection_store = selection_store

    def prepare(
        self,
        *,
        readiness_plan_id: str,
        candidate_set_id: str,
        candidate_id: UUID,
        reviewer: str,
        decided_at: datetime,
        now: datetime,
        idempotency_key: str,
    ) -> PilotCandidateSelectionCommand:
        if decided_at.tzinfo is None or decided_at.utcoffset() is None:
            raise PilotCandidateSelectionRejected(
                "pilot Candidate selection decision time must include a timezone"
            )
        inputs = self._authoritative_inputs(
            readiness_plan_id=readiness_plan_id,
            candidate_set_id=candidate_set_id,
            candidate_id=candidate_id,
            at=decided_at,
            now=now,
        )
        outcome, snapshot, graph, candidate_set, candidate, manifest = inputs
        values = {
            "readiness_plan_id": outcome.plan_id,
            "readiness_result_id": outcome.result.result_id,
            "readiness_result_digest": canonical_digest(outcome.result.model_dump(mode="python")),
            "readiness_artifact_digest": canonical_digest(
                outcome.artifact.model_dump(mode="python")
            ),
            "pilot_manifest_id": manifest.pilot_manifest_id,
            "candidate_set_id": candidate_set.candidate_set_id,
            "candidate_set_digest": canonical_digest(candidate_set.model_dump(mode="python")),
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate_content_digest(candidate),
            "source_graph_id": graph.graph_id,
            "source_graph_digest": canonical_digest(graph.model_dump(mode="python")),
            "target_manifest_id": snapshot.manifest.manifest_id,
            "target_id": snapshot.target.target_id,
            "target_version_digest": canonical_digest(snapshot.target.version),
            "scope_id": self.scope.scope_id,
            "scope_version": self.scope.version,
            "scope_digest": canonical_digest(self.scope.model_dump(mode="python")),
            "reviewer": reviewer,
            "decided_at": decided_at,
            "expires_at": self.scope.valid_until,
            "idempotency_key": idempotency_key,
        }
        try:
            return PilotCandidateSelectionCommand.create(**values)
        except ValidationError as exc:
            raise PilotCandidateSelectionRejected(
                "pilot Candidate selection command is invalid"
            ) from exc

    def record(
        self, command: PilotCandidateSelectionCommand, *, now: datetime
    ) -> PilotCandidateSelectionRecord:
        try:
            command = PilotCandidateSelectionCommand.model_validate(command)
        except ValidationError as exc:
            raise PilotCandidateSelectionRejected(
                "pilot Candidate selection boundary validation failed"
            ) from exc
        if now < command.decided_at or now >= command.expires_at:
            raise PilotCandidateSelectionTimedOut(
                "pilot Candidate selection is outside its validity window"
            )
        inputs = self._authoritative_inputs(
            readiness_plan_id=command.readiness_plan_id,
            candidate_set_id=command.candidate_set_id,
            candidate_id=command.candidate_id,
            at=command.decided_at,
            now=now,
        )
        outcome, snapshot, graph, candidate_set, candidate, manifest = inputs
        expected = self.prepare(
            readiness_plan_id=outcome.plan_id,
            candidate_set_id=candidate_set.candidate_set_id,
            candidate_id=candidate.candidate_id,
            reviewer=command.reviewer,
            decided_at=command.decided_at,
            now=now,
            idempotency_key=command.idempotency_key,
        )
        if (
            command != expected
            or command.command_id != pilot_candidate_selection_command_digest(command)
            or snapshot.manifest.manifest_id != command.target_manifest_id
            or graph.graph_id != command.source_graph_id
            or manifest.pilot_manifest_id != command.pilot_manifest_id
        ):
            raise PilotCandidateSelectionRejected(
                "pilot Candidate selection command binding drifted"
            )
        claim = self.selection_store.claim(command, now=now)
        if not claim.created:
            assert claim.record is not None
            return claim.record
        values = {
            "command_id": command.command_id,
            "readiness_plan_id": command.readiness_plan_id,
            "readiness_result_id": command.readiness_result_id,
            "pilot_manifest_id": command.pilot_manifest_id,
            "candidate_set_id": command.candidate_set_id,
            "candidate_id": command.candidate_id,
            "candidate_digest": command.candidate_digest,
            "target_id": command.target_id,
            "target_version_digest": command.target_version_digest,
            "scope_id": command.scope_id,
            "scope_version": command.scope_version,
            "reviewer": command.reviewer,
            "decided_at": command.decided_at,
            "expires_at": command.expires_at,
        }
        record = PilotCandidateSelectionRecord(record_id=canonical_digest(values), **values)
        self.selection_store.complete(record, now=now)
        return record

    def _authoritative_inputs(
        self,
        *,
        readiness_plan_id: str,
        candidate_set_id: str,
        candidate_id: UUID,
        at: datetime,
        now: datetime,
    ):
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= at <= now < self.scope.valid_until
        ):
            raise PilotCandidateSelectionRejected(
                "pilot Candidate selection requires a currently approved Scope"
            )
        try:
            outcome = self.readiness_store.load_completed(readiness_plan_id)
            stored_result = self.readiness_artifact_store.read_result(outcome.artifact)
            candidate_set = self.candidate_store.load(candidate_set_id)
            graph = self.graph_store.load(candidate_set.source_graph_id)
            snapshot = self.ingestion.load_snapshot(graph.manifest_id)
            IngestionService.require_snapshot_scope(snapshot, self.scope, now)
        except (
            OSError,
            ValueError,
            ValidationError,
            IngestionError,
            AuthorizedPilotReadinessRecoveryRequired,
        ) as exc:
            raise PilotCandidateSelectionRejected(
                "pilot Candidate selection authoritative object verification failed"
            ) from exc
        matches = tuple(
            item for item in candidate_set.candidates if item.candidate_id == candidate_id
        )
        if len(matches) != 1 or matches[0].state is not CandidateState.PROPOSED:
            raise PilotCandidateSelectionRejected(
                "pilot Candidate selection requires one exact proposed Candidate"
            )
        candidate = matches[0]
        try:
            manifest = AuthorizedPilotManifest.create(
                scope=self.scope,
                snapshot=snapshot,
                graph=graph,
                candidate_set=candidate_set,
            )
        except ValueError as exc:
            raise PilotCandidateSelectionRejected(
                "pilot Candidate selection static provenance mismatch"
            ) from exc
        result = outcome.result
        if (
            stored_result != result
            or result.gate_status is not BenchmarkGateStatus.PASSED
            or result.violations
            or result.completed_at > at
            or result.pilot_manifest_id != manifest.pilot_manifest_id
            or result.metrics.candidate_count != len(candidate_set.candidates)
            or result.metrics.proposed_candidate_count != len(candidate_set.candidates)
            or candidate_set.scope_id != self.scope.scope_id
            or candidate_set.scope_version != self.scope.version
        ):
            raise PilotCandidateSelectionRejected(
                "pilot Candidate selection requires an exact passing readiness result"
            )
        return outcome, snapshot, graph, candidate_set, candidate, manifest
