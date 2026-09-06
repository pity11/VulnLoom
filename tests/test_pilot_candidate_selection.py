from __future__ import annotations

import json
from datetime import timedelta
from uuid import uuid4

import pytest

from vulnloom.analyzers import SourceGraphStore
from vulnloom.benchmark import (
    AuthorizedPilotReadinessArtifactStore,
    AuthorizedPilotReadinessPlan,
    AuthorizedPilotReadinessPolicy,
    AuthorizedPilotReadinessService,
    AuthorizedPilotReadinessStore,
    LocalSourceEffectCounters,
    PilotCandidateSelectionConsumptionConflict,
    PilotCandidateSelectionRecoveryRequired,
    PilotCandidateSelectionRejected,
    PilotCandidateSelectionService,
    PilotCandidateSelectionStore,
    PilotCandidateSelectionTimedOut,
)
from vulnloom.benchmark.pilot_readiness_fixture import PILOT_NOW, build_pilot_fixture
from vulnloom.domain.models import CandidateState, ScopeState
from vulnloom.hypotheses import CandidateSetStore
from vulnloom.ingestion import IngestionService


def _services(tmp_path, *, scope_state=None, failed_readiness=False):
    fixture = build_pilot_fixture(tmp_path / "fixture")
    graph_store = SourceGraphStore(tmp_path / "analysis")
    candidate_store = CandidateSetStore(tmp_path / "candidates")
    graph_store.put(fixture.graph)
    candidate_store.put(fixture.candidate_set)
    readiness_store = AuthorizedPilotReadinessStore(tmp_path / "readiness.sqlite3")
    readiness_artifacts = AuthorizedPilotReadinessArtifactStore(tmp_path / "readiness-artifacts")
    plan = fixture.plan
    if failed_readiness:
        plan = AuthorizedPilotReadinessPlan.create(
            manifest=fixture.manifest,
            quality_profile=fixture.quality_profile,
            quality_result=fixture.quality_result,
            policy=AuthorizedPilotReadinessPolicy(),
            effects=LocalSourceEffectCounters(submissions=1),
            created_at=PILOT_NOW,
            deadline=PILOT_NOW + timedelta(minutes=15),
            idempotency_key="failed-readiness",
        )
    outcome = AuthorizedPilotReadinessService(
        store=readiness_store, artifact_store=readiness_artifacts
    ).evaluate(
        scope=fixture.scope,
        snapshot=fixture.snapshot,
        target_store_root=fixture.target_store_root,
        graph=fixture.graph,
        candidate_set=fixture.candidate_set,
        quality_profile=fixture.quality_profile,
        quality_result=fixture.quality_result,
        manifest=fixture.manifest,
        plan=plan,
        now=PILOT_NOW,
    )
    selection_store = PilotCandidateSelectionStore(tmp_path / "selections.sqlite3")
    service = PilotCandidateSelectionService(
        scope=(
            fixture.scope.model_copy(update={"state": scope_state})
            if scope_state is not None
            else fixture.scope
        ),
        ingestion=IngestionService(fixture.target_store_root),
        graph_store=graph_store,
        candidate_store=candidate_store,
        readiness_store=readiness_store,
        readiness_artifact_store=readiness_artifacts,
        selection_store=selection_store,
    )
    return fixture, outcome, readiness_store, selection_store, service


def _command(service, fixture, outcome, *, candidate_id=None, key="pilot-selection"):
    return service.prepare(
        readiness_plan_id=outcome.plan_id,
        candidate_set_id=fixture.candidate_set.candidate_set_id,
        candidate_id=candidate_id or fixture.candidate_set.candidates[0].candidate_id,
        reviewer="human-reviewer",
        decided_at=PILOT_NOW,
        now=PILOT_NOW,
        idempotency_key=key,
    )


def test_human_selection_records_one_proposed_candidate_and_replays(tmp_path):
    fixture, outcome, readiness_store, selection_store, service = _services(tmp_path)
    try:
        command = _command(service, fixture, outcome)
        first = service.record(command, now=PILOT_NOW)
        second = service.record(command, now=PILOT_NOW)
        loaded = selection_store.load_completed(outcome.plan_id)
    finally:
        selection_store.close()
        readiness_store.close()

    assert first == second == loaded
    assert first.candidate_id == fixture.candidate_set.candidates[0].candidate_id
    assert fixture.candidate_set.candidates[0].state is CandidateState.PROPOSED
    persisted = (tmp_path / "selections.sqlite3").read_bytes()
    assert b"runner" not in persisted
    assert b"broker" not in persisted
    assert b"validation_plan" not in persisted
    assert b"submission" not in persisted


def test_selection_rejects_absent_candidate_and_failed_readiness(tmp_path):
    fixture, outcome, readiness_store, selection_store, service = _services(tmp_path / "absent")
    try:
        with pytest.raises(PilotCandidateSelectionRejected, match="exact proposed Candidate"):
            _command(service, fixture, outcome, candidate_id=uuid4())
    finally:
        selection_store.close()
        readiness_store.close()

    fixture, outcome, readiness_store, selection_store, service = _services(
        tmp_path / "failed", failed_readiness=True
    )
    try:
        with pytest.raises(PilotCandidateSelectionRejected, match="passing readiness"):
            _command(service, fixture, outcome)
    finally:
        selection_store.close()
        readiness_store.close()


def test_selection_rejects_revoked_scope_and_timeout_before_checkpoint(tmp_path):
    fixture, outcome, readiness_store, selection_store, service = _services(
        tmp_path / "revoked", scope_state=ScopeState.REVOKED
    )
    try:
        with pytest.raises(PilotCandidateSelectionRejected, match="approved Scope"):
            _command(service, fixture, outcome)
        count = selection_store.connection.execute(
            "SELECT COUNT(*) FROM pilot_candidate_selections"
        ).fetchone()[0]
    finally:
        selection_store.close()
        readiness_store.close()
    assert count == 0

    fixture, outcome, readiness_store, selection_store, service = _services(tmp_path / "timeout")
    try:
        command = _command(service, fixture, outcome)
        with pytest.raises(PilotCandidateSelectionTimedOut):
            service.record(command, now=fixture.scope.valid_until)
        count = selection_store.connection.execute(
            "SELECT COUNT(*) FROM pilot_candidate_selections"
        ).fetchone()[0]
    finally:
        selection_store.close()
        readiness_store.close()
    assert count == 0


def test_selection_conflict_and_unfinished_checkpoint_fail_closed(tmp_path):
    fixture, outcome, readiness_store, selection_store, service = _services(tmp_path)
    try:
        first = _command(service, fixture, outcome, key="first")
        tampered = first.model_copy(update={"candidate_digest": "0" * 64})
        with pytest.raises(PilotCandidateSelectionRejected, match="boundary validation failed"):
            service.record(tampered, now=PILOT_NOW)
        second = _command(
            service,
            fixture,
            outcome,
            candidate_id=fixture.candidate_set.candidates[1].candidate_id,
            key="second",
        )
        service.record(first, now=PILOT_NOW)
        with pytest.raises(PilotCandidateSelectionConsumptionConflict):
            service.record(second, now=PILOT_NOW)
    finally:
        selection_store.close()
        readiness_store.close()


def test_selection_schemas_exclude_operational_authority():
    from vulnloom.benchmark import (
        PilotCandidateSelectionCommand,
        PilotCandidateSelectionRecord,
    )

    encoded = json.dumps(
        {
            "command": PilotCandidateSelectionCommand.model_json_schema(),
            "record": PilotCandidateSelectionRecord.model_json_schema(),
        },
        sort_keys=True,
    ).lower()
    for forbidden in (
        "runner",
        "broker",
        "validation_plan",
        "approval",
        "submission",
        "request_body",
        "credential",
    ):
        assert forbidden not in encoded


def test_selection_unfinished_checkpoint_requires_recovery(tmp_path):
    fixture, outcome, readiness_store, selection_store, service = _services(tmp_path / "recovery")
    try:
        command = _command(service, fixture, outcome)
        selection_store.claim(command, now=PILOT_NOW)
        with pytest.raises(PilotCandidateSelectionRecoveryRequired):
            service.record(command, now=PILOT_NOW)
    finally:
        selection_store.close()
        readiness_store.close()
