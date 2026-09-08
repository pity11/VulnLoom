"""Human selection is explicit, authoritative, and cannot start Validation."""

import json
import os
import threading
from contextlib import contextmanager
from datetime import timedelta
from http.client import HTTPConnection
from urllib.request import ProxyHandler, build_opener

import pytest
from test_candidate_recommendation_generation import case as generation_case
from test_candidate_recommendation_generation import execute

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState
from vulnloom.recommendations import (
    CandidateRecommendationAdmissionService,
    CandidateRecommendationSelectionService,
    CandidateRecommendationSelectionStore,
    CandidateRecommendationStore,
)
from vulnloom.recommendations.review_web import (
    CandidateRecommendationReviewApplication,
    create_review_server,
)
from vulnloom.recommendations.selection_service import (
    CandidateRecommendationSelectionRejected,
    CandidateRecommendationSelectionTimedOut,
)
from vulnloom.recommendations.selection_store import (
    CandidateRecommendationSelectionConflict,
    CandidateRecommendationSelectionRecoveryRequired,
)


@contextmanager
def selection_case(tmp_path, approved_scope, now):
    with generation_case(tmp_path, approved_scope, now) as values:
        generation, generation_plan, approval, _, candidate_set, candidate, generation_store = (
            values
        )
        outcome = execute(generation, generation_plan, approval)
        with (
            CandidateRecommendationStore(tmp_path / "admissions.db") as recommendation_store,
            CandidateRecommendationSelectionStore(tmp_path / "selections.db") as selection_store,
        ):
            admission_service = CandidateRecommendationAdmissionService(
                scope=generation.scope,
                graph_store=generation.graphs,
                candidate_store=generation.candidates,
                store=recommendation_store,
                generation_store=generation_store,
            )
            admission_plan = admission_service.prepare_generated(
                generation_plan_id=generation_plan.plan_id,
                now=now,
                deadline=now + timedelta(seconds=60),
                idempotency_key="selection-fixture-admission",
            )
            admission = admission_service.admit_generated(admission_plan, now=now)
            service = CandidateRecommendationSelectionService(
                scope=generation.scope,
                graph_store=generation.graphs,
                candidate_store=generation.candidates,
                recommendation_store=recommendation_store,
                generation_store=generation_store,
                selection_store=selection_store,
            )
            yield service, admission, outcome, candidate_set, candidate, selection_store


def command(service, admission, now, decision="accept", key="selection-one"):
    return service.prepare(
        admission_record_id=admission.record_id,
        decision=decision,
        reviewer_id="workspace-owner",
        decided_at=now,
        expires_at=now + timedelta(seconds=60),
        idempotency_key=key,
    )


def test_accept_records_human_selection_without_changing_candidate(tmp_path, approved_scope, now):
    with selection_case(tmp_path, approved_scope, now) as values:
        service, admission, outcome, candidate_set, candidate, store = values
        original = candidate_set.model_dump_json()
        prepared = command(service, admission, now)
        record = service.record(prepared, now=now)
        assert record.admission_record_id == admission.record_id
        assert record.generation_outcome_id == outcome.outcome_id
        assert record.decision.value == "accept"
        assert record.eligible_for_validation_intake
        assert record.requires_separate_validation_approval
        assert record.candidate_unchanged
        assert service.record(prepared, now=now) == record
        assert (
            service.candidate_store.load(candidate_set.candidate_set_id).model_dump_json()
            == original
        )
        assert candidate.state is CandidateState.PROPOSED
        assert len(store.list_completed()) == 1


def test_defer_can_be_followed_by_accept_but_terminal_decision_is_final(
    tmp_path, approved_scope, now
):
    with selection_case(tmp_path, approved_scope, now) as values:
        service, admission, _, _, _, store = values
        deferred = service.record(
            command(service, admission, now, decision="defer", key="selection-defer"), now=now
        )
        assert not deferred.eligible_for_validation_intake
        accepted = service.record(
            command(service, admission, now, decision="accept", key="selection-accept"), now=now
        )
        assert accepted.eligible_for_validation_intake
        with pytest.raises(CandidateRecommendationSelectionConflict):
            service.record(
                command(service, admission, now, decision="reject", key="selection-reject"),
                now=now,
            )
        assert tuple(item.decision.value for item in store.list_completed()) == (
            "defer",
            "accept",
        )


def test_selection_rejects_tamper_missing_and_expired_commands(tmp_path, approved_scope, now):
    with selection_case(tmp_path, approved_scope, now) as values:
        service, admission, _, _, _, store = values
        prepared = command(service, admission, now)
        payload = prepared.model_dump(mode="python")
        payload["candidate_digest"] = "f" * 64
        payload["command_id"] = canonical_digest(
            {key: value for key, value in payload.items() if key != "command_id"}
        )
        with pytest.raises(CandidateRecommendationSelectionRejected, match="drifted"):
            service.record(prepared.__class__.model_validate(payload), now=now)
        with pytest.raises(CandidateRecommendationSelectionRejected, match="authoritative"):
            service.prepare(
                admission_record_id="f" * 64,
                decision="accept",
                reviewer_id="workspace-owner",
                decided_at=now,
                expires_at=now + timedelta(seconds=60),
                idempotency_key="selection-missing",
            )
        with pytest.raises(CandidateRecommendationSelectionTimedOut):
            service.record(prepared, now=prepared.expires_at)
        assert not store.list_completed()


def test_selection_timeout_and_interrupted_completion_fail_closed(
    tmp_path, approved_scope, now, monkeypatch
):
    with selection_case(tmp_path, approved_scope, now) as values:
        service, admission, _, _, _, store = values
        ticks = iter((0.0, 3.0))
        service.clock = lambda: next(ticks)
        with pytest.raises(CandidateRecommendationSelectionTimedOut):
            command(service, admission, now)
        service.clock = lambda: 0.0
        prepared = command(service, admission, now)

        def fail(_):
            raise OSError("synthetic completion failure")

        monkeypatch.setattr(store, "complete", fail)
        with pytest.raises(OSError):
            service.record(prepared, now=now)
        with pytest.raises(CandidateRecommendationSelectionRecoveryRequired):
            service.record(prepared, now=now)


def test_selection_cli_records_acceptance(tmp_path, approved_scope, now, monkeypatch, capsys):
    from vulnloom import cli
    from vulnloom.recommendations import selection_cli

    with selection_case(tmp_path, approved_scope, now) as values:
        service, admission, _, _, _, _ = values
        scope_file = tmp_path / "selection-scope.json"
        command_file = tmp_path / "selection-command.json"
        scope_file.write_text(service.scope.model_dump_json())
        monkeypatch.setattr(selection_cli, "utc_now", lambda: now)
        common = [
            "--scope-file",
            str(scope_file),
            "--generation-db",
            str(tmp_path / "generations.db"),
            "--recommendation-db",
            str(tmp_path / "admissions.db"),
            "--selection-db",
            str(tmp_path / "cli-selections.db"),
            "--graph-store",
            str(tmp_path / "graphs"),
            "--candidate-store",
            str(tmp_path / "candidates"),
        ]
        assert (
            cli.main(
                [
                    "candidate-recommendation-selection-prepare-local",
                    *common,
                    "--admission-record-id",
                    admission.record_id,
                    "--decision",
                    "accept",
                    "--reviewer-id",
                    "workspace-owner",
                    "--idempotency-key",
                    "cli-selection",
                ]
            )
            == 0
        )
        prepared = json.loads(capsys.readouterr().out)
        command_file.write_text(json.dumps(prepared))
        assert (
            cli.main(
                [
                    "candidate-recommendation-selection-record-local",
                    *common,
                    "--command-file",
                    str(command_file),
                ]
            )
            == 0
        )
        record = json.loads(capsys.readouterr().out)
        assert record["decision"] == "accept"
        assert record["eligible_for_validation_intake"]


def test_review_application_requires_two_steps_and_csrf(tmp_path, approved_scope, now):
    with selection_case(tmp_path, approved_scope, now) as values:
        service, admission, _, _, _, store = values
        app = CandidateRecommendationReviewApplication(
            service,
            reviewer_id="workspace-owner",
            csrf_token="fixed-csrf-token",
            now=lambda: now,
        )
        index = app.index().decode()
        review = app.review(admission.record_id).decode()
        assert "Candidate 人工审阅" in index
        assert "接受并准备选择" in review
        with pytest.raises(ValueError, match="CSRF"):
            app.prepare({"csrf": "wrong", "record_id": admission.record_id, "decision": "accept"})
        with pytest.raises(ValueError, match="fields"):
            app.prepare(
                {
                    "csrf": "fixed-csrf-token",
                    "record_id": admission.record_id,
                    "decision": "accept",
                    "unexpected": "value",
                }
            )
        confirmation = app.prepare(
            {
                "csrf": "fixed-csrf-token",
                "record_id": admission.record_id,
                "decision": "accept",
            }
        ).decode()
        assert "确认人工选择" in confirmation
        assert not store.list_completed()
        command_id = next(iter(app.pending))
        completed = app.record(
            {"csrf": "fixed-csrf-token", "command_id": command_id, "confirm": "yes"}
        ).decode()
        assert "选择已写入账本" in completed
        assert store.list_completed()[0].eligible_for_validation_intake
        terminal = app.review(admission.record_id).decode()
        assert "已完成终态选择" in terminal
        assert "接受并准备选择" not in terminal


def test_review_application_rejects_unsafe_identity_and_csrf_token():
    with pytest.raises(ValueError, match="reviewer id"):
        CandidateRecommendationReviewApplication(object(), reviewer_id="<script>")
    with pytest.raises(ValueError, match="CSRF token"):
        CandidateRecommendationReviewApplication(
            object(), reviewer_id="workspace-owner", csrf_token="too-short"
        )


@pytest.mark.socket_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_SOCKET_INTEGRATION") != "1",
    reason="set VULNLOOM_SOCKET_INTEGRATION=1 to run the loopback review UI probe",
)
def test_review_server_binds_only_loopback_and_sets_security_headers(tmp_path, approved_scope, now):
    with selection_case(tmp_path, approved_scope, now) as values:
        service, _, _, _, _, _ = values
        app = CandidateRecommendationReviewApplication(
            service,
            reviewer_id="workspace-owner",
            csrf_token="fixed-csrf-token",
            now=lambda: now,
        )
        server = create_review_server(app, port=0)
        observed = {}

        def fetch():
            opener = build_opener(ProxyHandler({}))
            with opener.open(f"http://127.0.0.1:{server.server_port}/", timeout=2) as response:
                observed["status"] = response.status
                observed["cache"] = response.headers["Cache-Control"]
                observed["csp"] = response.headers["Content-Security-Policy"]
                observed["body"] = response.read().decode()

        thread = threading.Thread(target=fetch, daemon=True)
        thread.start()
        try:
            assert server.server_address[0] == "127.0.0.1"
            server.handle_request()
            thread.join(timeout=2)
            assert observed["status"] == 200
            assert observed["cache"] == "no-store"
            assert "default-src 'none'" in observed["csp"]
            assert "Candidate 人工审阅" in observed["body"]
        finally:
            server.server_close()

        rejected = {}
        server = create_review_server(app, port=0)

        def fetch_bad_host():
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            connection.request("GET", "/", headers={"Host": "attacker.example"})
            response = connection.getresponse()
            rejected["status"] = response.status
            rejected["body"] = response.read().decode()
            connection.close()

        thread = threading.Thread(target=fetch_bad_host, daemon=True)
        thread.start()
        try:
            server.handle_request()
            thread.join(timeout=2)
            assert rejected["status"] == 400
            assert "请求被拒绝" in rejected["body"]
        finally:
            server.server_close()
