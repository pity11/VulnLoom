"""Accepted Recommendation selection can enter only a sealed offline Validation Intake."""

import json
from datetime import timedelta

import pytest
from test_agent_validation_intake import (
    _validation_plan,
    _validation_plan_with_approval_gate,
)
from test_candidate_recommendation_selection import command, selection_case

from vulnloom.domain.models import CandidateState
from vulnloom.validation import (
    CandidateRecommendationValidationIntakeConflict,
    CandidateRecommendationValidationIntakeRecoveryRequired,
    CandidateRecommendationValidationIntakeRejected,
    CandidateRecommendationValidationIntakeService,
    CandidateRecommendationValidationIntakeStore,
    CandidateRecommendationValidationIntakeTimedOut,
)


def intake_case(tmp_path, approved_scope, now, *, decision="accept"):
    context = selection_case(tmp_path, approved_scope, now)
    values = context.__enter__()
    selection_service, admission, _, candidate_set, candidate, selection_store = values
    selection = selection_service.record(
        command(
            selection_service,
            admission,
            now,
            decision=decision,
            key=f"intake-selection-{decision}",
        ),
        now=now,
    )
    selected_at = now + timedelta(seconds=1)
    validation_plan = _validation_plan(
        selected_at,
        selection_service.scope,
        candidate,
        key=f"recommendation-intake-{decision}",
    )
    store = CandidateRecommendationValidationIntakeStore(tmp_path / "validation-intakes.db")
    service = CandidateRecommendationValidationIntakeService(
        scope=selection_service.scope,
        selection_service=selection_service,
        store=store,
    )
    return (
        context,
        service,
        store,
        selection,
        validation_plan,
        candidate_set,
        candidate,
        selection_store,
        selected_at,
    )


def close_case(context, store):
    store.connection.close()
    context.__exit__(None, None, None)


def test_accepted_selection_creates_replayable_intake_without_execution(
    tmp_path, approved_scope, now
):
    values = intake_case(tmp_path, approved_scope, now)
    context, service, store, selection, validation_plan, candidate_set, candidate, _, at = values
    try:
        original = service.selection_service.candidate_store.load(
            candidate_set.candidate_set_id
        ).model_dump_json()
        plan = service.prepare(
            selection_record_id=selection.record_id,
            validation_plan=validation_plan,
            now=at,
            deadline=at + timedelta(seconds=60),
            idempotency_key="recommendation-validation-intake-one",
        )
        record = service.intake(plan, validation_plan=validation_plan, now=at)
        replay = service.intake(plan, validation_plan=validation_plan, now=at)
        assert record == replay == store.load_completed(plan.plan_id)
        assert record.selection_record_id == selection.record_id
        assert record.validation_plan_id == validation_plan.plan_id
        assert record.requires_run_validation_approval
        assert not record.validation_executed
        assert record.candidate_unchanged
        assert candidate.state is CandidateState.PROPOSED
        assert (
            service.selection_service.candidate_store.load(
                candidate_set.candidate_set_id
            ).model_dump_json()
            == original
        )
        persisted = (tmp_path / "validation-intakes.db").read_bytes().lower()
        assert b"credential" not in persisted
        assert b"submission" not in persisted
        assert not (tmp_path / "validation.db").exists()
        tampered_values = record.model_dump(mode="python", exclude={"record_id"})
        tampered_values["selected_by"] = "different-reviewer"
        tampered = record.__class__.create(**tampered_values)
        with store.connection:
            store.connection.execute(
                "UPDATE candidate_recommendation_validation_intakes SET record_json=? "
                "WHERE plan_id=?",
                (tampered.model_dump_json(), plan.plan_id),
            )
        with pytest.raises(CandidateRecommendationValidationIntakeRejected, match="record drifted"):
            service.intake(plan, validation_plan=validation_plan, now=at)
    finally:
        close_case(context, store)


@pytest.mark.parametrize("decision", ("reject", "defer"))
def test_non_accepted_selection_is_rejected_before_intake(
    tmp_path, approved_scope, now, decision
):
    values = intake_case(tmp_path, approved_scope, now, decision=decision)
    context, service, store, selection, validation_plan, _, candidate, _, at = values
    try:
        with pytest.raises(CandidateRecommendationValidationIntakeRejected, match="does not match"):
            service.prepare(
                selection_record_id=selection.record_id,
                validation_plan=validation_plan,
                now=at,
                deadline=at + timedelta(seconds=60),
                idempotency_key=f"recommendation-validation-intake-{decision}",
            )
        assert candidate.state is CandidateState.PROPOSED
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_recommendation_validation_intakes"
        ).fetchone()[0] == 0
    finally:
        close_case(context, store)


def test_intake_rejects_tamper_missing_selection_and_timeout(tmp_path, approved_scope, now):
    values = intake_case(tmp_path, approved_scope, now)
    context, service, store, selection, validation_plan, _, _, _, at = values
    try:
        with pytest.raises(CandidateRecommendationValidationIntakeRejected, match="authoritative"):
            service.prepare(
                selection_record_id="f" * 64,
                validation_plan=validation_plan,
                now=at,
                deadline=at + timedelta(seconds=60),
                idempotency_key="recommendation-validation-intake-missing",
            )
        plan = service.prepare(
            selection_record_id=selection.record_id,
            validation_plan=validation_plan,
            now=at,
            deadline=at + timedelta(seconds=30),
            idempotency_key="recommendation-validation-intake-timeout",
        )
        with pytest.raises(CandidateRecommendationValidationIntakeTimedOut):
            service.intake(plan, validation_plan=validation_plan, now=plan.deadline)
        broken = plan.model_copy(update={"candidate_digest": "f" * 64})
        with pytest.raises(CandidateRecommendationValidationIntakeRejected, match="boundary"):
            service.intake(broken, validation_plan=validation_plan, now=at)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_recommendation_validation_intakes"
        ).fetchone()[0] == 0
    finally:
        close_case(context, store)


def test_intake_completion_failure_leaves_recovery_checkpoint(
    tmp_path, approved_scope, now, monkeypatch
):
    values = intake_case(tmp_path, approved_scope, now)
    context, service, store, selection, validation_plan, _, candidate, _, at = values
    try:
        plan = service.prepare(
            selection_record_id=selection.record_id,
            validation_plan=validation_plan,
            now=at,
            deadline=at + timedelta(seconds=60),
            idempotency_key="recommendation-validation-intake-recovery",
        )

        def fail(_):
            raise OSError("synthetic completion failure")

        monkeypatch.setattr(store, "complete", fail)
        with pytest.raises(OSError):
            service.intake(plan, validation_plan=validation_plan, now=at)
        with pytest.raises(CandidateRecommendationValidationIntakeRecoveryRequired):
            service.intake(plan, validation_plan=validation_plan, now=at)
        with pytest.raises(CandidateRecommendationValidationIntakeConflict):
            changed = plan.model_copy(
                update={
                    "idempotency_key": "recommendation-validation-intake-conflict",
                }
            )
            service.store.claim(changed)
        assert candidate.state is CandidateState.PROPOSED
    finally:
        close_case(context, store)


def test_validation_intake_cli_records_without_running_validation(
    tmp_path, approved_scope, now, monkeypatch, capsys
):
    from vulnloom import cli
    from vulnloom.recommendations import selection_cli

    values = intake_case(tmp_path, approved_scope, now)
    context, _, store, selection, validation_plan, _, candidate, _, at = values
    try:
        scope_file = tmp_path / "scope.json"
        plan_file = tmp_path / "validation-plan.json"
        scope_file.write_text(values[1].scope.model_dump_json(), encoding="utf-8")
        plan_file.write_text(validation_plan.model_dump_json(), encoding="utf-8")
        monkeypatch.setattr(selection_cli, "utc_now", lambda: at)
        result = cli.main(
            [
                "candidate-recommendation-validation-intake-local",
                "--scope-file",
                str(scope_file),
                "--generation-db",
                str(tmp_path / "generations.db"),
                "--recommendation-db",
                str(tmp_path / "admissions.db"),
                "--selection-db",
                str(tmp_path / "selections.db"),
                "--graph-store",
                str(tmp_path / "graphs"),
                "--candidate-store",
                str(tmp_path / "candidates"),
                "--validation-intake-db",
                str(tmp_path / "cli-validation-intakes.db"),
                "--selection-record-id",
                selection.record_id,
                "--validation-plan-file",
                str(plan_file),
                "--idempotency-key",
                "recommendation-validation-intake-cli",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert result == 0
        assert payload["status"] == "intake_ready"
        assert not payload["validation_executed"]
        assert payload["requires_run_validation_approval"]
        assert payload["record"]["selection_record_id"] == selection.record_id
        assert candidate.state is CandidateState.PROPOSED
    finally:
        close_case(context, store)


def test_intake_rejects_broker_plan_and_enforces_runtime_timeout(
    tmp_path, approved_scope, now
):
    values = intake_case(tmp_path, approved_scope, now)
    context, service, store, selection, _, _, candidate, _, at = values
    try:
        networked_plan = _validation_plan_with_approval_gate(at, service.scope, candidate)
        with pytest.raises(CandidateRecommendationValidationIntakeRejected, match="does not match"):
            service.prepare(
                selection_record_id=selection.record_id,
                validation_plan=networked_plan,
                now=at,
                deadline=at + timedelta(seconds=30),
                idempotency_key="recommendation-intake-broker-rejected",
            )
        service.clock = iter((0.0, 3.0)).__next__
        with pytest.raises(CandidateRecommendationValidationIntakeTimedOut, match="timed out"):
            service.prepare(
                selection_record_id=selection.record_id,
                validation_plan=values[4],
                now=at,
                deadline=at + timedelta(seconds=30),
                idempotency_key="recommendation-intake-runtime-timeout",
            )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_recommendation_validation_intakes"
        ).fetchone()[0] == 0
    finally:
        close_case(context, store)
