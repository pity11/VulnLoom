"""M9.10 offline provenance admission: no execution during outcome binding."""

from contextlib import ExitStack, contextmanager
from datetime import timedelta

import pytest
from test_agent_validation_intake import (
    _audit_bundle,
    _FixedResultJudge,
    _pilot_execution_service,
    _pilot_intake_case,
    _pilot_validation_approval,
)

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, EvidenceKind
from vulnloom.runners import OfflineScenario
from vulnloom.validation import (
    AgentValidationOutcomeBindingService,
    AgentValidationOutcomeBindingStore,
)
from vulnloom.validation.pilot_outcome import (
    PilotValidationOutcomeRejected,
    PilotValidationOutcomeService,
    PilotValidationOutcomeTimedOut,
)
from vulnloom.validation.pilot_outcome_models import (
    PilotValidationOutcomeBinding,
    PilotValidationOutcomePlan,
)
from vulnloom.validation.pilot_outcome_store import (
    PilotValidationOutcomeConflict,
    PilotValidationOutcomeRecoveryRequired,
    PilotValidationOutcomeStore,
)


@contextmanager
def _case(tmp_path, now, scope, candidate, *, synthetic_result=None):
    with ExitStack() as stack:
        (
            intake,
            pilot_store,
            selection_store,
            intake_store,
            validation,
            intake_plan,
            pilot_plan,
            _,
        ) = _pilot_intake_case(tmp_path, now, scope, candidate)
        execution, execution_store, validation_store, runner = _pilot_execution_service(
            tmp_path, scope, intake
        )
        for store in (
            pilot_store,
            selection_store,
            intake_store,
            execution_store,
            validation_store,
        ):
            stack.callback(store.close)
        approval = _pilot_validation_approval(
            execution, pilot_plan, intake_plan, validation, now + timedelta(seconds=2)
        )
        execution_plan = execution.prepare(
            pilot_intake_plan_id=pilot_plan.plan_id,
            intake_plan_id=intake_plan.intake_plan_id,
            validation_plan=validation,
            approval=approval,
            now=now + timedelta(seconds=2),
            deadline=now + timedelta(seconds=60),
            idempotency_key="m9.10-execution",
        )
        if synthetic_result is not None:
            # Test-only synthetic observation; never a production reproduction claim.
            evidence = execution.validation_service.evidence_store.capture_text(
                "Synthetic offline provenance fixture",
                kind=EvidenceKind.TEST,
                source_ref="pilot-critic-fixture",
                producer="test.pilot-critic",
                target_version=candidate.target_version,
                summary="Synthetic provenance fixture",
            )
            runner.scenario = OfflineScenario(
                wall_seconds=0.01, evidence_refs=(evidence.evidence_id,)
            )
            execution.validation_service.judge = _FixedResultJudge(synthetic_result)
            runner.evidence = evidence
        execution.execute(
            execution_plan,
            intake_plan_id=intake_plan.intake_plan_id,
            validation_plan=validation,
            approval=approval,
            now=now + timedelta(seconds=3),
        )
        intake_service = intake.intake_service
        artifact = intake_service.audit_artifact_store.put(
            _audit_bundle(now - timedelta(seconds=1), scope, candidate)
        )
        m8_store = stack.enter_context(AgentValidationOutcomeBindingStore(tmp_path / "m8.db"))
        m8 = AgentValidationOutcomeBindingService(
            scope=scope,
            audit_store=intake_service.audit_artifact_store,
            candidate_store=intake_service.candidate_set_store,
            intake_store=intake_store,
            validation_store=validation_store,
            evidence_store=execution.validation_service.evidence_store,
            binding_store=m8_store,
        )
        outcome_plan = m8.prepare(
            intake_plan_id=intake_plan.intake_plan_id,
            audit_artifact=artifact,
            candidate_set_id=intake_plan.candidate_set_id,
            candidate_id=candidate.candidate_id,
            validation_plan=validation,
            now=now + timedelta(seconds=4),
            idempotency_key="m9.10-m8",
        )
        store = stack.enter_context(PilotValidationOutcomeStore(tmp_path / "pilot-outcome.db"))
        service = PilotValidationOutcomeService(
            execution_store=execution_store,
            pilot_intake_store=pilot_store,
            outcome_service=m8,
            store=store,
        )
        kwargs = dict(
            outcome_plan=outcome_plan, audit_artifact=artifact, validation_plan=validation
        )
        plan = service.prepare(
            execution_plan_id=execution_plan.execution_plan_id,
            **kwargs,
            now=now + timedelta(seconds=4),
            deadline=now + timedelta(seconds=60),
            idempotency_key="m9.10",
        )
        yield service, plan, kwargs, runner


def test_pilot_outcome_success_replay_conflict_and_no_effects(
    tmp_path, now, approved_scope, candidate
):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):
        binding = service.execute(plan, **kwargs, now=now + timedelta(seconds=5))
        assert service.execute(plan, **kwargs, now=now + timedelta(seconds=6)) == binding
        assert service.store.load_completed(plan.plan_id) == binding
        assert binding.execution_binding_id == plan.execution_binding_id
        assert candidate.state is CandidateState.PROPOSED
        assert runner.calls == 1
        assert not hasattr(service, "runner")
        assert not hasattr(service, "validation_service")
        values = plan.model_dump(mode="python", exclude={"plan_id"})
        values["idempotency_key"] = "conflict"
        with pytest.raises(PilotValidationOutcomeConflict):
            service.execute(
                PilotValidationOutcomePlan.create(**values),
                **kwargs,
                now=now + timedelta(seconds=5),
            )
        for forbidden in (b"runner_request", b"broker_calls", b"credential", b"submission"):
            assert forbidden not in (tmp_path / "pilot-outcome.db").read_bytes()


@pytest.mark.parametrize(
    "drift",
    [
        "missing",
        "started",
        "approval_digest",
        "source_candidate_digest",
        "final_candidate_digest",
        "validation_outcome_digest",
        "completed_at",
        "plan_json",
        "intake",
        "scope",
        "audit",
        "plan",
    ],
)
def test_pilot_outcome_drift_denied_before_checkpoint(
    tmp_path,
    now,
    approved_scope,
    candidate,
    drift,
):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):
        conn = service.execution_store.connection
        if drift == "missing":
            conn.execute("DELETE FROM pilot_validation_executions")
        elif drift == "started":
            conn.execute("UPDATE pilot_validation_executions SET state='started'")
        elif drift in {"completed_at", "plan_json"}:
            conn.execute(f"UPDATE pilot_validation_executions SET {drift}=?", ("invalid",))
        elif drift == "intake":
            service.pilot_intake_store.connection.execute("DELETE FROM pilot_validation_intakes")
        elif drift == "scope":
            service.outcome_service.scope = approved_scope.model_copy(update={"version": 999})
        elif drift == "audit":
            kwargs["audit_artifact"] = kwargs["audit_artifact"].model_copy(
                update={"json_sha256": "0" * 64}
            )
        elif drift == "plan":
            values = plan.model_dump(mode="python", exclude={"plan_id"})
            values["execution_binding_digest"] = "0" * 64
            plan = PilotValidationOutcomePlan.create(**values)
        else:
            binding = service.execution_store.load_completed(plan.execution_plan_id)
            values = binding.model_dump(mode="python", exclude={"binding_id"})
            values[drift] = "0" * 64
            altered = type(binding)(binding_id=canonical_digest(values), **values)
            conn.execute(
                "UPDATE pilot_validation_executions SET binding_json=?",
                (altered.model_dump_json(),),
            )
        with pytest.raises(PilotValidationOutcomeRejected):
            service.execute(plan, **kwargs, now=now + timedelta(seconds=5))
        assert (
            service.store.connection.execute(
                "SELECT count(*) FROM pilot_validation_outcomes"
            ).fetchone()[0]
            == 0
        )
        assert not service.outcome_service.binding_store.has_validation_checkpoint(
            plan.validation_plan_id
        )
        assert runner.calls == 1


def test_pilot_outcome_timeout_and_started_cleanup(
    tmp_path, now, approved_scope, candidate, monkeypatch
):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):
        for instant in (plan.created_at - timedelta(seconds=1), plan.deadline):
            with pytest.raises(PilotValidationOutcomeTimedOut):
                service.execute(plan, **kwargs, now=instant)

        def fail(_binding):
            raise OSError("fixture completion failure")

        monkeypatch.setattr(service.store, "complete", fail)
        with pytest.raises(OSError):
            service.execute(plan, **kwargs, now=now + timedelta(seconds=5))
        with pytest.raises(PilotValidationOutcomeRecoveryRequired):
            service.execute(plan, **kwargs, now=now + timedelta(seconds=6))
        assert runner.calls == 1
        assert not tuple(tmp_path.rglob("*.tmp"))
        assert candidate.state is CandidateState.PROPOSED


def test_pilot_outcome_rejects_bare_m8_checkpoint(tmp_path, now, approved_scope, candidate):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):
        service.outcome_service.binding_store.claim(kwargs["outcome_plan"], now=now)
        with pytest.raises(PilotValidationOutcomeRejected, match="predates"):
            service.execute(plan, **kwargs, now=now + timedelta(seconds=5))
        assert not service.store.has_validation_checkpoint(plan.validation_plan_id)
        assert runner.calls == 1


def test_pilot_outcome_schema_requires_execution_and_excludes_authority():
    for model in (PilotValidationOutcomePlan, PilotValidationOutcomeBinding):
        schema = model.model_json_schema()
        assert "execution_binding_id" in schema["required"]
        assert schema["additionalProperties"] is False
        for forbidden in ("runner_request", "broker_calls", "credential", "submission", "approval"):
            assert forbidden not in schema["properties"]


@pytest.mark.parametrize("field", ["final_candidate_digest", "audit_bundle_id", "candidate_digest"])
def test_pilot_outcome_replay_rechecks_m8_binding(
    tmp_path,
    now,
    approved_scope,
    candidate,
    field,
):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):
        service.execute(plan, **kwargs, now=now + timedelta(seconds=5))
        store = service.outcome_service.binding_store
        result = store.load_completed(kwargs["outcome_plan"].binding_plan_id)
        values = result.model_dump(mode="python", exclude={"binding_id"})
        values[field] = "0" * 64
        altered = type(result)(binding_id=canonical_digest(values), **values)
        store.connection.execute(
            "UPDATE agent_validation_outcome_bindings SET binding_json=?",
            (altered.model_dump_json(),),
        )
        with pytest.raises(PilotValidationOutcomeRejected, match="provenance"):
            service.execute(plan, **kwargs, now=now + timedelta(seconds=6))
        assert runner.calls == 1


def test_pilot_outcome_cli_replays_without_execution(
    tmp_path,
    now,
    approved_scope,
    candidate,
    monkeypatch,
    capsys,
):
    import json

    from vulnloom import cli
    from vulnloom.validation import ValidationService

    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):

        def forbidden(*_args, **_kwargs):
            pytest.fail("M9.10 must never execute Validation")

        monkeypatch.setattr(ValidationService, "execute", forbidden)
        monkeypatch.setattr(cli, "utc_now", lambda: now + timedelta(seconds=5))
        args = ["pilot-validation-outcome-bind-local"]
        for name, value in (
            ("plan", plan),
            ("outcome-plan", kwargs["outcome_plan"]),
            ("validation-plan", kwargs["validation_plan"]),
            ("scope", approved_scope),
            ("audit-artifact", kwargs["audit_artifact"]),
        ):
            path = tmp_path / f"{name}.json"
            path.write_text(value.model_dump_json())
            args.extend((f"--{name}-file", str(path)))
        for name, path in (
            ("audit-store", "intake/audits"),
            ("candidate-store", "intake/candidates"),
            ("evidence-store", "validation-evidence"),
            ("intake-db", "intake/intake.sqlite3"),
            ("pilot-intake-db", "pilot-intake.sqlite3"),
            ("pilot-execution-db", "pilot-execution.sqlite3"),
            ("validation-db", "validation.sqlite3"),
            ("outcome-db", "m8.db"),
            ("pilot-outcome-db", "pilot-outcome.db"),
        ):
            args.extend((f"--{name}", str(tmp_path / path)))
        assert cli.main(args) == 0
        first = json.loads(capsys.readouterr().out)
        assert cli.main(args) == 0
        assert json.loads(capsys.readouterr().out) == first
        assert first["validation_executed"] is False
        assert first["candidate_changed"] is False
        assert first["network_accessed"] is False
        assert runner.calls == 1


@pytest.mark.parametrize("field", ["idempotency_key", "completed_at", "started_at"])
def test_pilot_outcome_ledger_drift_rejected(tmp_path, now, approved_scope, candidate, field):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):
        service.execute(plan, **kwargs, now=now + timedelta(seconds=5))
        service.store.connection.execute(
            f"UPDATE pilot_validation_outcomes SET {field}=?", ("invalid",)
        )
        with pytest.raises(PilotValidationOutcomeRecoveryRequired):
            service.execute(plan, **kwargs, now=now + timedelta(seconds=6))
        assert runner.calls == 1


def test_pilot_outcome_rejects_expanded_window(tmp_path, now, approved_scope, candidate):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):
        with pytest.raises(PilotValidationOutcomeRejected, match="deadline"):
            service.prepare(
                execution_plan_id=plan.execution_plan_id,
                **kwargs,
                now=plan.created_at,
                deadline=kwargs["outcome_plan"].deadline + timedelta(seconds=1),
                idempotency_key="expanded-window",
            )
        assert not service.store.has_validation_checkpoint(plan.validation_plan_id)
        assert runner.calls == 1
