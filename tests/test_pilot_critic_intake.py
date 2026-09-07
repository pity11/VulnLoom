"""M9.11 synthetic offline provenance tests; no vulnerability execution or Critic run."""

from contextlib import contextmanager
from datetime import timedelta

import pytest
from test_agent_validation_intake import _critic_plan
from test_pilot_validation_outcome import _case as _outcome_case

from vulnloom.critic import (
    AgentCriticIntakeCommand,
    AgentCriticIntakeDecision,
    AgentCriticIntakeReason,
    AgentCriticIntakeService,
    AgentCriticIntakeStore,
    PilotCriticIntakeBinding,
    PilotCriticIntakeConflict,
    PilotCriticIntakePlan,
    PilotCriticIntakeRecoveryRequired,
    PilotCriticIntakeRejected,
    PilotCriticIntakeService,
    PilotCriticIntakeStore,
    PilotCriticIntakeTimedOut,
    agent_critic_intake_plan_digest,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, ValidationResult


@contextmanager
def _case(tmp_path, now, scope, candidate, *, result=ValidationResult.REPRODUCED):
    with _outcome_case(tmp_path, now, scope, candidate, synthetic_result=result) as (
        upstream,
        outcome_plan,
        inputs,
        runner,
    ):
        upstream.execute(outcome_plan, **inputs, now=now + timedelta(seconds=5))
        with (
            AgentCriticIntakeStore(tmp_path / "critic-intake.db") as intake_store,
            PilotCriticIntakeStore(tmp_path / "pilot-critic.db") as store,
        ):
            m8 = upstream.outcome_service
            intake = AgentCriticIntakeService(
                scope=scope,
                audit_store=m8.audit_store,
                candidate_store=m8.candidate_store,
                outcome_binding_store=m8.binding_store,
                validation_store=m8.validation_store,
                evidence_store=m8.evidence_store,
                store=intake_store,
            )
            _, outcome = m8.validation_store.load_completed(inputs["validation_plan"].plan_id)
            critic_plan = _critic_plan(
                now + timedelta(seconds=1), outcome, outcome.verdict.evidence_refs[0]
            )
            service = PilotCriticIntakeService(
                pilot_outcome_service=upstream,
                intake_service=intake,
                store=store,
            )
            kwargs = dict(pilot_outcome_plan=outcome_plan, **inputs, critic_plan=critic_plan)
            if result is not ValidationResult.REPRODUCED:
                yield service, None, kwargs, runner
                return
            intake_plan = intake.prepare(
                outcome_binding_plan=inputs["outcome_plan"],
                audit_artifact=inputs["audit_artifact"],
                critic_plan=critic_plan,
                now=now + timedelta(seconds=6),
                decision_deadline=now + timedelta(seconds=40),
                idempotency_key="m9.11-intake",
            )
            command = AgentCriticIntakeCommand.create(
                intake_plan_id=intake_plan.intake_plan_id,
                intake_plan_digest=agent_critic_intake_plan_digest(intake_plan),
                outcome_binding_id=intake_plan.outcome_binding_id,
                candidate_id=intake_plan.candidate_id,
                critic_plan_id=intake_plan.critic_plan_id,
                critic_plan_digest=intake_plan.critic_plan_digest,
                decision=AgentCriticIntakeDecision.ACCEPT,
                reason_code=AgentCriticIntakeReason.HUMAN_ACCEPTED_EXACT_PLAN,
                reviewer="pilot-human-critic-reviewer",
                decided_at=now + timedelta(seconds=7),
            )
            kwargs.update(intake_plan=intake_plan, command=command)
            plan = service.prepare(
                **kwargs,
                now=now + timedelta(seconds=7),
                deadline=now + timedelta(seconds=35),
                idempotency_key="m9.11",
            )
            yield service, plan, kwargs, runner


def _no_claim(service):
    for store, table in (
        (service.store, "pilot_critic_intakes"),
        (service.intake_service.store, "agent_critic_intakes"),
    ):
        assert store.connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


def test_pilot_critic_success_replay_no_execution(
    tmp_path, now, approved_scope, candidate, monkeypatch
):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):

        def forbidden(*_args, **_kwargs):
            pytest.fail("M9.11 must only read existing M9.10")

        monkeypatch.setattr(service.pilot_outcome_service, "execute", forbidden)
        monkeypatch.setattr(service.pilot_outcome_service.outcome_service, "execute", forbidden)
        result = service.execute(plan, **kwargs, now=now + timedelta(seconds=8))
        monkeypatch.setattr(service.intake_service, "decide", forbidden)
        assert service.execute(plan, **kwargs, now=now + timedelta(seconds=9)) == result
        assert result == service.store.load_completed(plan.plan_id)
        assert result.pilot_outcome_binding_id == plan.pilot_outcome_binding_id
        assert runner.calls == 1 and candidate.state is CandidateState.PROPOSED
        assert not (tmp_path / "critic.sqlite3").exists()
        values = plan.model_dump(mode="python", exclude={"plan_id"})
        values["idempotency_key"] = "conflict"
        with pytest.raises(PilotCriticIntakeConflict):
            service.execute(
                PilotCriticIntakePlan.create(**values), **kwargs, now=now + timedelta(seconds=9)
            )
        for marker in (
            b"rationale",
            b"assessments",
            b"runner_request",
            b"broker_calls",
            b"credential",
        ):
            assert marker not in (tmp_path / "pilot-critic.db").read_bytes()


@pytest.mark.parametrize(
    "drift",
    [
        "missing",
        "started",
        "pilot-binding",
        "pilot-ledger",
        "execution",
        "m8",
        "intake-plan",
        "critic-plan",
        "command",
        "reject",
        "defer",
        "scope",
        "artifact",
        "evidence",
        "plan",
        "future-command",
    ],
)
def test_pilot_critic_rejects_drift_before_intake(tmp_path, now, approved_scope, candidate, drift):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):
        upstream = service.pilot_outcome_service
        if drift == "missing":
            upstream.store.connection.execute("DELETE FROM pilot_validation_outcomes")
        elif drift == "started":
            upstream.store.connection.execute(
                "UPDATE pilot_validation_outcomes SET state='started'"
            )
        elif drift == "pilot-binding":
            binding = upstream.store.load_completed(kwargs["pilot_outcome_plan"].plan_id)
            values = binding.model_dump(mode="python", exclude={"binding_id"})
            values["outcome_binding_digest"] = "0" * 64
            changed = type(binding)(binding_id=canonical_digest(values), **values)
            upstream.store.connection.execute(
                "UPDATE pilot_validation_outcomes SET binding_json=?", (changed.model_dump_json(),)
            )
        elif drift == "pilot-ledger":
            upstream.store.connection.execute(
                "UPDATE pilot_validation_outcomes SET idempotency_key='drift'"
            )
        elif drift == "execution":
            upstream.execution_store.connection.execute("DELETE FROM pilot_validation_executions")
        elif drift == "m8":
            upstream.outcome_service.binding_store.connection.execute(
                "DELETE FROM agent_validation_outcome_bindings"
            )
        elif drift in {
            "intake-plan",
            "critic-plan",
            "command",
            "future-command",
            "reject",
            "defer",
        }:
            key, field = {
                "intake-plan": ("intake_plan", "validated_candidate_digest"),
                "critic-plan": ("critic_plan", "candidate_digest"),
                "command": ("command", "critic_plan_digest"),
            }.get(drift, ("command", "decided_at"))
            model = kwargs[key]
            id_field = (
                "command_id"
                if key == "command"
                else "intake_plan_id"
                if key == "intake_plan"
                else "plan_id"
            )
            values = model.model_dump(mode="python", exclude={id_field})
            if drift in {"reject", "defer"}:
                values["decision"] = AgentCriticIntakeDecision(drift)
                values["reason_code"] = (
                    AgentCriticIntakeReason.HUMAN_REJECTED
                    if drift == "reject"
                    else AgentCriticIntakeReason.HUMAN_DEFERRED
                )
            else:
                values[field] = (
                    now + timedelta(seconds=20) if drift == "future-command" else "0" * 64
                )
            kwargs[key] = type(model)(**{id_field: canonical_digest(values)}, **values)
        elif drift == "scope":
            service.intake_service.scope = approved_scope.model_copy(update={"version": 99})
        elif drift == "artifact":
            kwargs["audit_artifact"] = kwargs["audit_artifact"].model_copy(
                update={"json_sha256": "0" * 64}
            )
        elif drift == "evidence":
            # Corrupt the digest-addressed object without executing any fixture code.
            upstream.outcome_service.evidence_store.contains = lambda _ref: False
        elif drift == "plan":
            values = plan.model_dump(mode="python", exclude={"plan_id"})
            values["pilot_outcome_binding_digest"] = "0" * 64
            plan = PilotCriticIntakePlan.create(**values)
        with pytest.raises(PilotCriticIntakeRejected):
            service.execute(plan, **kwargs, now=now + timedelta(seconds=8))
        _no_claim(service)
        assert runner.calls == 1 and candidate.state is CandidateState.PROPOSED


def test_pilot_critic_timeout_failure_cleanup(
    tmp_path, now, approved_scope, candidate, monkeypatch
):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):
        for instant in (plan.created_at - timedelta(seconds=1), plan.deadline):
            with pytest.raises(PilotCriticIntakeTimedOut):
                service.execute(plan, **kwargs, now=instant)
        _no_claim(service)

        def fail(_binding):
            raise OSError("fixture ledger write failure")

        monkeypatch.setattr(service.store, "complete", fail)
        with pytest.raises(OSError):
            service.execute(plan, **kwargs, now=now + timedelta(seconds=8))
        with pytest.raises(PilotCriticIntakeRecoveryRequired):
            service.execute(plan, **kwargs, now=now + timedelta(seconds=9))
        assert runner.calls == 1
        assert not tuple(tmp_path.rglob("*.tmp"))


@pytest.mark.parametrize("completed", [False, True])
def test_pilot_critic_refuses_bare_intake(tmp_path, now, approved_scope, candidate, completed):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):
        intake, command = kwargs["intake_plan"], kwargs["command"]
        if completed:
            service.intake_service.decide(
                intake,
                command,
                outcome_binding_plan=kwargs["outcome_plan"],
                audit_artifact=kwargs["audit_artifact"],
                critic_plan=kwargs["critic_plan"],
                now=now + timedelta(seconds=8),
            )
        else:
            service.intake_service.store.claim(intake, command, now=now + timedelta(seconds=8))
        with pytest.raises(PilotCriticIntakeRejected, match="predates"):
            service.execute(plan, **kwargs, now=now + timedelta(seconds=8))
        assert not service.store.has_critic_checkpoint(plan.critic_plan_id)
        assert runner.calls == 1


def test_pilot_critic_replay_rejects_resealed_record(tmp_path, now, approved_scope, candidate):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):
        service.execute(plan, **kwargs, now=now + timedelta(seconds=8))
        store = service.intake_service.store
        record = store.load_completed(plan.intake_plan_id)
        values = record.model_dump(mode="python", exclude={"record_id"})
        values["reviewer"] = "wrong-reviewer"
        changed = type(record)(record_id=canonical_digest(values), **values)
        store.connection.execute(
            "UPDATE agent_critic_intakes SET record_json=?", (changed.model_dump_json(),)
        )
        with pytest.raises(PilotCriticIntakeRejected, match="provenance"):
            service.execute(plan, **kwargs, now=now + timedelta(seconds=9))
        assert runner.calls == 1


def test_pilot_critic_schemas_are_digest_only():
    for model in (PilotCriticIntakePlan, PilotCriticIntakeBinding):
        schema = model.model_json_schema()
        assert "pilot_outcome_binding_id" in schema["required"]
        assert schema["additionalProperties"] is False
        for field in (
            "assessments",
            "rationale",
            "runner_request",
            "broker_calls",
            "approval",
            "submission",
        ):
            assert field not in schema["properties"]


def test_inconclusive_pilot_cannot_enter_critic(tmp_path, now, approved_scope, candidate):
    from vulnloom.critic import AgentCriticIntakeRejected

    with _case(tmp_path, now, approved_scope, candidate, result=ValidationResult.INCONCLUSIVE) as (
        service,
        _,
        kwargs,
        runner,
    ):
        with pytest.raises(AgentCriticIntakeRejected):
            service.intake_service.prepare(
                outcome_binding_plan=kwargs["outcome_plan"],
                audit_artifact=kwargs["audit_artifact"],
                critic_plan=kwargs["critic_plan"],
                now=now + timedelta(seconds=6),
                decision_deadline=now + timedelta(seconds=40),
                idempotency_key="inconclusive",
            )
        _no_claim(service)
        assert runner.calls == 1 and candidate.state is CandidateState.PROPOSED


def test_pilot_critic_cli_is_read_only_except_intake(
    tmp_path,
    now,
    approved_scope,
    candidate,
    monkeypatch,
    capsys,
):
    import json

    from vulnloom import cli
    from vulnloom.critic import DeterministicCritic
    from vulnloom.validation import PilotValidationOutcomeService, ValidationService

    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):

        def forbidden(*_args, **_kwargs):
            pytest.fail("CLI cannot execute Validation, Critic or M9.10 binding")

        monkeypatch.setattr(ValidationService, "execute", forbidden)
        monkeypatch.setattr(DeterministicCritic, "review", forbidden)
        monkeypatch.setattr(PilotValidationOutcomeService, "execute", forbidden)
        monkeypatch.setattr(cli, "utc_now", lambda: now + timedelta(seconds=8))
        args = ["pilot-critic-intake-bind-local"]
        for name, value in (
            ("plan", plan),
            ("pilot-outcome-plan", kwargs["pilot_outcome_plan"]),
            ("outcome-plan", kwargs["outcome_plan"]),
            ("intake-plan", kwargs["intake_plan"]),
            ("intake-command", kwargs["command"]),
            ("critic-plan", kwargs["critic_plan"]),
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
            ("critic-intake-db", "critic-intake.db"),
            ("pilot-critic-db", "pilot-critic.db"),
        ):
            args.extend((f"--{name}", str(tmp_path / path)))
        assert cli.main(args) == 0
        first = json.loads(capsys.readouterr().out)
        assert cli.main(args) == 0
        assert json.loads(capsys.readouterr().out) == first
        for field in (
            "critic_executed",
            "validation_executed",
            "candidate_changed",
            "network_accessed",
        ):
            assert first[field] is False
        assert runner.calls == 1


@pytest.mark.parametrize("field", ["started_at", "completed_at", "idempotency_key", "plan_json"])
def test_pilot_critic_ledger_drift(tmp_path, now, approved_scope, candidate, field):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):
        service.execute(plan, **kwargs, now=now + timedelta(seconds=8))
        service.store.connection.execute(f"UPDATE pilot_critic_intakes SET {field}=?", ("invalid",))
        with pytest.raises((PilotCriticIntakeRecoveryRequired, PilotCriticIntakeConflict)):
            service.execute(plan, **kwargs, now=now + timedelta(seconds=9))
        assert runner.calls == 1


def test_pilot_critic_expired_upstream_and_expanded_deadline(
    tmp_path,
    now,
    approved_scope,
    candidate,
):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, kwargs, runner):
        with pytest.raises(PilotCriticIntakeRejected, match="deadline"):
            service.prepare(
                **kwargs,
                now=plan.created_at,
                deadline=now + timedelta(minutes=10),
                idempotency_key="expanded",
            )
        # The M9.10 reader cannot claim a missing checkpoint or refresh expired authority.
        with pytest.raises(ValueError):
            service.pilot_outcome_service.load_verified(
                kwargs["pilot_outcome_plan"],
                outcome_plan=kwargs["outcome_plan"],
                audit_artifact=kwargs["audit_artifact"],
                validation_plan=kwargs["validation_plan"],
                now=kwargs["outcome_plan"].deadline,
            )
        _no_claim(service)
        assert runner.calls == 1
