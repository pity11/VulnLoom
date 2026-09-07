"""M9.12 Approval and provenance regression with synthetic offline Evidence only."""

from contextlib import contextmanager
from datetime import timedelta
from uuid import uuid4

import pytest
from test_pilot_critic_intake import _case as _intake_case

from vulnloom.critic import (
    PILOT_CRITIC_EFFECTS,
    AgentCriticOutcomeBindingService,
    AgentCriticOutcomeBindingStore,
    CounterevidenceDisposition,
    CriticStore,
    DeterministicCritic,
    PilotCriticApprovalAction,
    PilotCriticExecutionBinding,
    PilotCriticExecutionConflict,
    PilotCriticExecutionPlan,
    PilotCriticExecutionRecoveryRequired,
    PilotCriticExecutionRejected,
    PilotCriticExecutionService,
    PilotCriticExecutionStore,
    PilotCriticExecutionTimedOut,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ApprovalAction, ApprovalRequest, ApprovalStatus, CandidateState


@contextmanager
def _case(tmp_path, now, scope, candidate, *, disposition=CounterevidenceDisposition.RULED_OUT):
    with _intake_case(tmp_path, now, scope, candidate, disposition=disposition) as (
        intake,
        intake_plan,
        inputs,
        runner,
    ):
        intake.execute(intake_plan, **inputs, now=now + timedelta(seconds=8))
        with (
            CriticStore(tmp_path / "critic.db") as critic_store,
            AgentCriticOutcomeBindingStore(tmp_path / "critic-outcomes.db") as outcome_store,
            PilotCriticExecutionStore(tmp_path / "pilot-critic-execution.db") as store,
        ):
            m8 = intake.intake_service
            critic = DeterministicCritic(
                scope=scope, evidence_store=m8.evidence_store, store=critic_store
            )
            outcomes = AgentCriticOutcomeBindingService(
                scope=scope,
                critic_intake_store=m8.store,
                outcome_binding_store=m8.outcome_binding_store,
                validation_store=m8.validation_store,
                critic_store=critic_store,
                evidence_store=m8.evidence_store,
                binding_store=outcome_store,
            )
            service = PilotCriticExecutionService(
                pilot_intake_service=intake,
                critic=critic,
                outcome_service=outcomes,
                store=store,
            )
            inputs.update(pilot_intake_plan=intake_plan, evidence=(runner.evidence,))
            action = service.approval_action(**inputs, now=now + timedelta(seconds=9))
            approval = ApprovalRequest(
                engagement_id=scope.engagement_id,
                target_id=candidate.target_id,
                action=ApprovalAction.RUN_CRITIC,
                action_digest=action.action_id,
                expected_side_effects=PILOT_CRITIC_EFFECTS,
                evidence_summary="Synthetic local Critic review",
                policy_version=scope.version,
                expires_at=now + timedelta(seconds=30),
                status=ApprovalStatus.GRANTED,
                decided_by="independent-human-approver",
                decided_at=now + timedelta(seconds=9),
            )
            plan = service.prepare(
                **inputs,
                approval=approval,
                now=now + timedelta(seconds=10),
                deadline=now + timedelta(seconds=25),
                idempotency_key="m9.12",
            )
            yield service, plan, approval, inputs, runner


def _no_claim(service):
    assert (
        service.store.connection.execute("SELECT count(*) FROM pilot_critic_executions").fetchone()[
            0
        ]
        == 0
    )
    assert (
        service.critic.store.connection.execute(
            "SELECT count(*) FROM critic_executions"
        ).fetchone()[0]
        == 0
    )
    assert (
        service.outcome_service.binding_store.connection.execute(
            "SELECT count(*) FROM agent_critic_outcome_bindings"
        ).fetchone()[0]
        == 0
    )


@pytest.mark.parametrize(
    "disposition,state",
    [
        (CounterevidenceDisposition.RULED_OUT, CandidateState.CRITIC_REVIEWED),
        (CounterevidenceDisposition.CONFIRMED, CandidateState.REJECTED),
        (CounterevidenceDisposition.INCONCLUSIVE, CandidateState.VALIDATED),
    ],
)
def test_pilot_critic_approved_review_binds_all_verdicts_and_replays(
    tmp_path,
    now,
    approved_scope,
    candidate,
    monkeypatch,
    disposition,
    state,
):
    with _case(tmp_path, now, approved_scope, candidate, disposition=disposition) as (
        service,
        plan,
        approval,
        inputs,
        runner,
    ):

        def forbidden(*_args, **_kwargs):
            pytest.fail("completed replay must not execute any prior stage")

        monkeypatch.setattr(service.pilot_intake_service, "execute", forbidden)
        result = service.execute(plan, approval=approval, **inputs, now=now + timedelta(seconds=11))
        assert result.final_candidate_state is state
        assert result.approval_id == approval.approval_id
        _, outcome = service.critic.store.load_completed(plan.critic_plan_id)
        assert outcome.candidate.state is state
        assert result.critic_outcome_digest == canonical_digest(outcome.model_dump(mode="python"))
        assert (
            service.outcome_service.binding_store.load_completed(
                result.outcome_binding_plan_id
            ).binding_id
            == result.outcome_binding_id
        )
        monkeypatch.setattr(service.critic, "review", forbidden)
        monkeypatch.setattr(service.outcome_service, "execute", forbidden)
        assert (
            service.execute(plan, approval=approval, **inputs, now=now + timedelta(seconds=12))
            == result
        )
        assert service.store.load_completed(plan.execution_plan_id) == result
        assert runner.calls == 1 and candidate.state is CandidateState.PROPOSED
        values = plan.model_dump(mode="python", exclude={"execution_plan_id"})
        values["idempotency_key"] = "conflict"
        with pytest.raises(PilotCriticExecutionConflict):
            service.execute(
                PilotCriticExecutionPlan.create(**values),
                approval=approval,
                **inputs,
                now=now + timedelta(seconds=12),
            )
        for marker in (
            b"assessments",
            b"rationale",
            b"runner_request",
            b"broker_calls",
            b"Synthetic local",
        ):
            assert marker not in (tmp_path / "pilot-critic-execution.db").read_bytes()


@pytest.mark.parametrize(
    "drift",
    [
        "pending",
        "denied",
        "revoked",
        "action",
        "action_digest",
        "target_id",
        "engagement_id",
        "policy_version",
        "effects",
        "expired",
        "future",
        "before_intake",
        "decider",
        "approval_id",
    ],
)
def test_pilot_critic_requires_exact_approval_before_claim(
    tmp_path,
    now,
    approved_scope,
    candidate,
    drift,
):
    with _case(tmp_path, now, approved_scope, candidate) as (
        service,
        plan,
        approval,
        inputs,
        runner,
    ):
        updates = {
            "pending": {"status": ApprovalStatus.PENDING},
            "denied": {"status": ApprovalStatus.DENIED},
            "revoked": {"status": ApprovalStatus.REVOKED},
            "action": {"action": ApprovalAction.RUN_VALIDATION},
            "action_digest": {"action_digest": "0" * 64},
            "target_id": {"target_id": uuid4()},
            "engagement_id": {"engagement_id": uuid4()},
            "policy_version": {"policy_version": 99},
            "effects": {"expected_side_effects": ("other",)},
            "expired": {"expires_at": now + timedelta(seconds=10)},
            "future": {"decided_at": now + timedelta(seconds=20)},
            "before_intake": {"decided_at": now + timedelta(seconds=7)},
            "decider": {"decided_by": "someone-else"},
            "approval_id": {"approval_id": uuid4()},
        }[drift]
        changed = approval.model_copy(update=updates)
        with pytest.raises(ValueError):
            service.execute(plan, approval=changed, **inputs, now=now + timedelta(seconds=11))
        _no_claim(service)
        assert runner.calls == 1


@pytest.mark.parametrize(
    "drift", ["missing_intake", "started_intake", "catalog", "evidence", "plan", "critic", "scope"]
)
def test_pilot_critic_provenance_rejected_before_claim(
    tmp_path, now, approved_scope, candidate, drift
):
    with _case(tmp_path, now, approved_scope, candidate) as (
        service,
        plan,
        approval,
        inputs,
        runner,
    ):
        if drift == "missing_intake":
            service.pilot_intake_service.store.connection.execute(
                "DELETE FROM pilot_critic_intakes"
            )
        elif drift == "started_intake":
            service.pilot_intake_service.store.connection.execute(
                "UPDATE pilot_critic_intakes SET state='started'"
            )
        elif drift == "catalog":
            inputs["evidence"] = ()
        elif drift == "evidence":
            inputs["evidence"] = (
                inputs["evidence"][0].model_copy(update={"target_version": "different-version"}),
            )
        elif drift == "plan":
            values = plan.model_dump(mode="python", exclude={"execution_plan_id"})
            values["evidence_catalog_digest"] = "0" * 64
            plan = PilotCriticExecutionPlan.create(**values)
        elif drift == "critic":
            inputs["critic_plan"] = inputs["critic_plan"].model_copy(
                update={"candidate_digest": "0" * 64}
            )
        elif drift == "scope":
            service.critic.scope = approved_scope.model_copy(update={"version": 99})
        with pytest.raises(PilotCriticExecutionRejected):
            service.execute(plan, approval=approval, **inputs, now=now + timedelta(seconds=11))
        _no_claim(service)
        assert runner.calls == 1


@pytest.mark.parametrize("completed", [False, True])
def test_pilot_critic_refuses_bare_critic_checkpoint(
    tmp_path, now, approved_scope, candidate, completed
):
    with _case(tmp_path, now, approved_scope, candidate) as (
        service,
        plan,
        approval,
        inputs,
        runner,
    ):
        if completed:
            _, _, validation = service._load(**inputs, now=now + timedelta(seconds=10))
            service.critic.review(
                validation.candidate,
                validation.validation_run,
                validation.evidence_bundle,
                inputs["evidence"],
                inputs["critic_plan"],
                now=now + timedelta(seconds=10),
            )
        else:
            service.critic.store.claim(inputs["critic_plan"], now=now + timedelta(seconds=10))
        with pytest.raises(PilotCriticExecutionRejected, match="predates"):
            service.execute(plan, approval=approval, **inputs, now=now + timedelta(seconds=11))
        assert not service.store.has_critic_plan_checkpoint(plan.critic_plan_id)
        assert runner.calls == 1


@pytest.mark.parametrize("failure_stage", ["critic", "outcome", "wrapper"])
def test_pilot_critic_timeout_failure_cleanup(
    tmp_path, now, approved_scope, candidate, monkeypatch, failure_stage
):
    with _case(tmp_path, now, approved_scope, candidate) as (
        service,
        plan,
        approval,
        inputs,
        runner,
    ):
        for instant in (plan.created_at - timedelta(seconds=1), plan.deadline):
            with pytest.raises(PilotCriticExecutionTimedOut):
                service.execute(plan, approval=approval, **inputs, now=instant)
        _no_claim(service)

        def fail(_value):
            raise OSError("synthetic completion failure")

        target = {
            "critic": service.critic.store,
            "outcome": service.outcome_service.binding_store,
            "wrapper": service.store,
        }[failure_stage]
        monkeypatch.setattr(target, "complete", fail)
        with pytest.raises(OSError):
            service.execute(plan, approval=approval, **inputs, now=now + timedelta(seconds=11))
        with pytest.raises(PilotCriticExecutionRecoveryRequired):
            service.execute(plan, approval=approval, **inputs, now=now + timedelta(seconds=12))
        assert runner.calls == 1 and candidate.state is CandidateState.PROPOSED
        assert not tuple(tmp_path.rglob("*.tmp"))


def test_pilot_critic_contracts_are_digest_only():
    for model in (PilotCriticApprovalAction, PilotCriticExecutionPlan, PilotCriticExecutionBinding):
        schema = model.model_json_schema()
        assert schema["additionalProperties"] is False
        assert "pilot_intake_binding_id" in schema["required"]
        for field in (
            "assessments",
            "rationale",
            "evidence",
            "runner_request",
            "broker_calls",
            "submission",
        ):
            assert field not in schema["properties"]


@pytest.mark.parametrize("drift", ["outcome", "m8-binding", "ledger", "bare-m8"])
def test_pilot_critic_rechecks_completed_provenance(
    tmp_path, now, approved_scope, candidate, drift
):
    with _case(tmp_path, now, approved_scope, candidate) as (
        service,
        plan,
        approval,
        inputs,
        runner,
    ):
        binding = service.execute(
            plan, approval=approval, **inputs, now=now + timedelta(seconds=11)
        )
        if drift == "outcome":
            _, outcome = service.critic.store.load_completed(plan.critic_plan_id)
            altered = outcome.model_copy(
                update={"review": outcome.review.model_copy(update={"rationale_code": "wrong"})}
            )
            service.critic.store.connection.execute(
                "UPDATE critic_executions SET outcome_json=?", (altered.model_dump_json(),)
            )
        elif drift == "m8-binding":
            store = service.outcome_service.binding_store
            result = store.load_completed(binding.outcome_binding_plan_id)
            values = result.model_dump(mode="python", exclude={"binding_id"})
            values["final_candidate_digest"] = "0" * 64
            altered = type(result)(binding_id=canonical_digest(values), **values)
            store.connection.execute(
                "UPDATE agent_critic_outcome_bindings SET binding_json=?",
                (altered.model_dump_json(),),
            )
        elif drift == "ledger":
            service.store.connection.execute(
                "UPDATE pilot_critic_executions SET approval_id=?", (str(uuid4()),)
            )
        elif drift == "bare-m8":
            service.store.connection.execute("DELETE FROM pilot_critic_executions")
            service.critic.store.connection.execute("DELETE FROM critic_executions")
        with pytest.raises((ValueError, PilotCriticExecutionRecoveryRequired)):
            service.execute(plan, approval=approval, **inputs, now=now + timedelta(seconds=12))
        assert runner.calls == 1


def test_pilot_critic_execution_cli(tmp_path, now, approved_scope, candidate, monkeypatch, capsys):
    import json

    from vulnloom import cli
    from vulnloom.critic import PilotCriticIntakeService
    from vulnloom.validation import PilotValidationOutcomeService, ValidationService

    with _case(tmp_path, now, approved_scope, candidate) as (
        service,
        plan,
        approval,
        inputs,
        runner,
    ):

        def forbidden(*_args, **_kwargs):
            pytest.fail("execution cannot run Validation or create a prior human Intake")

        monkeypatch.setattr(ValidationService, "execute", forbidden)
        monkeypatch.setattr(PilotValidationOutcomeService, "execute", forbidden)
        monkeypatch.setattr(PilotCriticIntakeService, "execute", forbidden)
        monkeypatch.setattr(cli, "utc_now", lambda: now + timedelta(seconds=11))
        review_calls = []
        original = DeterministicCritic.review

        def counted(self, *args, **kwargs):
            review_calls.append(1)
            return original(self, *args, **kwargs)

        monkeypatch.setattr(DeterministicCritic, "review", counted)
        args = ["pilot-critic-run-local"]
        for name, value in (
            ("plan", plan),
            ("approval", approval),
            ("pilot-intake-plan", inputs["pilot_intake_plan"]),
            ("pilot-outcome-plan", inputs["pilot_outcome_plan"]),
            ("outcome-plan", inputs["outcome_plan"]),
            ("intake-plan", inputs["intake_plan"]),
            ("intake-command", inputs["command"]),
            ("critic-plan", inputs["critic_plan"]),
            ("validation-plan", inputs["validation_plan"]),
            ("scope", approved_scope),
            ("audit-artifact", inputs["audit_artifact"]),
        ):
            path = tmp_path / f"{name}.json"
            path.write_text(value.model_dump_json())
            args.extend((f"--{name}-file", str(path)))
        catalog = tmp_path / "catalog.json"
        catalog.write_text(
            json.dumps([item.model_dump(mode="json") for item in inputs["evidence"]])
        )
        args.extend(("--evidence-catalog-file", str(catalog)))
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
            ("critic-db", "critic.db"),
            ("critic-outcome-db", "critic-outcomes.db"),
            ("pilot-critic-execution-db", "pilot-critic-execution.db"),
        ):
            args.extend((f"--{name}", str(tmp_path / path)))
        assert cli.main(args) == 0
        first = json.loads(capsys.readouterr().out)
        assert cli.main(args) == 0
        assert json.loads(capsys.readouterr().out) == first
        assert first["review_recorded"] is True
        assert first["source_candidate_unchanged"] is True
        assert first["network_accessed"] is False
        assert first["validation_executed"] is False
        assert review_calls == [1] and runner.calls == 1
