"""M9.13 provenance admission using only synthetic offline Critic observations."""

from contextlib import contextmanager
from datetime import timedelta
from uuid import uuid4

import pytest
from test_pilot_critic_execution import _case as _execution_case

from vulnloom.critic import CounterevidenceDisposition, agent_critic_outcome_binding_digest
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState
from vulnloom.findings import (
    AgentFindingIntakeCommand,
    AgentFindingIntakeDecision,
    AgentFindingIntakeReason,
    AgentFindingIntakeService,
    AgentFindingIntakeStore,
    DuplicateCheckResult,
    FindingDuplicateCheck,
    FindingDuplicateCheckStore,
    FindingPromotionPlan,
    PilotFindingIntakeBinding,
    PilotFindingIntakeConflict,
    PilotFindingIntakePlan,
    PilotFindingIntakeRecoveryRequired,
    PilotFindingIntakeRejected,
    PilotFindingIntakeService,
    PilotFindingIntakeStore,
    PilotFindingIntakeTimedOut,
    agent_finding_intake_plan_digest,
    finding_duplicate_check_digest,
)


def _digest(value):
    return canonical_digest(value.model_dump(mode="python"))


@contextmanager
def _case(tmp_path, now, scope, candidate, *, disposition=CounterevidenceDisposition.RULED_OUT):
    with _execution_case(tmp_path, now, scope, candidate, disposition=disposition) as (
        execution,
        execution_plan,
        approval,
        execution_inputs,
        runner,
    ):
        binding = execution.execute(
            execution_plan, approval=approval, **execution_inputs, now=now + timedelta(seconds=11)
        )
        critic_binding_plan = execution.outcome_service.prepare(
            critic_intake_plan=execution_inputs["intake_plan"],
            now=now + timedelta(seconds=11),
            idempotency_key=f"pilot-critic:{execution_plan.execution_plan_id}",
        )
        critic_binding = execution.outcome_service.binding_store.load_completed(
            binding.outcome_binding_plan_id
        )
        _, critic_outcome = execution.critic.store.load_completed(execution_plan.critic_plan_id)
        _, validation = execution.outcome_service.validation_store.load_completed(
            execution_inputs["validation_plan"].plan_id
        )
        reviewed = critic_outcome.candidate
        duplicate = FindingDuplicateCheck.create(
            candidate_id=reviewed.candidate_id,
            candidate_digest=_digest(reviewed),
            target_version_digest=canonical_digest(reviewed.target_version),
            scope_id=scope.scope_id,
            scope_version=scope.version,
            result=DuplicateCheckResult.CLEAR,
            duplicate_family_id=None,
            checked_by="human-duplicate-reviewer",
            checked_at=now + timedelta(seconds=12),
            expires_at=now + timedelta(seconds=40),
        )
        with (
            FindingDuplicateCheckStore(tmp_path / "duplicates.db") as duplicates,
            AgentFindingIntakeStore(tmp_path / "finding-intake.db") as intake_store,
            PilotFindingIntakeStore(tmp_path / "pilot-finding.db") as store,
        ):
            duplicates.publish(duplicate)
            promotion = FindingPromotionPlan.create(
                critic_outcome_binding_plan_id=critic_binding_plan.binding_plan_id,
                critic_outcome_binding_id=critic_binding.binding_id,
                critic_outcome_binding_digest=agent_critic_outcome_binding_digest(critic_binding),
                candidate_id=reviewed.candidate_id,
                candidate_digest=_digest(reviewed),
                validation_run_ids=(validation.validation_run.run_id,),
                validation_run_digests=(_digest(validation.validation_run),),
                evidence_bundle_id=validation.evidence_bundle.bundle_id,
                evidence_bundle_digest=_digest(validation.evidence_bundle),
                critic_review_id=critic_outcome.review.review_id,
                critic_review_digest=_digest(critic_outcome.review),
                duplicate_check_id=duplicate.check_id,
                duplicate_check_digest=finding_duplicate_check_digest(duplicate),
                finding_id=uuid4(),
                root_cause="Synthetic local fixture root cause",
                affected_versions=(reviewed.target_version,),
                impact="Synthetic local fixture impact",
                severity_assessment={"rating": "high"},
                scope_id=scope.scope_id,
                scope_version=scope.version,
                created_at=now + timedelta(seconds=13),
                deadline=now + timedelta(seconds=38),
                idempotency_key="promotion:m9.13",
            )
            upstream = execution.outcome_service
            intake = AgentFindingIntakeService(
                scope=scope,
                critic_binding_store=upstream.binding_store,
                validation_binding_store=upstream.outcome_binding_store,
                validation_store=upstream.validation_store,
                critic_store=upstream.critic_store,
                evidence_store=upstream.evidence_store,
                duplicate_check_store=duplicates,
                store=intake_store,
            )
            service = PilotFindingIntakeService(
                critic_execution_service=execution, intake_service=intake, store=store
            )
            inputs = dict(
                critic_execution_plan=execution_plan,
                execution_approval=approval,
                execution_inputs=execution_inputs,
                critic_binding_plan=critic_binding_plan,
                promotion_plan=promotion,
                duplicate_check=duplicate,
            )
            if disposition is not CounterevidenceDisposition.RULED_OUT:
                yield service, None, inputs, runner
                return
            intake_plan = intake.prepare(
                critic_binding_plan=critic_binding_plan,
                promotion_plan=promotion,
                duplicate_check=duplicate,
                now=now + timedelta(seconds=14),
                decision_deadline=now + timedelta(seconds=36),
                idempotency_key="m8.5:m9.13",
            )
            command = AgentFindingIntakeCommand.create(
                intake_plan_id=intake_plan.intake_plan_id,
                intake_plan_digest=agent_finding_intake_plan_digest(intake_plan),
                critic_outcome_binding_id=intake_plan.critic_outcome_binding_id,
                promotion_plan_id=intake_plan.promotion_plan_id,
                promotion_plan_digest=intake_plan.promotion_plan_digest,
                candidate_id=intake_plan.candidate_id,
                finding_id=intake_plan.finding_id,
                decision=AgentFindingIntakeDecision.ACCEPT,
                reason_code=AgentFindingIntakeReason.HUMAN_ACCEPTED_EXACT_PROMOTION,
                reviewer="independent-finding-reviewer",
                decided_at=now + timedelta(seconds=15),
            )
            inputs.update(intake_plan=intake_plan, command=command)
            plan = service.prepare(
                **inputs,
                now=now + timedelta(seconds=15),
                deadline=now + timedelta(seconds=35),
                idempotency_key="m9.13",
            )
            yield service, plan, inputs, runner


def _no_claim(service):
    for store, table in (
        (service.store, "pilot_finding_intakes"),
        (service.intake_service.store, "agent_finding_intakes"),
    ):
        assert store.connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


def test_pilot_finding_success_readonly_replay_and_conflict(
    tmp_path, now, approved_scope, candidate, monkeypatch
):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, inputs, runner):

        def forbidden(*_args, **_kwargs):
            pytest.fail("Finding Intake must not execute or create prior checkpoints")

        upstream = service.critic_execution_service
        monkeypatch.setattr(upstream, "execute", forbidden)
        monkeypatch.setattr(upstream.critic, "review", forbidden)
        monkeypatch.setattr(upstream.outcome_service, "execute", forbidden)
        binding = service.execute(plan, **inputs, now=now + timedelta(seconds=16))
        monkeypatch.setattr(service.intake_service, "decide", forbidden)
        # Past the execution Approval expiry: historical completion grants no new authority.
        assert service.execute(plan, **inputs, now=now + timedelta(seconds=31)) == binding
        assert service.store.load_completed(plan.plan_id) == binding
        assert binding.critic_execution_binding_id == plan.critic_execution_binding_id
        assert candidate.state is CandidateState.PROPOSED and runner.calls == 1
        assert (
            upstream.critic.store.load_completed(inputs["critic_execution_plan"].critic_plan_id)[
                1
            ].candidate.state
            is CandidateState.CRITIC_REVIEWED
        )
        assert not (tmp_path / "promotion.db").exists()
        values = plan.model_dump(mode="python", exclude={"plan_id"})
        values["idempotency_key"] = "conflict"
        with pytest.raises(PilotFindingIntakeConflict):
            service.execute(
                PilotFindingIntakePlan.create(**values), **inputs, now=now + timedelta(seconds=17)
            )
        for marker in (
            b"root_cause",
            b"severity_assessment",
            b"Synthetic local",
            b"runner_request",
            b"broker_calls",
            b"credential",
        ):
            assert marker not in (tmp_path / "pilot-finding.db").read_bytes()


@pytest.mark.parametrize(
    "drift",
    [
        "missing",
        "started",
        "execution-binding",
        "m8.4",
        "promotion",
        "plan",
        "command",
        "reject",
        "defer",
        "scope",
        "evidence",
        "duplicate-stale",
        "duplicate-missing",
    ],
)
def test_pilot_finding_rejects_before_checkpoint(tmp_path, now, approved_scope, candidate, drift):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, inputs, runner):
        execution = service.critic_execution_service
        if drift == "missing":
            execution.store.connection.execute("DELETE FROM pilot_critic_executions")
        elif drift == "started":
            execution.store.connection.execute("UPDATE pilot_critic_executions SET state='started'")
        elif drift == "execution-binding":
            execution.store.connection.execute(
                "UPDATE pilot_critic_executions SET approval_id=?", (str(uuid4()),)
            )
        elif drift == "m8.4":
            execution.outcome_service.binding_store.connection.execute(
                "DELETE FROM agent_critic_outcome_bindings"
            )
        elif drift == "scope":
            service.intake_service.scope = approved_scope.model_copy(update={"version": 99})
        elif drift == "evidence":
            service.intake_service.evidence_store.contains = lambda _ref: False
        elif drift == "duplicate-missing":
            service.intake_service.duplicate_check_store.connection.execute(
                "DELETE FROM finding_duplicate_checks"
            )
        elif drift == "duplicate-stale":
            values = inputs["duplicate_check"].model_dump(mode="python", exclude={"check_id"})
            values.update(
                checked_at=now + timedelta(seconds=16),
                result=DuplicateCheckResult.DUPLICATE,
                duplicate_family_id=uuid4(),
            )
            service.intake_service.duplicate_check_store.publish(
                FindingDuplicateCheck.create(**values)
            )
        elif drift in {"command", "reject", "defer"}:
            values = inputs["command"].model_dump(mode="python", exclude={"command_id"})
            if drift == "command":
                values["finding_id"] = uuid4()
            else:
                values["decision"] = AgentFindingIntakeDecision(drift)
                values["reason_code"] = (
                    AgentFindingIntakeReason.HUMAN_REJECTED
                    if drift == "reject"
                    else AgentFindingIntakeReason.HUMAN_DEFERRED
                )
            inputs["command"] = AgentFindingIntakeCommand.create(**values)
        elif drift == "promotion":
            values = inputs["promotion_plan"].model_dump(
                mode="python", exclude={"promotion_plan_id"}
            )
            values["root_cause"] = "changed after human selection"
            inputs["promotion_plan"] = FindingPromotionPlan.create(**values)
        elif drift == "plan":
            values = plan.model_dump(mode="python", exclude={"plan_id"})
            values["critic_execution_binding_digest"] = "0" * 64
            plan = PilotFindingIntakePlan.create(**values)
        with pytest.raises(PilotFindingIntakeRejected):
            service.execute(plan, **inputs, now=now + timedelta(seconds=17))
        _no_claim(service)
        assert runner.calls == 1


@pytest.mark.parametrize(
    "disposition", [CounterevidenceDisposition.CONFIRMED, CounterevidenceDisposition.INCONCLUSIVE]
)
def test_only_accepted_critic_can_enter_finding(
    tmp_path, now, approved_scope, candidate, disposition
):
    from vulnloom.findings import AgentFindingIntakeRejected

    with _case(tmp_path, now, approved_scope, candidate, disposition=disposition) as (
        service,
        _,
        inputs,
        runner,
    ):
        with pytest.raises(AgentFindingIntakeRejected):
            service.intake_service.prepare(
                critic_binding_plan=inputs["critic_binding_plan"],
                promotion_plan=inputs["promotion_plan"],
                duplicate_check=inputs["duplicate_check"],
                now=now + timedelta(seconds=14),
                decision_deadline=now + timedelta(seconds=35),
                idempotency_key="denied",
            )
        _no_claim(service)
        assert runner.calls == 1


@pytest.mark.parametrize("stage", ["m8.5", "pilot"])
def test_pilot_finding_timeout_failed_completion_cleanup(
    tmp_path, now, approved_scope, candidate, monkeypatch, stage
):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, inputs, runner):
        for instant in (plan.created_at - timedelta(seconds=1), plan.deadline):
            with pytest.raises(PilotFindingIntakeTimedOut):
                service.execute(plan, **inputs, now=instant)
        _no_claim(service)

        def fail(_record):
            raise OSError("synthetic ledger failure")

        monkeypatch.setattr(
            service.store if stage == "pilot" else service.intake_service.store, "complete", fail
        )
        with pytest.raises(OSError):
            service.execute(plan, **inputs, now=now + timedelta(seconds=16))
        with pytest.raises(PilotFindingIntakeRecoveryRequired):
            service.execute(plan, **inputs, now=now + timedelta(seconds=17))
        assert not tuple(tmp_path.rglob("*.tmp"))
        assert candidate.state is CandidateState.PROPOSED and runner.calls == 1


@pytest.mark.parametrize("completed", [False, True])
def test_pilot_finding_refuses_bare_m85(tmp_path, now, approved_scope, candidate, completed):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, inputs, runner):
        if completed:
            service.intake_service.decide(
                inputs["intake_plan"],
                inputs["command"],
                critic_binding_plan=inputs["critic_binding_plan"],
                promotion_plan=inputs["promotion_plan"],
                duplicate_check=inputs["duplicate_check"],
                now=now + timedelta(seconds=16),
            )
        else:
            service.intake_service.store.claim(
                inputs["intake_plan"], inputs["command"], now=now + timedelta(seconds=16)
            )
        with pytest.raises(PilotFindingIntakeRejected, match="predates"):
            service.execute(plan, **inputs, now=now + timedelta(seconds=16))
        assert not service.store.has_promotion_checkpoint(plan.promotion_plan_id)
        assert runner.calls == 1


def test_pilot_finding_schema_has_no_promotion_authority():
    for model in (PilotFindingIntakePlan, PilotFindingIntakeBinding):
        schema = model.model_json_schema()
        assert "critic_execution_binding_id" in schema["required"]
        assert schema["additionalProperties"] is False
        for field in (
            "root_cause",
            "impact",
            "severity_assessment",
            "approval",
            "submission",
            "runner_request",
            "broker_calls",
        ):
            assert field not in schema["properties"]


def test_pilot_finding_intake_cli(tmp_path, now, approved_scope, candidate, monkeypatch, capsys):
    import json

    from vulnloom import cli
    from vulnloom.critic import (
        DeterministicCritic,
        PilotCriticExecutionService,
        PilotCriticIntakeService,
    )
    from vulnloom.findings import FindingPromotionService
    from vulnloom.validation import PilotValidationOutcomeService, ValidationService

    with _case(tmp_path, now, approved_scope, candidate) as (
        service,
        plan,
        inputs,
        runner,
    ):
        upstream = inputs["execution_inputs"]

        def forbidden(*_args, **_kwargs):
            pytest.fail("execution cannot run Validation or create a prior human Intake")

        monkeypatch.setattr(ValidationService, "execute", forbidden)
        monkeypatch.setattr(PilotValidationOutcomeService, "execute", forbidden)
        monkeypatch.setattr(PilotCriticIntakeService, "execute", forbidden)
        monkeypatch.setattr(cli, "utc_now", lambda: now + timedelta(seconds=16))
        monkeypatch.setattr(DeterministicCritic, "review", forbidden)
        monkeypatch.setattr(PilotCriticExecutionService, "execute", forbidden)
        monkeypatch.setattr(FindingPromotionService, "execute", forbidden)
        args = ["pilot-finding-intake-bind-local"]
        for name, value in (
            ("plan", plan),
            ("critic-execution-plan", inputs["critic_execution_plan"]),
            ("critic-binding-plan", inputs["critic_binding_plan"]),
            ("finding-intake-plan", inputs["intake_plan"]),
            ("finding-intake-command", inputs["command"]),
            ("promotion-plan", inputs["promotion_plan"]),
            ("duplicate-check", inputs["duplicate_check"]),
            ("approval", inputs["execution_approval"]),
            ("pilot-intake-plan", upstream["pilot_intake_plan"]),
            ("pilot-outcome-plan", upstream["pilot_outcome_plan"]),
            ("outcome-plan", upstream["outcome_plan"]),
            ("intake-plan", upstream["intake_plan"]),
            ("intake-command", upstream["command"]),
            ("critic-plan", upstream["critic_plan"]),
            ("validation-plan", upstream["validation_plan"]),
            ("scope", approved_scope),
            ("audit-artifact", upstream["audit_artifact"]),
        ):
            path = tmp_path / f"{name}.json"
            path.write_text(value.model_dump_json())
            args.extend((f"--{name}-file", str(path)))
        catalog = tmp_path / "catalog.json"
        catalog.write_text(
            json.dumps([item.model_dump(mode="json") for item in upstream["evidence"]])
        )
        args.extend(("--evidence-catalog-file", str(catalog)))
        for name, path in (
            ("duplicate-check-db", "duplicates.db"),
            ("finding-intake-db", "finding-intake.db"),
            ("pilot-finding-db", "pilot-finding.db"),
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
        for key in (
            "finding_created",
            "candidate_changed",
            "critic_executed",
            "validation_executed",
            "network_accessed",
        ):
            assert first[key] is False
        assert runner.calls == 1


@pytest.mark.parametrize("stage", ["record", "ledger", "binding"])
def test_pilot_finding_replay_rejects_persisted_drift(
    tmp_path, now, approved_scope, candidate, monkeypatch, stage
):
    import json

    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, inputs, runner):
        binding = service.execute(plan, **inputs, now=now + timedelta(seconds=16))

        def forbidden(*_args, **_kwargs):
            pytest.fail("completed replay must not write another Intake")

        monkeypatch.setattr(service.intake_service, "decide", forbidden)
        if stage == "record":
            connection = service.intake_service.store.connection
            record = service.intake_service.store.load_completed(plan.intake_plan_id)
            values = record.model_dump(mode="python", exclude={"record_id"})
            values["reviewer"] = "different-reviewer"
            changed = type(record)(record_id=canonical_digest(values), **values)
            connection.execute(
                "UPDATE agent_finding_intakes SET record_json=?", (changed.model_dump_json(),)
            )
        else:
            connection = service.store.connection
            if stage == "ledger":
                connection.execute("UPDATE pilot_finding_intakes SET command_id='drifted'")
            else:
                values = binding.model_dump(mode="python", exclude={"binding_id"})
                values["intake_record_digest"] = "0" * 64
                changed = type(binding)(binding_id=canonical_digest(values), **values)
                connection.execute(
                    "UPDATE pilot_finding_intakes SET binding_json=?",
                    (json.dumps(changed.model_dump(mode="json")),),
                )
        connection.commit()
        with pytest.raises((PilotFindingIntakeRejected, PilotFindingIntakeRecoveryRequired)):
            service.execute(plan, **inputs, now=now + timedelta(seconds=17))
        assert runner.calls == 1
