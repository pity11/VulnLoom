"""Approved local record promotion with synthetic offline pilot provenance."""

from contextlib import contextmanager
from datetime import timedelta
from uuid import uuid4

import pytest
from test_pilot_finding_intake import _case as _intake_case

from vulnloom.domain.models import ApprovalAction, ApprovalRequest, ApprovalStatus, CandidateState
from vulnloom.findings import (
    FINDING_PROMOTION_SIDE_EFFECTS,
    FindingPromotionService,
    FindingPromotionStore,
    PilotFindingPromotionBinding,
    PilotFindingPromotionConflict,
    PilotFindingPromotionPlan,
    PilotFindingPromotionRecoveryRequired,
    PilotFindingPromotionRejected,
    PilotFindingPromotionService,
    PilotFindingPromotionStore,
    PilotFindingPromotionTimedOut,
)


@contextmanager
def _case(tmp_path, now, scope, candidate):
    with _intake_case(tmp_path, now, scope, candidate) as (intake, intake_plan, inputs, runner):
        intake.execute(intake_plan, **inputs, now=now + timedelta(seconds=16))
        with (
            FindingPromotionStore(tmp_path / "promotion.db") as outcomes,
            PilotFindingPromotionStore(tmp_path / "pilot-promotion.db") as store,
        ):
            promotion = FindingPromotionService(
                intake_service=intake.intake_service, store=outcomes
            )
            service = PilotFindingPromotionService(
                pilot_intake_service=intake,
                promotion_service=promotion,
                store=store,
            )
            record = intake.intake_service.store.load_completed(
                inputs["intake_plan"].intake_plan_id
            )
            action = promotion.approval_action(
                record=record, promotion_plan=inputs["promotion_plan"]
            )
            approval = ApprovalRequest(
                engagement_id=scope.engagement_id,
                target_id=candidate.target_id,
                action=ApprovalAction.MUTATE_TARGET_STATE,
                action_digest=action.action_id,
                expected_side_effects=FINDING_PROMOTION_SIDE_EFFECTS,
                evidence_summary="Synthetic local Finding promotion",
                policy_version=scope.version,
                expires_at=now + timedelta(seconds=32),
                status=ApprovalStatus.GRANTED,
                decided_by="human-promotion-approver",
                decided_at=now + timedelta(seconds=17),
            )
            execution = promotion.prepare(
                **service._promotion_inputs(inputs, approval),
                now=now + timedelta(seconds=18),
                deadline=now + timedelta(seconds=30),
                idempotency_key="m8.6-pilot",
            )
            call = dict(
                pilot_intake_plan=intake_plan,
                intake_inputs=inputs,
                execution_plan=execution,
                approval=approval,
            )
            plan = service.prepare(
                **call,
                now=now + timedelta(seconds=18),
                deadline=now + timedelta(seconds=29),
                idempotency_key="m9.14",
            )
            yield service, plan, call, runner


def _no_claim(service):
    for store, table in (
        (service.store, "pilot_finding_promotions"),
        (service.promotion_service.store, "finding_promotions"),
    ):
        assert store.connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


def test_pilot_promotion_success_replay(tmp_path, now, approved_scope, candidate, monkeypatch):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, inputs, runner):

        def forbidden(*_args, **_kwargs):
            pytest.fail("must not rerun upstream Intake or execution")

        monkeypatch.setattr(service.pilot_intake_service, "execute", forbidden)
        monkeypatch.setattr(
            service.pilot_intake_service.critic_execution_service, "execute", forbidden
        )
        binding = service.execute(plan, **inputs, now=now + timedelta(seconds=19))
        outcome = service.promotion_service.store.load_completed(plan.execution_plan_id)
        assert outcome.finding.finding_id == plan.finding_id
        assert outcome.promoted_candidate.state is CandidateState.PROMOTED
        assert binding.finding_digest == outcome.finding_digest
        assert candidate.state is CandidateState.PROPOSED and runner.calls == 1
        monkeypatch.setattr(service.promotion_service, "execute", forbidden)
        assert service.execute(plan, **inputs, now=now + timedelta(seconds=20)) == binding
        changed = plan.model_dump(mode="python", exclude={"plan_id"})
        changed["idempotency_key"] = "other"
        with pytest.raises(PilotFindingPromotionConflict):
            service.execute(
                PilotFindingPromotionPlan.create(**changed),
                **inputs,
                now=now + timedelta(seconds=20),
            )
        persisted = service.store.connection.execute(
            "SELECT plan_json,binding_json FROM pilot_finding_promotions"
        ).fetchone()
        assert '"root_cause"' not in "".join(persisted)
        assert '"impact"' not in "".join(persisted)


@pytest.mark.parametrize(
    "change",
    [
        "denied",
        "expired",
        "action",
        "effects",
        "approver",
        "early",
        "scope",
        "missing",
        "started",
        "command",
        "promotion",
        "evidence",
        "plan",
        "duplicate",
    ],
)
def test_pilot_promotion_rejects_before_claim(
    tmp_path,
    now,
    approved_scope,
    candidate,
    change,
):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, inputs, runner):
        approval = inputs["approval"]
        upstream = inputs["intake_inputs"]
        if change in {"denied", "expired", "action", "effects", "approver", "early"}:
            fields = {
                "denied": {"status": ApprovalStatus.DENIED},
                "expired": {"expires_at": now + timedelta(seconds=19)},
                "action": {"action_digest": "0" * 64},
                "effects": {"expected_side_effects": ("submission",)},
                "approver": {"decided_by": None},
                "early": {"decided_at": now + timedelta(seconds=15)},
            }
            inputs["approval"] = approval.model_copy(update=fields[change])
        elif change in {"missing", "started"}:
            conn = service.pilot_intake_service.store.connection
            conn.execute(
                "DELETE FROM pilot_finding_intakes"
                if change == "missing"
                else "UPDATE pilot_finding_intakes SET state='started'"
            )
            conn.commit()
        elif change == "scope":
            service.promotion_service.scope = approved_scope.model_copy(update={"version": 99})
        elif change == "command":
            upstream["command"] = upstream["command"].model_copy(update={"reviewer": "changed"})
        elif change == "promotion":
            upstream["promotion_plan"] = upstream["promotion_plan"].model_copy(
                update={"impact": "drifted"}
            )
        elif change == "evidence":
            service.promotion_service.intake_service.evidence_store.contains = lambda *_: False
        elif change == "duplicate":
            conn = service.promotion_service.intake_service.duplicate_check_store.connection
            conn.execute("DELETE FROM finding_duplicate_checks")
            conn.commit()
        else:
            values = plan.model_dump(mode="python", exclude={"plan_id"})
            values["pilot_intake_binding_digest"] = "0" * 64
            plan = PilotFindingPromotionPlan.create(**values)
        with pytest.raises((PilotFindingPromotionRejected, ValueError)):
            service.execute(plan, **inputs, now=now + timedelta(seconds=19))
        _no_claim(service)
        assert runner.calls == 1


@pytest.mark.parametrize("completed", [False, True])
def test_pilot_promotion_bare_checkpoint(tmp_path, now, approved_scope, candidate, completed):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, inputs, _):
        if completed:
            service.promotion_service.execute(
                inputs["execution_plan"],
                **service._promotion_inputs(inputs["intake_inputs"], inputs["approval"]),
                now=now + timedelta(seconds=19),
            )
        else:
            service.promotion_service.store.claim(
                inputs["execution_plan"], now=now + timedelta(seconds=19)
            )
        with pytest.raises(PilotFindingPromotionRejected, match="predates"):
            service.execute(plan, **inputs, now=now + timedelta(seconds=20))
        assert not service.store.has_promotion_checkpoint(plan.promotion_plan_id)


@pytest.mark.parametrize("stage", ["promotion", "pilot"])
def test_pilot_promotion_timeout_failure_cleanup(
    tmp_path,
    now,
    approved_scope,
    candidate,
    monkeypatch,
    stage,
):
    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, inputs, _):
        for instant in (plan.created_at - timedelta(seconds=1), plan.deadline):
            with pytest.raises(PilotFindingPromotionTimedOut):
                service.execute(plan, **inputs, now=instant)
        _no_claim(service)

        def fail(*_args):
            raise OSError("synthetic persistence failure")

        store = service.store if stage == "pilot" else service.promotion_service.store
        monkeypatch.setattr(store, "complete", fail)
        with pytest.raises(OSError):
            service.execute(plan, **inputs, now=now + timedelta(seconds=19))
        with pytest.raises(PilotFindingPromotionRecoveryRequired):
            service.execute(plan, **inputs, now=now + timedelta(seconds=20))
        assert not tuple(tmp_path.rglob("*.tmp"))


def test_pilot_promotion_schema():
    for model in (PilotFindingPromotionPlan, PilotFindingPromotionBinding):
        schema = model.model_json_schema()
        assert schema["additionalProperties"] is False
        assert {"approval_id", "pilot_intake_binding_id"} <= set(schema["required"])
        assert not {"root_cause", "impact", "runner_request", "broker_calls", "submission"} & set(
            schema["properties"]
        )


def test_pilot_promotion_cli(tmp_path, now, approved_scope, candidate, monkeypatch, capsys):
    import json

    from vulnloom import cli
    from vulnloom.critic import (
        DeterministicCritic,
        PilotCriticExecutionService,
        PilotCriticIntakeService,
    )
    from vulnloom.findings import (
        AgentFindingIntakeService,
        FindingPromotionService,
        PilotFindingIntakeService,
    )
    from vulnloom.validation import PilotValidationOutcomeService, ValidationService

    with _case(tmp_path, now, approved_scope, candidate) as (
        service,
        plan,
        inputs,
        runner,
    ):
        call = inputs
        inputs = call["intake_inputs"]
        upstream = inputs["execution_inputs"]

        def forbidden(*_args, **_kwargs):
            pytest.fail("execution cannot run Validation or create a prior human Intake")

        monkeypatch.setattr(ValidationService, "execute", forbidden)
        monkeypatch.setattr(PilotValidationOutcomeService, "execute", forbidden)
        monkeypatch.setattr(PilotCriticIntakeService, "execute", forbidden)
        monkeypatch.setattr(cli, "utc_now", lambda: now + timedelta(seconds=19))
        monkeypatch.setattr(DeterministicCritic, "review", forbidden)
        monkeypatch.setattr(PilotCriticExecutionService, "execute", forbidden)
        monkeypatch.setattr(PilotFindingIntakeService, "execute", forbidden)
        monkeypatch.setattr(AgentFindingIntakeService, "decide", forbidden)
        args = ["pilot-finding-promote-local"]
        for name, value in (
            ("plan", plan),
            ("pilot-finding-intake-plan", call["pilot_intake_plan"]),
            ("promotion-execution-plan", call["execution_plan"]),
            ("promotion-approval", call["approval"]),
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
            ("promotion-db", "promotion.db"),
            ("pilot-promotion-db", "pilot-promotion.db"),
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
        monkeypatch.setattr(FindingPromotionService, "execute", forbidden)
        assert cli.main(args) == 0
        assert json.loads(capsys.readouterr().out) == first
        for key in (
            "critic_executed",
            "validation_executed",
            "network_accessed",
        ):
            assert first[key] is False
        assert first["finding_recorded"] is True
        assert first["source_candidate_unchanged"] is True
        assert runner.calls == 1


@pytest.mark.parametrize("stage", ["binding", "pilot-ledger", "outcome", "m86-ledger", "m913"])
def test_pilot_promotion_replay_tamper(
    tmp_path,
    now,
    approved_scope,
    candidate,
    monkeypatch,
    stage,
):
    from vulnloom.domain.digests import canonical_digest

    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, inputs, _):
        binding = service.execute(plan, **inputs, now=now + timedelta(seconds=19))

        def forbidden(*_args, **_kwargs):
            pytest.fail("replay cannot persist another promotion")

        monkeypatch.setattr(service.promotion_service, "execute", forbidden)
        if stage == "binding":
            values = binding.model_dump(mode="python", exclude={"binding_id"})
            values["finding_digest"] = "0" * 64
            changed = type(binding)(binding_id=canonical_digest(values), **values)
            conn = service.store.connection
            conn.execute(
                "UPDATE pilot_finding_promotions SET binding_json=?", (changed.model_dump_json(),)
            )
        elif stage == "pilot-ledger":
            conn = service.store.connection
            conn.execute("UPDATE pilot_finding_promotions SET approval_id='drifted'")
        elif stage == "m913":
            conn = service.pilot_intake_service.store.connection
            conn.execute("DELETE FROM pilot_finding_intakes")
        elif stage == "m86-ledger":
            conn = service.promotion_service.store.connection
            conn.execute("UPDATE finding_promotions SET idempotency_key='drifted'")
        else:
            outcome = service.promotion_service.store.load_completed(plan.execution_plan_id)
            finding = outcome.finding.model_copy(update={"impact": "tampered impact"})
            values = outcome.model_dump(mode="python", exclude={"outcome_id"})
            values.update(
                finding=finding.model_dump(mode="python"),
                finding_digest=canonical_digest(finding.model_dump(mode="python")),
            )
            changed = type(outcome)(outcome_id=canonical_digest(values), **values)
            conn = service.promotion_service.store.connection
            conn.execute(
                "UPDATE finding_promotions SET outcome_json=?", (changed.model_dump_json(),)
            )
        conn.commit()
        with pytest.raises((ValueError, RuntimeError)):
            service.execute(plan, **inputs, now=now + timedelta(seconds=20))


def test_pilot_promotion_rejects_superseded_duplicate(tmp_path, now, approved_scope, candidate):
    from vulnloom.findings import DuplicateCheckResult, FindingDuplicateCheck

    with _case(tmp_path, now, approved_scope, candidate) as (service, plan, inputs, _):
        proof = inputs["intake_inputs"]["duplicate_check"]
        values = proof.model_dump(mode="python", exclude={"check_id"})
        values.update(
            checked_at=now + timedelta(seconds=19),
            result=DuplicateCheckResult.DUPLICATE,
            duplicate_family_id=uuid4(),
        )
        # A newly recorded human decision supersedes the original CLEAR proof.
        newer = FindingDuplicateCheck.create(**values)
        service.promotion_service.intake_service.duplicate_check_store.publish(newer)
        with pytest.raises(PilotFindingPromotionRejected):
            service.execute(plan, **inputs, now=now + timedelta(seconds=20))
        _no_claim(service)
