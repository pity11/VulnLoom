from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from uuid import uuid4

import pytest

from vulnloom.broker import (
    BrokerCall,
    BrokerStatus,
    HttpRequestPlan,
    OfflineHttpHop,
    OfflineHttpTransport,
    StaticResolver,
    ToolBroker,
    default_tool_registry,
)
from vulnloom.cli import main
from vulnloom.domain.models import CandidateState, EvidenceKind, ValidationResult
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore
from vulnloom.hypotheses import CandidateSetStore
from vulnloom.hypotheses.models import CandidateSet, candidate_set_digest
from vulnloom.policy import PolicyEngine
from vulnloom.runners import (
    NetworkGrant,
    OfflineSandboxRunner,
    SandboxRunStatus,
    ToolInvocation,
    validation_profile,
)
from vulnloom.runners.models import SandboxRunRequest, sandbox_profile_digest
from vulnloom.validation import (
    DeterministicHttpJudge,
    HttpResponseAssertion,
    ValidationIdempotencyConflict,
    ValidationPlan,
    ValidationRecoveryRequired,
    ValidationRejected,
    ValidationService,
    ValidationStore,
    ValidationVerdict,
    candidate_content_digest,
)

IMAGE = "sha256:" + "1" * 64
SNAPSHOT = "2" * 64
EVIDENCE_TEXT = "authorized fixture evidence"
EVIDENCE = hashlib.sha256(EVIDENCE_TEXT.encode()).hexdigest()
BODY_SHA256 = hashlib.sha256(b"authorized fixture response").hexdigest()
IP = "192.0.2.10"
URL = "https://app.example.test/items?id=7"


class ReproducedJudge:
    def evaluate(self, *, evidence_refs, **_):
        return ValidationVerdict(
            result=ValidationResult.REPRODUCED,
            rationale_code="fixture_assertion_matched",
            evidence_refs=evidence_refs,
        )


class ForeignEvidenceJudge:
    def evaluate(self, **_):
        return ValidationVerdict(
            result=ValidationResult.REPRODUCED,
            rationale_code="untrusted_evidence",
            evidence_refs=("f" * 64,),
        )


class ControlResultJudge:
    def evaluate(self, **_):
        return ValidationVerdict(
            result=ValidationResult.POLICY_STOPPED,
            rationale_code="manufactured_policy_stop",
        )


class CountingRunner:
    def __init__(self, *, mismatch=False):
        self.delegate = OfflineSandboxRunner(frozenset({"sandbox.test"}))
        self.calls = 0
        self.mismatch = mismatch

    def execute(self, request, *, now):
        self.calls += 1
        result = self.delegate.execute(request, now=now)
        return result.model_copy(update={"task_id": uuid4()}) if self.mismatch else result


def _task(now, scope, candidate, profile, *, key, deadline=None):
    return TaskEnvelope(
        engagement_id=scope.engagement_id,
        target_id=candidate.target_id,
        target_version=candidate.target_version,
        scope_id=scope.scope_id,
        worker_role=WorkerRole.VALIDATOR,
        scope_version=scope.version,
        policy_digest=PolicyEngine(scope).policy_digest,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest=default_tool_registry().digest,
        input_refs=(f"candidate:{candidate_content_digest(candidate)}",),
        allowed_tools=profile.allowed_tools,
        budget=TaskBudget(wall_seconds=60, model_tokens=0, tool_calls=3),
        deadline=deadline or now + timedelta(minutes=1),
        idempotency_key=key,
    )


def _plan(
    now,
    scope,
    candidate,
    *,
    broker_url=URL,
    runner_deadline=None,
    expected_body_sha256=None,
    match_result=ValidationResult.REPRODUCED,
    key="validation:1",
):
    runner_profile = validation_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT)
    runner_task = _task(
        now,
        scope,
        candidate,
        runner_profile,
        key=f"{key}:runner-task",
        deadline=runner_deadline,
    )
    runner_request = SandboxRunRequest(
        task=runner_task,
        profile=runner_profile,
        invocation=ToolInvocation(
            tool_id="sandbox.test", arguments=("authorized-fixture",), working_directory="source"
        ),
        environment={"VULNLOOM_TASK_ID": str(runner_task.task_id)},
        idempotency_key=f"{key}:runner",
    )
    host = "outside.example" if "outside.example" in broker_url else "app.example.test"
    broker_profile = validation_profile(
        image_digest=IMAGE,
        snapshot_id=SNAPSHOT,
        network_grants=(
            NetworkGrant(host=host, ports=frozenset({443}), schemes=frozenset({"https"})),
        ),
    )
    broker_task = _task(
        now, scope, candidate, broker_profile, key=f"{key}:broker-task"
    ).model_copy(update={"allowed_tools": frozenset({"http.request"})})
    call = BrokerCall(
        task=broker_task,
        profile=broker_profile,
        tool_id="http.request",
        http=HttpRequestPlan(method="GET", url=broker_url, test_class="read_only"),
        idempotency_key=f"{key}:broker",
    )
    assertion = (
        HttpResponseAssertion.create(
            call_id=call.call_id,
            expected_status_code=200,
            expected_body_sha256=expected_body_sha256,
            match_result=match_result,
        )
        if expected_body_sha256 is not None
        else None
    )
    return ValidationPlan.create(
        candidate_id=candidate.candidate_id,
        candidate_digest=candidate_content_digest(candidate),
        target_id=candidate.target_id,
        target_version=candidate.target_version,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        selected_by="human-reviewer",
        selected_at=now,
        selection_reason="Cheapest authorized disproof requires one read-only fixture request",
        runner_request=runner_request,
        broker_calls=(call,),
        http_assertion=assertion,
        idempotency_key=key,
    )


def _broker(scope, *, url=URL, evidence_ref=EVIDENCE):
    host = "outside.example" if "outside.example" in url else "app.example.test"
    transport = OfflineHttpTransport(
        {
            url: OfflineHttpHop(
                status_code=200,
                peer_ip=IP,
                response_bytes=32,
                response_body_sha256=BODY_SHA256,
                evidence_ref=evidence_ref,
            )
        }
    )
    broker = ToolBroker(
        scope=scope,
        registry=default_tool_registry(),
        resolver=StaticResolver({host: (IP,)}),
        http_transport=transport,
    )
    return broker, transport


def _reseal(plan, **updates):
    values = {
        "candidate_id": plan.candidate_id,
        "candidate_digest": plan.candidate_digest,
        "target_id": plan.target_id,
        "target_version": plan.target_version,
        "scope_id": plan.scope_id,
        "scope_version": plan.scope_version,
        "selected_by": plan.selected_by,
        "selected_at": plan.selected_at,
        "selection_reason": plan.selection_reason,
        "runner_request": plan.runner_request,
        "broker_calls": plan.broker_calls,
        "http_assertion": plan.http_assertion,
        "idempotency_key": plan.idempotency_key,
    }
    values.update(updates)
    return ValidationPlan.create(**values)


def _service(tmp_path, scope, broker, *, judge=None):
    store = ValidationStore(tmp_path / "validation.db")
    evidence_store = _evidence_store(tmp_path)
    service = ValidationService(
        scope=scope,
        runner=OfflineSandboxRunner(frozenset({"sandbox.test"})),
        broker=broker,
        store=store,
        evidence_store=evidence_store,
        judge=judge,
    )
    return service, store


def _offline_deterministic_judge():
    return DeterministicHttpJudge(trusted_registry_digest=default_tool_registry().digest)


def _evidence_store(tmp_path):
    evidence_store = EvidenceStore(tmp_path / "evidence")
    evidence = evidence_store.capture_text(
        EVIDENCE_TEXT,
        kind=EvidenceKind.TEST,
        source_ref="authorized-fixture",
        producer="test.validation",
        target_version="fixture-v1",
        summary="Authorized deterministic fixture Evidence",
    )
    assert evidence.evidence_id == EVIDENCE
    return evidence_store


def test_default_judge_seals_evidence_but_does_not_claim_reproduction(
    tmp_path, approved_scope, candidate, now
):
    plan = _plan(now, approved_scope, candidate)
    broker, transport = _broker(approved_scope)
    service, store = _service(tmp_path, approved_scope, broker)
    try:
        first = service.execute(candidate, plan, now=now)
        repeated = service.execute(candidate, plan, now=now + timedelta(seconds=1))
    finally:
        store.close()

    assert first == repeated
    assert len(transport.calls) == 1
    assert first.runner_result.status is SandboxRunStatus.COMPLETED
    assert first.broker_results[0].status is BrokerStatus.COMPLETED
    assert first.validation_run.result is ValidationResult.INCONCLUSIVE
    assert first.candidate.state is CandidateState.INCONCLUSIVE
    assert first.evidence_bundle is not None
    assert first.evidence_bundle.evidence_refs == (EVIDENCE,)
    assert first.validation_run.side_effects == ()


def test_only_trusted_judge_with_collected_evidence_can_validate(
    tmp_path, approved_scope, candidate, now
):
    plan = _plan(now, approved_scope, candidate)
    broker, _ = _broker(approved_scope)
    service, store = _service(tmp_path, approved_scope, broker, judge=ReproducedJudge())
    try:
        outcome = service.execute(candidate, plan, now=now)
    finally:
        store.close()
    assert outcome.validation_run.result is ValidationResult.REPRODUCED
    assert outcome.candidate.state is CandidateState.VALIDATED
    assert outcome.verdict.evidence_refs == (EVIDENCE,)


def test_deterministic_http_assertion_can_reproduce_exact_fixture(
    tmp_path, approved_scope, candidate, now
):
    plan = _plan(
        now,
        approved_scope,
        candidate,
        expected_body_sha256=BODY_SHA256,
    )
    broker, _ = _broker(approved_scope)
    service, store = _service(
        tmp_path,
        approved_scope,
        broker,
        judge=_offline_deterministic_judge(),
    )
    try:
        outcome = service.execute(candidate, plan, now=now)
    finally:
        store.close()
    assert outcome.validation_run.result is ValidationResult.REPRODUCED
    assert outcome.candidate.state is CandidateState.VALIDATED
    assert outcome.verdict.rationale_code == "http_response_assertion_matched"
    assert outcome.broker_results[0].http.response_body_sha256 == BODY_SHA256


def test_deterministic_http_assertion_mismatch_is_inconclusive(
    tmp_path, approved_scope, candidate, now
):
    plan = _plan(
        now,
        approved_scope,
        candidate,
        expected_body_sha256="f" * 64,
    )
    broker, _ = _broker(approved_scope)
    service, store = _service(
        tmp_path,
        approved_scope,
        broker,
        judge=_offline_deterministic_judge(),
    )
    try:
        outcome = service.execute(candidate, plan, now=now)
    finally:
        store.close()
    assert outcome.validation_run.result is ValidationResult.INCONCLUSIVE
    assert outcome.candidate.state is CandidateState.INCONCLUSIVE
    assert outcome.verdict.rationale_code == "http_response_assertion_mismatched"


def test_deterministic_judge_rejects_offline_registry_by_default(
    tmp_path, approved_scope, candidate, now
):
    plan = _plan(
        now,
        approved_scope,
        candidate,
        expected_body_sha256=BODY_SHA256,
    )
    broker, _ = _broker(approved_scope)
    service, store = _service(
        tmp_path,
        approved_scope,
        broker,
        judge=DeterministicHttpJudge(),
    )
    try:
        outcome = service.execute(candidate, plan, now=now)
    finally:
        store.close()
    assert outcome.validation_run.result is ValidationResult.INCONCLUSIVE
    assert outcome.verdict.rationale_code == "http_assertion_untrusted_registry"


def test_exact_secure_fixture_assertion_can_record_not_reproduced(
    tmp_path, approved_scope, candidate, now
):
    plan = _plan(
        now,
        approved_scope,
        candidate,
        expected_body_sha256=BODY_SHA256,
        match_result=ValidationResult.NOT_REPRODUCED,
    )
    broker, _ = _broker(approved_scope)
    service, store = _service(
        tmp_path,
        approved_scope,
        broker,
        judge=_offline_deterministic_judge(),
    )
    try:
        outcome = service.execute(candidate, plan, now=now)
    finally:
        store.close()
    assert outcome.validation_run.result is ValidationResult.NOT_REPRODUCED
    assert outcome.candidate.state is CandidateState.INCONCLUSIVE


def test_http_assertion_cannot_reference_a_call_outside_plan(
    approved_scope, candidate, now
):
    plan = _plan(now, approved_scope, candidate)
    assertion = HttpResponseAssertion.create(
        call_id=uuid4(),
        expected_status_code=200,
        expected_body_sha256=BODY_SHA256,
        match_result=ValidationResult.REPRODUCED,
    )
    with pytest.raises(ValueError, match="outside the ValidationPlan"):
        _reseal(plan, http_assertion=assertion)


def test_foreign_judge_evidence_is_rejected_fail_closed(
    tmp_path, approved_scope, candidate, now
):
    plan = _plan(now, approved_scope, candidate)
    broker, _ = _broker(approved_scope)
    service, store = _service(tmp_path, approved_scope, broker, judge=ForeignEvidenceJudge())
    try:
        with pytest.raises(ValidationRejected, match="not produced"):
            service.execute(candidate, plan, now=now)
    finally:
        store.close()


def test_unavailable_broker_evidence_is_rejected_before_judging(
    tmp_path, approved_scope, candidate, now
):
    plan = _plan(
        now,
        approved_scope,
        candidate,
        expected_body_sha256=BODY_SHA256,
    )
    broker, _ = _broker(approved_scope, evidence_ref="f" * 64)
    service, store = _service(
        tmp_path,
        approved_scope,
        broker,
        judge=_offline_deterministic_judge(),
    )
    try:
        with pytest.raises(ValidationRejected, match="unavailable or corrupt Evidence"):
            service.execute(candidate, plan, now=now)
    finally:
        store.close()


def test_scope_denial_becomes_policy_stopped_and_never_validated(
    tmp_path, approved_scope, candidate, now
):
    url = "https://outside.example/items"
    plan = _plan(now, approved_scope, candidate, broker_url=url)
    broker, transport = _broker(approved_scope, url=url)
    service, store = _service(tmp_path, approved_scope, broker, judge=ReproducedJudge())
    try:
        outcome = service.execute(candidate, plan, now=now)
    finally:
        store.close()
    assert outcome.validation_run.result is ValidationResult.POLICY_STOPPED
    assert outcome.candidate.state is CandidateState.INCONCLUSIVE
    assert outcome.broker_results[0].status is BrokerStatus.DENIED
    assert transport.calls == []


def test_runner_timeout_stops_before_broker_and_persists_terminal_outcome(
    tmp_path, approved_scope, candidate, now
):
    plan = _plan(now, approved_scope, candidate, runner_deadline=now)
    broker, transport = _broker(approved_scope)
    service, store = _service(tmp_path, approved_scope, broker)
    try:
        outcome = service.execute(candidate, plan, now=now)
    finally:
        store.close()
    assert outcome.runner_result.status is SandboxRunStatus.TIMED_OUT
    assert outcome.validation_run.result is ValidationResult.TIMED_OUT
    assert outcome.runner_result.cleanup.complete
    assert outcome.broker_results == ()
    assert transport.calls == []


def test_preflight_rejects_candidate_provenance_before_checkpoint(
    tmp_path, approved_scope, candidate, now
):
    plan = _plan(now, approved_scope, candidate)
    changed = candidate.model_copy(update={"target_version": "f" * 40})
    broker, _ = _broker(approved_scope)
    service, store = _service(tmp_path, approved_scope, broker)
    try:
        with pytest.raises(ValidationRejected, match="provenance"):
            service.execute(changed, plan, now=now)
    finally:
        store.close()


def test_candidate_content_change_with_same_uuid_is_rejected(
    tmp_path, approved_scope, candidate, now
):
    plan = _plan(now, approved_scope, candidate)
    changed = candidate.model_copy(update={"hypothesis": "Different unreviewed hypothesis"})
    broker, _ = _broker(approved_scope)
    service, store = _service(tmp_path, approved_scope, broker)
    try:
        with pytest.raises(ValidationRejected, match="provenance"):
            service.execute(changed, plan, now=now)
    finally:
        store.close()


def test_started_checkpoint_refuses_automatic_replay(tmp_path, approved_scope, candidate, now):
    plan = _plan(now, approved_scope, candidate)
    broker, transport = _broker(approved_scope)
    service, store = _service(tmp_path, approved_scope, broker)
    try:
        store.claim(plan, now=now)
        with pytest.raises(ValidationRecoveryRequired, match="automatic replay"):
            service.execute(candidate, plan, now=now)
    finally:
        store.close()
    assert transport.calls == []


def test_idempotency_key_cannot_name_different_plan(tmp_path, approved_scope, candidate, now):
    first = _plan(now, approved_scope, candidate)
    second = _plan(
        now,
        approved_scope,
        candidate,
        broker_url="https://app.example.test/other",
    )
    store = ValidationStore(tmp_path / "validation.db")
    try:
        store.claim(first, now=now)
        with pytest.raises(ValidationIdempotencyConflict):
            store.claim(second, now=now)
    finally:
        store.close()


def test_broker_static_mismatch_is_rejected_before_runner_or_checkpoint(
    tmp_path, approved_scope, candidate, now
):
    original = _plan(now, approved_scope, candidate)
    call = original.broker_calls[0]
    bad_task = call.task.model_copy(update={"tool_registry_digest": "f" * 64})
    plan = _reseal(original, broker_calls=(call.model_copy(update={"task": bad_task}),))
    broker, _ = _broker(approved_scope)
    runner = CountingRunner()
    store = ValidationStore(tmp_path / "validation.db")
    service = ValidationService(
        scope=approved_scope,
        runner=runner,
        broker=broker,
        store=store,
        evidence_store=_evidence_store(tmp_path),
    )
    try:
        with pytest.raises(ValidationRejected, match="Broker call failed static preflight"):
            service.execute(candidate, plan, now=now)
    finally:
        store.close()
    assert runner.calls == 0


def test_runner_result_binding_mismatch_fails_closed(tmp_path, approved_scope, candidate, now):
    plan = _plan(now, approved_scope, candidate)
    broker, transport = _broker(approved_scope)
    store = ValidationStore(tmp_path / "validation.db")
    service = ValidationService(
        scope=approved_scope,
        runner=CountingRunner(mismatch=True),
        broker=broker,
        store=store,
        evidence_store=_evidence_store(tmp_path),
    )
    try:
        with pytest.raises(ValidationRejected, match="Runner result does not match"):
            service.execute(candidate, plan, now=now)
    finally:
        store.close()
    assert transport.calls == []


def test_task_deadline_cannot_outlive_scope(tmp_path, approved_scope, candidate, now):
    original = _plan(now, approved_scope, candidate)
    request = original.runner_request
    task = request.task.model_copy(
        update={"deadline": approved_scope.valid_until + timedelta(seconds=1)}
    )
    plan = _reseal(original, runner_request=request.model_copy(update={"task": task}))
    broker, _ = _broker(approved_scope)
    service, store = _service(tmp_path, approved_scope, broker)
    try:
        with pytest.raises(ValidationRejected, match="policy binding mismatch"):
            service.execute(candidate, plan, now=now)
    finally:
        store.close()


def test_judge_cannot_manufacture_policy_control_result(
    tmp_path, approved_scope, candidate, now
):
    plan = _plan(now, approved_scope, candidate)
    broker, _ = _broker(approved_scope)
    service, store = _service(tmp_path, approved_scope, broker, judge=ControlResultJudge())
    try:
        with pytest.raises(ValidationRejected, match="cannot manufacture"):
            service.execute(candidate, plan, now=now)
    finally:
        store.close()


def test_cli_runs_only_networkless_offline_orchestration(
    tmp_path, capsys, approved_scope, candidate, now
):
    partial = CandidateSet(
        candidate_set_id="0" * 64,
        source_graph_id=candidate.source_graph_id,
        target_id=candidate.target_id,
        target_version=candidate.target_version,
        scope_id=candidate.scope_id,
        scope_version=candidate.scope_version,
        generator_version="test",
        candidates=(candidate,),
    )
    candidate_set = partial.model_copy(
        update={"candidate_set_id": candidate_set_digest(partial)}
    )
    candidate_store = tmp_path / "candidates"
    CandidateSetStore(candidate_store).put(candidate_set)
    runner_profile = validation_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT)
    task = _task(now, approved_scope, candidate, runner_profile, key="cli:runner-task")
    request = SandboxRunRequest(
        task=task,
        profile=runner_profile,
        invocation=ToolInvocation(tool_id="sandbox.test", working_directory="source"),
        environment={},
        idempotency_key="cli:runner",
    )
    plan = ValidationPlan.create(
        candidate_id=candidate.candidate_id,
        candidate_digest=candidate_content_digest(candidate),
        target_id=candidate.target_id,
        target_version=candidate.target_version,
        scope_id=candidate.scope_id,
        scope_version=candidate.scope_version,
        selected_by="reviewer",
        selected_at=now,
        selection_reason="Offline control-plane smoke test",
        runner_request=request,
        idempotency_key="cli:validation",
    )
    scope_file = tmp_path / "scope.json"
    plan_file = tmp_path / "plan.json"
    scope_file.write_text(approved_scope.model_dump_json(), encoding="utf-8")
    plan_file.write_text(plan.model_dump_json(), encoding="utf-8")
    args = [
        "--db",
        str(tmp_path / "events.db"),
        "validation-run-offline",
        "--scope-file",
        str(scope_file),
        "--candidate-store",
        str(candidate_store),
        "--candidate-set-id",
        candidate_set.candidate_set_id,
        "--candidate-id",
        str(candidate.candidate_id),
        "--plan-file",
        str(plan_file),
        "--validation-db",
        str(tmp_path / "validation.db"),
        "--evidence-store",
        str(tmp_path / "evidence"),
    ]

    assert main(args) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["event_created"] is True
    assert first["validation"]["mode"] == "offline_orchestration_only"
    assert first["validation"]["result"] == "inconclusive"

    assert main(args) == 0
    repeated = json.loads(capsys.readouterr().out)
    assert repeated["event_created"] is False
    assert repeated["validation"] == first["validation"]
