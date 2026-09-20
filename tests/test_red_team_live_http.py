from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from vulnloom.broker import (
    EvidenceStoreHttpSink,
    OfflineHttpHop,
    PinnedHttpTransport,
    ToolBroker,
    pinned_http_tool_registry,
)
from vulnloom.broker.implementation import PINNED_HTTP_IMPLEMENTATION_DIGEST
from vulnloom.broker.models import url_digest
from vulnloom.domain.models import EvidenceKind, NetworkTargetScope, Scope, ScopeState
from vulnloom.evidence import EvidenceStore
from vulnloom.red_team import (
    EndpointReconLimits,
    EndpointReconOutcomeKind,
    EndpointReconRejected,
    EndpointReconReservationState,
    EndpointReconService,
    EndpointReconStore,
    IsolatedLocalHttpReconAdapter,
    IsolatedLocalReconAdmission,
    ReconOutcome,
    RedTeamActionKind,
    RedTeamAdapterInterrupted,
    RedTeamFlowStatus,
    RedTeamReconObservation,
    RedTeamRejected,
    RedTeamService,
    RedTeamStore,
)
from vulnloom.runners import NetworkGrant, validation_profile
from vulnloom.workflows import Visibility

HOST = "fixture.internal.test"
IP = "10.23.45.67"
IMAGE = "sha256:" + "1" * 64
EVIDENCE_TEXT = "redacted local fixture evidence"
EVIDENCE = hashlib.sha256(EVIDENCE_TEXT.encode()).hexdigest()
BODY = "3" * 64


class _PinnedResolver:
    implementation_digest = PINNED_HTTP_IMPLEMENTATION_DIGEST

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = 0

    def resolve(self, host):
        answer = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        return answer if host == HOST else ()


class _PinnedTransport:
    implementation_digest = PINNED_HTTP_IMPLEMENTATION_DIGEST

    def __init__(self, hops):
        self.hops = list(hops)
        self.calls = []

    def send(self, request):
        self.calls.append(request)
        hop = self.hops[len(self.calls) - 1]
        if isinstance(hop, BaseException):
            raise hop
        return hop


def _scope(now, port=8080):
    return Scope(
        engagement_id=uuid4(),
        authority_reference="isolated-local-red-team-fixture",
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(minutes=10),
        network_targets=(
            NetworkTargetScope(
                host=HOST,
                ports=frozenset({port}),
                schemes=frozenset({"http"}),
            ),
        ),
        allowed_test_classes=frozenset({"read_only"}),
        state=ScopeState.APPROVED,
        approved_by="integration-owner",
        approved_at=now,
    )


def _runtime(tmp_path, now, *, port=8080, resolver=None, transport=None):
    scope = _scope(now, port)
    store = RedTeamStore(tmp_path / "red-team.sqlite3")
    service = RedTeamService(store=store)
    plan = service.prepare(
        scope=scope,
        target_url=f"http://{HOST}:{port}/",
        visibility=Visibility.BLACK_BOX,
        allowed_test_classes=("read_only",),
        max_actions=2,
        max_consecutive_failures=2,
        emergency_contact_ref="contact:fixture-owner",
        now=now,
        deadline=now + timedelta(minutes=2),
        idempotency_key=f"red-team:local:{port}",
    )
    checkpoint = service.create_and_start(plan, scope=scope, now=now)
    command = service.prepare_recon(
        plan=plan,
        checkpoint=checkpoint,
        scope=scope,
        kind=RedTeamActionKind.HTTP_HEAD,
        test_class="read_only",
        now=now,
        ttl_seconds=30,
        idempotency_key=f"red-team:local-head:{port}",
    )
    profile = validation_profile(
        image_digest=IMAGE,
        snapshot_id=plan.plan_id,
        network_grants=(
            NetworkGrant(
                host=HOST,
                ports=frozenset({port}),
                schemes=frozenset({"http"}),
            ),
        ),
    )
    admission = IsolatedLocalReconAdmission.create(
        fixture_ref="fixture:red-team-head-v1",
        host=HOST,
        port=port,
        scheme="http",
        allowed_peer_ips=(IP,),
        expires_at=now + timedelta(minutes=2),
    )
    broker = ToolBroker(
        scope=scope,
        registry=pinned_http_tool_registry(),
        resolver=resolver or _PinnedResolver(((IP,),)),
        http_transport=transport
        or _PinnedTransport(
            (
                OfflineHttpHop(
                    status_code=204,
                    peer_ip=IP,
                    response_bytes=0,
                    response_body_sha256=BODY,
                    evidence_ref=EVIDENCE,
                ),
            )
        ),
        allowed_resolved_ips=frozenset({IP}),
    )
    evidence_store = EvidenceStore(tmp_path / "evidence")
    evidence = evidence_store.capture_text(
        EVIDENCE_TEXT,
        kind=EvidenceKind.HTTP,
        source_ref="url-sha256:" + "4" * 64,
        producer="test.red-team.pinned",
        target_version=plan.plan_id,
        summary="redacted fixture response",
    )
    assert evidence.evidence_id == EVIDENCE
    adapter = IsolatedLocalHttpReconAdapter(
        plan=plan,
        broker=broker,
        profile=profile,
        admission=admission,
        evidence_store=evidence_store,
    )
    return scope, store, service, plan, checkpoint, command, adapter


def test_live_recon_adapter_routes_head_and_persists_redacted_attack_surface(tmp_path, now):
    scope, store, service, plan, checkpoint, command, adapter = _runtime(tmp_path, now)
    advanced, observation = service.execute_recon(
        command=command, scope=scope, adapter=adapter, now=now
    )

    assert advanced.status is RedTeamFlowStatus.RUNNING
    assert observation.outcome is ReconOutcome.SUCCEEDED
    assert observation.attack_surface is not None
    assert observation.attack_surface.evidence_refs == (EVIDENCE,)
    assert observation.attack_surface.requested_url_digest not in plan.target.url
    assert store.observation(observation.observation_id) == observation
    persisted = (tmp_path / "red-team.sqlite3").read_text(errors="ignore")
    assert plan.target.url not in observation.model_dump_json()
    assert "authorization" not in persisted.lower()
    assert adapter.calls == 1

    replayed, replay = service.execute_recon(
        command=command, scope=scope, adapter=adapter, now=now + timedelta(seconds=1)
    )
    assert replayed == advanced
    assert replay == observation
    assert adapter.calls == 1
    store.close()


def test_exact_endpoint_plan_consumes_flow_ledger_through_zero_redirect_broker(tmp_path, now):
    hop = OfflineHttpHop(
        status_code=204,
        peer_ip=IP,
        response_bytes=0,
        response_body_sha256=BODY,
        evidence_ref=EVIDENCE,
    )
    scope, store, _, flow, checkpoint, _, base_adapter = _runtime(
        tmp_path, now, transport=_PinnedTransport((hop, hop))
    )
    recon_store = EndpointReconStore(tmp_path / "endpoint-recon.sqlite3")
    endpoint_service = EndpointReconService(
        red_team_store=store,
        recon_store=recon_store,
        evidence_store=base_adapter.evidence_store,
    )
    seed_set = endpoint_service.seal_seed_set(
        flow_plan=flow,
        checkpoint=checkpoint,
        scope=scope,
        operator_ref="operator:fixture-owner",
        paths=("/health", "/ready"),
        now=now,
        expires_at=now + timedelta(minutes=1),
        idempotency_key="endpoint-live:set",
    )
    endpoint_plan = endpoint_service.prepare(
        seed_set_id=seed_set.seed_set_id,
        scope=scope,
        test_class="read_only",
        limits=EndpointReconLimits(
            max_steps=2,
            max_requests=2,
            per_request_seconds=2,
            total_seconds=10,
        ),
        now=now,
        deadline=now + timedelta(seconds=10),
        idempotency_key="endpoint-live:plan",
    )
    adapter = IsolatedLocalHttpReconAdapter(
        plan=flow,
        broker=base_adapter.broker,
        profile=base_adapter.profile,
        admission=base_adapter.admission,
        evidence_store=base_adapter.evidence_store,
        max_redirects=0,
        allowed_url_digests=tuple(sorted(step.target_url_digest for step in endpoint_plan.steps)),
    )
    outcome = endpoint_service.execute_via_flow(
        endpoint_plan,
        scope=scope,
        adapter=adapter,
        now=now,
    )

    assert outcome.outcome is EndpointReconOutcomeKind.SUCCEEDED
    assert {item.target_url_digest for item in outcome.results} == {
        url_digest(f"http://{HOST}:8080/health"),
        url_digest(f"http://{HOST}:8080/ready"),
    }
    assert store.latest(flow.plan_id).actions_used == 2
    observation = store.observation(store.latest(flow.plan_id).observation_ids[-1])
    assert observation.attack_surface is not None
    assert observation.attack_surface.redirect_count == 0
    assert (
        recon_store.reservation(endpoint_plan.endpoint_recon_plan_id).state
        is EndpointReconReservationState.CONSUMED
    )
    replay_adapter = IsolatedLocalHttpReconAdapter(
        plan=flow,
        broker=base_adapter.broker,
        profile=base_adapter.profile,
        admission=base_adapter.admission,
        evidence_store=base_adapter.evidence_store,
        max_redirects=0,
        allowed_url_digests=tuple(sorted(step.target_url_digest for step in endpoint_plan.steps)),
    )
    assert (
        endpoint_service.execute_via_flow(
            endpoint_plan,
            scope=scope,
            adapter=replay_adapter,
            now=now,
        )
        == outcome
    )
    assert replay_adapter.calls == 0
    recon_store.close()
    store.close()


def test_exact_url_allowlist_rejects_unsealed_action_before_broker(tmp_path, now):
    scope, store, service, flow, _, command, base_adapter = _runtime(tmp_path, now)
    allowed = url_digest(f"http://{HOST}:8080/health")
    adapter = IsolatedLocalHttpReconAdapter(
        plan=flow,
        broker=base_adapter.broker,
        profile=base_adapter.profile,
        admission=base_adapter.admission,
        evidence_store=base_adapter.evidence_store,
        max_redirects=0,
        allowed_url_digests=(allowed,),
    )
    _, observation = service.execute_recon(command=command, scope=scope, adapter=adapter, now=now)
    assert observation.outcome is ReconOutcome.REJECTED
    assert observation.reason_code == "local_action_not_admitted"
    assert adapter.broker.http_transport.calls == []
    store.close()


def test_exact_url_allowlist_rejects_empty_or_redirecting_configuration(tmp_path, now):
    _, store, _, flow, _, _, base_adapter = _runtime(tmp_path, now)
    common = {
        "plan": flow,
        "broker": base_adapter.broker,
        "profile": base_adapter.profile,
        "admission": base_adapter.admission,
        "evidence_store": base_adapter.evidence_store,
    }
    with pytest.raises(RedTeamRejected, match="allowlist is invalid"):
        IsolatedLocalHttpReconAdapter(
            **common,
            max_redirects=0,
            allowed_url_digests=(),
        )
    with pytest.raises(RedTeamRejected, match="allowlist is invalid"):
        IsolatedLocalHttpReconAdapter(
            **common,
            max_redirects=1,
            allowed_url_digests=(url_digest(f"http://{HOST}:8080/health"),),
        )
    store.close()


def test_endpoint_flow_execution_recovers_interrupted_exact_action(tmp_path, now):
    scope, store, _, flow, checkpoint, _, base_adapter = _runtime(tmp_path, now)
    recon_store = EndpointReconStore(tmp_path / "endpoint-recon.sqlite3")
    endpoint_service = EndpointReconService(
        red_team_store=store,
        recon_store=recon_store,
        evidence_store=base_adapter.evidence_store,
    )
    seed_set = endpoint_service.seal_seed_set(
        flow_plan=flow,
        checkpoint=checkpoint,
        scope=scope,
        operator_ref="operator:fixture-owner",
        paths=("/health",),
        now=now,
        expires_at=now + timedelta(minutes=1),
        idempotency_key="endpoint-recovery:set",
    )
    endpoint_plan = endpoint_service.prepare(
        seed_set_id=seed_set.seed_set_id,
        scope=scope,
        test_class="read_only",
        limits=EndpointReconLimits(max_steps=1, max_requests=1),
        now=now,
        deadline=now + timedelta(seconds=30),
        idempotency_key="endpoint-recovery:plan",
    )
    step = endpoint_plan.steps[0]
    exact_adapter = IsolatedLocalHttpReconAdapter(
        plan=flow,
        broker=base_adapter.broker,
        profile=base_adapter.profile,
        admission=base_adapter.admission,
        evidence_store=base_adapter.evidence_store,
        max_redirects=0,
        allowed_url_digests=(step.target_url_digest,),
    )

    class InterruptOnce:
        def __init__(self):
            self.calls = 0

        def execute(self, action, *, now):
            self.calls += 1
            if self.calls == 1:
                raise RedTeamAdapterInterrupted("synthetic interruption")
            return exact_adapter.execute(action, now=now)

    adapter = InterruptOnce()
    with pytest.raises(RedTeamAdapterInterrupted):
        endpoint_service.execute_via_flow(endpoint_plan, scope=scope, adapter=adapter, now=now)
    assert store.latest(flow.plan_id).actions_used == 0
    assert (
        recon_store.reservation(endpoint_plan.endpoint_recon_plan_id).state
        is EndpointReconReservationState.ACTIVE
    )
    outcome = endpoint_service.recover_via_flow(
        endpoint_plan,
        scope=scope,
        adapter=adapter,
        now=now + timedelta(seconds=1),
    )
    assert outcome.outcome is EndpointReconOutcomeKind.SUCCEEDED
    assert outcome.attempt == 2
    assert store.latest(flow.plan_id).actions_used == 1
    assert exact_adapter.calls == 1
    recon_store.close()
    store.close()


def test_partial_endpoint_plan_holds_flow_budget_across_checkpoints(tmp_path, now):
    scope, store, _, flow, checkpoint, _, base_adapter = _runtime(tmp_path, now)
    recon_store = EndpointReconStore(tmp_path / "endpoint-recon.sqlite3")
    endpoint_service = EndpointReconService(
        red_team_store=store,
        recon_store=recon_store,
        evidence_store=base_adapter.evidence_store,
    )
    seed_set = endpoint_service.seal_seed_set(
        flow_plan=flow,
        checkpoint=checkpoint,
        scope=scope,
        operator_ref="operator:fixture-owner",
        paths=("/health", "/ready"),
        now=now,
        expires_at=now + timedelta(minutes=1),
        idempotency_key="endpoint-held-budget:set",
    )
    endpoint_plan = endpoint_service.prepare(
        seed_set_id=seed_set.seed_set_id,
        scope=scope,
        test_class="read_only",
        limits=EndpointReconLimits(max_steps=2, max_requests=2),
        now=now,
        deadline=now + timedelta(seconds=30),
        idempotency_key="endpoint-held-budget:plan",
    )
    exact_adapter = IsolatedLocalHttpReconAdapter(
        plan=flow,
        broker=base_adapter.broker,
        profile=base_adapter.profile,
        admission=base_adapter.admission,
        evidence_store=base_adapter.evidence_store,
        max_redirects=0,
        allowed_url_digests=tuple(
            sorted(step.target_url_digest for step in endpoint_plan.steps)
        ),
    )

    class InterruptSecond:
        def __init__(self):
            self.calls = 0

        def execute(self, action, *, now):
            self.calls += 1
            if self.calls == 2:
                raise RedTeamAdapterInterrupted("synthetic second-step interruption")
            return exact_adapter.execute(action, now=now)

    with pytest.raises(RedTeamAdapterInterrupted):
        endpoint_service.execute_via_flow(
            endpoint_plan,
            scope=scope,
            adapter=InterruptSecond(),
            now=now,
        )
    assert store.latest(flow.plan_id).actions_used == 1
    reservation = recon_store.reservation(endpoint_plan.endpoint_recon_plan_id)
    assert reservation.state is EndpointReconReservationState.ACTIVE
    assert reservation.consumed_requests == 1

    next_seed_set = endpoint_service.seal_seed_set(
        flow_plan=flow,
        checkpoint=store.latest(flow.plan_id),
        scope=scope,
        operator_ref="operator:fixture-owner",
        paths=("/third",),
        now=now,
        expires_at=now + timedelta(minutes=1),
        idempotency_key="endpoint-held-budget:next-set",
    )
    with pytest.raises(EndpointReconRejected, match="reservations exceed"):
        endpoint_service.prepare(
            seed_set_id=next_seed_set.seed_set_id,
            scope=scope,
            test_class="read_only",
            limits=EndpointReconLimits(max_steps=1, max_requests=1),
            now=now,
            deadline=now + timedelta(seconds=30),
            idempotency_key="endpoint-held-budget:next-plan",
        )
    with pytest.raises(EndpointReconRejected, match="requires recovery"):
        endpoint_service.cancel_reservation(
            endpoint_plan.endpoint_recon_plan_id,
            operator_ref="operator:fixture-owner",
            now=now,
        )
    recon_store.close()
    store.close()


def test_endpoint_flow_rejects_intervening_action_without_dispatch(tmp_path, now):
    scope, store, service, flow, checkpoint, command, base_adapter = _runtime(tmp_path, now)
    recon_store = EndpointReconStore(tmp_path / "endpoint-recon.sqlite3")
    endpoint_service = EndpointReconService(
        red_team_store=store,
        recon_store=recon_store,
        evidence_store=base_adapter.evidence_store,
    )
    seed_set = endpoint_service.seal_seed_set(
        flow_plan=flow,
        checkpoint=checkpoint,
        scope=scope,
        operator_ref="operator:fixture-owner",
        paths=("/health",),
        now=now,
        expires_at=now + timedelta(minutes=1),
        idempotency_key="endpoint-intervening:set",
    )
    endpoint_plan = endpoint_service.prepare(
        seed_set_id=seed_set.seed_set_id,
        scope=scope,
        test_class="read_only",
        limits=EndpointReconLimits(max_steps=1, max_requests=1),
        now=now,
        deadline=now + timedelta(seconds=30),
        idempotency_key="endpoint-intervening:plan",
    )
    service.execute_recon(command=command, scope=scope, adapter=base_adapter, now=now)
    step = endpoint_plan.steps[0]
    exact_adapter = IsolatedLocalHttpReconAdapter(
        plan=flow,
        broker=base_adapter.broker,
        profile=base_adapter.profile,
        admission=base_adapter.admission,
        evidence_store=base_adapter.evidence_store,
        max_redirects=0,
        allowed_url_digests=(step.target_url_digest,),
    )
    with pytest.raises(EndpointReconRejected, match="binding is invalid"):
        endpoint_service.execute_via_flow(
            endpoint_plan, scope=scope, adapter=exact_adapter, now=now
        )
    assert exact_adapter.calls == 0
    assert recon_store.state(endpoint_plan.endpoint_recon_plan_id) is None
    recon_store.close()
    store.close()


def test_endpoint_flow_timeout_consumes_once_and_closes_cleanly(tmp_path, now):
    transport = _PinnedTransport((TimeoutError("synthetic timeout"),))
    scope, store, _, flow, checkpoint, _, base_adapter = _runtime(
        tmp_path, now, transport=transport
    )
    recon_store = EndpointReconStore(tmp_path / "endpoint-recon.sqlite3")
    endpoint_service = EndpointReconService(
        red_team_store=store,
        recon_store=recon_store,
        evidence_store=base_adapter.evidence_store,
    )
    seed_set = endpoint_service.seal_seed_set(
        flow_plan=flow,
        checkpoint=checkpoint,
        scope=scope,
        operator_ref="operator:fixture-owner",
        paths=("/health",),
        now=now,
        expires_at=now + timedelta(minutes=1),
        idempotency_key="endpoint-timeout:set",
    )
    endpoint_plan = endpoint_service.prepare(
        seed_set_id=seed_set.seed_set_id,
        scope=scope,
        test_class="read_only",
        limits=EndpointReconLimits(max_steps=1, max_requests=1),
        now=now,
        deadline=now + timedelta(seconds=30),
        idempotency_key="endpoint-timeout:plan",
    )
    adapter = IsolatedLocalHttpReconAdapter(
        plan=flow,
        broker=base_adapter.broker,
        profile=base_adapter.profile,
        admission=base_adapter.admission,
        evidence_store=base_adapter.evidence_store,
        max_redirects=0,
        allowed_url_digests=(endpoint_plan.steps[0].target_url_digest,),
    )
    outcome = endpoint_service.execute_via_flow(
        endpoint_plan, scope=scope, adapter=adapter, now=now
    )
    assert outcome.outcome is EndpointReconOutcomeKind.TIMED_OUT
    assert outcome.cleanup_complete
    assert store.latest(flow.plan_id).actions_used == 1
    assert store.latest(flow.plan_id).status is RedTeamFlowStatus.TIMED_OUT
    assert (
        recon_store.reservation(endpoint_plan.endpoint_recon_plan_id).state
        is EndpointReconReservationState.CONSUMED
    )
    recon_store.close()
    store.close()


def test_endpoint_flow_closes_invalid_success_as_failed_and_replays(tmp_path, now):
    scope, store, _, flow, checkpoint, _, base_adapter = _runtime(tmp_path, now)
    recon_store = EndpointReconStore(tmp_path / "endpoint-recon.sqlite3")
    endpoint_service = EndpointReconService(
        red_team_store=store,
        recon_store=recon_store,
        evidence_store=base_adapter.evidence_store,
    )
    seed_set = endpoint_service.seal_seed_set(
        flow_plan=flow,
        checkpoint=checkpoint,
        scope=scope,
        operator_ref="operator:fixture-owner",
        paths=("/health",),
        now=now,
        expires_at=now + timedelta(minutes=1),
        idempotency_key="endpoint-invalid-success:set",
    )
    endpoint_plan = endpoint_service.prepare(
        seed_set_id=seed_set.seed_set_id,
        scope=scope,
        test_class="read_only",
        limits=EndpointReconLimits(max_steps=1, max_requests=1),
        now=now,
        deadline=now + timedelta(seconds=30),
        idempotency_key="endpoint-invalid-success:plan",
    )

    class MissingSnapshotAdapter:
        def __init__(self):
            self.calls = 0

        def execute(self, action, *, now):
            self.calls += 1
            return RedTeamReconObservation.create(
                action_id=action.action_id,
                outcome=ReconOutcome.SUCCEEDED,
                status_code=204,
                reason_code="synthetic_missing_snapshot",
                cleanup_complete=True,
                sensitive_data_redacted=True,
                observed_at=now,
            )

    adapter = MissingSnapshotAdapter()
    outcome = endpoint_service.execute_via_flow(
        endpoint_plan, scope=scope, adapter=adapter, now=now
    )
    assert outcome.outcome is EndpointReconOutcomeKind.FAILED
    assert outcome.results[0].reason_code == "endpoint_observation_invalid"
    assert outcome.results[0].status_code is None
    assert recon_store.state(endpoint_plan.endpoint_recon_plan_id)[0].value == "completed"
    assert (
        recon_store.reservation(endpoint_plan.endpoint_recon_plan_id).state
        is EndpointReconReservationState.CONSUMED
    )
    assert (
        endpoint_service.execute_via_flow(
            endpoint_plan, scope=scope, adapter=adapter, now=now
        )
        == outcome
    )
    assert adapter.calls == 1
    recon_store.close()
    store.close()


def test_live_recon_refuses_snapshot_when_evidence_object_is_missing(tmp_path, now):
    scope, store, service, _, _, command, adapter = _runtime(tmp_path, now)
    (adapter.evidence_store.objects / EVIDENCE).unlink()
    checkpoint, observation = service.execute_recon(
        command=command, scope=scope, adapter=adapter, now=now
    )
    assert observation.outcome is ReconOutcome.FAILED
    assert observation.reason_code == "evidence_integrity_failed"
    assert observation.attack_surface is None
    assert checkpoint.actions_used == 1
    store.close()


def test_live_recon_rechecks_redirect_and_rejects_private_dns_drift(tmp_path, now):
    redirect = OfflineHttpHop(
        status_code=302,
        peer_ip=IP,
        response_bytes=0,
        response_body_sha256=BODY,
        evidence_ref=EVIDENCE,
        location="/next",
    )
    transport = _PinnedTransport((redirect,))
    resolver = _PinnedResolver(((IP,), ("10.23.45.68",)))
    scope, store, service, _, _, command, adapter = _runtime(
        tmp_path, now, resolver=resolver, transport=transport
    )

    checkpoint, observation = service.execute_recon(
        command=command, scope=scope, adapter=adapter, now=now
    )

    assert observation.outcome is ReconOutcome.REJECTED
    assert observation.reason_code == "broker.resolved_address_forbidden"
    assert observation.attack_surface is None
    assert len(transport.calls) == 1
    assert checkpoint.status is RedTeamFlowStatus.RUNNING
    store.close()


def test_live_recon_timeout_is_typed_and_connection_cleanup_is_reported(tmp_path, now):
    scope, store, service, _, _, command, adapter = _runtime(
        tmp_path, now, transport=_PinnedTransport((TimeoutError("synthetic timeout"),))
    )
    checkpoint, observation = service.execute_recon(
        command=command, scope=scope, adapter=adapter, now=now
    )
    assert observation.outcome is ReconOutcome.TIMED_OUT
    assert observation.reason_code == "broker.http_transport_timeout"
    assert observation.cleanup_complete
    assert checkpoint.status is RedTeamFlowStatus.TIMED_OUT
    store.close()


def test_cancelled_flow_never_reaches_live_recon_adapter(tmp_path, now):
    scope, store, service, plan, checkpoint, command, adapter = _runtime(tmp_path, now)
    cancelled = service.cancel(plan, checkpoint, scope=scope, now=now)
    assert cancelled.status is RedTeamFlowStatus.CANCELLED
    with pytest.raises(RedTeamRejected, match="stale or not running"):
        service.execute_recon(command=command, scope=scope, adapter=adapter, now=now)
    assert adapter.calls == 0
    store.close()


def test_expired_local_admission_is_a_completed_fail_closed_observation(tmp_path, now):
    scope, store, service, _, _, command, adapter = _runtime(tmp_path, now)
    expired = IsolatedLocalReconAdmission.create(
        fixture_ref=adapter.admission.fixture_ref,
        host=adapter.admission.host,
        port=adapter.admission.port,
        scheme=adapter.admission.scheme,
        allowed_peer_ips=adapter.admission.allowed_peer_ips,
        expires_at=now - timedelta(seconds=1),
    )
    expired_adapter = IsolatedLocalHttpReconAdapter(
        plan=adapter.plan,
        broker=adapter.broker,
        profile=adapter.profile,
        admission=expired,
        evidence_store=adapter.evidence_store,
    )
    checkpoint, observation = service.execute_recon(
        command=command, scope=scope, adapter=expired_adapter, now=now
    )
    assert observation.outcome is ReconOutcome.REJECTED
    assert observation.reason_code == "local_admission_expired"
    assert checkpoint.actions_used == 1
    assert store.completed_action(command) == observation
    store.close()


def test_local_admission_and_adapter_fail_closed_on_unsafe_or_broader_binding(tmp_path, now):
    for address in ("127.0.0.1", "8.8.8.8", "169.254.169.254"):
        with pytest.raises(ValueError, match="private non-loopback"):
            IsolatedLocalReconAdmission.create(
                fixture_ref="fixture:unsafe",
                host=HOST,
                port=8080,
                scheme="http",
                allowed_peer_ips=(address,),
                expires_at=now + timedelta(minutes=1),
            )

    scope, store, _, plan, _, _, _ = _runtime(tmp_path, now)
    broad = validation_profile(
        image_digest=IMAGE,
        snapshot_id=plan.plan_id,
        network_grants=(
            NetworkGrant(host=HOST, ports=frozenset({8080}), schemes=frozenset({"http"})),
            NetworkGrant(
                host="other.internal.test",
                ports=frozenset({8080}),
                schemes=frozenset({"http"}),
            ),
        ),
    )
    admission = IsolatedLocalReconAdmission.create(
        fixture_ref="fixture:strict",
        host=HOST,
        port=8080,
        scheme="http",
        allowed_peer_ips=(IP,),
        expires_at=now + timedelta(minutes=1),
    )
    broker = ToolBroker(
        scope=scope,
        registry=pinned_http_tool_registry(),
        resolver=_PinnedResolver(((IP,),)),
        http_transport=_PinnedTransport(()),
        allowed_resolved_ips=frozenset({IP}),
    )
    with pytest.raises(RedTeamRejected, match="binding is invalid"):
        IsolatedLocalHttpReconAdapter(
            plan=plan,
            broker=broker,
            profile=broad,
            admission=admission,
            evidence_store=EvidenceStore(tmp_path / "broad-evidence"),
        )
    store.close()


def _safe_local_ipv4() -> str | None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # UDP connect selects a local route without sending a packet.
        probe.connect(("192.0.2.1", 9))
        candidates = (probe.getsockname()[0],)
    except OSError:
        try:
            records = socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET)
        except OSError:
            return None
        candidates = tuple(record[4][0] for record in records)
    finally:
        probe.close()
    for value in candidates:
        address = ipaddress.ip_address(value)
        if address.is_private and not address.is_loopback and not address.is_link_local:
            return str(address)
    return None


@pytest.mark.red_team_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_RED_TEAM_INTEGRATION") != "1",
    reason="set VULNLOOM_RED_TEAM_INTEGRATION=1 for isolated local HTTP Recon",
)
def test_real_local_fixture_process_is_pinned_redacted_and_cleaned(tmp_path: Path):
    address = _safe_local_ipv4()
    if address is None:
        pytest.skip("no private non-loopback IPv4 is available")
    program = """
import http.server
import sys
class Handler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Set-Cookie', 'session=must-not-persist')
        self.send_header('X-Authorization', 'Bearer must-not-persist')
        self.end_headers()
    def log_message(self, *args):
        pass
server = http.server.ThreadingHTTPServer((sys.argv[1], 0), Handler)
print(server.server_address[1], flush=True)
server.serve_forever()
"""
    process = subprocess.Popen(
        [sys.executable, "-c", program, address],
        env={"PYTHONUNBUFFERED": "1"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        port = int(process.stdout.readline().strip())
        now = datetime.now(UTC)
        scope, store, service, plan, _, command, _ = _runtime(tmp_path, now, port=port)
        evidence_store = EvidenceStore(tmp_path / "evidence")
        sink = EvidenceStoreHttpSink(evidence_store, target_version=plan.plan_id)
        broker = ToolBroker(
            scope=scope,
            registry=pinned_http_tool_registry(),
            resolver=_PinnedResolver(((address,),)),
            http_transport=PinnedHttpTransport(sink),
            allowed_resolved_ips=frozenset({address}),
        )
        profile = validation_profile(
            image_digest=IMAGE,
            snapshot_id=plan.plan_id,
            network_grants=(
                NetworkGrant(
                    host=HOST,
                    ports=frozenset({port}),
                    schemes=frozenset({"http"}),
                ),
            ),
        )
        admission = IsolatedLocalReconAdmission.create(
            fixture_ref="fixture:real-process-v1",
            host=HOST,
            port=port,
            scheme="http",
            allowed_peer_ips=(address,),
            expires_at=now + timedelta(minutes=1),
        )
        adapter = IsolatedLocalHttpReconAdapter(
            plan=plan,
            broker=broker,
            profile=profile,
            admission=admission,
            evidence_store=evidence_store,
        )
        advanced, observation = service.execute_recon(
            command=command, scope=scope, adapter=adapter, now=now
        )
        assert observation.attack_surface is not None
        evidence = sink.records[observation.attack_surface.evidence_refs[0]]
        content = evidence_store.read_text(evidence).lower()
        assert "must-not-persist" not in content
        assert plan.target.url not in content
        recon_store = EndpointReconStore(tmp_path / "endpoint-recon.sqlite3")
        endpoint_service = EndpointReconService(
            red_team_store=store,
            recon_store=recon_store,
            evidence_store=evidence_store,
        )
        seed_set = endpoint_service.seal_seed_set(
            flow_plan=plan,
            checkpoint=advanced,
            scope=scope,
            operator_ref="operator:fixture-owner",
            paths=("/health",),
            now=now,
            expires_at=now + timedelta(seconds=30),
            idempotency_key="endpoint-real:set",
        )
        endpoint_plan = endpoint_service.prepare(
            seed_set_id=seed_set.seed_set_id,
            scope=scope,
            test_class="read_only",
            limits=EndpointReconLimits(max_steps=1, max_requests=1),
            now=now,
            deadline=now + timedelta(seconds=20),
            idempotency_key="endpoint-real:plan",
        )
        exact_adapter = IsolatedLocalHttpReconAdapter(
            plan=plan,
            broker=broker,
            profile=profile,
            admission=admission,
            evidence_store=evidence_store,
            max_redirects=0,
            allowed_url_digests=(endpoint_plan.steps[0].target_url_digest,),
        )
        exact_outcome = endpoint_service.execute_via_flow(
            endpoint_plan,
            scope=scope,
            adapter=exact_adapter,
            now=now,
        )
        assert exact_outcome.outcome is EndpointReconOutcomeKind.SUCCEEDED
        assert store.latest(plan.plan_id).actions_used == 2
        recon_store.close()
        store.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    assert process.poll() is not None
