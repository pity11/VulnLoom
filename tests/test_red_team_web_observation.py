from __future__ import annotations

import hashlib
from datetime import timedelta

import pytest
from pydantic import ValidationError

from vulnloom.broker import (
    OfflineHttpHop,
    ToolBroker,
    pinned_http_tool_registry,
)
from vulnloom.broker.implementation import PINNED_HTTP_IMPLEMENTATION_DIGEST
from vulnloom.domain.models import EvidenceKind
from vulnloom.evidence import EvidenceStore
from vulnloom.red_team import (
    EndpointReconLimits,
    EndpointReconOutcomeKind,
    EndpointReconReservationState,
    EndpointReconService,
    EndpointReconStore,
    IsolatedLocalHttpReconAdapter,
    IsolatedLocalReconAdmission,
    OfflineEndpointReconAdapter,
    ReconOutcome,
    RedTeamActionKind,
    RedTeamReconAction,
    RedTeamReconCommand,
    RedTeamReconObservation,
    RedTeamRejected,
    RedTeamService,
    RedTeamStore,
    WebResponseSnapshot,
)
from vulnloom.runners import NetworkGrant, validation_profile
from vulnloom.workflows import Visibility

_IP = "10.23.45.67"
_IMAGE = "sha256:" + "1" * 64
_BODY = b'{"status":"ok"}'
_BODY_DIGEST = hashlib.sha256(_BODY).hexdigest()


class _Resolver:
    implementation_digest = PINNED_HTTP_IMPLEMENTATION_DIGEST

    def resolve(self, host):
        return (_IP,) if host == "app.example.test" else ()


class _Transport:
    implementation_digest = PINNED_HTTP_IMPLEMENTATION_DIGEST

    def __init__(self, hop):
        self.hop = hop
        self.calls = []

    def send(self, request):
        self.calls.append(request)
        if isinstance(self.hop, BaseException):
            raise self.hop
        return self.hop


def _runtime(tmp_path, approved_scope, now, *, hop=None):
    red_store = RedTeamStore(tmp_path / "red-team.sqlite3")
    recon_store = EndpointReconStore(tmp_path / "endpoint-recon.sqlite3")
    flow_service = RedTeamService(store=red_store)
    flow = flow_service.prepare(
        scope=approved_scope,
        target_url="https://app.example.test/",
        visibility=Visibility.BLACK_BOX,
        allowed_test_classes=("read_only",),
        max_actions=2,
        max_consecutive_failures=2,
        emergency_contact_ref="contact:web-observation-owner",
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="b2:web-observation:flow",
    )
    checkpoint = flow_service.create_and_start(flow, scope=approved_scope, now=now)
    evidence_store = EvidenceStore(tmp_path / "evidence")
    evidence = evidence_store.capture_text(
        _BODY.decode(),
        kind=EvidenceKind.HTTP,
        source_ref="url-sha256:" + "a" * 64,
        producer="test.b2.sealed-get",
        target_version=flow.plan_id,
        summary="redacted sealed GET response",
    )
    transport = _Transport(
        hop
        or OfflineHttpHop(
            status_code=200,
            peer_ip=_IP,
            response_bytes=len(_BODY),
            response_body_sha256=_BODY_DIGEST,
            evidence_ref=evidence.evidence_id,
        )
    )
    broker = ToolBroker(
        scope=approved_scope,
        registry=pinned_http_tool_registry(),
        resolver=_Resolver(),
        http_transport=transport,
        allowed_resolved_ips=frozenset({_IP}),
    )
    profile = validation_profile(
        image_digest=_IMAGE,
        snapshot_id=flow.plan_id,
        network_grants=(
            NetworkGrant(
                host="app.example.test",
                ports=frozenset({443}),
                schemes=frozenset({"https"}),
            ),
        ),
    )
    admission = IsolatedLocalReconAdmission.create(
        fixture_ref="fixture:b2-sealed-get-v1",
        host="app.example.test",
        port=443,
        scheme="https",
        allowed_peer_ips=(_IP,),
        expires_at=now + timedelta(minutes=5),
    )
    endpoint_service = EndpointReconService(
        red_team_store=red_store,
        recon_store=recon_store,
        evidence_store=evidence_store,
    )
    seed_set = endpoint_service.seal_seed_set(
        flow_plan=flow,
        checkpoint=checkpoint,
        scope=approved_scope,
        operator_ref="operator:web-owner",
        paths=("/api/status",),
        now=now,
        expires_at=now + timedelta(minutes=2),
        idempotency_key="b2:web-observation:seeds",
    )
    endpoint_plan = endpoint_service.prepare(
        seed_set_id=seed_set.seed_set_id,
        scope=approved_scope,
        test_class="read_only",
        limits=EndpointReconLimits(max_steps=1, max_requests=1),
        method="GET",
        now=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="b2:web-observation:plan",
    )
    adapter = IsolatedLocalHttpReconAdapter(
        plan=flow,
        broker=broker,
        profile=profile,
        admission=admission,
        evidence_store=evidence_store,
        max_redirects=0,
        allowed_url_digests=(endpoint_plan.steps[0].target_url_digest,),
    )
    return (
        endpoint_service,
        red_store,
        recon_store,
        flow_service,
        flow,
        checkpoint,
        endpoint_plan,
        adapter,
        transport,
    )


def test_exact_sealed_get_records_digest_only_web_observation(tmp_path, approved_scope, now):
    (
        service,
        red_store,
        recon_store,
        _,
        flow,
        _,
        plan,
        adapter,
        transport,
    ) = _runtime(tmp_path, approved_scope, now)

    outcome = service.execute_via_flow(plan, scope=approved_scope, adapter=adapter, now=now)

    result = outcome.results[0]
    observation = red_store.observation(red_store.latest(flow.plan_id).observation_ids[-1])
    request = transport.calls[0]
    assert plan.steps[0].method == "GET"
    assert outcome.outcome is EndpointReconOutcomeKind.SUCCEEDED
    assert result.response_bytes == len(_BODY)
    assert result.response_body_sha256 == _BODY_DIGEST
    assert result.web_response_snapshot_id == observation.web_response.snapshot_id
    assert observation.attack_surface is None
    assert observation.web_response.response_body_sha256 == _BODY_DIGEST
    assert request.method.value == "GET"
    assert request.headers == ()
    assert request.credential_ref is None
    assert request.body_ref is None and request.body_bytes == 0
    assert "/api/status" not in outcome.model_dump_json()
    assert _BODY.decode() not in outcome.model_dump_json()
    assert (
        recon_store.reservation(plan.endpoint_recon_plan_id).state
        is EndpointReconReservationState.CONSUMED
    )
    replay = service.execute_via_flow(
        plan, scope=approved_scope, adapter=adapter, now=now + timedelta(seconds=1)
    )
    assert replay == outcome
    assert len(transport.calls) == 1
    red_store.close()
    recon_store.close()


def test_get_cannot_bypass_sealed_endpoint_authority(tmp_path, approved_scope, now):
    (
        _,
        red_store,
        recon_store,
        flow_service,
        flow,
        checkpoint,
        plan,
        adapter,
        transport,
    ) = _runtime(tmp_path, approved_scope, now)
    with pytest.raises(RedTeamRejected, match="operator-sealed"):
        flow_service.prepare_recon(
            plan=flow,
            checkpoint=checkpoint,
            scope=approved_scope,
            kind=RedTeamActionKind.HTTP_GET,
            test_class="read_only",
            now=now,
            ttl_seconds=30,
            idempotency_key="b2:unsealed-get",
        )

    action = RedTeamReconAction.create(
        plan_id=flow.plan_id,
        expected_checkpoint_id=checkpoint.checkpoint_id,
        kind=RedTeamActionKind.HTTP_GET,
        target_url="https://app.example.test/outside-seed",
        test_class="read_only",
        created_at=now,
        deadline=now + timedelta(seconds=30),
        idempotency_key="b2:outside-seed",
    )
    with pytest.raises(RedTeamRejected, match="operator-sealed"):
        flow_service.execute_recon(
            command=RedTeamReconCommand.create(action=action, attempt=1),
            scope=approved_scope,
            adapter=adapter,
            now=now,
        )
    rejected = adapter.execute(action, now=now)
    assert rejected.outcome is ReconOutcome.REJECTED
    assert rejected.reason_code == "local_action_not_admitted"
    assert transport.calls == []
    assert plan.steps[0].target_url != action.target_url
    red_store.close()
    recon_store.close()


def test_sealed_get_rejects_legacy_offline_success_without_web_snapshot(
    tmp_path, approved_scope, now
):
    (
        service,
        red_store,
        recon_store,
        _,
        _,
        _,
        plan,
        _,
        _,
    ) = _runtime(tmp_path, approved_scope, now)
    with pytest.raises(ValueError, match="provenance"):
        service.execute(
            plan,
            scope=approved_scope,
            adapter=OfflineEndpointReconAdapter(),
            now=now,
        )
    red_store.close()
    recon_store.close()


def test_web_snapshot_rejects_raw_body_and_redirect_binding(tmp_path, approved_scope, now):
    (
        service,
        red_store,
        recon_store,
        _,
        flow,
        _,
        plan,
        adapter,
        _,
    ) = _runtime(tmp_path, approved_scope, now)
    service.execute_via_flow(plan, scope=approved_scope, adapter=adapter, now=now)
    observation = red_store.observation(red_store.latest(flow.plan_id).observation_ids[-1])
    payload = observation.web_response.model_dump(mode="python")
    with pytest.raises(ValidationError):
        WebResponseSnapshot.model_validate(payload | {"response_body": _BODY.decode()})
    with pytest.raises(ValidationError, match="content binding"):
        WebResponseSnapshot.model_validate(payload | {"final_url_digest": "f" * 64})
    red_store.close()
    recon_store.close()


@pytest.mark.parametrize(
    ("hop", "expected", "cleanup"),
    [
        (TimeoutError("offline timeout"), EndpointReconOutcomeKind.TIMED_OUT, True),
        (None, EndpointReconOutcomeKind.FAILED, False),
    ],
)
def test_sealed_get_timeout_and_cleanup_failure_are_terminal(
    tmp_path, approved_scope, now, hop, expected, cleanup
):
    (
        service,
        red_store,
        recon_store,
        _,
        _,
        _,
        plan,
        adapter,
        _,
    ) = _runtime(tmp_path, approved_scope, now, hop=hop)

    if not cleanup:

        class _CleanupFailure:
            def execute(self, action, *, now):
                return RedTeamReconObservation.create(
                    action_id=action.action_id,
                    outcome=ReconOutcome.FAILED,
                    status_code=None,
                    reason_code="sealed_get_cleanup_unproven",
                    cleanup_complete=False,
                    observed_at=now,
                )

        adapter = _CleanupFailure()

    outcome = service.execute_via_flow(plan, scope=approved_scope, adapter=adapter, now=now)
    assert outcome.outcome is expected
    assert outcome.cleanup_complete is cleanup
    assert (
        recon_store.reservation(plan.endpoint_recon_plan_id).state
        is EndpointReconReservationState.CONSUMED
    )
    red_store.close()
    recon_store.close()
