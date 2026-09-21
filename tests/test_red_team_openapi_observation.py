from __future__ import annotations

import hashlib
import json
from datetime import timedelta

import pytest
from pydantic import ValidationError

from vulnloom.broker import OfflineHttpHop, ToolBroker, pinned_http_tool_registry
from vulnloom.broker.implementation import PINNED_HTTP_IMPLEMENTATION_DIGEST
from vulnloom.domain.models import EvidenceKind
from vulnloom.evidence import EvidenceStore
from vulnloom.red_team import (
    EndpointReconLimits,
    EndpointReconService,
    EndpointReconStore,
    IsolatedLocalHttpReconAdapter,
    IsolatedLocalReconAdmission,
    OpenApiObservationLimits,
    OpenApiObservationRecoveryRequired,
    OpenApiObservationRejected,
    OpenApiObservationService,
    OpenApiObservationState,
    OpenApiObservationStore,
    OpenApiObservationTimedOut,
    OpenApiPathDiscovery,
    RedTeamService,
    RedTeamStore,
)
from vulnloom.runners import NetworkGrant, validation_profile
from vulnloom.workflows import Visibility

_IP = "10.23.45.67"
_IMAGE = "sha256:" + "1" * 64


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
        return self.hop


def _document():
    return {
        "openapi": "3.1.0",
        "info": {"title": "Authorized fixture", "version": "1"},
        "servers": [
            {"url": "https://outside.example/"},
            {"url": "https://app.example.test/"},
        ],
        "paths": {
            "/health": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/users/{user_id}": {
                "get": {"responses": {"200": {"description": "ok"}}},
                "post": {
                    "requestBody": {"$ref": "https://outside.example/schema.json"},
                    "responses": {"201": {"description": "created"}},
                },
            },
        },
    }


def _runtime(tmp_path, approved_scope, now, *, document=None, raw_json=None):
    red_store = RedTeamStore(tmp_path / "red-team.sqlite3")
    endpoint_store = EndpointReconStore(tmp_path / "endpoint-recon.sqlite3")
    observation_store = OpenApiObservationStore(tmp_path / "openapi.sqlite3")
    evidence_store = EvidenceStore(tmp_path / "evidence")
    flow_service = RedTeamService(store=red_store)
    flow = flow_service.prepare(
        scope=approved_scope,
        target_url="https://app.example.test/",
        visibility=Visibility.BLACK_BOX,
        allowed_test_classes=("read_only",),
        max_actions=2,
        max_consecutive_failures=2,
        emergency_contact_ref="contact:openapi-owner",
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="b2:openapi:flow",
    )
    checkpoint = flow_service.create_and_start(flow, scope=approved_scope, now=now)
    body = raw_json or json.dumps(
        document if document is not None else _document(),
        sort_keys=True,
        separators=(",", ":"),
    )
    transcript = (
        "method: GET\n"
        "url_sha256: " + "a" * 64 + "\n"
        "peer_ip: " + _IP + "\n"
        "status: 200\n"
        f"response_bytes: {len(body.encode())}\n"
        "content-type: application/json\n\n"
        + body
    )
    evidence = evidence_store.capture_text(
        transcript,
        kind=EvidenceKind.HTTP,
        source_ref="url-sha256:" + "a" * 64,
        producer="test.b2.openapi",
        target_version=flow.plan_id,
        summary="redacted OpenAPI fixture response",
    )
    transport = _Transport(
        OfflineHttpHop(
            status_code=200,
            peer_ip=_IP,
            response_bytes=len(body.encode()),
            response_body_sha256=hashlib.sha256(body.encode()).hexdigest(),
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
        fixture_ref="fixture:b2-openapi-v1",
        host="app.example.test",
        port=443,
        scheme="https",
        allowed_peer_ips=(_IP,),
        expires_at=now + timedelta(minutes=5),
    )
    endpoint_service = EndpointReconService(
        red_team_store=red_store,
        recon_store=endpoint_store,
        evidence_store=evidence_store,
    )
    seed_set = endpoint_service.seal_seed_set(
        flow_plan=flow,
        checkpoint=checkpoint,
        scope=approved_scope,
        operator_ref="operator:openapi-owner",
        paths=("/openapi.json",),
        now=now,
        expires_at=now + timedelta(minutes=2),
        idempotency_key="b2:openapi:seeds",
    )
    endpoint_plan = endpoint_service.prepare(
        seed_set_id=seed_set.seed_set_id,
        scope=approved_scope,
        test_class="read_only",
        limits=EndpointReconLimits(max_steps=1, max_requests=1),
        method="GET",
        now=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="b2:openapi:get",
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
    endpoint_service.execute_via_flow(
        endpoint_plan,
        scope=approved_scope,
        adapter=adapter,
        now=now,
    )
    service = OpenApiObservationService(
        red_team_store=red_store,
        endpoint_recon_store=endpoint_store,
        observation_store=observation_store,
        evidence_store=evidence_store,
    )
    return service, red_store, endpoint_store, observation_store, endpoint_plan, transport


def _prepare(service, endpoint_plan, scope, now, *, limits=None):
    return service.prepare(
        endpoint_recon_plan_id=endpoint_plan.endpoint_recon_plan_id,
        scope=scope,
        limits=limits or OpenApiObservationLimits(),
        now=now + timedelta(seconds=1),
        deadline=now + timedelta(minutes=1),
        idempotency_key="b2:openapi:observe",
    )


def _close(red_store, endpoint_store, observation_store):
    red_store.close()
    endpoint_store.close()
    observation_store.close()


def test_sealed_openapi_document_becomes_non_executable_discoveries(
    tmp_path, approved_scope, now
):
    service, red_store, endpoint_store, store, endpoint_plan, transport = _runtime(
        tmp_path, approved_scope, now
    )
    plan = _prepare(service, endpoint_plan, approved_scope, now)
    outcome = service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=1)
    )

    observation = outcome.observation
    by_path = {item.path_template: item for item in observation.paths}
    assert observation.openapi_version == "3.1.0"
    assert observation.operation_count == 3
    assert observation.server_entries_ignored == 2
    assert observation.reference_entries_ignored == 1
    assert tuple(item.value for item in by_path["/users/{user_id}"].methods) == (
        "GET",
        "POST",
    )
    assert not any(item.execution_authorized for item in observation.paths)
    assert observation.target_expansion_authorized is False
    encoded = observation.model_dump_json()
    assert "outside.example" not in encoded
    assert "schema.json" not in encoded
    assert transport.calls[0].method.value == "GET"
    assert service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=2)
    ) == outcome
    assert store.state(plan.plan_id) == (OpenApiObservationState.COMPLETED, 1)
    _close(red_store, endpoint_store, store)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"openapi": "2.0", "paths": {"/ok": {"get": {}}}}, "sealed"),
        ({"openapi": "3.1.0", "paths": {"https://evil/": {"get": {}}}}, "template"),
        ({"openapi": "3.1.0", "paths": {"/ok": {"get": "not-object"}}}, "operation"),
        ({"openapi": "3.1.0", "paths": {"/ok": {"parameters": []}}}, "no bounded"),
    ],
)
def test_openapi_parser_rejects_unsupported_or_unsafe_documents(
    tmp_path, approved_scope, now, document, message
):
    service, red_store, endpoint_store, store, endpoint_plan, _ = _runtime(
        tmp_path, approved_scope, now, document=document
    )
    plan = _prepare(service, endpoint_plan, approved_scope, now)
    with pytest.raises(OpenApiObservationRejected, match=message):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    assert store.state(plan.plan_id) is None
    _close(red_store, endpoint_store, store)


def test_openapi_duplicate_keys_and_structure_budgets_fail_closed(
    tmp_path, approved_scope, now
):
    raw = '{"openapi":"3.1.0","paths":{"/a":{"get":{}},"/a":{"post":{}}}}'
    service, red_store, endpoint_store, store, endpoint_plan, _ = _runtime(
        tmp_path, approved_scope, now, raw_json=raw
    )
    plan = _prepare(service, endpoint_plan, approved_scope, now)
    with pytest.raises(OpenApiObservationRejected, match="duplicate"):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    _close(red_store, endpoint_store, store)

    deep = {"openapi": "3.1.0", "paths": {"/ok": {"get": {}}}, "x": {"a": {}}}
    service, red_store, endpoint_store, store, endpoint_plan, _ = _runtime(
        tmp_path / "deep", approved_scope, now, document=deep
    )
    plan = _prepare(
        service,
        endpoint_plan,
        approved_scope,
        now,
        limits=OpenApiObservationLimits(max_depth=2),
    )
    with pytest.raises(OpenApiObservationRejected, match="structure budget"):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    _close(red_store, endpoint_store, store)

    service, red_store, endpoint_store, store, endpoint_plan, _ = _runtime(
        tmp_path / "paths", approved_scope, now
    )
    plan = _prepare(
        service,
        endpoint_plan,
        approved_scope,
        now,
        limits=OpenApiObservationLimits(max_paths=1),
    )
    with pytest.raises(OpenApiObservationRejected, match="path budget"):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    assert store.state(plan.plan_id) is None
    _close(red_store, endpoint_store, store)


def test_openapi_timeout_leaves_no_partial_result(tmp_path, approved_scope, now):
    service, red_store, endpoint_store, store, endpoint_plan, _ = _runtime(
        tmp_path, approved_scope, now
    )
    ticks = iter((0.0, 11.0))
    service.monotonic = lambda: next(ticks)
    plan = _prepare(
        service,
        endpoint_plan,
        approved_scope,
        now,
        limits=OpenApiObservationLimits(timeout_seconds=10),
    )
    with pytest.raises(OpenApiObservationTimedOut):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    assert store.state(plan.plan_id) is None
    _close(red_store, endpoint_store, store)


def test_openapi_plan_cannot_replace_its_bound_source(
    tmp_path, approved_scope, now
):
    service, red_store, endpoint_store, store, endpoint_plan, _ = _runtime(
        tmp_path, approved_scope, now
    )
    plan = _prepare(service, endpoint_plan, approved_scope, now)
    values = plan.model_dump(mode="python", exclude={"plan_id"})
    values["limits"] = plan.limits
    values["source_checkpoint_id"] = "f" * 64
    drifted = type(plan).create(**values)

    with pytest.raises(OpenApiObservationRejected, match="binding drifted"):
        service.execute(
            drifted, scope=approved_scope, now=now + timedelta(seconds=1)
        )
    assert store.state(drifted.plan_id) is None
    _close(red_store, endpoint_store, store)


def test_openapi_started_checkpoint_requires_bounded_recovery(
    tmp_path, approved_scope, now
):
    service, red_store, endpoint_store, store, endpoint_plan, _ = _runtime(
        tmp_path, approved_scope, now
    )
    plan = _prepare(service, endpoint_plan, approved_scope, now)
    store.claim(plan, now=now + timedelta(seconds=1))
    with pytest.raises(OpenApiObservationRecoveryRequired, match="unfinished"):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    outcome = service.recover(
        plan, scope=approved_scope, now=now + timedelta(seconds=2)
    )
    assert outcome.attempt == 2
    assert outcome.cleanup_complete is True
    assert store.state(plan.plan_id) == (OpenApiObservationState.COMPLETED, 2)
    _close(red_store, endpoint_store, store)


def test_openapi_discovery_schema_cannot_grant_execution():
    discovery = OpenApiPathDiscovery.create(
        path_template="/users/{id}", methods=("GET",)  # type: ignore[arg-type]
    )
    with pytest.raises(ValidationError):
        OpenApiPathDiscovery.model_validate(
            discovery.model_dump(mode="python")
            | {"execution_authorized": True, "target_url": "https://outside.example/"}
        )
