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
    GraphQlQueryFieldDiscovery,
    GraphQlSchemaObservationLimits,
    GraphQlSchemaObservationRecoveryRequired,
    GraphQlSchemaObservationRejected,
    GraphQlSchemaObservationService,
    GraphQlSchemaObservationState,
    GraphQlSchemaObservationStore,
    GraphQlSchemaObservationTimedOut,
    IsolatedLocalHttpReconAdapter,
    IsolatedLocalReconAdmission,
    OpenApiDiscoveryPromotionLimits,
    OpenApiDiscoveryPromotionRecoveryRequired,
    OpenApiDiscoveryPromotionRejected,
    OpenApiDiscoveryPromotionService,
    OpenApiDiscoveryPromotionState,
    OpenApiDiscoveryPromotionStore,
    OpenApiDiscoveryPromotionStoreRejected,
    OpenApiDiscoveryPromotionTimedOut,
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
        max_actions=4,
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


def _graphql_runtime(tmp_path, approved_scope, now, sdl, *, monotonic=None):
    _, red_store, endpoint_store, openapi_store, endpoint_plan, transport = _runtime(
        tmp_path, approved_scope, now, raw_json=sdl
    )
    store = GraphQlSchemaObservationStore(tmp_path / "graphql.sqlite3")
    service = GraphQlSchemaObservationService(
        red_team_store=red_store,
        endpoint_recon_store=endpoint_store,
        observation_store=store,
        evidence_store=EvidenceStore(tmp_path / "evidence"),
        **({"monotonic": monotonic} if monotonic is not None else {}),
    )
    return (
        service,
        red_store,
        endpoint_store,
        openapi_store,
        store,
        endpoint_plan,
        transport,
    )


def _prepare_graphql(service, endpoint_plan, scope, now, *, limits=None):
    return service.prepare(
        endpoint_recon_plan_id=endpoint_plan.endpoint_recon_plan_id,
        scope=scope,
        limits=limits or GraphQlSchemaObservationLimits(),
        now=now + timedelta(seconds=1),
        deadline=now + timedelta(minutes=1),
        idempotency_key="b2:graphql:observe",
    )


def _close_graphql(red_store, endpoint_store, openapi_store, graphql_store):
    red_store.close()
    endpoint_store.close()
    openapi_store.close()
    graphql_store.close()


def test_sealed_graphql_sdl_becomes_non_executable_query_field_summaries(
    tmp_path, approved_scope, now
):
    sdl = '''
        schema { query: RootQuery mutation: Mutation subscription: Subscription }
        """Root query description must not be retained."""
        type RootQuery {
          viewer(id: ID!, secretDefault: String = "redact-me"): User!
            @deprecated(reason: "do not retain")
          health: String!
        }
        type Mutation { updateName(name: String!): User }
        type Subscription { changed: User }
        input Filter { active: Boolean }
        type User { id: ID! name: String }
        scalar DateTime
    '''
    (
        service,
        red_store,
        endpoint_store,
        openapi_store,
        store,
        endpoint_plan,
        transport,
    ) = _graphql_runtime(tmp_path, approved_scope, now, sdl)
    plan = _prepare_graphql(service, endpoint_plan, approved_scope, now)
    outcome = service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=1)
    )

    observation = outcome.observation
    fields = {item.field_name: item for item in observation.query_fields}
    assert observation.query_root_type == "RootQuery"
    assert fields["viewer"].return_named_type == "User"
    assert fields["health"].return_named_type == "String"
    assert observation.type_count == 6
    assert observation.mutation_fields_ignored == 1
    assert observation.subscription_fields_ignored == 1
    assert observation.directive_uses_ignored == 1
    assert observation.operation_execution_authorized is False
    assert observation.target_expansion_authorized is False
    assert all(not item.execution_authorized for item in observation.query_fields)
    encoded = observation.model_dump_json()
    assert "secretDefault" not in encoded
    assert "redact-me" not in encoded
    assert "deprecated" not in encoded
    assert len(transport.calls) == 1
    assert service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=2)
    ) == outcome
    assert store.state(plan.plan_id) == (GraphQlSchemaObservationState.COMPLETED, 1)
    _close_graphql(red_store, endpoint_store, openapi_store, store)


@pytest.mark.parametrize(
    ("sdl", "message"),
    [
        ("query { viewer { id } }", "executable"),
        ("type User { id: ID! }", "query root"),
        ("type Query { viewer: User viewer: String }", "repeats an object field"),
        ("type Query { viewer: [User! }", "unbalanced"),
        ("extend type Query { health: String }", "undefined"),
    ],
)
def test_graphql_sdl_rejects_executable_malformed_or_ambiguous_documents(
    tmp_path, approved_scope, now, sdl, message
):
    (
        service,
        red_store,
        endpoint_store,
        openapi_store,
        store,
        endpoint_plan,
        _,
    ) = _graphql_runtime(tmp_path, approved_scope, now, sdl)
    plan = _prepare_graphql(service, endpoint_plan, approved_scope, now)
    with pytest.raises(GraphQlSchemaObservationRejected, match=message):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    assert store.state(plan.plan_id) is None
    _close_graphql(red_store, endpoint_store, openapi_store, store)


def test_graphql_sdl_budgets_and_timeout_leave_no_partial_result(
    tmp_path, approved_scope, now
):
    sdl = "type Query { first: String second: String }"
    (
        service,
        red_store,
        endpoint_store,
        openapi_store,
        store,
        endpoint_plan,
        _,
    ) = _graphql_runtime(tmp_path / "budget", approved_scope, now, sdl)
    plan = _prepare_graphql(
        service,
        endpoint_plan,
        approved_scope,
        now,
        limits=GraphQlSchemaObservationLimits(max_query_fields=1),
    )
    with pytest.raises(GraphQlSchemaObservationRejected, match="field budget"):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    assert store.state(plan.plan_id) is None
    _close_graphql(red_store, endpoint_store, openapi_store, store)

    ticks = iter((0.0, 11.0))
    (
        service,
        red_store,
        endpoint_store,
        openapi_store,
        store,
        endpoint_plan,
        _,
    ) = _graphql_runtime(
        tmp_path / "timeout", approved_scope, now, "type Query { ok: String }",
        monotonic=lambda: next(ticks),
    )
    plan = _prepare_graphql(service, endpoint_plan, approved_scope, now)
    with pytest.raises(GraphQlSchemaObservationTimedOut):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    assert store.state(plan.plan_id) is None
    _close_graphql(red_store, endpoint_store, openapi_store, store)


def test_graphql_plan_binding_and_started_recovery_are_fail_closed(
    tmp_path, approved_scope, now
):
    (
        service,
        red_store,
        endpoint_store,
        openapi_store,
        store,
        endpoint_plan,
        _,
    ) = _graphql_runtime(
        tmp_path, approved_scope, now, "type Query { viewer: User } type User { id: ID! }"
    )
    plan = _prepare_graphql(service, endpoint_plan, approved_scope, now)
    values = plan.model_dump(mode="python", exclude={"plan_id"})
    values["limits"] = plan.limits
    values["source_checkpoint_id"] = "f" * 64
    drifted = type(plan).create(**values)
    with pytest.raises(GraphQlSchemaObservationRejected, match="binding drifted"):
        service.execute(
            drifted, scope=approved_scope, now=now + timedelta(seconds=1)
        )
    assert store.state(drifted.plan_id) is None

    store.claim(plan, now=now + timedelta(seconds=1))
    with pytest.raises(GraphQlSchemaObservationRecoveryRequired, match="unfinished"):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    outcome = service.recover(
        plan, scope=approved_scope, now=now + timedelta(seconds=2)
    )
    assert outcome.attempt == 2
    assert outcome.cleanup_complete is True
    assert store.state(plan.plan_id) == (GraphQlSchemaObservationState.COMPLETED, 2)
    _close_graphql(red_store, endpoint_store, openapi_store, store)


def test_graphql_query_field_schema_cannot_grant_execution_or_disclose_arguments():
    discovery = GraphQlQueryFieldDiscovery.create(
        field_name="viewer", return_named_type="User"
    )
    with pytest.raises(ValidationError):
        GraphQlQueryFieldDiscovery.model_validate(
            discovery.model_dump(mode="python")
            | {
                "execution_authorized": True,
                "arguments_disclosed": True,
                "argument_names": ["id"],
            }
        )


def _promotion_runtime(tmp_path, approved_scope, now, *, document=None):
    (
        observation_service,
        red_store,
        endpoint_store,
        observation_store,
        endpoint_plan,
        transport,
    ) = _runtime(tmp_path, approved_scope, now, document=document)
    observation_plan = _prepare(
        observation_service, endpoint_plan, approved_scope, now
    )
    observation_outcome = observation_service.execute(
        observation_plan,
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )
    endpoint_service = EndpointReconService(
        red_team_store=red_store,
        recon_store=endpoint_store,
        evidence_store=EvidenceStore(tmp_path / "evidence"),
    )
    promotion_store = OpenApiDiscoveryPromotionStore(endpoint_store)
    promotion_service = OpenApiDiscoveryPromotionService(
        red_team_store=red_store,
        endpoint_recon_service=endpoint_service,
        observation_store=observation_store,
        promotion_store=promotion_store,
    )
    return (
        promotion_service,
        endpoint_service,
        red_store,
        endpoint_store,
        observation_store,
        promotion_store,
        observation_plan,
        observation_outcome,
        transport,
    )


def _prepare_promotion(
    service,
    observation_plan,
    observation_outcome,
    scope,
    now,
    *,
    path_template="/users/{user_id}",
    concrete_path="/users/42",
    limits=None,
):
    discoveries = {
        item.path_template: item
        for item in observation_outcome.observation.paths
    }
    discovery = discoveries[path_template]
    return service.prepare(
        openapi_observation_plan_id=observation_plan.plan_id,
        scope=scope,
        operator_ref="operator:openapi-reviewer",
        selections=((discovery.discovery_id, concrete_path),),
        limits=limits or OpenApiDiscoveryPromotionLimits(),
        now=now + timedelta(seconds=2),
        deadline=now + timedelta(minutes=1),
        seed_set_expires_at=now + timedelta(minutes=2),
        idempotency_key="b2:openapi:promotion",
    )


def test_reviewed_discovery_promotion_atomically_publishes_exact_seed(
    tmp_path, approved_scope, now
):
    (
        service,
        endpoint_service,
        red_store,
        endpoint_store,
        observation_store,
        promotion_store,
        observation_plan,
        observation_outcome,
        transport,
    ) = _promotion_runtime(tmp_path, approved_scope, now)
    plan = _prepare_promotion(
        service,
        observation_plan,
        observation_outcome,
        approved_scope,
        now,
    )
    outcome = service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=2)
    )

    seed_set = endpoint_store.seed_set(outcome.seed_set_id)
    assert tuple(seed.path for seed in seed_set.seeds) == ("/users/42",)
    assert seed_set.source_checkpoint_id == plan.source_checkpoint_id
    assert seed_set.operator_ref == "operator:openapi-reviewer"
    assert promotion_store.state(plan.promotion_plan_id) == (
        OpenApiDiscoveryPromotionState.COMPLETED,
        1,
    )
    assert outcome.cleanup_complete is True
    assert service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=3)
    ) == outcome
    prepared = endpoint_service.prepare(
        seed_set_id=seed_set.seed_set_id,
        scope=approved_scope,
        test_class="read_only",
        limits=EndpointReconLimits(max_steps=1, max_requests=1),
        method="HEAD",
        now=now + timedelta(seconds=3),
        deadline=now + timedelta(minutes=1),
        idempotency_key="b2:openapi:promoted-head",
    )
    assert prepared.steps[0].target_url == "https://app.example.test/users/42"
    assert len(transport.calls) == 1
    _close(red_store, endpoint_store, observation_store)


def test_discovery_promotion_rejects_implicit_or_unreviewed_expansion(
    tmp_path, approved_scope, now
):
    (
        service,
        _,
        red_store,
        endpoint_store,
        observation_store,
        promotion_store,
        observation_plan,
        observation_outcome,
        _,
    ) = _promotion_runtime(tmp_path, approved_scope, now)
    discovery = next(
        item
        for item in observation_outcome.observation.paths
        if item.path_template == "/users/{user_id}"
    )
    common = dict(
        openapi_observation_plan_id=observation_plan.plan_id,
        scope=approved_scope,
        operator_ref="operator:openapi-reviewer",
        limits=OpenApiDiscoveryPromotionLimits(),
        now=now + timedelta(seconds=2),
        deadline=now + timedelta(minutes=1),
        seed_set_expires_at=now + timedelta(minutes=2),
        idempotency_key="b2:openapi:rejected-promotion",
    )
    with pytest.raises(OpenApiDiscoveryPromotionRejected, match="explicit selection"):
        service.prepare(selections=(), **common)
    with pytest.raises(OpenApiDiscoveryPromotionRejected, match="not authoritative"):
        service.prepare(
            selections=(("f" * 64, "/users/42"),),
            **common,
        )
    with pytest.raises(OpenApiDiscoveryPromotionRejected, match="does not match"):
        service.prepare(
            selections=((discovery.discovery_id, "/admin/42"),),
            **common,
        )
    with pytest.raises(OpenApiDiscoveryPromotionRejected, match="does not match"):
        service.prepare(
            selections=((discovery.discovery_id, "/users/{user_id}"),),
            **common,
        )
    assert promotion_store.state("f" * 64) is None
    assert endpoint_store.connection.execute(
        "SELECT COUNT(*) FROM endpoint_seed_sets"
    ).fetchone()[0] == 1
    _close(red_store, endpoint_store, observation_store)


def test_discovery_promotion_rejects_non_read_only_document_operation(
    tmp_path, approved_scope, now
):
    document = {
        "openapi": "3.1.0",
        "paths": {"/mutate": {"post": {"responses": {"204": {}}}}},
    }
    (
        service,
        _,
        red_store,
        endpoint_store,
        observation_store,
        _,
        observation_plan,
        observation_outcome,
        _,
    ) = _promotion_runtime(tmp_path, approved_scope, now, document=document)
    discovery = observation_outcome.observation.paths[0]
    with pytest.raises(OpenApiDiscoveryPromotionRejected, match="no read-only"):
        service.prepare(
            openapi_observation_plan_id=observation_plan.plan_id,
            scope=approved_scope,
            operator_ref="operator:openapi-reviewer",
            selections=((discovery.discovery_id, "/mutate"),),
            limits=OpenApiDiscoveryPromotionLimits(),
            now=now + timedelta(seconds=2),
            deadline=now + timedelta(minutes=1),
            seed_set_expires_at=now + timedelta(minutes=2),
            idempotency_key="b2:openapi:post-only",
        )
    _close(red_store, endpoint_store, observation_store)


def test_discovery_promotion_timeout_is_recoverable_without_partial_seed(
    tmp_path, approved_scope, now
):
    (
        service,
        _,
        red_store,
        endpoint_store,
        observation_store,
        promotion_store,
        observation_plan,
        observation_outcome,
        _,
    ) = _promotion_runtime(tmp_path, approved_scope, now)
    plan = _prepare_promotion(
        service,
        observation_plan,
        observation_outcome,
        approved_scope,
        now,
    )
    ticks = iter((0.0, 0.0, 11.0))
    service.monotonic = lambda: next(ticks)
    with pytest.raises(OpenApiDiscoveryPromotionTimedOut):
        service.execute(
            plan, scope=approved_scope, now=now + timedelta(seconds=2)
        )
    assert promotion_store.state(plan.promotion_plan_id) == (
        OpenApiDiscoveryPromotionState.STARTED,
        1,
    )
    assert endpoint_store.connection.execute(
        "SELECT COUNT(*) FROM endpoint_seed_sets"
    ).fetchone()[0] == 1
    service.monotonic = lambda: 0.0
    with pytest.raises(OpenApiDiscoveryPromotionRecoveryRequired, match="unfinished"):
        service.execute(
            plan, scope=approved_scope, now=now + timedelta(seconds=3)
        )

    outcome = service.recover(
        plan, scope=approved_scope, now=now + timedelta(seconds=3)
    )
    assert outcome.attempt == 2
    assert endpoint_store.seed_set(outcome.seed_set_id).seeds[0].path == "/users/42"
    assert endpoint_store.connection.execute(
        "SELECT COUNT(*) FROM endpoint_seed_sets"
    ).fetchone()[0] == 2
    _close(red_store, endpoint_store, observation_store)


def test_discovery_promotion_retries_and_idempotency_are_bounded(
    tmp_path, approved_scope, now
):
    (
        service,
        _,
        red_store,
        endpoint_store,
        observation_store,
        promotion_store,
        observation_plan,
        observation_outcome,
        _,
    ) = _promotion_runtime(tmp_path, approved_scope, now)
    plan = _prepare_promotion(
        service,
        observation_plan,
        observation_outcome,
        approved_scope,
        now,
    )
    assert promotion_store.claim(
        plan, now=now + timedelta(seconds=2)
    ).attempt == 1
    assert promotion_store.recover(
        plan, now=now + timedelta(seconds=3)
    ).attempt == 2
    assert promotion_store.recover(
        plan, now=now + timedelta(seconds=4)
    ).attempt == 3
    with pytest.raises(OpenApiDiscoveryPromotionRecoveryRequired, match="exhausted"):
        promotion_store.recover(plan, now=now + timedelta(seconds=5))

    health_plan = _prepare_promotion(
        service,
        observation_plan,
        observation_outcome,
        approved_scope,
        now,
        path_template="/health",
        concrete_path="/health",
    )
    health_values = health_plan.model_dump(
        mode="python", exclude={"promotion_plan_id"}
    )
    health_values["limits"] = health_plan.limits
    health_values["selections"] = health_plan.selections
    health_values["idempotency_key"] = plan.idempotency_key
    conflicting = type(plan).create(**health_values)
    with pytest.raises(OpenApiDiscoveryPromotionStoreRejected, match="different content"):
        promotion_store.claim(
            conflicting, now=now + timedelta(seconds=5)
        )
    with pytest.raises(OpenApiDiscoveryPromotionRecoveryRequired, match="unavailable"):
        promotion_store.outcome(plan.promotion_plan_id)
    assert endpoint_store.connection.execute(
        "SELECT COUNT(*) FROM endpoint_seed_sets"
    ).fetchone()[0] == 1
    _close(red_store, endpoint_store, observation_store)


def test_discovery_promotion_plan_cannot_replace_checkpoint_or_add_authority(
    tmp_path, approved_scope, now
):
    (
        service,
        _,
        red_store,
        endpoint_store,
        observation_store,
        promotion_store,
        observation_plan,
        observation_outcome,
        _,
    ) = _promotion_runtime(tmp_path, approved_scope, now)
    plan = _prepare_promotion(
        service,
        observation_plan,
        observation_outcome,
        approved_scope,
        now,
    )
    values = plan.model_dump(mode="python", exclude={"promotion_plan_id"})
    values["limits"] = plan.limits
    values["selections"] = plan.selections
    values["source_checkpoint_id"] = "f" * 64
    drifted = type(plan).create(**values)
    with pytest.raises(OpenApiDiscoveryPromotionRejected, match="binding drifted"):
        service.execute(
            drifted, scope=approved_scope, now=now + timedelta(seconds=2)
        )
    with pytest.raises(ValidationError):
        type(plan).model_validate(
            plan.model_dump(mode="python")
            | {
                "target_url": "https://outside.example/",
                "execution_authorized": True,
            }
        )
    assert promotion_store.state(drifted.promotion_plan_id) is None
    _close(red_store, endpoint_store, observation_store)
