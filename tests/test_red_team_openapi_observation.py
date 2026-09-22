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
    EvidenceAssertionMaterializationLimits,
    EvidenceAssertionMaterializationRecoveryRequired,
    EvidenceAssertionMaterializationRejected,
    EvidenceAssertionMaterializationService,
    EvidenceAssertionMaterializationState,
    EvidenceAssertionMaterializationStore,
    EvidenceAssertionMaterializationTimedOut,
    EvidenceAssessmentLimits,
    EvidenceAssessmentService,
    EvidenceAssessmentStore,
    EvidenceAssessmentVerdict,
    EvidenceFactKind,
    EvidenceFactVerdict,
    EvidenceReplayValidationLimits,
    EvidenceReplayValidationRecoveryRequired,
    EvidenceReplayValidationRejected,
    EvidenceReplayValidationService,
    EvidenceReplayValidationState,
    EvidenceReplayValidationStore,
    EvidenceReplayValidationTimedOut,
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


def _runtime(
    tmp_path,
    approved_scope,
    now,
    *,
    document=None,
    raw_json=None,
    evidence_root=None,
    transcript_marker=None,
):
    red_store = RedTeamStore(tmp_path / "red-team.sqlite3")
    endpoint_store = EndpointReconStore(tmp_path / "endpoint-recon.sqlite3")
    observation_store = OpenApiObservationStore(tmp_path / "openapi.sqlite3")
    evidence_store = EvidenceStore(evidence_root or tmp_path / "evidence")
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
        "content-type: application/json\n"
        + (f"fixture-run: {transcript_marker}\n" if transcript_marker else "")
        + "\n"
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


def _materialization_runtime(
    tmp_path,
    approved_scope,
    now,
    body,
    *,
    monotonic=None,
    evidence_root=None,
    transcript_marker=None,
):
    _, red_store, endpoint_store, openapi_store, endpoint_plan, transport = _runtime(
        tmp_path,
        approved_scope,
        now,
        raw_json=body,
        evidence_root=evidence_root,
        transcript_marker=transcript_marker,
    )
    store = EvidenceAssertionMaterializationStore(
        tmp_path / "assertion-materialization.sqlite3"
    )
    service = EvidenceAssertionMaterializationService(
        red_team_store=red_store,
        endpoint_recon_store=endpoint_store,
        materialization_store=store,
        evidence_store=EvidenceStore(evidence_root or tmp_path / "evidence"),
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


def _prepare_materialization(service, endpoint_plan, scope, now, *, limits=None):
    return service.prepare(
        endpoint_recon_plan_id=endpoint_plan.endpoint_recon_plan_id,
        scope=scope,
        limits=limits or EvidenceAssertionMaterializationLimits(),
        now=now + timedelta(seconds=1),
        deadline=now + timedelta(minutes=1),
        idempotency_key="b3.2:materialize",
    )


def _close_materialization(red_store, endpoint_store, openapi_store, store):
    red_store.close()
    endpoint_store.close()
    openapi_store.close()
    store.close()


def test_sealed_redacted_get_materializes_bounded_assertions_only(
    tmp_path, approved_scope, now
):
    body = json.dumps(
        {"records": [{"email": "[REDACTED]", "display": "fixture-user"}]},
        sort_keys=True,
        separators=(",", ":"),
    )
    (
        service,
        red_store,
        endpoint_store,
        openapi_store,
        store,
        endpoint_plan,
        transport,
    ) = _materialization_runtime(tmp_path, approved_scope, now, body)
    plan = _prepare_materialization(service, endpoint_plan, approved_scope, now)
    outcome = service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=1)
    )

    materialization = outcome.materialization
    by_fact = {item.fact: item for item in materialization.assertions}
    assert len(by_fact) == 6
    assert (
        by_fact[EvidenceFactKind.SENSITIVE_DATA_CLASS_PRESENT].verdict
        is EvidenceFactVerdict.SUPPORTED
    )
    assert materialization.matched_field_count == 1
    assert materialization.raw_values_retained is False
    assert materialization.field_names_retained is False
    assert materialization.request_execution_authorized is False
    assert materialization.candidate_proposal_eligible is False
    assert materialization.finding_authorized is False
    encoded = materialization.model_dump_json()
    assert "fixture-user" not in encoded
    assert "email" not in encoded
    assert len(transport.calls) == 1
    assert service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=2)
    ) == outcome
    assert store.state(plan.plan_id) == (
        EvidenceAssertionMaterializationState.COMPLETED,
        1,
    )

    assessment_store = EvidenceAssessmentStore(tmp_path / "assessment.sqlite3")
    assessment_service = EvidenceAssessmentService(
        store=assessment_store,
        evidence_store=EvidenceStore(tmp_path / "evidence"),
    )
    assessment_plan = assessment_service.prepare(
        target_id=plan.target_id,
        target_version=plan.target_version,
        scope=approved_scope,
        assertions=materialization.assertions,
        limits=EvidenceAssessmentLimits(),
        now=now + timedelta(seconds=2),
        deadline=now + timedelta(minutes=1),
        idempotency_key="b3.2:partial-assessment",
    )
    assessment = assessment_service.execute(
        assessment_plan,
        scope=approved_scope,
        now=now + timedelta(seconds=3),
    ).assessment
    assert assessment.verdict is EvidenceAssessmentVerdict.INCONCLUSIVE
    assert assessment.cleanup_requirement_satisfied is True
    assert assessment.candidate_proposal_eligible is False
    assert EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED in assessment.unresolved_facts
    assert EvidenceFactKind.ACCESS_CONTROL_ENFORCED in assessment.unresolved_facts
    assessment_store.close()
    _close_materialization(red_store, endpoint_store, openapi_store, store)


def test_absence_is_inconclusive_and_unredacted_sensitive_value_is_rejected(
    tmp_path, approved_scope, now
):
    body = json.dumps({"status": "ok"}, sort_keys=True, separators=(",", ":"))
    (
        service,
        red_store,
        endpoint_store,
        openapi_store,
        store,
        endpoint_plan,
        _,
    ) = _materialization_runtime(tmp_path / "absent", approved_scope, now, body)
    plan = _prepare_materialization(service, endpoint_plan, approved_scope, now)
    materialization = service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=1)
    ).materialization
    assert (
        materialization.sensitive_data_presence
        is EvidenceFactVerdict.INCONCLUSIVE
    )
    assert materialization.matched_field_count == 0
    _close_materialization(red_store, endpoint_store, openapi_store, store)

    body = json.dumps(
        {"email": "synthetic-unredacted-value"},
        sort_keys=True,
        separators=(",", ":"),
    )
    (
        service,
        red_store,
        endpoint_store,
        openapi_store,
        store,
        endpoint_plan,
        _,
    ) = _materialization_runtime(tmp_path / "unsafe", approved_scope, now, body)
    plan = _prepare_materialization(service, endpoint_plan, approved_scope, now)
    with pytest.raises(EvidenceAssertionMaterializationRejected, match="not redacted"):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    assert store.state(plan.plan_id) is None
    _close_materialization(red_store, endpoint_store, openapi_store, store)


def test_materializer_rejects_malformed_or_over_budget_json(
    tmp_path, approved_scope, now
):
    cases = (
        ('{"email":"[REDACTED]","email":"[REDACTED]"}', None, "duplicate"),
        (
            json.dumps({"outer": {"email": "[REDACTED]"}}),
            EvidenceAssertionMaterializationLimits(max_depth=2),
            "structure budget",
        ),
    )
    for index, (body, limits, message) in enumerate(cases):
        (
            service,
            red_store,
            endpoint_store,
            openapi_store,
            store,
            endpoint_plan,
            _,
        ) = _materialization_runtime(
            tmp_path / str(index), approved_scope, now, body
        )
        plan = _prepare_materialization(
            service,
            endpoint_plan,
            approved_scope,
            now,
            limits=limits,
        )
        with pytest.raises(EvidenceAssertionMaterializationRejected, match=message):
            service.execute(
                plan, scope=approved_scope, now=now + timedelta(seconds=1)
            )
        assert store.state(plan.plan_id) is None
        _close_materialization(red_store, endpoint_store, openapi_store, store)


def test_materializer_timeout_binding_and_started_recovery(
    tmp_path, approved_scope, now
):
    body = json.dumps({"email": "[REDACTED]"})
    ticks = iter((0.0, 11.0))
    (
        service,
        red_store,
        endpoint_store,
        openapi_store,
        store,
        endpoint_plan,
        _,
    ) = _materialization_runtime(
        tmp_path / "timeout",
        approved_scope,
        now,
        body,
        monotonic=lambda: next(ticks),
    )
    plan = _prepare_materialization(service, endpoint_plan, approved_scope, now)
    with pytest.raises(EvidenceAssertionMaterializationTimedOut):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    assert store.state(plan.plan_id) is None
    _close_materialization(red_store, endpoint_store, openapi_store, store)

    (
        service,
        red_store,
        endpoint_store,
        openapi_store,
        store,
        endpoint_plan,
        _,
    ) = _materialization_runtime(
        tmp_path / "recovery", approved_scope, now, body
    )
    plan = _prepare_materialization(service, endpoint_plan, approved_scope, now)
    values = plan.model_dump(mode="python", exclude={"plan_id"})
    values["limits"] = plan.limits
    values["source_checkpoint_id"] = "f" * 64
    drifted = type(plan).create(**values)
    with pytest.raises(EvidenceAssertionMaterializationRejected, match="binding drifted"):
        service.execute(
            drifted, scope=approved_scope, now=now + timedelta(seconds=1)
        )
    assert store.state(drifted.plan_id) is None

    store.claim(plan, now=now + timedelta(seconds=1))
    with pytest.raises(
        EvidenceAssertionMaterializationRecoveryRequired, match="unfinished"
    ):
        service.execute(plan, scope=approved_scope, now=now + timedelta(seconds=1))
    outcome = service.recover(
        plan, scope=approved_scope, now=now + timedelta(seconds=2)
    )
    assert outcome.attempt == 2
    assert outcome.cleanup_complete is True
    assert store.state(plan.plan_id) == (
        EvidenceAssertionMaterializationState.COMPLETED,
        2,
    )
    _close_materialization(red_store, endpoint_store, openapi_store, store)


def test_materialization_schema_cannot_retain_raw_data_or_grant_authority(
    tmp_path, approved_scope, now
):
    body = json.dumps({"email": "[REDACTED]"})
    (
        service,
        red_store,
        endpoint_store,
        openapi_store,
        store,
        endpoint_plan,
        _,
    ) = _materialization_runtime(tmp_path, approved_scope, now, body)
    plan = _prepare_materialization(service, endpoint_plan, approved_scope, now)
    materialization = service.execute(
        plan, scope=approved_scope, now=now + timedelta(seconds=1)
    ).materialization
    with pytest.raises(ValidationError):
        type(materialization).model_validate(
            materialization.model_dump(mode="python")
            | {
                "raw_values_retained": True,
                "field_names_retained": True,
                "request_execution_authorized": True,
                "candidate_proposal_eligible": True,
                "finding_authorized": True,
                "raw_values": ["forbidden"],
            }
        )
    _close_materialization(red_store, endpoint_store, openapi_store, store)


class _MaterializationPairSource:
    def __init__(self, pairs):
        self.plans = {plan.plan_id: plan for plan, _ in pairs}
        self.outcomes = {plan.plan_id: outcome for plan, outcome in pairs}

    def plan(self, plan_id):
        return self.plans[plan_id]

    def outcome(self, plan_id):
        return self.outcomes[plan_id]


def _independent_materializations(
    tmp_path,
    approved_scope,
    now,
    *,
    baseline_body,
    current_body=None,
):
    evidence_root = tmp_path / "evidence"
    pairs = []
    handles = []
    transports = []
    for name, offset, body in (
        ("baseline", 0, baseline_body),
        ("current", 4, current_body or baseline_body),
    ):
        run_now = now + timedelta(seconds=offset)
        (
            service,
            red_store,
            endpoint_store,
            openapi_store,
            store,
            endpoint_plan,
            transport,
        ) = _materialization_runtime(
            tmp_path / name,
            approved_scope,
            run_now,
            body,
            evidence_root=evidence_root,
            transcript_marker=name,
        )
        plan = _prepare_materialization(
            service, endpoint_plan, approved_scope, run_now
        )
        outcome = service.execute(
            plan,
            scope=approved_scope,
            now=run_now + timedelta(seconds=1),
        )
        pairs.append((plan, outcome))
        handles.append((red_store, endpoint_store, openapi_store, store))
        transports.append(transport)
    return pairs, handles, transports, evidence_root


def _prepare_replay(service, pairs, scope, now):
    return service.prepare(
        baseline_materialization_plan_id=pairs[0][0].plan_id,
        current_materialization_plan_id=pairs[1][0].plan_id,
        scope=scope,
        limits=EvidenceReplayValidationLimits(),
        now=now + timedelta(seconds=6),
        deadline=now + timedelta(minutes=1),
        idempotency_key="b3.3:independent-replay",
    )


def _close_independent_materializations(handles):
    for handle in handles:
        _close_materialization(*handle)


def test_independent_replay_materializes_validation_assertions_without_request(
    tmp_path, approved_scope, now
):
    body = json.dumps(
        {"records": [{"email": "[REDACTED]", "display": "fixture-user"}]},
        sort_keys=True,
        separators=(",", ":"),
    )
    pairs, handles, transports, evidence_root = _independent_materializations(
        tmp_path,
        approved_scope,
        now,
        baseline_body=body,
    )
    replay_store = EvidenceReplayValidationStore(tmp_path / "replay.sqlite3")
    replay_service = EvidenceReplayValidationService(
        materialization_source=_MaterializationPairSource(pairs),
        store=replay_store,
        evidence_store=EvidenceStore(evidence_root),
    )
    plan = _prepare_replay(replay_service, pairs, approved_scope, now)
    outcome = replay_service.execute(
        plan,
        scope=approved_scope,
        now=now + timedelta(seconds=6),
    )

    validation = outcome.validation
    by_fact = {item.fact: item for item in validation.assertions}
    assert validation.content_match is True
    assert validation.replay_verdict is EvidenceFactVerdict.SUPPORTED
    assert set(by_fact) == {
        EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED,
        EvidenceFactKind.REDACTION_BOUNDARY_PROVEN,
    }
    assert all(
        item.evidence_refs == plan.evidence_refs
        and item.context_id == plan.plan_id
        and item.producer_ref == "validator:sealed-get-replay-v1"
        for item in validation.assertions
    )
    assert validation.request_execution_authorized is False
    assert validation.candidate_proposal_eligible is False
    assert validation.finding_authorized is False
    assert [len(transport.calls) for transport in transports] == [1, 1]
    assert replay_service.execute(
        plan,
        scope=approved_scope,
        now=now + timedelta(seconds=7),
    ) == outcome
    assert replay_store.state(plan.plan_id) == (
        EvidenceReplayValidationState.COMPLETED,
        1,
    )

    baseline_assertions = tuple(
        item
        for item in pairs[0][1].materialization.assertions
        if item.fact is not EvidenceFactKind.REDACTION_BOUNDARY_PROVEN
    )
    assessment_store = EvidenceAssessmentStore(tmp_path / "assessment.sqlite3")
    assessment_service = EvidenceAssessmentService(
        store=assessment_store,
        evidence_store=EvidenceStore(evidence_root),
    )
    assessment_plan = assessment_service.prepare(
        target_id=plan.target_id,
        target_version=plan.target_version,
        scope=approved_scope,
        assertions=baseline_assertions + validation.assertions,
        limits=EvidenceAssessmentLimits(),
        now=now + timedelta(seconds=7),
        deadline=now + timedelta(minutes=1),
        idempotency_key="b3.3:partial-assessment",
    )
    assessment = assessment_service.execute(
        assessment_plan,
        scope=approved_scope,
        now=now + timedelta(seconds=8),
    ).assessment
    assert assessment.verdict is EvidenceAssessmentVerdict.INCONCLUSIVE
    assert EvidenceFactKind.INDEPENDENT_REPLAY_MATCHED in assessment.satisfied_facts
    assert EvidenceFactKind.REDACTION_BOUNDARY_PROVEN in assessment.satisfied_facts
    assert EvidenceFactKind.ACCESS_CONTROL_ENFORCED in assessment.unresolved_facts
    assert assessment.candidate_proposal_eligible is False
    assessment_store.close()
    replay_store.close()
    _close_independent_materializations(handles)


def test_independent_replay_mismatch_is_inconclusive(tmp_path, approved_scope, now):
    baseline = json.dumps({"email": "[REDACTED]", "page": 1}, sort_keys=True)
    current = json.dumps({"email": "[REDACTED]", "page": 2}, sort_keys=True)
    pairs, handles, transports, evidence_root = _independent_materializations(
        tmp_path,
        approved_scope,
        now,
        baseline_body=baseline,
        current_body=current,
    )
    store = EvidenceReplayValidationStore(tmp_path / "replay.sqlite3")
    service = EvidenceReplayValidationService(
        materialization_source=_MaterializationPairSource(pairs),
        store=store,
        evidence_store=EvidenceStore(evidence_root),
    )
    plan = _prepare_replay(service, pairs, approved_scope, now)
    validation = service.execute(
        plan,
        scope=approved_scope,
        now=now + timedelta(seconds=6),
    ).validation
    assert validation.content_match is False
    assert validation.replay_verdict is EvidenceFactVerdict.INCONCLUSIVE
    assert validation.candidate_proposal_eligible is False
    assert [len(transport.calls) for transport in transports] == [1, 1]
    store.close()
    _close_independent_materializations(handles)


def test_replay_rejects_same_execution_missing_evidence_and_binding_drift(
    tmp_path, approved_scope, now
):
    body = json.dumps({"email": "[REDACTED]"})
    pairs, handles, _, evidence_root = _independent_materializations(
        tmp_path,
        approved_scope,
        now,
        baseline_body=body,
    )
    source = _MaterializationPairSource(pairs)
    store = EvidenceReplayValidationStore(tmp_path / "replay.sqlite3")
    service = EvidenceReplayValidationService(
        materialization_source=source,
        store=store,
        evidence_store=EvidenceStore(evidence_root),
    )
    with pytest.raises(EvidenceReplayValidationRejected, match="independent"):
        service.prepare(
            baseline_materialization_plan_id=pairs[0][0].plan_id,
            current_materialization_plan_id=pairs[0][0].plan_id,
            scope=approved_scope,
            limits=EvidenceReplayValidationLimits(),
            now=now + timedelta(seconds=6),
            deadline=now + timedelta(minutes=1),
            idempotency_key="b3.3:same-run",
        )

    unavailable = EvidenceReplayValidationService(
        materialization_source=source,
        store=store,
        evidence_store=EvidenceStore(tmp_path / "empty-evidence"),
    )
    with pytest.raises(EvidenceReplayValidationRejected, match="integrity"):
        _prepare_replay(unavailable, pairs, approved_scope, now)

    plan = _prepare_replay(service, pairs, approved_scope, now)
    values = plan.model_dump(mode="python", exclude={"plan_id"})
    values["limits"] = plan.limits
    values["current_snapshot_id"] = "f" * 64
    drifted = type(plan).create(**values)
    with pytest.raises(EvidenceReplayValidationRejected, match="binding drifted"):
        service.execute(
            drifted,
            scope=approved_scope,
            now=now + timedelta(seconds=6),
        )
    assert store.state(drifted.plan_id) is None
    store.close()
    _close_independent_materializations(handles)


def test_replay_timeout_started_recovery_and_schema_authority_boundary(
    tmp_path, approved_scope, now
):
    body = json.dumps({"email": "[REDACTED]"})
    pairs, handles, _, evidence_root = _independent_materializations(
        tmp_path,
        approved_scope,
        now,
        baseline_body=body,
    )
    source = _MaterializationPairSource(pairs)
    timeout_store = EvidenceReplayValidationStore(tmp_path / "timeout.sqlite3")
    ticks = iter((0.0, 11.0))
    timeout_service = EvidenceReplayValidationService(
        materialization_source=source,
        store=timeout_store,
        evidence_store=EvidenceStore(evidence_root),
        monotonic=lambda: next(ticks),
    )
    timeout_plan = _prepare_replay(timeout_service, pairs, approved_scope, now)
    with pytest.raises(EvidenceReplayValidationTimedOut):
        timeout_service.execute(
            timeout_plan,
            scope=approved_scope,
            now=now + timedelta(seconds=6),
        )
    assert timeout_store.state(timeout_plan.plan_id) is None
    timeout_store.close()

    store = EvidenceReplayValidationStore(tmp_path / "recovery.sqlite3")
    service = EvidenceReplayValidationService(
        materialization_source=source,
        store=store,
        evidence_store=EvidenceStore(evidence_root),
    )
    plan = _prepare_replay(service, pairs, approved_scope, now)
    store.claim(plan, now=now + timedelta(seconds=6))
    with pytest.raises(EvidenceReplayValidationRecoveryRequired, match="unfinished"):
        service.execute(
            plan,
            scope=approved_scope,
            now=now + timedelta(seconds=6),
        )
    outcome = service.recover(
        plan,
        scope=approved_scope,
        now=now + timedelta(seconds=7),
    )
    assert outcome.attempt == 2
    assert outcome.cleanup_complete is True
    assert store.state(plan.plan_id) == (EvidenceReplayValidationState.COMPLETED, 2)
    with pytest.raises(ValidationError):
        type(outcome.validation).model_validate(
            outcome.validation.model_dump(mode="python")
            | {
                "request_execution_authorized": True,
                "candidate_proposal_eligible": True,
                "finding_authorized": True,
                "raw_values": ["forbidden"],
            }
        )
    encoded = outcome.validation.model_dump_json()
    assert "[REDACTED]" not in encoded
    assert "email" not in encoded
    store.close()
    _close_independent_materializations(handles)


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
