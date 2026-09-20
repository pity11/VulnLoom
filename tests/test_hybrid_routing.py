from __future__ import annotations

import json
import stat
from datetime import timedelta
from uuid import uuid4

import pytest

from vulnloom.broker import (
    HttpMethod,
    OfflineHttpHop,
    OfflineHttpTransport,
    StaticResolver,
    ToolBroker,
    default_tool_registry,
)
from vulnloom.broker.models import url_digest
from vulnloom.domain.models import CandidateState, EvidenceKind, ValidationResult
from vulnloom.evidence import EvidenceStore
from vulnloom.hybrid import (
    DeploymentProof,
    EnvironmentLiveEndpointProvider,
    HybridRouteIdempotencyConflict,
    HybridRouteOutcome,
    HybridRoutePolicy,
    HybridRouteRecoveryRequired,
    HybridRouteRequest,
    HybridRouteService,
    HybridRouteState,
    HybridRouteStore,
    LiveEndpointReference,
)
from vulnloom.runners import OfflineSandboxRunner
from vulnloom.validation import DeterministicHttpJudge, ValidationService, ValidationStore

URL = "https://app.example.test/items/7"
OUTSIDE_URL = "https://outside.example/items/7"


def _proof(candidate, now, *, endpoint=URL):
    return DeploymentProof.create(
        source_target_id=candidate.target_id,
        source_target_version=candidate.target_version,
        source_manifest_digest="3" * 64,
        live_target_id=uuid4(),
        endpoint_url_digest=url_digest(endpoint),
        deployed_artifact_digest="4" * 64,
        attestation_evidence_ref="5" * 64,
        attested_by="operator:release",
        attested_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(hours=1),
    )


def _runtime(tmp_path, candidate, now, *, endpoint=URL, clock=None):
    reference = LiveEndpointReference.create(
        configuration_key="HYBRID_ENDPOINT_PREPROD_APP"
    )
    provider = EnvironmentLiveEndpointProvider(
        {reference.configuration_key: endpoint}, allowed_references=(reference,)
    )
    policy = HybridRoutePolicy.create(
        validation_image_digest="sha256:" + "6" * 64,
        tool_registry_digest=default_tool_registry().digest,
    )
    store = HybridRouteStore(tmp_path / "hybrid-route.sqlite3")
    kwargs = {
        "policy": policy,
        "tool_registry": default_tool_registry(),
        "endpoint_provider": provider,
        "store": store,
    }
    if clock is not None:
        kwargs["monotonic"] = clock
    service = HybridRouteService(**kwargs)
    return service, store, policy, reference


def _request(service, candidate, proof, reference, scope, now, *, key="hybrid-route:1"):
    return service.prepare(
        candidate=candidate,
        deployment_proof=proof,
        endpoint_reference=reference,
        expected_status_code=200,
        expected_body_sha256="7" * 64,
        test_class="read_only",
        scope=scope,
        selected_by="operator:hybrid",
        created_at=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key=key,
    )


def test_hybrid_route_materializes_one_exact_safe_validation_and_replays(
    tmp_path, approved_scope, candidate, now
):
    service, store, _, reference = _runtime(tmp_path, candidate, now)
    proof = _proof(candidate, now)
    request = _request(service, candidate, proof, reference, approved_scope, now)

    first = service.execute(
        request,
        candidate=candidate,
        deployment_proof=proof,
        scope=approved_scope,
        now=now,
    )
    replay = service.execute(
        request,
        candidate=candidate,
        deployment_proof=proof,
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )
    plan = store.prepared_validation(request.route_id)

    assert replay == first
    assert first.state is HybridRouteState.COMPLETED
    assert first.validation_plan_id == plan.plan_id
    assert len(plan.broker_calls) == 1
    call = plan.broker_calls[0]
    assert call.http is not None
    assert call.http.method is HttpMethod.GET
    assert call.http.url == URL
    assert not call.http.headers
    assert call.http.credential_ref is None
    assert call.http.body_ref is None
    assert not call.http.follow_redirects
    assert call.http.limits.max_redirects == 0
    assert call.http.limits.max_requests == 1
    assert plan.runner_request.environment == {
        "VULNLOOM_TASK_ID": str(plan.runner_request.task.task_id)
    }
    assert plan.runner_request.task.allowed_tools == {"sandbox.test"}
    assert plan.runner_request.profile.allowed_tools == {"sandbox.test"}
    projection = first.model_dump_json()
    assert URL not in projection
    assert reference.configuration_key not in projection
    assert "authorization" not in projection.lower()
    assert stat.S_IMODE((tmp_path / "hybrid-route.sqlite3").stat().st_mode) == 0o600
    store.close()


def test_routed_plan_executes_only_through_offline_trusted_validation(
    tmp_path, approved_scope, candidate, now
):
    route_service, route_store, _, reference = _runtime(tmp_path, candidate, now)
    proof = _proof(candidate, now)
    request = _request(route_service, candidate, proof, reference, approved_scope, now)
    route_service.execute(
        request,
        candidate=candidate,
        deployment_proof=proof,
        scope=approved_scope,
        now=now,
    )
    plan = route_store.prepared_validation(request.route_id)
    evidence_store = EvidenceStore(tmp_path / "evidence")
    evidence = evidence_store.capture_text(
        "redacted routed HTTP facts",
        kind=EvidenceKind.HTTP,
        source_ref="url-sha256:" + url_digest(URL),
        producer="test.hybrid.route",
        target_version=candidate.target_version,
        summary="exact routed endpoint matched",
    )
    broker = ToolBroker(
        scope=approved_scope,
        registry=default_tool_registry(),
        resolver=StaticResolver({"app.example.test": ("192.0.2.10",)}),
        http_transport=OfflineHttpTransport(
            {
                URL: OfflineHttpHop(
                    status_code=200,
                    peer_ip="192.0.2.10",
                    response_bytes=32,
                    response_body_sha256="7" * 64,
                    evidence_ref=evidence.evidence_id,
                )
            }
        ),
    )
    validation_store = ValidationStore(tmp_path / "validation.sqlite3")
    validation_service = ValidationService(
        scope=approved_scope,
        runner=OfflineSandboxRunner(frozenset({"sandbox.test"})),
        broker=broker,
        store=validation_store,
        evidence_store=evidence_store,
        judge=DeterministicHttpJudge(
            trusted_registry_digest=default_tool_registry().digest
        ),
    )
    outcome = validation_service.execute(candidate, plan, now=now)
    assert outcome.verdict.result is ValidationResult.REPRODUCED
    assert outcome.validation_run.result is ValidationResult.REPRODUCED
    assert outcome.evidence_bundle is not None
    assert outcome.evidence_bundle.evidence_refs == (evidence.evidence_id,)
    validation_store.close()
    route_store.close()


def test_hybrid_route_rejects_source_and_scope_drift_before_claim(
    tmp_path, approved_scope, candidate, now
):
    service, store, _, reference = _runtime(tmp_path, candidate, now)
    proof = _proof(candidate, now)
    request = _request(service, candidate, proof, reference, approved_scope, now)

    changed = candidate.model_copy(update={"state": CandidateState.REJECTED})
    with pytest.raises(ValueError, match="authorized source"):
        service.execute(
            request,
            candidate=changed,
            deployment_proof=proof,
            scope=approved_scope,
            now=now,
        )
    drifted_scope = approved_scope.model_copy(update={"version": approved_scope.version + 1})
    with pytest.raises(ValueError, match="authorized source"):
        service.execute(
            request,
            candidate=candidate,
            deployment_proof=proof,
            scope=drifted_scope,
            now=now,
        )
    assert store.state(request.route_id) is None
    store.close()


def test_hybrid_route_fails_closed_for_digest_scope_and_reference_errors(
    tmp_path, approved_scope, candidate, now
):
    service, store, _, reference = _runtime(
        tmp_path, candidate, now, endpoint=OUTSIDE_URL
    )
    proof = _proof(candidate, now, endpoint=OUTSIDE_URL)
    request = _request(service, candidate, proof, reference, approved_scope, now)
    outcome = service.execute(
        request,
        candidate=candidate,
        deployment_proof=proof,
        scope=approved_scope,
        now=now,
    )
    assert outcome.state is HybridRouteState.FAILED
    assert outcome.reason_code == "hybrid_endpoint_admission_failed"
    assert outcome.cleanup_complete
    with pytest.raises(HybridRouteRecoveryRequired):
        store.prepared_validation(request.route_id)
    store.close()

    service, store, _, reference = _runtime(tmp_path / "digest", candidate, now)
    proof = _proof(candidate, now, endpoint=OUTSIDE_URL)
    request = _request(
        service, candidate, proof, reference, approved_scope, now, key="hybrid-route:2"
    )
    outcome = service.execute(
        request,
        candidate=candidate,
        deployment_proof=proof,
        scope=approved_scope,
        now=now,
    )
    assert outcome.state is HybridRouteState.FAILED
    assert outcome.cleanup_complete
    store.close()


def test_hybrid_route_timeout_closes_without_persisting_raw_plan(
    tmp_path, approved_scope, candidate, now
):
    ticks = iter((0.0, 11.0))
    service, store, _, reference = _runtime(
        tmp_path, candidate, now, clock=lambda: next(ticks)
    )
    proof = _proof(candidate, now)
    request = _request(service, candidate, proof, reference, approved_scope, now)
    outcome = service.execute(
        request,
        candidate=candidate,
        deployment_proof=proof,
        scope=approved_scope,
        now=now,
    )
    assert outcome.state is HybridRouteState.TIMED_OUT
    assert outcome.cleanup_complete
    assert outcome.validation_plan_id is None
    with pytest.raises(HybridRouteRecoveryRequired):
        store.prepared_validation(request.route_id)
    store.close()


def test_hybrid_route_recovery_and_idempotency_are_bounded(
    tmp_path, approved_scope, candidate, now
):
    service, store, policy, reference = _runtime(tmp_path, candidate, now)
    proof = _proof(candidate, now)
    request = _request(service, candidate, proof, reference, approved_scope, now)
    store.claim(request, now=now)
    with pytest.raises(HybridRouteRecoveryRequired):
        service.execute(
            request,
            candidate=candidate,
            deployment_proof=proof,
            scope=approved_scope,
            now=now,
        )
    outcome = service.execute(
        request,
        candidate=candidate,
        deployment_proof=proof,
        scope=approved_scope,
        now=now,
        recover=True,
    )
    assert outcome.attempt == 2

    collision = request.model_copy(
        update={"route_id": "a" * 64, "candidate_digest": "b" * 64}
    )
    with pytest.raises(HybridRouteIdempotencyConflict):
        store.claim(collision, now=now)
    store.close()

    service, store, policy, reference = _runtime(tmp_path / "exhaust", candidate, now)
    request = _request(
        service, candidate, proof, reference, approved_scope, now, key="hybrid-route:3"
    )
    store.claim(request, now=now)
    store.recover(request, policy, now=now + timedelta(seconds=1))
    store.recover(request, policy, now=now + timedelta(seconds=2))
    with pytest.raises(HybridRouteRecoveryRequired, match="exhausted"):
        store.recover(request, policy, now=now + timedelta(seconds=3))
    assert store.state(request.route_id) == (HybridRouteState.FAILED, 3)
    store.close()


def test_hybrid_route_contracts_are_redacted_and_closed():
    schemas = " ".join(
        json.dumps(model.model_json_schema()).lower()
        for model in (
            LiveEndpointReference,
            HybridRoutePolicy,
            HybridRouteRequest,
            HybridRouteOutcome,
        )
    )
    for forbidden in (
        '"url"',
        "authorization",
        "cookie",
        "credential",
        "response_body",
        "api_key",
        "secret",
    ):
        assert forbidden not in schemas
