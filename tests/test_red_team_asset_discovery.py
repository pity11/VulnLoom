from __future__ import annotations

import sqlite3
from datetime import timedelta

import pytest
from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.red_team.asset_discovery_adapters import (
    AssetDiscoveryAdapterInterrupted,
    OfflineAssetDiscoveryAdapter,
)
from vulnloom.red_team.asset_discovery_models import (
    AssetAdmissionVerdict,
    AssetAttributionEvidence,
    AssetAttributionKind,
    AssetAuthorizationMode,
    AssetDiscoveryBatch,
    AssetDiscoveryLimits,
    AssetDiscoveryObservation,
    AssetDiscoverySelectorKind,
    AssetDiscoverySource,
    AssetDiscoveryState,
    AssetLocatorKind,
    AttributionVerdict,
    DiscoveredAsset,
)
from vulnloom.red_team.asset_discovery_service import (
    AssetDiscoveryRejected,
    AssetDiscoveryService,
    AssetDiscoveryTimedOut,
)
from vulnloom.red_team.asset_discovery_store import (
    AssetDiscoveryRecoveryRequired,
    AssetDiscoveryStore,
    AssetDiscoveryStoreRejected,
)

_CONNECTIONS: list[sqlite3.Connection] = []


@pytest.fixture(autouse=True)
def _close_connections():
    yield
    while _CONNECTIONS:
        _CONNECTIONS.pop().close()


def _service(adapter, *, monotonic=None):
    connection = sqlite3.connect(":memory:")
    _CONNECTIONS.append(connection)
    kwargs = {
        "store": AssetDiscoveryStore(connection),
        "adapter": adapter,
    }
    if monotonic is not None:
        kwargs["monotonic"] = monotonic
    return AssetDiscoveryService(**kwargs)


def _authorization(service, scope, now, *, mode=AssetAuthorizationMode.ENTITY_BOUND):
    return service.authorize(
        scope=scope,
        mode=mode,
        exact_hosts=("app.example.test",),
        root_domains=() if mode is AssetAuthorizationMode.EXACT_ASSIGNMENT else ("example.test",),
        icp_registration_digests=(
            ()
            if mode is AssetAuthorizationMode.EXACT_ASSIGNMENT
            else (canonical_digest("Example ICP 42"),)
        ),
        excluded_domain_suffixes=("hospital.example.test",),
        allowed_sources=(
            AssetDiscoverySource.FOFA,
            AssetDiscoverySource.ICP_REGISTRY,
            AssetDiscoverySource.SHODAN,
        ),
        now=now,
    )


def _plan(service, scope, authorization, now, *, selector=None, limit=10):
    return service.prepare(
        authorization=authorization,
        scope=scope,
        selectors=(
            selector
            or (
                AssetDiscoverySource.FOFA,
                AssetDiscoverySelectorKind.DOMAIN,
                "example.test",
                limit,
            ),
        ),
        limits=AssetDiscoveryLimits(max_records=limit),
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="asset-discovery-1",
    )


def _observation(
    plan,
    now,
    *,
    locator="portal.example.test",
    evidence_kind=None,
    subject=None,
    query_index=0,
):
    query = plan.queries[query_index]
    asset = DiscoveredAsset.create(
        plan_id=plan.plan_id,
        query_id=query.query_id,
        source=query.source,
        locator_kind=(
            AssetLocatorKind.IP_ADDRESS
            if locator[0].isdigit()
            else AssetLocatorKind.HOSTNAME
        ),
        locator=locator,
        port=443,
        scheme="https",
        observed_at=now - timedelta(days=2),
        source_record_ref=f"fixture:record-{query_index}-{locator.replace('.', '-')}",
        source_evidence_digest="a" * 64,
    )
    attribution = ()
    if evidence_kind is not None:
        evidence = AssetAttributionEvidence.create(
            asset_id=asset.asset_id,
            kind=evidence_kind,
            verdict=AttributionVerdict.SUPPORTED,
            evidence_ref="b" * 64,
            subject_digest=canonical_digest(subject or locator),
            observed_at=now,
        )
        attribution = (evidence,)
    return AssetDiscoveryObservation(asset=asset, attribution=attribution)


def _batch(plan, observations, *, query_index=0):
    return AssetDiscoveryBatch(
        query_id=plan.queries[query_index].query_id,
        observations=tuple(observations),
    )


def test_fofa_domain_discovery_admits_related_asset_and_publishes_atomically(
    approved_scope, now
):
    adapter = OfflineAssetDiscoveryAdapter({})
    service = _service(adapter)
    authorization = _authorization(service, approved_scope, now)
    plan = _plan(service, approved_scope, authorization, now)
    observation = _observation(
        plan,
        now,
        evidence_kind=AssetAttributionKind.AUTHORIZED_ROOT_DOMAIN,
        subject="example.test",
    )
    adapter._batches[plan.queries[0].query_id] = _batch(plan, (observation,))

    outcome = service.execute(plan, scope=approved_scope, now=now)

    assert outcome.observation_count == 1
    assert outcome.decisions[0].verdict is AssetAdmissionVerdict.ADMITTED
    assert outcome.decisions[0].reason_code == "authorized_domain_derivation"
    assert len(outcome.authorized_asset_ids) == 1
    published = service.store.authorized_asset(outcome.authorized_asset_ids[0])
    assert published.asset.locator == "portal.example.test"
    assert published.target_materialization_authorized is True
    assert published.active_testing_authorized is False
    assert published.finding_authorized is False
    assert service.execute(plan, scope=approved_scope, now=now) == outcome
    assert adapter.calls == [plan.queries[0].query_id]


def test_icp_derived_ip_can_be_admitted_but_fingerprint_only_requires_review(
    approved_scope, now
):
    adapter = OfflineAssetDiscoveryAdapter({})
    service = _service(adapter)
    authorization = _authorization(service, approved_scope, now)
    plan = _plan(
        service,
        approved_scope,
        authorization,
        now,
        selector=(
            AssetDiscoverySource.ICP_REGISTRY,
            AssetDiscoverySelectorKind.ICP_REGISTRATION,
            "Example ICP 42",
            10,
        ),
    )
    icp = _observation(
        plan,
        now,
        locator="203.0.113.10",
        evidence_kind=AssetAttributionKind.ICP_REGISTRATION_MATCH,
        subject="Example ICP 42",
    )
    fingerprint = _observation(
        plan,
        now,
        locator="198.51.100.20",
        evidence_kind=AssetAttributionKind.PRODUCT_FINGERPRINT,
    )
    adapter._batches[plan.queries[0].query_id] = _batch(plan, (icp, fingerprint))

    outcome = service.execute(plan, scope=approved_scope, now=now)

    by_asset = {item.asset_id: item for item in outcome.decisions}
    assert by_asset[icp.asset.asset_id].verdict is AssetAdmissionVerdict.ADMITTED
    assert (
        by_asset[fingerprint.asset.asset_id].verdict
        is AssetAdmissionVerdict.APPROVAL_REQUIRED
    )
    assert len(outcome.authorized_asset_ids) == 1


@pytest.mark.parametrize(
    ("locator", "kind", "reason"),
    [
        ("lab.hospital.example.test", None, "explicit_exclusion"),
        (
            "vendor.example.test",
            AssetAttributionKind.CROSS_LEGAL_ENTITY,
            "excluded_ownership",
        ),
    ],
)
def test_excluded_or_cross_entity_assets_are_rejected(
    approved_scope, now, locator, kind, reason
):
    adapter = OfflineAssetDiscoveryAdapter({})
    service = _service(adapter)
    authorization = _authorization(service, approved_scope, now)
    plan = _plan(service, approved_scope, authorization, now)
    observation = _observation(plan, now, locator=locator, evidence_kind=kind)
    adapter._batches[plan.queries[0].query_id] = _batch(plan, (observation,))

    outcome = service.execute(plan, scope=approved_scope, now=now)

    assert outcome.decisions[0].verdict is AssetAdmissionVerdict.REJECTED
    assert outcome.decisions[0].reason_code == reason
    assert outcome.authorized_asset_ids == ()


def test_supply_chain_related_asset_always_requires_approval(approved_scope, now):
    adapter = OfflineAssetDiscoveryAdapter({})
    service = _service(adapter)
    authorization = _authorization(
        service,
        approved_scope,
        now,
        mode=AssetAuthorizationMode.SUPPLY_CHAIN_WITH_APPROVAL,
    )
    plan = _plan(service, approved_scope, authorization, now)
    observation = _observation(
        plan,
        now,
        evidence_kind=AssetAttributionKind.AUTHORIZED_ROOT_DOMAIN,
        subject="example.test",
    )
    adapter._batches[plan.queries[0].query_id] = _batch(plan, (observation,))

    outcome = service.execute(plan, scope=approved_scope, now=now)

    assert outcome.decisions[0].verdict is AssetAdmissionVerdict.APPROVAL_REQUIRED
    assert outcome.decisions[0].reason_code == "supply_chain_review"
    assert service.store.authorized_asset_count() == 0


def test_exact_assignment_rejects_entity_expansion_and_unassigned_results(
    approved_scope, now
):
    adapter = OfflineAssetDiscoveryAdapter({})
    service = _service(adapter)
    with pytest.raises(AssetDiscoveryRejected, match="cannot expand"):
        service.authorize(
            scope=approved_scope,
            mode=AssetAuthorizationMode.EXACT_ASSIGNMENT,
            exact_hosts=("app.example.test",),
            root_domains=("example.test",),
            allowed_sources=(AssetDiscoverySource.FOFA,),
            now=now,
        )
    authorization = _authorization(
        service,
        approved_scope,
        now,
        mode=AssetAuthorizationMode.EXACT_ASSIGNMENT,
    )
    plan = _plan(
        service,
        approved_scope,
        authorization,
        now,
        selector=(
            AssetDiscoverySource.FOFA,
            AssetDiscoverySelectorKind.EXACT_HOST,
            "app.example.test",
            10,
        ),
    )
    observation = _observation(plan, now, locator="other.example.test")
    adapter._batches[plan.queries[0].query_id] = _batch(plan, (observation,))

    outcome = service.execute(plan, scope=approved_scope, now=now)

    assert outcome.decisions[0].verdict is AssetAdmissionVerdict.REJECTED
    assert outcome.decisions[0].reason_code == "not_exactly_assigned"


def test_exact_assignment_does_not_expand_original_port_or_scheme(
    approved_scope, now
):
    adapter = OfflineAssetDiscoveryAdapter({})
    service = _service(adapter)
    authorization = _authorization(
        service,
        approved_scope,
        now,
        mode=AssetAuthorizationMode.EXACT_ASSIGNMENT,
    )
    plan = _plan(
        service,
        approved_scope,
        authorization,
        now,
        selector=(
            AssetDiscoverySource.FOFA,
            AssetDiscoverySelectorKind.EXACT_HOST,
            "app.example.test",
            10,
        ),
    )
    query = plan.queries[0]
    wrong_port = DiscoveredAsset.create(
        plan_id=plan.plan_id,
        query_id=query.query_id,
        source=query.source,
        locator_kind=AssetLocatorKind.HOSTNAME,
        locator="app.example.test",
        port=80,
        scheme="http",
        observed_at=now,
        source_record_ref="fofa:wrong-port",
        source_evidence_digest="c" * 64,
    )
    adapter._batches[query.query_id] = _batch(
        plan, (AssetDiscoveryObservation(asset=wrong_port),)
    )

    outcome = service.execute(plan, scope=approved_scope, now=now)

    assert outcome.decisions[0].verdict is AssetAdmissionVerdict.REJECTED
    assert outcome.decisions[0].reason_code == "not_exactly_assigned"


def test_queries_are_typed_authorization_derived_and_have_no_credential_surface(
    approved_scope, now
):
    service = _service(OfflineAssetDiscoveryAdapter({}))
    authorization = _authorization(service, approved_scope, now)
    with pytest.raises(AssetDiscoveryRejected, match="could not be sealed"):
        _plan(
            service,
            approved_scope,
            authorization,
            now,
            selector=(
                AssetDiscoverySource.FOFA,
                AssetDiscoverySelectorKind.DOMAIN,
                'example.test" || body="secret',
                10,
            ),
        )
    with pytest.raises(AssetDiscoveryRejected, match="not authorization-derived"):
        _plan(
            service,
            approved_scope,
            authorization,
            now,
            selector=(
                AssetDiscoverySource.FOFA,
                AssetDiscoverySelectorKind.DOMAIN,
                "unrelated.test",
                10,
            ),
        )
    with pytest.raises(AssetDiscoveryRejected, match="unsupported by source"):
        _plan(
            service,
            approved_scope,
            authorization,
            now,
            selector=(
                AssetDiscoverySource.SHODAN,
                AssetDiscoverySelectorKind.ICP_REGISTRATION,
                "Example ICP 42",
                10,
            ),
        )

    plan = _plan(service, approved_scope, authorization, now)
    serialized = plan.model_dump_json()
    assert plan.adapter_credential_ref is None
    assert plan.worker_execution_authorized is False
    assert plan.active_scanning_authorized is False
    assert "FOFA_API_KEY" not in serialized
    assert "token" not in serialized.lower()


def test_budget_drift_scope_and_cleanup_fail_closed_without_publication(
    approved_scope, now
):
    adapter = OfflineAssetDiscoveryAdapter({})
    service = _service(adapter)
    authorization = _authorization(service, approved_scope, now)
    plan = _plan(service, approved_scope, authorization, now, limit=1)
    first = _observation(plan, now, locator="one.example.test")
    second = _observation(plan, now, locator="two.example.test")
    adapter._batches[plan.queries[0].query_id] = _batch(plan, (first, second))
    with pytest.raises(AssetDiscoveryRejected, match="result budget"):
        service.execute(plan, scope=approved_scope, now=now)
    assert service.store.authorized_asset_count() == 0
    assert service.store.state(plan.plan_id) == (AssetDiscoveryState.STARTED, 1)

    drifted = approved_scope.model_copy(update={"version": 999})
    with pytest.raises(AssetDiscoveryRejected, match="drifted"):
        service.recover(plan, scope=drifted, now=now)


def test_unproven_adapter_cleanup_or_credential_boundary_is_rejected(
    approved_scope, now
):
    class UnsafeAdapter:
        def __init__(self):
            self.batch = None

        def discover(self, query):
            return self.batch

    adapter = UnsafeAdapter()
    service = _service(adapter)
    authorization = _authorization(service, approved_scope, now)
    plan = _plan(service, approved_scope, authorization, now)
    adapter.batch = AssetDiscoveryBatch.model_construct(
        query_id=plan.queries[0].query_id,
        observations=(),
        raw_response_retained=True,
        credential_material_absent=False,
        adapter_session_closed=False,
    )

    with pytest.raises(AssetDiscoveryRejected, match="adapter safety"):
        service.execute(plan, scope=approved_scope, now=now)
    assert service.store.authorized_asset_count() == 0
    assert service.store.state(plan.plan_id) == (AssetDiscoveryState.STARTED, 1)


def test_interruption_timeout_recovery_and_attempt_limit(approved_scope, now):
    adapter = OfflineAssetDiscoveryAdapter({})
    service = _service(adapter)
    authorization = _authorization(service, approved_scope, now)
    plan = _plan(service, approved_scope, authorization, now)
    query_id = plan.queries[0].query_id
    adapter._batches[query_id] = AssetDiscoveryAdapterInterrupted("fixture stop")

    with pytest.raises(AssetDiscoveryAdapterInterrupted):
        service.execute(plan, scope=approved_scope, now=now)
    with pytest.raises(AssetDiscoveryAdapterInterrupted):
        service.recover(plan, scope=approved_scope, now=now)
    with pytest.raises(AssetDiscoveryAdapterInterrupted):
        service.recover(plan, scope=approved_scope, now=now)
    with pytest.raises(AssetDiscoveryRecoveryRequired, match="exhausted"):
        service.recover(plan, scope=approved_scope, now=now)
    assert service.store.authorized_asset_count() == 0

    ticks = iter((0.0, 0.0, 11.0))
    timeout_service = _service(
        OfflineAssetDiscoveryAdapter({query_id: _batch(plan, ())}),
        monotonic=lambda: next(ticks),
    )
    with pytest.raises(AssetDiscoveryTimedOut):
        timeout_service.execute(plan, scope=approved_scope, now=now)
    assert timeout_service.store.authorized_asset_count() == 0


def test_recovery_reuses_completed_query_checkpoint_without_requery(
    approved_scope, now
):
    adapter = OfflineAssetDiscoveryAdapter({})
    service = _service(adapter)
    authorization = _authorization(service, approved_scope, now)
    plan = service.prepare(
        authorization=authorization,
        scope=approved_scope,
        selectors=(
            (
                AssetDiscoverySource.FOFA,
                AssetDiscoverySelectorKind.DOMAIN,
                "example.test",
                5,
            ),
            (
                AssetDiscoverySource.SHODAN,
                AssetDiscoverySelectorKind.DOMAIN,
                "example.test",
                5,
            ),
        ),
        limits=AssetDiscoveryLimits(max_queries=2, max_records=10),
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="asset-discovery-checkpoints",
    )
    first = _observation(
        plan,
        now,
        locator="one.example.test",
        evidence_kind=AssetAttributionKind.AUTHORIZED_ROOT_DOMAIN,
        subject="example.test",
        query_index=0,
    )
    second = _observation(
        plan,
        now,
        locator="two.example.test",
        evidence_kind=AssetAttributionKind.AUTHORIZED_ROOT_DOMAIN,
        subject="example.test",
        query_index=1,
    )
    first_query, second_query = plan.queries
    adapter._batches[first_query.query_id] = _batch(
        plan, (first,), query_index=0
    )
    adapter._batches[second_query.query_id] = AssetDiscoveryAdapterInterrupted(
        "second source interrupted"
    )

    with pytest.raises(AssetDiscoveryAdapterInterrupted):
        service.execute(plan, scope=approved_scope, now=now)
    assert service.store.batch(plan.plan_id, first_query.query_id) is not None
    adapter._batches[second_query.query_id] = _batch(
        plan, (second,), query_index=1
    )

    outcome = service.recover(plan, scope=approved_scope, now=now)

    assert outcome.observation_count == 2
    assert len(outcome.authorized_asset_ids) == 2
    assert adapter.calls == [first_query.query_id, second_query.query_id, second_query.query_id]


def test_schema_rejects_permission_escalation_and_store_identity_conflict(
    approved_scope, now
):
    adapter = OfflineAssetDiscoveryAdapter({})
    service = _service(adapter)
    authorization = _authorization(service, approved_scope, now)
    plan = _plan(service, approved_scope, authorization, now)
    with pytest.raises(ValidationError):
        type(plan).model_validate(
            plan.model_dump(mode="python") | {"active_scanning_authorized": True}
        )

    observation = _observation(
        plan,
        now,
        evidence_kind=AssetAttributionKind.AUTHORIZED_ROOT_DOMAIN,
        subject="example.test",
    )
    adapter._batches[plan.queries[0].query_id] = _batch(plan, (observation,))
    outcome = service.execute(plan, scope=approved_scope, now=now)
    published = service.store.authorized_asset(outcome.authorized_asset_ids[0])
    forged = published.model_copy(update={"authorized_asset_id": "f" * 64})
    with pytest.raises(AssetDiscoveryStoreRejected, match="binding"):
        service.store.complete(plan, outcome, (forged,))
