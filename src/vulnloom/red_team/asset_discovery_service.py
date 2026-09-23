"""Trusted service for bounded passive discovery and deterministic admission."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Scope, ScopeState

from .asset_discovery_adapters import AssetDiscoveryAdapter
from .asset_discovery_models import (
    AssetAdmissionDecision,
    AssetAdmissionVerdict,
    AssetAttributionKind,
    AssetAuthorizationMode,
    AssetDiscoveryAuthorization,
    AssetDiscoveryLimits,
    AssetDiscoveryObservation,
    AssetDiscoveryOutcome,
    AssetDiscoveryPlan,
    AssetDiscoveryQuery,
    AssetDiscoverySelectorKind,
    AssetDiscoverySource,
    AssetLocatorKind,
    AttributionVerdict,
    AuthorizedAsset,
    canonical_hostname,
)
from .asset_discovery_store import AssetDiscoveryStore


class AssetDiscoveryRejected(ValueError):
    pass


class AssetDiscoveryTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.seconds = seconds
        self.clock = clock
        self.started = clock()

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise AssetDiscoveryTimedOut("asset discovery timed out")


class AssetDiscoveryService:
    def __init__(
        self,
        *,
        store: AssetDiscoveryStore,
        adapter: AssetDiscoveryAdapter,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.store = store
        self.adapter = adapter
        self.monotonic = monotonic

    def authorize(
        self,
        *,
        scope: Scope,
        mode: AssetAuthorizationMode,
        exact_hosts: tuple[str, ...] = (),
        root_domains: tuple[str, ...] = (),
        icp_registration_digests: tuple[str, ...] = (),
        excluded_domain_suffixes: tuple[str, ...] = (),
        allowed_sources: tuple[AssetDiscoverySource, ...],
        now: datetime,
    ) -> AssetDiscoveryAuthorization:
        self._scope(scope, now=now)
        scoped_hosts = {canonical_hostname(item.host) for item in scope.network_targets}
        normalized_exact = {canonical_hostname(item) for item in exact_hosts}
        if not normalized_exact <= scoped_hosts:
            raise AssetDiscoveryRejected(
                "exact discovery hosts must already be present in Scope"
            )
        if mode is AssetAuthorizationMode.EXACT_ASSIGNMENT and (
            root_domains or icp_registration_digests
        ):
            raise AssetDiscoveryRejected(
                "exact-assignment authorization cannot expand by entity selectors"
            )
        if mode is not AssetAuthorizationMode.EXACT_ASSIGNMENT and not (
            root_domains or icp_registration_digests
        ):
            raise AssetDiscoveryRejected(
                "entity-derived authorization requires a domain or ICP selector"
            )
        try:
            return AssetDiscoveryAuthorization.create(
                scope_id=scope.scope_id,
                scope_version=scope.version,
                authority_reference_digest=canonical_digest(scope.authority_reference),
                mode=mode,
                exact_hosts=tuple(normalized_exact),
                exact_endpoints=tuple(
                    f"{scheme}://{canonical_hostname(target.host)}:{port}"
                    for target in scope.network_targets
                    if canonical_hostname(target.host) in normalized_exact
                    for scheme in target.schemes
                    for port in target.ports
                ),
                root_domains=root_domains,
                icp_registration_digests=icp_registration_digests,
                excluded_domain_suffixes=excluded_domain_suffixes,
                allowed_sources=allowed_sources,
                valid_from=scope.valid_from,
                valid_until=scope.valid_until,
                created_at=now,
            )
        except ValueError as exc:
            raise AssetDiscoveryRejected(
                "asset discovery authorization could not be sealed"
            ) from exc

    def prepare(
        self,
        *,
        authorization: AssetDiscoveryAuthorization,
        scope: Scope,
        selectors: tuple[
            tuple[AssetDiscoverySource, AssetDiscoverySelectorKind, str, int], ...
        ],
        limits: AssetDiscoveryLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AssetDiscoveryPlan:
        self._authorization(authorization, scope=scope, now=now)
        try:
            queries = tuple(
                AssetDiscoveryQuery.create(
                    source=source,
                    selector_kind=kind,
                    selector=selector,
                    result_limit=result_limit,
                )
                for source, kind, selector, result_limit in selectors
            )
        except ValueError as exc:
            raise AssetDiscoveryRejected(
                "asset discovery selector could not be sealed"
            ) from exc
        for query in queries:
            self._query(authorization, query)
        stop_at = min(deadline, scope.valid_until)
        if stop_at <= now:
            raise AssetDiscoveryRejected("asset discovery deadline is invalid")
        try:
            return AssetDiscoveryPlan.create(
                authorization=authorization,
                queries=queries,
                limits=limits,
                created_at=now,
                deadline=stop_at,
                idempotency_key=idempotency_key,
            )
        except ValueError as exc:
            raise AssetDiscoveryRejected(
                "asset discovery plan could not be sealed"
            ) from exc

    def execute(
        self, plan: AssetDiscoveryPlan, *, scope: Scope, now: datetime
    ) -> AssetDiscoveryOutcome:
        authoritative = AssetDiscoveryPlan.model_validate(plan.model_dump(mode="python"))
        self._binding(authoritative, scope=scope, now=now)
        claim = self.store.claim(authoritative, now=now)
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome
        return self._run(
            authoritative, scope=scope, now=now, attempt=claim.attempt
        )

    def recover(
        self, plan: AssetDiscoveryPlan, *, scope: Scope, now: datetime
    ) -> AssetDiscoveryOutcome:
        authoritative = AssetDiscoveryPlan.model_validate(plan.model_dump(mode="python"))
        self._binding(authoritative, scope=scope, now=now)
        claim = self.store.recover(authoritative, now=now)
        return self._run(
            authoritative, scope=scope, now=now, attempt=claim.attempt
        )

    def _run(self, plan, *, scope, now, attempt):
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        observations: list[AssetDiscoveryObservation] = []
        for query in plan.queries:
            deadline.check()
            batch = self.store.batch(plan.plan_id, query.query_id)
            if batch is None:
                batch = self.adapter.discover(query)
                deadline.check()
                self._batch(plan, query, batch, now=now)
                self.store.save_batch(plan, batch)
            self._batch(plan, query, batch, now=now)
            observations.extend(batch.observations)
            if len(observations) > plan.limits.max_records:
                raise AssetDiscoveryRejected("asset discovery record budget exceeded")

        asset_ids = tuple(item.asset.asset_id for item in observations)
        if len(asset_ids) != len(set(asset_ids)):
            raise AssetDiscoveryRejected("asset discovery returned duplicate assets")

        self._binding(plan, scope=scope, now=now)
        decisions = tuple(
            self._decide(plan.authorization, observation, now=now)
            for observation in observations
        )
        authorized_assets = tuple(
            AuthorizedAsset.create(
                authorization_id=plan.authorization.authorization_id,
                decision_id=decision.decision_id,
                asset=observation.asset,
                admitted_at=now,
            )
            for observation, decision in zip(observations, decisions, strict=True)
            if decision.verdict is AssetAdmissionVerdict.ADMITTED
        )
        outcome = AssetDiscoveryOutcome.create(
            plan_id=plan.plan_id,
            observation_count=len(observations),
            decisions=decisions,
            authorized_asset_ids=tuple(
                item.authorized_asset_id for item in authorized_assets
            ),
            attempt=attempt,
            completed_at=now,
        )
        deadline.check()
        self.store.complete(plan, outcome, authorized_assets)
        return outcome

    def _batch(self, plan, query, batch, *, now):
        if (
            batch.query_id != query.query_id
            or batch.raw_response_retained
            or not batch.credential_material_absent
            or not batch.adapter_session_closed
        ):
            raise AssetDiscoveryRejected(
                "asset discovery adapter safety or query binding is invalid"
            )
        if len(batch.observations) > query.result_limit:
            raise AssetDiscoveryRejected("asset discovery query result budget exceeded")
        for observation in batch.observations:
            asset = observation.asset
            if (
                asset.plan_id != plan.plan_id
                or asset.query_id != query.query_id
                or asset.source is not query.source
                or asset.observed_at > now
                or len(observation.attribution)
                > plan.limits.max_evidence_per_asset
                or any(item.observed_at > now for item in observation.attribution)
            ):
                raise AssetDiscoveryRejected(
                    "asset discovery observation provenance is invalid"
                )

    def _decide(self, authorization, observation, *, now):
        asset = observation.asset
        attribution = observation.attribution
        attribution_ids = tuple(item.attribution_id for item in attribution)
        supported = {
            item.kind: item
            for item in attribution
            if item.verdict is AttributionVerdict.SUPPORTED
        }

        if asset.locator_kind is AssetLocatorKind.HOSTNAME and any(
            asset.locator == suffix or asset.locator.endswith(f".{suffix}")
            for suffix in authorization.excluded_domain_suffixes
        ):
            return self._decision(
                authorization, asset, attribution_ids, now, "explicit_exclusion"
            )
        if {
            AssetAttributionKind.CROSS_LEGAL_ENTITY,
            AssetAttributionKind.EXPLICIT_EXCLUSION,
        }.intersection(supported):
            return self._decision(
                authorization, asset, attribution_ids, now, "excluded_ownership"
            )
        if (
            asset.locator_kind is AssetLocatorKind.HOSTNAME
            and asset.locator in authorization.exact_hosts
            and f"{asset.scheme}://{asset.locator}:{asset.port}"
            in authorization.exact_endpoints
        ):
            return self._decision(
                authorization, asset, attribution_ids, now, "exact_scope_match"
            )

        if authorization.mode is AssetAuthorizationMode.EXACT_ASSIGNMENT:
            return self._decision(
                authorization, asset, attribution_ids, now, "not_exactly_assigned"
            )
        if authorization.mode is AssetAuthorizationMode.SUPPLY_CHAIN_WITH_APPROVAL:
            return self._decision(
                authorization, asset, attribution_ids, now, "supply_chain_review"
            )

        root_evidence = supported.get(AssetAttributionKind.AUTHORIZED_ROOT_DOMAIN)
        if asset.locator_kind is AssetLocatorKind.HOSTNAME and root_evidence is not None:
            matching_roots = {
                root
                for root in authorization.root_domains
                if asset.locator == root or asset.locator.endswith(f".{root}")
            }
            if any(
                root_evidence.subject_digest == canonical_digest(root)
                for root in matching_roots
            ):
                return self._decision(
                    authorization,
                    asset,
                    attribution_ids,
                    now,
                    "authorized_domain_derivation",
                )

        icp_evidence = supported.get(AssetAttributionKind.ICP_REGISTRATION_MATCH)
        if (
            icp_evidence is not None
            and icp_evidence.subject_digest in authorization.icp_registration_digests
        ):
            return self._decision(
                authorization, asset, attribution_ids, now, "authorized_icp_derivation"
            )
        inventory = supported.get(AssetAttributionKind.OPERATOR_INVENTORY_MATCH)
        if inventory is not None and inventory.subject_digest == canonical_digest(
            asset.locator
        ):
            return self._decision(
                authorization, asset, attribution_ids, now, "operator_inventory_match"
            )
        return self._decision(
            authorization, asset, attribution_ids, now, "ownership_review_required"
        )

    @staticmethod
    def _decision(authorization, asset, attribution_ids, now, reason):
        if reason in {"explicit_exclusion", "excluded_ownership", "not_exactly_assigned"}:
            verdict = AssetAdmissionVerdict.REJECTED
        elif reason in {"supply_chain_review", "ownership_review_required"}:
            verdict = AssetAdmissionVerdict.APPROVAL_REQUIRED
        else:
            verdict = AssetAdmissionVerdict.ADMITTED
        return AssetAdmissionDecision.create(
            authorization_id=authorization.authorization_id,
            asset_id=asset.asset_id,
            verdict=verdict,
            reason_code=reason,
            attribution_ids=attribution_ids,
            decided_at=now,
        )

    @staticmethod
    def _query(authorization, query):
        if query.source not in authorization.allowed_sources:
            raise AssetDiscoveryRejected("asset discovery source is not authorized")
        supported_kinds = {
            AssetDiscoverySource.FOFA: {
                AssetDiscoverySelectorKind.DOMAIN,
                AssetDiscoverySelectorKind.ICP_REGISTRATION,
                AssetDiscoverySelectorKind.EXACT_HOST,
            },
            AssetDiscoverySource.QUAKE: {
                AssetDiscoverySelectorKind.DOMAIN,
                AssetDiscoverySelectorKind.ICP_REGISTRATION,
                AssetDiscoverySelectorKind.EXACT_HOST,
            },
            AssetDiscoverySource.SHODAN: {
                AssetDiscoverySelectorKind.DOMAIN,
                AssetDiscoverySelectorKind.EXACT_HOST,
            },
            AssetDiscoverySource.PASSIVE_DNS: {
                AssetDiscoverySelectorKind.DOMAIN,
                AssetDiscoverySelectorKind.EXACT_HOST,
            },
            AssetDiscoverySource.CERTIFICATE_TRANSPARENCY: {
                AssetDiscoverySelectorKind.DOMAIN,
                AssetDiscoverySelectorKind.EXACT_HOST,
            },
            AssetDiscoverySource.ICP_REGISTRY: {
                AssetDiscoverySelectorKind.DOMAIN,
                AssetDiscoverySelectorKind.ICP_REGISTRATION,
            },
            AssetDiscoverySource.OPERATOR_IMPORT: {
                AssetDiscoverySelectorKind.DOMAIN,
                AssetDiscoverySelectorKind.EXACT_HOST,
            },
        }
        if query.selector_kind not in supported_kinds[query.source]:
            raise AssetDiscoveryRejected(
                "asset discovery selector is unsupported by source"
            )
        if query.selector_kind is AssetDiscoverySelectorKind.EXACT_HOST:
            accepted = query.selector in authorization.exact_hosts
        elif query.selector_kind is AssetDiscoverySelectorKind.DOMAIN:
            accepted = query.selector in authorization.root_domains
        else:
            accepted = (
                canonical_digest(query.selector)
                in authorization.icp_registration_digests
            )
        if not accepted:
            raise AssetDiscoveryRejected(
                "asset discovery selector is not authorization-derived"
            )

    @staticmethod
    def _scope(scope, *, now):
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
        ):
            raise AssetDiscoveryRejected(
                "asset discovery requires a current approved Scope"
            )

    def _authorization(self, authorization, *, scope, now):
        self._scope(scope, now=now)
        if (
            authorization.scope_id != scope.scope_id
            or authorization.scope_version != scope.version
            or authorization.authority_reference_digest
            != canonical_digest(scope.authority_reference)
            or authorization.valid_from != scope.valid_from
            or authorization.valid_until != scope.valid_until
            or not authorization.valid_from <= now < authorization.valid_until
        ):
            raise AssetDiscoveryRejected(
                "asset discovery authorization drifted from Scope"
            )

    def _binding(self, plan, *, scope, now):
        if not plan.created_at <= now < plan.deadline:
            raise AssetDiscoveryRejected("asset discovery plan is not active")
        self._authorization(plan.authorization, scope=scope, now=now)
        for query in plan.queries:
            self._query(plan.authorization, query)
