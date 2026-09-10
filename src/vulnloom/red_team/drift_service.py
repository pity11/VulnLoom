"""Trusted offline comparison of two authoritative Attack Surface inventories."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from vulnloom.domain.models import Scope, ScopeState
from vulnloom.evidence import EvidenceStore

from .drift_models import (
    AttackSurfaceChange,
    AttackSurfaceChangeKind,
    AttackSurfaceDriftLimits,
    AttackSurfaceDriftOutcome,
    AttackSurfaceDriftPlan,
    AttackSurfaceDriftReport,
)
from .drift_store import AttackSurfaceDriftStore
from .surface_models import AttackSurfaceInventory, AttackSurfaceReductionOutcome


class AttackSurfaceDriftRejected(ValueError):
    pass


class AttackSurfaceDriftTimedOut(TimeoutError):
    pass


class AttackSurfaceInventorySource(Protocol):
    def outcome(self, reduction_id: str) -> AttackSurfaceReductionOutcome: ...


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.seconds = seconds
        self.clock = clock
        self.started = clock()

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise AttackSurfaceDriftTimedOut("Attack Surface drift comparison timed out")


@dataclass(slots=True)
class _SurfaceFacts:
    endpoint_ids: set[str] = field(default_factory=set)
    identity_ids: set[str] = field(default_factory=set)
    peers: set[str] = field(default_factory=set)
    final_destinations: set[str] = field(default_factory=set)
    statuses: set[int] = field(default_factory=set)
    redirects: set[int] = field(default_factory=set)
    tls_versions: set[str] = field(default_factory=set)
    ciphers: set[tuple[str, int]] = field(default_factory=set)
    certificates: set[str] = field(default_factory=set)
    evidence_refs: set[str] = field(default_factory=set)


class AttackSurfaceDriftService:
    def __init__(
        self,
        *,
        inventory_source: AttackSurfaceInventorySource,
        drift_store: AttackSurfaceDriftStore,
        evidence_store: EvidenceStore,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.inventory_source = inventory_source
        self.drift_store = drift_store
        self.evidence_store = evidence_store
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        baseline_reduction_id: str,
        current_reduction_id: str,
        scope: Scope,
        limits: AttackSurfaceDriftLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AttackSurfaceDriftPlan:
        baseline = self._load(baseline_reduction_id)
        current = self._load(current_reduction_id)
        self._binding(baseline, current, scope=scope, now=now)
        self._budgets(baseline, current, limits)
        self._verify_evidence(baseline, current)
        stop_at = min(deadline, scope.valid_until)
        if stop_at <= now:
            raise AttackSurfaceDriftRejected("Attack Surface drift deadline is invalid")
        return AttackSurfaceDriftPlan.create(
            baseline_reduction_id=baseline_reduction_id,
            baseline_inventory_id=baseline.inventory_id,
            current_reduction_id=current_reduction_id,
            current_inventory_id=current.inventory_id,
            target_id=current.target_id,
            scope_id=current.scope_id,
            scope_version=current.scope_version,
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def execute(
        self, plan: AttackSurfaceDriftPlan, *, scope: Scope, now: datetime
    ) -> AttackSurfaceDriftOutcome:
        plan = AttackSurfaceDriftPlan.model_validate(plan.model_dump(mode="python"))
        report = self._compare(plan, scope=scope, now=now)
        claim = self.drift_store.claim(plan, now=now)
        if not claim.created:
            if claim.outcome is None or claim.outcome.report != report:
                raise AttackSurfaceDriftRejected(
                    "completed Attack Surface drift outcome drifted"
                )
            return claim.outcome
        return self._complete(plan, report, attempt=claim.attempt, scope=scope, now=now)

    def recover(
        self, plan: AttackSurfaceDriftPlan, *, scope: Scope, now: datetime
    ) -> AttackSurfaceDriftOutcome:
        plan = AttackSurfaceDriftPlan.model_validate(plan.model_dump(mode="python"))
        report = self._compare(plan, scope=scope, now=now)
        claim = self.drift_store.recover(plan, now=now)
        return self._complete(plan, report, attempt=claim.attempt, scope=scope, now=now)

    def _complete(self, plan, report, *, attempt, scope, now):
        baseline, current = self._bound_sources(plan, scope=scope, now=now)
        self._verify_evidence(baseline, current)
        outcome = AttackSurfaceDriftOutcome(
            comparison_id=plan.comparison_id,
            report=report,
            attempt=attempt,
            cleanup_complete=True,
        )
        self.drift_store.complete(outcome, completed_at=now)
        return outcome

    def _compare(self, plan, *, scope, now):
        if not plan.created_at <= now < plan.deadline:
            raise AttackSurfaceDriftRejected("Attack Surface drift plan is not active")
        baseline, current = self._bound_sources(plan, scope=scope, now=now)
        self._budgets(baseline, current, plan.limits)
        self._verify_evidence(baseline, current)
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        old = self._facts(baseline, deadline)
        new = self._facts(current, deadline)
        keys = tuple(sorted(set(old) | set(new)))
        if len(keys) > plan.limits.max_surfaces:
            raise AttackSurfaceDriftRejected("Attack Surface drift surface budget exceeded")
        changes = []
        for key in keys:
            deadline.check()
            change = self._change(key, old.get(key), new.get(key))
            if change is not None:
                changes.append(change)
        evidence_refs = tuple(
            sorted({ref for change in changes for ref in change.evidence_refs})
        )
        if len(evidence_refs) > plan.limits.max_evidence_refs:
            raise AttackSurfaceDriftRejected("Attack Surface drift Evidence budget exceeded")
        return AttackSurfaceDriftReport.create(
            comparison_id=plan.comparison_id,
            baseline_inventory_id=baseline.inventory_id,
            current_inventory_id=current.inventory_id,
            target_id=plan.target_id,
            scope_id=plan.scope_id,
            scope_version=plan.scope_version,
            compared_surface_count=len(keys),
            unchanged_surface_count=len(keys) - len(changes),
            changes=tuple(changes),
            evidence_refs=evidence_refs,
            compared_at=plan.created_at,
        )

    def _bound_sources(self, plan, *, scope, now):
        baseline = self._load(plan.baseline_reduction_id)
        current = self._load(plan.current_reduction_id)
        self._binding(baseline, current, scope=scope, now=now)
        if (
            baseline.inventory_id != plan.baseline_inventory_id
            or current.inventory_id != plan.current_inventory_id
            or current.target_id != plan.target_id
            or current.scope_id != plan.scope_id
            or current.scope_version != plan.scope_version
        ):
            raise AttackSurfaceDriftRejected("Attack Surface drift source binding changed")
        return baseline, current

    def _load(self, reduction_id: str) -> AttackSurfaceInventory:
        try:
            outcome = self.inventory_source.outcome(reduction_id)
            outcome = AttackSurfaceReductionOutcome.model_validate(
                outcome.model_dump(mode="python")
            )
        except (ValueError, RuntimeError, KeyError) as exc:
            raise AttackSurfaceDriftRejected(
                "completed Attack Surface inventory is unavailable"
            ) from exc
        if outcome.reduction_id != reduction_id or not outcome.cleanup_complete:
            raise AttackSurfaceDriftRejected("Attack Surface inventory source is invalid")
        return outcome.inventory

    @staticmethod
    def _binding(baseline, current, *, scope, now):
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or baseline.target_id != current.target_id
            or baseline.scope_id != current.scope_id
            or baseline.scope_id != scope.scope_id
            or baseline.scope_version > current.scope_version
            or current.scope_version != scope.version
            or baseline.reduced_at >= current.reduced_at
            or current.reduced_at > now
        ):
            raise AttackSurfaceDriftRejected(
                "Attack Surface drift requires ordered inventories in current Scope"
            )

    @staticmethod
    def _budgets(baseline, current, limits):
        keys = {
            *(item.requested_url_digest for item in baseline.endpoints),
            *(item.requested_url_digest for item in current.endpoints),
            *(item.identity.endpoint_url_digest for item in baseline.service_identities),
            *(item.identity.endpoint_url_digest for item in current.service_identities),
        }
        evidence = set(baseline.evidence_refs) | set(current.evidence_refs)
        if len(keys) > limits.max_surfaces:
            raise AttackSurfaceDriftRejected("Attack Surface drift surface budget exceeded")
        if len(evidence) > limits.max_evidence_refs:
            raise AttackSurfaceDriftRejected("Attack Surface drift Evidence budget exceeded")

    def _verify_evidence(self, baseline, current):
        refs = set(baseline.evidence_refs) | set(current.evidence_refs)
        if not all(self.evidence_store.contains(item) for item in refs):
            raise AttackSurfaceDriftRejected("Attack Surface drift Evidence integrity failed")

    @staticmethod
    def _facts(inventory: AttackSurfaceInventory, deadline: _Deadline):
        facts: dict[str, _SurfaceFacts] = {}
        for endpoint in inventory.endpoints:
            deadline.check()
            item = facts.setdefault(endpoint.requested_url_digest, _SurfaceFacts())
            item.endpoint_ids.add(endpoint.endpoint_id)
            item.peers.add(endpoint.peer_ip)
            item.final_destinations.add(endpoint.final_url_digest)
            item.statuses.update(endpoint.status_codes)
            item.redirects.update(endpoint.redirect_counts)
            item.evidence_refs.update(endpoint.evidence_refs)
        for entry in inventory.service_identities:
            deadline.check()
            identity = entry.identity
            item = facts.setdefault(identity.endpoint_url_digest, _SurfaceFacts())
            item.identity_ids.add(identity.snapshot_id)
            item.peers.add(identity.peer_ip)
            item.tls_versions.add(identity.tls_version.value)
            item.ciphers.add((identity.cipher_suite, identity.cipher_bits))
            item.certificates.add(identity.leaf_certificate_sha256)
            item.evidence_refs.update(identity.evidence_refs)
        return facts

    @staticmethod
    def _change(key, baseline: _SurfaceFacts | None, current: _SurfaceFacts | None):
        old = baseline or _SurfaceFacts()
        new = current or _SurfaceFacts()
        kinds: set[AttackSurfaceChangeKind] = set()
        if not old.endpoint_ids and new.endpoint_ids:
            kinds.add(AttackSurfaceChangeKind.ENDPOINT_ADDED)
        elif old.endpoint_ids and not new.endpoint_ids:
            kinds.add(AttackSurfaceChangeKind.ENDPOINT_REMOVED)
        elif old.endpoint_ids and new.endpoint_ids:
            if old.final_destinations != new.final_destinations:
                kinds.add(AttackSurfaceChangeKind.FINAL_DESTINATION_CHANGED)
            if old.statuses != new.statuses:
                kinds.add(AttackSurfaceChangeKind.HTTP_STATUS_CHANGED)
            if old.redirects != new.redirects:
                kinds.add(AttackSurfaceChangeKind.REDIRECT_BEHAVIOR_CHANGED)
        old_present = bool(old.endpoint_ids or old.identity_ids)
        new_present = bool(new.endpoint_ids or new.identity_ids)
        if old_present and new_present and old.peers != new.peers:
            kinds.add(AttackSurfaceChangeKind.PEER_SET_CHANGED)
        if not old.identity_ids and new.identity_ids:
            kinds.add(AttackSurfaceChangeKind.TLS_IDENTITY_ADDED)
        elif old.identity_ids and not new.identity_ids:
            kinds.add(AttackSurfaceChangeKind.TLS_IDENTITY_REMOVED)
        elif old.identity_ids and new.identity_ids:
            if old.tls_versions != new.tls_versions:
                kinds.add(AttackSurfaceChangeKind.TLS_VERSION_CHANGED)
            if old.ciphers != new.ciphers:
                kinds.add(AttackSurfaceChangeKind.CIPHER_CHANGED)
            if old.certificates != new.certificates:
                kinds.add(AttackSurfaceChangeKind.CERTIFICATE_CHANGED)
        if not kinds:
            return None
        return AttackSurfaceChange(
            surface_key=key,
            change_kinds=tuple(sorted(kinds, key=lambda item: item.value)),
            baseline_endpoint_ids=tuple(sorted(old.endpoint_ids)),
            current_endpoint_ids=tuple(sorted(new.endpoint_ids)),
            baseline_identity_ids=tuple(sorted(old.identity_ids)),
            current_identity_ids=tuple(sorted(new.identity_ids)),
            evidence_refs=tuple(sorted(old.evidence_refs | new.evidence_refs)),
        )
