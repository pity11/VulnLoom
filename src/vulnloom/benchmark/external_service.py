"""Trusted orchestration for importing local external benchmark snapshots."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from vulnloom.domain.digests import canonical_digest

from .external_adapters import ExternalBenchmarkAdapter
from .external_io import (
    ExternalBenchmarkRejected,
    ImportDeadline,
    resolve_snapshot_root,
    verify_snapshot_directory,
)
from .external_models import (
    ExternalBenchmarkImportOutcome,
    ExternalBenchmarkImportPlan,
    ExternalBenchmarkSnapshot,
)
from .external_store import (
    ExternalBenchmarkArtifactStore,
    ExternalBenchmarkImportStore,
)


class ExternalBenchmarkImportService:
    def __init__(
        self,
        *,
        adapter: ExternalBenchmarkAdapter,
        store: ExternalBenchmarkImportStore,
        artifact_store: ExternalBenchmarkArtifactStore,
    ):
        self.adapter = adapter
        self.store = store
        self.artifact_store = artifact_store

    def import_snapshot(
        self,
        root: Path,
        snapshot: ExternalBenchmarkSnapshot,
        plan: ExternalBenchmarkImportPlan,
        *,
        now: datetime,
    ) -> ExternalBenchmarkImportOutcome:
        if now < plan.created_at or now >= plan.deadline:
            raise ExternalBenchmarkRejected("external Benchmark import plan is not active")
        if (
            plan.snapshot_id != snapshot.snapshot_id
            or plan.snapshot_digest != canonical_digest(snapshot.model_dump(mode="python"))
            or self.adapter.kind is not snapshot.kind
            or plan.adapter_id != self.adapter.adapter_id
            or plan.adapter_digest != self.adapter.adapter_digest
        ):
            raise ExternalBenchmarkRejected("external Benchmark import binding mismatch")
        available_seconds = min(
            plan.limits.timeout_seconds,
            max(0.001, (plan.deadline - now).total_seconds()),
        )
        deadline = ImportDeadline(available_seconds)
        canonical_root = resolve_snapshot_root(root)
        verify_snapshot_directory(
            canonical_root, snapshot, limits=plan.limits, deadline=deadline
        )
        suite, exclusions = self.adapter.normalize(
            canonical_root,
            snapshot,
            limits=plan.limits,
            deadline=deadline,
        )
        # Close the scan/parse TOCTOU window before binding the normalized suite.
        verify_snapshot_directory(
            canonical_root, snapshot, limits=plan.limits, deadline=deadline
        )

        claim = self.store.claim(plan, now=now)
        if not claim.created:
            if claim.outcome is None:
                raise RuntimeError("completed external import checkpoint has no outcome")
            if (
                claim.outcome.plan_id != plan.plan_id
                or claim.outcome.snapshot_id != snapshot.snapshot_id
            ):
                raise ExternalBenchmarkRejected("stored external import outcome binding mismatch")
            self.artifact_store.read_suite(claim.outcome.artifact)
            return claim.outcome

        artifact = self.artifact_store.put(suite)
        outcome = ExternalBenchmarkImportOutcome(
            plan_id=plan.plan_id,
            snapshot_id=snapshot.snapshot_id,
            suite=suite,
            exclusions=exclusions,
            artifact=artifact,
            completed_at=now,
        )
        self.store.complete(outcome)
        return outcome
