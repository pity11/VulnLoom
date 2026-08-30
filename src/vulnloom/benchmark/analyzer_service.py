"""Trusted offline orchestration for importing precomputed analyzer output."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from vulnloom.domain.digests import canonical_digest

from .analyzer_adapters import AnalyzerObservationAdapter
from .analyzer_io import (
    AnalyzerDeadline,
    AnalyzerImportRejected,
    load_cwe_map,
    load_sealed_json,
    verify_result_files,
)
from .analyzer_models import AnalyzerImportOutcome, AnalyzerImportPlan, AnalyzerResultSnapshot
from .analyzer_store import AnalyzerImportStore, AnalyzerObservationArtifactStore


class AnalyzerImportService:
    def __init__(
        self,
        *,
        adapter: AnalyzerObservationAdapter,
        store: AnalyzerImportStore,
        artifact_store: AnalyzerObservationArtifactStore,
    ):
        self.adapter = adapter
        self.store = store
        self.artifact_store = artifact_store

    def import_result(
        self,
        output_path: Path,
        snapshot: AnalyzerResultSnapshot,
        plan: AnalyzerImportPlan,
        *,
        now: datetime,
        cwe_map_path: Path | None = None,
    ) -> AnalyzerImportOutcome:
        if now < plan.created_at or now >= plan.deadline:
            raise AnalyzerImportRejected("analyzer import plan is not active")
        if (
            plan.snapshot_id != snapshot.snapshot_id
            or plan.snapshot_digest != canonical_digest(snapshot.model_dump(mode="python"))
            or self.adapter.kind is not snapshot.analyzer
            or plan.adapter_id != self.adapter.adapter_id
            or plan.adapter_digest != self.adapter.adapter_digest
        ):
            raise AnalyzerImportRejected("analyzer import binding mismatch")
        available_seconds = min(
            plan.limits.timeout_seconds,
            max(0.001, (plan.deadline - now).total_seconds()),
        )
        deadline = AnalyzerDeadline(available_seconds)
        verify_result_files(
            output_path,
            cwe_map_path,
            snapshot,
            limits=plan.limits,
            deadline=deadline,
        )
        document = load_sealed_json(
            output_path,
            snapshot.output,
            max_bytes=plan.limits.max_output_bytes,
            deadline=deadline,
        )
        cwe_map = load_cwe_map(
            cwe_map_path,
            snapshot.cwe_map,
            limits=plan.limits,
            deadline=deadline,
        )
        observations = self.adapter.normalize(
            snapshot,
            document,
            cwe_map,
            limits=plan.limits,
            deadline=deadline,
        )
        # Close the read/parse TOCTOU window before claiming the checkpoint.
        verify_result_files(
            output_path,
            cwe_map_path,
            snapshot,
            limits=plan.limits,
            deadline=deadline,
        )
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            if claim.outcome is None:
                raise RuntimeError("completed analyzer import checkpoint has no outcome")
            if (
                claim.outcome.plan_id != plan.plan_id
                or claim.outcome.snapshot_id != snapshot.snapshot_id
            ):
                raise AnalyzerImportRejected("stored analyzer import outcome binding mismatch")
            self.artifact_store.read(claim.outcome.artifact)
            return claim.outcome
        artifact = self.artifact_store.put(observations)
        outcome = AnalyzerImportOutcome(
            plan_id=plan.plan_id,
            snapshot_id=snapshot.snapshot_id,
            observation_set=observations,
            artifact=artifact,
            completed_at=now,
        )
        self.store.complete(outcome)
        return outcome
