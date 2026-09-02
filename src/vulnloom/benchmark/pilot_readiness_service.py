"""Offline, read-only qualification of an explicitly authorized local pilot."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from vulnloom.analyzers import PythonWebSourceMapper, SourceMappingError
from vulnloom.analyzers.models import SourceGraph, source_graph_digest
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import CandidateState, Scope, TargetSnapshot
from vulnloom.hypotheses import CandidateGenerationError, CandidateGenerator
from vulnloom.hypotheses.models import CandidateSet, candidate_set_digest
from vulnloom.ingestion import IngestionError, IngestionService

from .local_source_robustness import (
    LocalSourceRobustnessProfile,
    LocalSourceRobustnessResult,
)
from .models import BenchmarkGateStatus
from .pilot_readiness_models import (
    AuthorizedPilotManifest,
    AuthorizedPilotReadinessMetrics,
    AuthorizedPilotReadinessOutcome,
    AuthorizedPilotReadinessPlan,
    AuthorizedPilotReadinessResult,
    AuthorizedPilotReadinessViolation,
    authorized_pilot_manifest_digest,
    authorized_pilot_readiness_plan_digest,
    pilot_effect_count,
)
from .pilot_readiness_store import (
    AuthorizedPilotReadinessArtifactStore,
    AuthorizedPilotReadinessStore,
)


class AuthorizedPilotReadinessRejected(ValueError):
    pass


class AuthorizedPilotReadinessTimedOut(TimeoutError):
    pass


class AuthorizedPilotReadinessService:
    def __init__(
        self,
        *,
        store: AuthorizedPilotReadinessStore,
        artifact_store: AuthorizedPilotReadinessArtifactStore,
    ):
        self.store = store
        self.artifact_store = artifact_store

    def evaluate(
        self,
        *,
        scope: Scope,
        snapshot: TargetSnapshot,
        target_store_root: Path,
        graph: SourceGraph,
        candidate_set: CandidateSet,
        quality_profile: LocalSourceRobustnessProfile,
        quality_result: LocalSourceRobustnessResult,
        manifest: AuthorizedPilotManifest,
        plan: AuthorizedPilotReadinessPlan,
        now: datetime,
    ) -> AuthorizedPilotReadinessOutcome:
        if now < plan.created_at or now >= plan.deadline:
            raise AuthorizedPilotReadinessTimedOut(
                "authorized pilot readiness is outside its window"
            )
        self._preflight(
            scope=scope,
            snapshot=snapshot,
            target_store_root=target_store_root,
            graph=graph,
            candidate_set=candidate_set,
            quality_profile=quality_profile,
            quality_result=quality_result,
            manifest=manifest,
            plan=plan,
            now=now,
        )
        metrics, violations = _evaluate(manifest, candidate_set, quality_result, plan)
        claim = self.store.claim(plan, now=now)
        if not claim.created:
            assert claim.outcome is not None
            self.artifact_store.read_result(claim.outcome.artifact)
            return claim.outcome
        values = {
            "plan_id": plan.plan_id,
            "pilot_manifest_id": manifest.pilot_manifest_id,
            "metrics": metrics,
            "gate_status": (
                BenchmarkGateStatus.FAILED if violations else BenchmarkGateStatus.PASSED
            ),
            "violations": violations,
            "completed_at": now,
        }
        digest_values = {
            **values,
            "metrics": metrics.model_dump(mode="python"),
            "violations": tuple(item.model_dump(mode="python") for item in violations),
        }
        result = AuthorizedPilotReadinessResult(result_id=canonical_digest(digest_values), **values)
        artifact = self.artifact_store.put(result)
        outcome = AuthorizedPilotReadinessOutcome(
            plan_id=plan.plan_id, result=result, artifact=artifact
        )
        self.store.complete(outcome, now=now)
        return outcome

    @staticmethod
    def _preflight(
        *,
        scope: Scope,
        snapshot: TargetSnapshot,
        target_store_root: Path,
        graph: SourceGraph,
        candidate_set: CandidateSet,
        quality_profile: LocalSourceRobustnessProfile,
        quality_result: LocalSourceRobustnessResult,
        manifest: AuthorizedPilotManifest,
        plan: AuthorizedPilotReadinessPlan,
        now: datetime,
    ) -> None:
        try:
            AuthorizedPilotManifest.model_validate(manifest.model_dump(mode="python"))
            AuthorizedPilotReadinessPlan.model_validate(plan.model_dump(mode="python"))
            LocalSourceRobustnessProfile.model_validate(quality_profile.model_dump(mode="python"))
            LocalSourceRobustnessResult.model_validate(quality_result.model_dump(mode="python"))
        except ValueError as exc:
            raise AuthorizedPilotReadinessRejected(
                "authorized pilot typed input failed integrity validation"
            ) from exc
        try:
            IngestionService.require_snapshot_scope(snapshot, scope, now)
            loaded = IngestionService(target_store_root).load_snapshot(
                snapshot.manifest.manifest_id
            )
        except IngestionError as exc:
            raise AuthorizedPilotReadinessRejected(
                "authorized pilot Target Snapshot failed authorization or integrity checks"
            ) from exc
        if loaded != snapshot:
            raise AuthorizedPilotReadinessRejected("authorized pilot Target Snapshot drifted")
        try:
            rebuilt_graph = PythonWebSourceMapper().analyze(
                loaded, target_store_root, scope=scope, now=now
            )
            rebuilt_candidates = CandidateGenerator().generate(rebuilt_graph, scope=scope, now=now)
        except (SourceMappingError, CandidateGenerationError) as exc:
            raise AuthorizedPilotReadinessRejected(
                "authorized pilot static analysis could not be rebuilt"
            ) from exc
        if (
            source_graph_digest(graph) != graph.graph_id
            or candidate_set_digest(candidate_set) != candidate_set.candidate_set_id
            or rebuilt_graph != graph
            or rebuilt_candidates != candidate_set
        ):
            raise AuthorizedPilotReadinessRejected(
                "authorized pilot static analysis content drifted"
            )
        try:
            expected_manifest = AuthorizedPilotManifest.create(
                scope=scope,
                snapshot=snapshot,
                graph=graph,
                candidate_set=candidate_set,
            )
        except ValueError as exc:
            raise AuthorizedPilotReadinessRejected(
                "authorized pilot static provenance mismatch"
            ) from exc
        if (
            expected_manifest != manifest
            or authorized_pilot_manifest_digest(manifest) != manifest.pilot_manifest_id
            or authorized_pilot_readiness_plan_digest(plan) != plan.plan_id
            or plan.pilot_manifest_id != manifest.pilot_manifest_id
            or plan.pilot_manifest_digest != canonical_digest(manifest.model_dump(mode="python"))
            or plan.quality_profile_id != quality_profile.profile_id
            or plan.quality_profile_digest
            != canonical_digest(quality_profile.model_dump(mode="python"))
            or plan.quality_result_id != quality_result.result_id
            or plan.quality_result_digest
            != canonical_digest(quality_result.model_dump(mode="python"))
            or quality_result.profile_id != quality_profile.profile_id
            or quality_result.suite_id != quality_profile.suite_id
        ):
            raise AuthorizedPilotReadinessRejected("authorized pilot sealed input binding mismatch")


def _evaluate(
    manifest: AuthorizedPilotManifest,
    candidate_set: CandidateSet,
    quality_result: LocalSourceRobustnessResult,
    plan: AuthorizedPilotReadinessPlan,
) -> tuple[
    AuthorizedPilotReadinessMetrics,
    tuple[AuthorizedPilotReadinessViolation, ...],
]:
    policy = plan.policy
    candidate_count = len(candidate_set.candidates)
    proposed = sum(item.state is CandidateState.PROPOSED for item in candidate_set.candidates)
    effect_count = pilot_effect_count(plan.effects)
    metrics = AuthorizedPilotReadinessMetrics(
        source_file_count=manifest.source_file_count,
        source_total_bytes=manifest.source_total_bytes,
        candidate_count=candidate_count,
        proposed_candidate_count=proposed,
        human_gate_count=len(manifest.required_human_gates),
        forbidden_capability_count=len(manifest.forbidden_capabilities),
        forbidden_effect_count=effect_count,
    )
    failures = (
        (
            "source_file_limit_exceeded",
            manifest.source_file_count,
            policy.max_source_files,
            manifest.source_file_count > policy.max_source_files,
        ),
        (
            "source_byte_limit_exceeded",
            manifest.source_total_bytes,
            policy.max_source_bytes,
            manifest.source_total_bytes > policy.max_source_bytes,
        ),
        (
            "candidate_limit_exceeded",
            candidate_count,
            policy.max_candidates,
            candidate_count > policy.max_candidates,
        ),
        (
            "candidate_state_not_proposed",
            proposed,
            candidate_count,
            proposed != candidate_count,
        ),
        (
            "quality_gate_failed",
            int(quality_result.gate_status is BenchmarkGateStatus.PASSED),
            1,
            quality_result.gate_status is not BenchmarkGateStatus.PASSED,
        ),
        (
            "forbidden_effect_observed",
            effect_count,
            policy.max_forbidden_effects,
            effect_count > policy.max_forbidden_effects,
        ),
    )
    return metrics, tuple(
        AuthorizedPilotReadinessViolation(code=code, actual=actual, limit=limit)
        for code, actual, limit, failed in failures
        if failed
    )
