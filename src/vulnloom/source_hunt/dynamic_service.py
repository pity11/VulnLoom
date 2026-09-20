"""R9 Crash deduplication and fixed Benchmark PoV qualification."""

from __future__ import annotations

from datetime import datetime

from vulnloom.benchmark.models import BenchmarkGateStatus
from vulnloom.domain.digests import canonical_digest

from .dynamic_models import (
    SourceCrashRegistration,
    SourceCrashSignature,
    SourcePovArtifact,
    SourcePovBenchmarkCase,
    SourcePovBenchmarkResult,
)
from .dynamic_store import SourceCrashStore
from .execution_models import (
    SOURCE_EXECUTION_STAGES,
    SourceExecutionOutcome,
    SourceExecutionPlan,
    SourceExecutionStage,
    SourceExecutionStatus,
)
from .execution_store import SourceExecutionStore


class SourcePovQualificationRejected(ValueError):
    pass


class SourceCrashDeduplicationService:
    def __init__(self, *, store: SourceCrashStore):
        self.store = store

    def register(
        self,
        *,
        signature: SourceCrashSignature,
        plan: SourceExecutionPlan,
        outcome: SourceExecutionOutcome,
        observed_at: datetime,
        idempotency_key: str,
    ) -> SourceCrashRegistration:
        fingerprint, input_digest = _qualified_crash_identity(plan, outcome)
        if fingerprint != signature.fingerprint:
            raise SourcePovQualificationRejected("normalized Crash Signature drifted")
        return self.store.register(
            signature=signature,
            plan_id=plan.plan_id,
            input_digest=input_digest,
            observed_at=observed_at,
            idempotency_key=idempotency_key,
        )


class SourcePovBenchmarkService:
    def __init__(
        self,
        *,
        execution_store: SourceExecutionStore,
        crash_store: SourceCrashStore,
    ):
        self.execution_store = execution_store
        self.crash_store = crash_store

    def evaluate(
        self,
        *,
        case: SourcePovBenchmarkCase,
        plan: SourceExecutionPlan,
        outcome: SourceExecutionOutcome,
        now: datetime,
    ) -> SourcePovBenchmarkResult:
        if self.execution_store.load(plan.plan_id) != outcome:
            raise SourcePovQualificationRejected("PoV Benchmark requires authoritative execution")
        fingerprint, input_digest = _qualified_crash_identity(plan, outcome)
        crash = self.crash_store.load(fingerprint)
        sanitizer_receipt = outcome.stage_receipts[3]
        if (
            case.target_version != plan.target_version
            or case.candidate_digest != plan.candidate_digest
            or case.expected_crash_fingerprint != fingerprint
            or case.expected_sanitizer is not sanitizer_receipt.sanitizer
            or crash.signature.sanitizer is not sanitizer_receipt.sanitizer
            or plan.plan_id not in crash.observed_plan_ids
        ):
            raise SourcePovQualificationRejected("PoV Benchmark case or Crash catalog drifted")
        artifact = SourcePovArtifact.create(
            candidate_digest=plan.candidate_digest,
            crash_fingerprint=fingerprint,
            input_digest=input_digest,
            source_execution_plan_id=plan.plan_id,
            sanitizer=sanitizer_receipt.sanitizer,
            created_at=now,
        )
        return SourcePovBenchmarkResult.create(
            case_id=case.case_id,
            execution_plan_id=plan.plan_id,
            execution_outcome_digest=canonical_digest(outcome.model_dump(mode="python")),
            crash_record_fingerprint=crash.fingerprint,
            pov_artifact=artifact,
            gate_status=BenchmarkGateStatus.PASSED,
            violation_codes=(),
            completed_at=now,
        )


def _qualified_crash_identity(
    plan: SourceExecutionPlan, outcome: SourceExecutionOutcome
) -> tuple[str, str]:
    if (
        outcome.plan_id != plan.plan_id
        or outcome.status is not SourceExecutionStatus.COMPLETED
        or not outcome.reproducible_pov
        or outcome.executed_stages != SOURCE_EXECUTION_STAGES
        or len(outcome.stage_receipts) != len(SOURCE_EXECUTION_STAGES)
        or len(outcome.runner_results) != len(SOURCE_EXECUTION_STAGES)
        or not all(item.cleanup.complete for item in outcome.runner_results)
    ):
        raise SourcePovQualificationRejected("source execution is not a qualified PoV")
    fuzz, sanitizer, replay = outcome.stage_receipts[2:]
    fingerprints = {item.crash_fingerprint for item in (fuzz, sanitizer, replay)}
    inputs = {item.crash_input_digest for item in (fuzz, sanitizer, replay)}
    if (
        fuzz.stage is not SourceExecutionStage.FUZZ
        or fuzz.coverage_edges <= 0
        or sanitizer.stage is not SourceExecutionStage.SANITIZER
        or replay.stage is not SourceExecutionStage.POV_REPLAY
        or not replay.pov_reproduced
        or None in fingerprints
        or len(fingerprints) != 1
        or None in inputs
        or len(inputs) != 1
    ):
        raise SourcePovQualificationRejected("Crash or independent PoV identity is incomplete")
    return next(iter(fingerprints)), next(iter(inputs))  # type: ignore[return-value]
