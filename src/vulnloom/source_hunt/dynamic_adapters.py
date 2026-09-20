"""Trusted adapters for sealed native source-tool reports."""

from __future__ import annotations

import json
from collections.abc import Sequence

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import EvidenceKind
from vulnloom.evidence import EvidenceStore
from vulnloom.runners import RunnerOutputStore, SandboxRunResult

from .dynamic_models import (
    SourceDynamicToolchain,
    SourceDynamicToolRegistration,
    SourceToolReport,
)
from .execution import SourceExecutionRejected
from .execution_models import SourceExecutionStage, SourceStageReceipt

NATIVE_COVERAGE_ASAN_TOOL_VERSION = "gcc-11.4.0"
NATIVE_COVERAGE_ASAN_ADAPTER_ID = "native_coverage_asan_report_v1"
NATIVE_COVERAGE_ASAN_ADAPTER_DIGEST = canonical_digest(
    {
        "adapter_id": NATIVE_COVERAGE_ASAN_ADAPTER_ID,
        "protocol": "vulnloom.source-tool-report.v1",
        "stages": tuple(item.value for item in SourceExecutionStage),
        "normalization": "sanitizer-signal-failure-class-top-frames-v1",
    }
)


class SourceDynamicToolRegistry:
    """Immutable stage registry; Docker entries derive only from sealed argv."""

    def __init__(self, registrations: Sequence[SourceDynamicToolRegistration]):
        registrations = tuple(
            SourceDynamicToolRegistration.model_validate(item.model_dump(mode="python"))
            for item in registrations
        )
        self._registrations = {item.stage: item for item in registrations}
        if len(self._registrations) != len(registrations):
            raise ValueError("source dynamic tool stages must be unique")
        if set(self._registrations) != set(SourceExecutionStage):
            raise ValueError("source dynamic tool registry requires the fixed five stages")
        image_digests = {item.image_digest for item in registrations}
        if len(image_digests) != 1:
            raise ValueError("source dynamic tools must use one exact image")
        self.digest = canonical_digest(
            tuple(
                item.model_dump(mode="python")
                for item in sorted(registrations, key=lambda value: value.stage.value)
            )
        )

    def get(self, stage: SourceExecutionStage) -> SourceDynamicToolRegistration:
        return self._registrations[stage]

    @property
    def docker_tools(self):
        return tuple(
            item.docker_tool()
            for item in sorted(self._registrations.values(), key=lambda value: value.stage.value)
        )


class StructuredSourceToolEvidenceAdapter:
    """Convert one bounded tool report into redacted Evidence and a typed receipt."""

    def __init__(
        self,
        *,
        registry: SourceDynamicToolRegistry,
        output_store: RunnerOutputStore,
        evidence_store: EvidenceStore,
    ):
        self.registry = registry
        self.output_store = output_store
        self.evidence_store = evidence_store

    @property
    def registry_digest(self) -> str:
        return self.registry.digest

    def validate_request(self, stage, request) -> None:
        registration = self.registry.get(stage)
        if (
            request.profile.image_digest != registration.image_digest
            or request.invocation.tool_id != registration.tool_id
            or len(request.invocation.arguments) != 4
            or request.invocation.arguments[0] != registration.registration_id
            or request.invocation.arguments[2] != registration.adapter_digest
            or request.invocation.arguments[3] != registration.tool_version
            or request.environment != registration.environment
        ):
            raise SourceExecutionRejected("source dynamic tool request drifted")

    def capture(
        self,
        *,
        stage: SourceExecutionStage,
        result: SandboxRunResult,
        target_version: str,
    ) -> tuple[str, ...]:
        registration = self.registry.get(stage)
        if len(result.outputs) != 1:
            raise SourceExecutionRejected("source tool stage requires one bounded report")
        try:
            raw = self.output_store.read(result.outputs[0])
            if len(raw) > registration.max_report_bytes:
                raise ValueError("report exceeds registration limit")
            report = SourceToolReport.model_validate(
                json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_object)
            )
        except (UnicodeDecodeError, ValueError, ValidationError) as exc:
            raise SourceExecutionRejected("source tool report is invalid") from exc
        if (
            report.stage is not stage
            or report.registration_id != registration.registration_id
            or report.toolchain is not registration.toolchain
            or report.tool_version != registration.tool_version
            or report.adapter_digest != registration.adapter_digest
        ):
            raise SourceExecutionRejected("source tool report registration drifted")
        crash = report.crash_signature
        receipt = SourceStageReceipt.create(
            stage=stage,
            input_digest=report.input_digest,
            output_digest=report.output_digest,
            coverage_edges=report.coverage_edges,
            crash_fingerprint=crash.fingerprint if crash is not None else None,
            crash_input_digest=report.crash_input_digest,
            sanitizer=(
                crash.sanitizer if stage is SourceExecutionStage.SANITIZER and crash else None
            ),
            pov_reproduced=report.pov_reproduced,
        )
        report_evidence = self.evidence_store.capture_text(
            report.model_dump_json(),
            kind=EvidenceKind.TEST,
            source_ref=f"source-tool-report:{result.outputs[0].object_id}",
            producer=f"source-hunt.{stage.value}.adapter",
            target_version=target_version,
            summary=f"Normalized {stage.value} source tool report",
        )
        receipt_evidence = self.evidence_store.capture_text(
            receipt.model_dump_json(),
            kind=EvidenceKind.TEST,
            source_ref=f"source-stage-receipt:{receipt.receipt_id}",
            producer=f"source-hunt.{stage.value}.adapter",
            target_version=target_version,
            summary=f"Sealed {stage.value} stage receipt",
        )
        return report_evidence.evidence_id, receipt_evidence.evidence_id


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def native_coverage_asan_registrations(
    *, image_digest: str, image_environment: dict[str, str] | None = None
) -> tuple[SourceDynamicToolRegistration, ...]:
    """Build the only admitted R9 native toolchain contract.

    The image must contain the audited wrapper. It owns compiler/fuzzer arguments and
    emits exactly one v1 JSON report; callers cannot append runtime arguments.
    """
    registrations = []
    for stage in SourceExecutionStage:
        registrations.append(
            SourceDynamicToolRegistration.create(
                stage=stage,
                tool_id=f"source.{stage.value}",
                toolchain=SourceDynamicToolchain.NATIVE_COVERAGE_ASAN,
                tool_version=NATIVE_COVERAGE_ASAN_TOOL_VERSION,
                image_digest=image_digest,
                adapter_id=NATIVE_COVERAGE_ASAN_ADAPTER_ID,
                adapter_digest=NATIVE_COVERAGE_ASAN_ADAPTER_DIGEST,
                argv=(
                    "/usr/local/bin/vulnloom-source-stage",
                    "--protocol",
                    "vulnloom.source-tool-report.v1",
                    "--stage",
                    stage.value,
                    "--source-root",
                    "/workspace/source",
                ),
                environment={
                    **(image_environment or {}),
                    "HOME": "/tmp",
                    "TMPDIR": "/tmp",
                    "VULNLOOM_STAGE": stage.value,
                },
            )
        )
    return tuple(registrations)
