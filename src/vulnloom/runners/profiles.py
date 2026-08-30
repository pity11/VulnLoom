"""Safe-by-construction sandbox profile factories."""

from __future__ import annotations

from .models import (
    NetworkGrant,
    NetworkMode,
    SandboxLimits,
    SandboxMount,
    SandboxProfile,
    SandboxProfileKind,
)


def analyzer_profile(
    *,
    image_digest: str,
    snapshot_id: str,
    tool_id: str,
    limits: SandboxLimits,
    analyzer_data_id: str | None = None,
) -> SandboxProfile:
    """Create a network-disabled profile for one exact registered analyzer."""
    return SandboxProfile(
        kind=SandboxProfileKind.STATIC,
        image_digest=image_digest,
        run_as_uid=65_532,
        run_as_gid=65_532,
        mounts=(
            SandboxMount(
                kind="snapshot",
                destination="/workspace/source",
                object_id=snapshot_id,
                read_only=True,
            ),
            *(
                (
                    SandboxMount(
                        kind="analyzer_data",
                        destination="/workspace/analyzer-data",
                        object_id=analyzer_data_id,
                        read_only=True,
                    ),
                )
                if analyzer_data_id is not None
                else ()
            ),
            *_scratch_mounts(),
        ),
        allowed_tools=frozenset({tool_id}),
        limits=limits,
    )


def _scratch_mounts() -> tuple[SandboxMount, SandboxMount]:
    return (
        SandboxMount(kind="output", destination="/workspace/output", read_only=False),
        SandboxMount(kind="temp", destination="/tmp", read_only=False),
    )


def static_profile(*, image_digest: str, snapshot_id: str) -> SandboxProfile:
    return SandboxProfile(
        kind=SandboxProfileKind.STATIC,
        image_digest=image_digest,
        run_as_uid=65_532,
        run_as_gid=65_532,
        mounts=(
            SandboxMount(
                kind="snapshot",
                destination="/workspace/source",
                object_id=snapshot_id,
                read_only=True,
            ),
            *_scratch_mounts(),
        ),
        allowed_tools=frozenset({"source.read", "source.search", "analyzer.run"}),
        limits=_default_limits(wall_seconds=300),
    )


def validation_profile(
    *,
    image_digest: str,
    snapshot_id: str,
    network_grants: tuple[NetworkGrant, ...] = (),
) -> SandboxProfile:
    mode = NetworkMode.TARGET_ONLY if network_grants else NetworkMode.NONE
    return SandboxProfile(
        kind=SandboxProfileKind.VALIDATION,
        image_digest=image_digest,
        run_as_uid=65_532,
        run_as_gid=65_532,
        network_mode=mode,
        network_grants=network_grants,
        mounts=(
            SandboxMount(
                kind="snapshot",
                destination="/workspace/source",
                object_id=snapshot_id,
                read_only=True,
            ),
            *_scratch_mounts(),
        ),
        allowed_tools=frozenset({"sandbox.test", "http.request"}),
        execute_target_code=True,
        limits=_default_limits(wall_seconds=600),
    )


def report_profile(*, image_digest: str, evidence_object_id: str) -> SandboxProfile:
    return SandboxProfile(
        kind=SandboxProfileKind.REPORT,
        image_digest=image_digest,
        run_as_uid=65_532,
        run_as_gid=65_532,
        mounts=(
            SandboxMount(
                kind="evidence",
                destination="/workspace/evidence",
                object_id=evidence_object_id,
                read_only=True,
            ),
            *_scratch_mounts(),
        ),
        allowed_tools=frozenset({"evidence.read", "report.write"}),
        limits=_default_limits(wall_seconds=300),
    )


def _default_limits(*, wall_seconds: int) -> SandboxLimits:
    return SandboxLimits(
        wall_seconds=wall_seconds,
        cpu_millis=wall_seconds * 2_000,
        memory_bytes=512 * 1024 * 1024,
        pids=128,
        open_files=1024,
        file_bytes=64 * 1024 * 1024,
        tmp_bytes=256 * 1024 * 1024,
    )
