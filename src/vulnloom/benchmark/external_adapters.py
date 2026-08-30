"""Offline-only adapters for official BountyBench and AutoPenBench layouts."""

from __future__ import annotations

import json
import re
from typing import Protocol

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest

from .external_io import (
    ExternalBenchmarkRejected,
    ImportDeadline,
    read_verified_snapshot_file,
)
from .external_models import (
    ExternalBenchmarkKind,
    ExternalBenchmarkSnapshot,
    ExternalCaseExclusion,
    ExternalImportLimits,
)
from .models import (
    BenchmarkCase,
    BenchmarkSource,
    BenchmarkSuite,
    GroundTruthFinding,
)

BOUNTYBENCH_ADAPTER_ID = "bountybench.local-snapshot.v1"
AUTOPENBENCH_ADAPTER_ID = "autopenbench.local-snapshot.v1"
BOUNTYBENCH_ADAPTER_DIGEST = canonical_digest({"adapter": BOUNTYBENCH_ADAPTER_ID, "contract": 1})
AUTOPENBENCH_ADAPTER_DIGEST = canonical_digest({"adapter": AUTOPENBENCH_ADAPTER_ID, "contract": 1})


class ExternalBenchmarkAdapter(Protocol):
    adapter_id: str
    adapter_digest: str
    kind: ExternalBenchmarkKind

    def normalize(
        self,
        root,
        snapshot: ExternalBenchmarkSnapshot,
        *,
        limits: ExternalImportLimits,
        deadline: ImportDeadline,
    ) -> tuple[BenchmarkSuite, tuple[ExternalCaseExclusion, ...]]: ...


def _json_object(content: bytes) -> dict[str, object]:
    try:
        value = json.loads(
            content.decode("utf-8", "strict"),
            object_pairs_hook=_unique_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ExternalBenchmarkRejected(
            "benchmark metadata JSON is malformed or ambiguous"
        ) from exc
    if not isinstance(value, dict):
        raise ExternalBenchmarkRejected("benchmark metadata must be a JSON object")
    return value


def _unique_object(pairs):
    output = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in output:
            raise ValueError("duplicate or invalid JSON object key")
        output[key] = value
    return output


def _normalized_cwe(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"(?i)cwe-([1-9][0-9]*)", value.strip())
    return f"CWE-{match.group(1)}" if match else None


def _case(
    *,
    source: BenchmarkSource,
    snapshot: ExternalBenchmarkSnapshot,
    source_case_ref: str,
    target_version: str,
    cwe: str,
    duplicate_key: str,
) -> BenchmarkCase:
    case_id = canonical_digest(
        {
            "source": source.value,
            "snapshot_id": snapshot.snapshot_id,
            "source_case_ref": source_case_ref,
            "target_version": target_version,
        }
    )
    truth_id = canonical_digest({"case_id": case_id, "cwe": cwe})
    return BenchmarkCase(
        case_id=case_id,
        target_version=target_version,
        ground_truth=(
            GroundTruthFinding(
                truth_id=truth_id,
                cwe=cwe,
                duplicate_family=canonical_digest(
                    {"source": source.value, "duplicate_key": duplicate_key}
                ),
            ),
        ),
    )


class BountyBenchSnapshotAdapter:
    adapter_id = BOUNTYBENCH_ADAPTER_ID
    adapter_digest = BOUNTYBENCH_ADAPTER_DIGEST
    kind = ExternalBenchmarkKind.BOUNTYBENCH
    _metadata = re.compile(
        r"^(?P<project>[A-Za-z0-9_.-]+)/bounties/(?P<bounty>bounty_[0-9]+)/"
        r"bounty_metadata\.json$"
    )

    def normalize(
        self,
        root,
        snapshot: ExternalBenchmarkSnapshot,
        *,
        limits: ExternalImportLimits,
        deadline: ImportDeadline,
    ) -> tuple[BenchmarkSuite, tuple[ExternalCaseExclusion, ...]]:
        if snapshot.kind is not self.kind:
            raise ExternalBenchmarkRejected("BountyBench adapter received another snapshot kind")
        metadata = tuple(
            (item, self._metadata.fullmatch(item.path))
            for item in snapshot.files
            if item.path.endswith("/bounty_metadata.json")
        )
        matched = tuple((item, match) for item, match in metadata if match is not None)
        if not matched:
            raise ExternalBenchmarkRejected("BountyBench snapshot contains no bounty metadata")
        if len(matched) > limits.max_cases:
            raise ExternalBenchmarkRejected("BountyBench snapshot exceeds maximum case count")
        cases = []
        exclusions = []
        for item, match in matched:
            deadline.check()
            data = _json_object(
                read_verified_snapshot_file(
                    root, snapshot, item.path, limits=limits, deadline=deadline
                )
            )
            source_ref = f"{match.group('project')}/{match.group('bounty')}"
            cwe = _normalized_cwe(data.get("CWE"))
            version = data.get("vulnerable_commit")
            if cwe is None:
                exclusions.append(
                    ExternalCaseExclusion(
                        source_case_ref=source_ref,
                        reason_code="unsupported_or_missing_cwe",
                    )
                )
                continue
            if not isinstance(version, str) or not version.strip() or len(version) > 256:
                exclusions.append(
                    ExternalCaseExclusion(
                        source_case_ref=source_ref,
                        reason_code="missing_target_version",
                    )
                )
                continue
            cve = data.get("CVE")
            duplicate_key = (
                cve.strip().upper()
                if isinstance(cve, str) and re.fullmatch(r"(?i)CVE-[0-9]{4}-[0-9]{4,}", cve.strip())
                else source_ref
            )
            cases.append(
                _case(
                    source=BenchmarkSource.BOUNTYBENCH_SNAPSHOT,
                    snapshot=snapshot,
                    source_case_ref=source_ref,
                    target_version=version.strip(),
                    cwe=cwe,
                    duplicate_key=duplicate_key,
                )
            )
        return _suite_and_exclusions(
            snapshot,
            source=BenchmarkSource.BOUNTYBENCH_SNAPSHOT,
            cases=cases,
            exclusions=exclusions,
        )


class AutoPenBenchSnapshotAdapter:
    adapter_id = AUTOPENBENCH_ADAPTER_ID
    adapter_digest = AUTOPENBENCH_ADAPTER_DIGEST
    kind = ExternalBenchmarkKind.AUTOPENBENCH
    _target = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$")

    def normalize(
        self,
        root,
        snapshot: ExternalBenchmarkSnapshot,
        *,
        limits: ExternalImportLimits,
        deadline: ImportDeadline,
    ) -> tuple[BenchmarkSuite, tuple[ExternalCaseExclusion, ...]]:
        if snapshot.kind is not self.kind:
            raise ExternalBenchmarkRejected("AutoPenBench adapter received another snapshot kind")
        games = _json_object(
            read_verified_snapshot_file(
                root, snapshot, "data/games.json", limits=limits, deadline=deadline
            )
        )
        mapping_raw = _json_object(
            read_verified_snapshot_file(
                root,
                snapshot,
                "vulnloom-autopenbench-cwe.json",
                limits=limits,
                deadline=deadline,
            )
        )
        mapping = {}
        for target, value in mapping_raw.items():
            cwe = _normalized_cwe(value)
            if not self._target.fullmatch(target) or cwe is None:
                raise ExternalBenchmarkRejected("AutoPenBench CWE sidecar is invalid")
            mapping[target] = cwe

        discovered: dict[str, tuple[str, str]] = {}
        for level in sorted(games):
            categories = games[level]
            if not isinstance(categories, dict) or not self._target.fullmatch(level):
                raise ExternalBenchmarkRejected("AutoPenBench games hierarchy is invalid")
            for category in sorted(categories):
                entries = categories[category]
                if not isinstance(entries, list) or not self._target.fullmatch(category):
                    raise ExternalBenchmarkRejected("AutoPenBench games hierarchy is invalid")
                for entry in entries:
                    deadline.check()
                    if not isinstance(entry, dict):
                        raise ExternalBenchmarkRejected("AutoPenBench game entry is invalid")
                    target = entry.get("target")
                    vulnerability = entry.get("vulnerability")
                    if (
                        not isinstance(target, str)
                        or not self._target.fullmatch(target)
                        or not isinstance(vulnerability, str)
                        or not vulnerability
                    ):
                        raise ExternalBenchmarkRejected("AutoPenBench game identity is invalid")
                    if target in discovered:
                        raise ExternalBenchmarkRejected("AutoPenBench target identity is ambiguous")
                    discovered[target] = (f"{level}/{category}/{target}", vulnerability)
                    if len(discovered) > limits.max_cases:
                        raise ExternalBenchmarkRejected(
                            "AutoPenBench snapshot exceeds maximum case count"
                        )
        if set(mapping) - set(discovered):
            raise ExternalBenchmarkRejected("AutoPenBench CWE sidecar contains stale targets")
        cases = []
        exclusions = []
        for target in sorted(discovered):
            source_ref, vulnerability = discovered[target]
            cwe = mapping.get(target)
            if cwe is None:
                exclusions.append(
                    ExternalCaseExclusion(
                        source_case_ref=source_ref,
                        reason_code="missing_cwe_mapping",
                    )
                )
                continue
            cases.append(
                _case(
                    source=BenchmarkSource.AUTOPENBENCH_SNAPSHOT,
                    snapshot=snapshot,
                    source_case_ref=source_ref,
                    target_version=snapshot.upstream_revision,
                    cwe=cwe,
                    duplicate_key=canonical_digest(
                        {"target": target, "vulnerability": vulnerability}
                    ),
                )
            )
        return _suite_and_exclusions(
            snapshot,
            source=BenchmarkSource.AUTOPENBENCH_SNAPSHOT,
            cases=cases,
            exclusions=exclusions,
        )


def _suite_and_exclusions(
    snapshot: ExternalBenchmarkSnapshot,
    *,
    source: BenchmarkSource,
    cases: list[BenchmarkCase],
    exclusions: list[ExternalCaseExclusion],
) -> tuple[BenchmarkSuite, tuple[ExternalCaseExclusion, ...]]:
    try:
        suite = BenchmarkSuite.create(
            name=f"{source.value}:{snapshot.snapshot_id[:12]}",
            version=snapshot.upstream_revision,
            source=source,
            cases=tuple(sorted(cases, key=lambda item: item.case_id)),
        )
    except ValidationError as exc:
        raise ExternalBenchmarkRejected("external snapshot has no supported ground truth") from exc
    return suite, tuple(sorted(exclusions, key=lambda item: item.source_case_ref))
