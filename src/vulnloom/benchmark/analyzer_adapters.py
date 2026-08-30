"""Versioned adapters for precomputed CodeQL, Trivy, Checkov, and Kubesec JSON."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Protocol

from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest

from .analyzer_io import (
    AnalyzerDeadline,
    AnalyzerImportRejected,
    normalize_cwes,
    safe_rule_id,
)
from .analyzer_models import (
    AnalyzerExclusion,
    AnalyzerImportLimits,
    AnalyzerKind,
    AnalyzerLocation,
    AnalyzerObservation,
    AnalyzerObservationSet,
    AnalyzerResultSnapshot,
    AnalyzerSeverity,
)


def _adapter_digest(adapter_id: str, contract: str) -> str:
    return canonical_digest({"adapter_id": adapter_id, "contract": contract})


CODEQL_ADAPTER_ID = "codeql.sarif.precomputed.v1"
TRIVY_ADAPTER_ID = "trivy.json.precomputed.v1"
CHECKOV_ADAPTER_ID = "checkov.json.precomputed.v1"
KUBESEC_ADAPTER_ID = "kubesec.json.precomputed.v1"
CODEQL_ADAPTER_DIGEST = _adapter_digest(CODEQL_ADAPTER_ID, "sarif-2.1.0-no-execution")
TRIVY_ADAPTER_DIGEST = _adapter_digest(TRIVY_ADAPTER_ID, "trivy-results-no-execution")
CHECKOV_ADAPTER_DIGEST = _adapter_digest(CHECKOV_ADAPTER_ID, "failed-checks-no-execution")
KUBESEC_ADAPTER_DIGEST = _adapter_digest(KUBESEC_ADAPTER_ID, "scoring-no-execution")


class AnalyzerObservationAdapter(Protocol):
    kind: AnalyzerKind
    adapter_id: str
    adapter_digest: str

    def normalize(
        self,
        snapshot: AnalyzerResultSnapshot,
        document: object,
        cwe_map: Mapping[str, tuple[str, ...]],
        *,
        limits: AnalyzerImportLimits,
        deadline: AnalyzerDeadline,
    ) -> AnalyzerObservationSet: ...


class _BaseAdapter:
    kind: AnalyzerKind
    adapter_id: str
    adapter_digest: str

    def _build(
        self,
        snapshot: AnalyzerResultSnapshot,
        rows: Iterable[dict[str, Any]],
        cwe_map: Mapping[str, tuple[str, ...]],
        *,
        limits: AnalyzerImportLimits,
        deadline: AnalyzerDeadline,
    ) -> AnalyzerObservationSet:
        observations: list[AnalyzerObservation] = []
        exclusions: list[AnalyzerExclusion] = []
        seen_rule_ids: set[str] = set()
        for index, row in enumerate(rows):
            deadline.check()
            if index >= limits.max_observations:
                raise AnalyzerImportRejected("analyzer result exceeds observation limit")
            source_ref = canonical_digest(
                {"snapshot_id": snapshot.snapshot_id, "index": index, "analyzer": self.kind}
            )
            if isinstance(row.get("reason_code"), str):
                exclusions.append(
                    AnalyzerExclusion(
                        source_ref_digest=source_ref,
                        reason_code=row["reason_code"],
                    )
                )
                continue
            rule_id = safe_rule_id(row.get("rule_id"))
            if rule_id is None:
                exclusions.append(
                    AnalyzerExclusion(
                        source_ref_digest=source_ref,
                        reason_code="invalid_rule_identity",
                    )
                )
                continue
            seen_rule_ids.add(rule_id)
            cwes = normalize_cwes(row.get("cwes")) or cwe_map.get(rule_id, ())
            if not cwes:
                exclusions.append(
                    AnalyzerExclusion(
                        source_ref_digest=source_ref,
                        reason_code="missing_cwe_mapping",
                    )
                )
                continue
            raw_locations = row.get("locations", ())
            if not isinstance(raw_locations, list | tuple):
                raise AnalyzerImportRejected("analyzer locations must be a JSON array")
            if len(raw_locations) > limits.max_locations_per_observation:
                raise AnalyzerImportRejected("analyzer observation exceeds location limit")
            locations: list[AnalyzerLocation] = []
            for raw_location in raw_locations:
                try:
                    if isinstance(raw_location, Mapping):
                        locations.append(AnalyzerLocation.model_validate(raw_location))
                except ValidationError:
                    # Unsafe/unportable source locations are observational metadata only.
                    continue
            message = row.get("message")
            message_digest = canonical_digest(
                message if isinstance(message, str) else {"rule_id": rule_id}
            )
            severity = _severity(row.get("severity"))
            observations.append(
                AnalyzerObservation.create(
                    analyzer=self.kind,
                    target_id=snapshot.target_id,
                    target_version=snapshot.target_version,
                    rule_id=rule_id,
                    rule_fingerprint=canonical_digest(
                        {
                            "analyzer": self.kind,
                            "tool_version": snapshot.tool_version,
                            "rules_digest": snapshot.rules_digest,
                            "rule_id": rule_id,
                        }
                    ),
                    cwes=tuple(cwes),
                    severity=severity,
                    message_digest=message_digest,
                    locations=tuple(locations),
                )
            )
        if set(cwe_map) - seen_rule_ids:
            raise AnalyzerImportRejected("analyzer CWE map contains stale rule identities")
        deduplicated = {item.observation_id: item for item in observations}
        return AnalyzerObservationSet.create(
            snapshot=snapshot,
            adapter_id=self.adapter_id,
            adapter_digest=self.adapter_digest,
            observations=tuple(deduplicated.values()),
            exclusions=tuple(set(exclusions)),
        )


class CodeQLSarifAdapter(_BaseAdapter):
    kind = AnalyzerKind.CODEQL
    adapter_id = CODEQL_ADAPTER_ID
    adapter_digest = CODEQL_ADAPTER_DIGEST

    def normalize(self, snapshot, document, cwe_map, *, limits, deadline):
        if not isinstance(document, dict) or document.get("version") != "2.1.0":
            raise AnalyzerImportRejected("CodeQL input must be a SARIF 2.1.0 object")
        runs = document.get("runs")
        if not isinstance(runs, list):
            raise AnalyzerImportRejected("CodeQL SARIF runs must be an array")
        rows: list[dict[str, Any]] = []
        for run in runs:
            deadline.check()
            if not isinstance(run, dict):
                raise AnalyzerImportRejected("CodeQL SARIF run must be an object")
            rule_metadata = _sarif_rule_metadata(run)
            results = run.get("results", [])
            if not isinstance(results, list):
                raise AnalyzerImportRejected("CodeQL SARIF results must be an array")
            for result in results:
                if not isinstance(result, dict):
                    raise AnalyzerImportRejected("CodeQL SARIF result must be an object")
                rule_id = result.get("ruleId")
                metadata = rule_metadata.get(rule_id, {}) if isinstance(rule_id, str) else {}
                rows.append(
                    {
                        "rule_id": rule_id,
                        "cwes": _collect_cwes(result, metadata),
                        "severity": result.get("level") or metadata.get("severity"),
                        "message": _nested_text(result.get("message")),
                        "locations": _sarif_locations(result.get("locations", [])),
                    }
                )
        return self._build(snapshot, rows, cwe_map, limits=limits, deadline=deadline)


class TrivyJsonAdapter(_BaseAdapter):
    kind = AnalyzerKind.TRIVY
    adapter_id = TRIVY_ADAPTER_ID
    adapter_digest = TRIVY_ADAPTER_DIGEST

    def normalize(self, snapshot, document, cwe_map, *, limits, deadline):
        if not isinstance(document, dict) or not isinstance(document.get("Results"), list):
            raise AnalyzerImportRejected("Trivy input must contain a Results array")
        rows: list[dict[str, Any]] = []
        for result in document["Results"]:
            deadline.check()
            if not isinstance(result, dict):
                raise AnalyzerImportRejected("Trivy Result must be an object")
            target = result.get("Target")
            for item in _required_array(result, "Vulnerabilities"):
                rows.append(
                    {
                        "rule_id": item.get("VulnerabilityID"),
                        "cwes": item.get("CweIDs"),
                        "severity": item.get("Severity"),
                        "message": item.get("Title") or item.get("Description"),
                        "locations": _simple_location(target),
                    }
                )
            for item in _required_array(result, "Misconfigurations"):
                cause = item.get("CauseMetadata")
                rows.append(
                    {
                        "rule_id": item.get("ID") or item.get("AVDID"),
                        "cwes": item.get("CweIDs"),
                        "severity": item.get("Severity"),
                        "message": item.get("Title") or item.get("Message"),
                        "locations": _simple_location(
                            target,
                            start=(cause or {}).get("StartLine")
                            if isinstance(cause, dict)
                            else None,
                            end=(cause or {}).get("EndLine") if isinstance(cause, dict) else None,
                        ),
                    }
                )
            secrets = result.get("Secrets", [])
            if secrets is not None and not isinstance(secrets, list):
                raise AnalyzerImportRejected("Trivy Secrets must be an array")
            for secret_index, _ in enumerate(secrets or []):
                rows.append(
                    {
                        "source_index": secret_index,
                        "reason_code": "unsupported_secret_result",
                    }
                )
        return self._build(snapshot, rows, cwe_map, limits=limits, deadline=deadline)


class CheckovJsonAdapter(_BaseAdapter):
    kind = AnalyzerKind.CHECKOV
    adapter_id = CHECKOV_ADAPTER_ID
    adapter_digest = CHECKOV_ADAPTER_DIGEST

    def normalize(self, snapshot, document, cwe_map, *, limits, deadline):
        reports = document if isinstance(document, list) else [document]
        rows: list[dict[str, Any]] = []
        for report in reports:
            deadline.check()
            if not isinstance(report, dict):
                raise AnalyzerImportRejected("Checkov report must be an object")
            results = report.get("results")
            if not isinstance(results, dict):
                raise AnalyzerImportRejected("Checkov report requires a results object")
            failed = results.get("failed_checks")
            if not isinstance(failed, list):
                raise AnalyzerImportRejected("Checkov failed_checks must be an array")
            for item in failed:
                if not isinstance(item, dict):
                    raise AnalyzerImportRejected("Checkov failed check must be an object")
                line_range = item.get("file_line_range")
                start = line_range[0] if isinstance(line_range, list) and line_range else None
                end = (
                    line_range[1] if isinstance(line_range, list) and len(line_range) > 1 else None
                )
                rows.append(
                    {
                        "rule_id": item.get("check_id"),
                        "cwes": item.get("cwe"),
                        "severity": item.get("severity"),
                        "message": item.get("check_name"),
                        "locations": _simple_location(item.get("file_path"), start=start, end=end),
                    }
                )
        return self._build(snapshot, rows, cwe_map, limits=limits, deadline=deadline)


class KubesecJsonAdapter(_BaseAdapter):
    kind = AnalyzerKind.KUBESEC
    adapter_id = KUBESEC_ADAPTER_ID
    adapter_digest = KUBESEC_ADAPTER_DIGEST

    def normalize(self, snapshot, document, cwe_map, *, limits, deadline):
        reports = document if isinstance(document, list) else [document]
        rows: list[dict[str, Any]] = []
        for report in reports:
            deadline.check()
            if not isinstance(report, dict) or not isinstance(report.get("scoring"), dict):
                raise AnalyzerImportRejected("Kubesec report requires a scoring object")
            scoring = report["scoring"]
            for category, severity in (("critical", "critical"), ("advise", "low")):
                entries = scoring.get(category, [])
                if not isinstance(entries, list):
                    raise AnalyzerImportRejected("Kubesec scoring entries must be an array")
                for item in entries:
                    if not isinstance(item, dict):
                        raise AnalyzerImportRejected("Kubesec scoring entry must be an object")
                    rows.append(
                        {
                            "rule_id": item.get("id"),
                            "cwes": item.get("cwe"),
                            "severity": severity,
                            "message": item.get("reason"),
                            "locations": [],
                        }
                    )
        return self._build(snapshot, rows, cwe_map, limits=limits, deadline=deadline)


def default_analyzer_adapters() -> dict[AnalyzerKind, AnalyzerObservationAdapter]:
    return {
        AnalyzerKind.CODEQL: CodeQLSarifAdapter(),
        AnalyzerKind.TRIVY: TrivyJsonAdapter(),
        AnalyzerKind.CHECKOV: CheckovJsonAdapter(),
        AnalyzerKind.KUBESEC: KubesecJsonAdapter(),
    }


def _sarif_rule_metadata(run: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, dict) else None
    rules = driver.get("rules", []) if isinstance(driver, dict) else []
    if not isinstance(rules, list):
        raise AnalyzerImportRejected("CodeQL SARIF rules must be an array")
    result: dict[str, dict[str, Any]] = {}
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            continue
        properties = rule.get("properties")
        result[rule["id"]] = properties if isinstance(properties, dict) else {}
    return result


def _collect_cwes(*values: object) -> tuple[str, ...]:
    collected: list[object] = []
    for value in values:
        if isinstance(value, Mapping):
            collected.extend(value.get("tags", []) if isinstance(value.get("tags"), list) else [])
            collected.extend(value.get("cwe", []) if isinstance(value.get("cwe"), list) else [])
            properties = value.get("properties")
            if isinstance(properties, Mapping):
                collected.extend(
                    properties.get("tags", []) if isinstance(properties.get("tags"), list) else []
                )
    return normalize_cwes(collected)


def _sarif_locations(raw: object) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise AnalyzerImportRejected("CodeQL SARIF locations must be an array")
    locations: list[dict[str, Any]] = []
    for item in raw:
        physical = item.get("physicalLocation") if isinstance(item, dict) else None
        artifact = physical.get("artifactLocation") if isinstance(physical, dict) else None
        region = physical.get("region") if isinstance(physical, dict) else None
        path = artifact.get("uri") if isinstance(artifact, dict) else None
        if isinstance(path, str):
            locations.append(
                {
                    "path": path,
                    "start_line": region.get("startLine") if isinstance(region, dict) else None,
                    "end_line": region.get("endLine") if isinstance(region, dict) else None,
                    "start_column": region.get("startColumn") if isinstance(region, dict) else None,
                    "end_column": region.get("endColumn") if isinstance(region, dict) else None,
                }
            )
    return locations


def _nested_text(value: object) -> str | None:
    return (
        value.get("text")
        if isinstance(value, dict) and isinstance(value.get("text"), str)
        else None
    )


def _required_array(container: Mapping[str, Any], key: str) -> list[dict[str, Any]]:
    value = container.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise AnalyzerImportRejected(f"Trivy {key} must be an array of objects")
    return value


def _simple_location(path: object, *, start: object = None, end: object = None):
    if not isinstance(path, str):
        return []
    return [
        {
            "path": path.removeprefix("./"),
            "start_line": start if isinstance(start, int) and start > 0 else None,
            "end_line": end if isinstance(end, int) and end > 0 else None,
        }
    ]


def _severity(value: object) -> AnalyzerSeverity:
    if not isinstance(value, str):
        return AnalyzerSeverity.UNKNOWN
    normalized = value.lower()
    aliases = {"warning": "medium", "error": "high", "note": "info", "none": "unknown"}
    normalized = aliases.get(normalized, normalized)
    try:
        return AnalyzerSeverity(normalized)
    except ValueError:
        return AnalyzerSeverity.UNKNOWN
