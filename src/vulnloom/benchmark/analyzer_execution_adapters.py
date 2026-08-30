"""Exact source-only registrations for admitted Checkov, Kubesec, and Trivy CLIs."""

from __future__ import annotations

from vulnloom.domain.models import StaticFileCategory, TargetSnapshot

from .analyzer_adapters import (
    CHECKOV_ADAPTER_DIGEST,
    CHECKOV_ADAPTER_ID,
    KUBESEC_ADAPTER_DIGEST,
    KUBESEC_ADAPTER_ID,
    TRIVY_ADAPTER_DIGEST,
    TRIVY_ADAPTER_ID,
)
from .analyzer_execution_models import (
    AnalyzerOutputMode,
    AnalyzerToolRegistration,
)
from .analyzer_models import AnalyzerKind, AnalyzerResultFile
from .trivy_database import TrivyDatabaseSnapshot

TRIVY_TOOL_VERSION = "0.73.0"


def checkov_registration(
    *,
    tool_version: str,
    image_digest: str,
    rules_digest: str,
    cwe_map: AnalyzerResultFile,
) -> AnalyzerToolRegistration:
    return AnalyzerToolRegistration.create(
        tool_id="analyzer.checkov",
        analyzer=AnalyzerKind.CHECKOV,
        tool_version=tool_version,
        image_digest=image_digest,
        rules_digest=rules_digest,
        adapter_id=CHECKOV_ADAPTER_ID,
        adapter_digest=CHECKOV_ADAPTER_DIGEST,
        argv=(
            "/usr/local/bin/checkov",
            "--directory",
            "/workspace/source",
            "--framework",
            "kubernetes",
            "--output",
            "json",
            "--quiet",
            "--compact",
            "--soft-fail",
            "--skip-download",
            "--skip-results-upload",
        ),
        environment={
            "CHECKOV_KUSTOMIZE_ALLOWED_REMOTE_PREFIXES": "none",
            # Docker preserves image-declared variables. Listing every non-fixed
            # value here makes the Runner's exact environment comparison useful:
            # an image rebuilt with a different environment is rejected.
            "GPG_KEY": "A035C8C19219BA821ECEA86B64E628F8D684696D",
            "HOME": "/tmp",
            "PYTHON_SHA256": "91bcdebfdde239a003ae93738a7fce0f9230fee5c4bc2b86f6e6e8c6f98aabe8",
            "PYTHON_VERSION": "3.11.16",
            "RUN_IN_DOCKER": "True",
        },
        output_mode=AnalyzerOutputMode.STDOUT,
        cwe_map=cwe_map,
    )


def kubesec_registration(
    *,
    target: TargetSnapshot,
    input_paths: tuple[str, ...],
    tool_version: str,
    image_digest: str,
    rules_digest: str,
    cwe_map: AnalyzerResultFile,
) -> AnalyzerToolRegistration:
    known = {
        item.path
        for item in target.manifest.files
        if item.category is StaticFileCategory.KUBERNETES
    }
    if not input_paths or not set(input_paths) <= known:
        raise ValueError("Kubesec inputs must be Kubernetes files in the sealed Target manifest")
    ordered = tuple(sorted(set(input_paths)))
    if ordered != input_paths:
        raise ValueError("Kubesec inputs must be unique and sorted")
    return AnalyzerToolRegistration.create(
        tool_id="analyzer.kubesec",
        analyzer=AnalyzerKind.KUBESEC,
        tool_version=tool_version,
        image_digest=image_digest,
        rules_digest=rules_digest,
        adapter_id=KUBESEC_ADAPTER_ID,
        adapter_digest=KUBESEC_ADAPTER_DIGEST,
        argv=(
            "/bin/kubesec",
            "scan",
            *(f"/workspace/source/{path}" for path in ordered),
            "--format",
            "json",
        ),
        input_paths=ordered,
        environment={
            "HOME": "/tmp",
            "K8S_SCHEMA_VER": "",
            "SCHEMA_LOCATION": "/schemas",
        },
        output_mode=AnalyzerOutputMode.STDOUT,
        cwe_map=cwe_map,
    )


def trivy_registration(
    *,
    tool_version: str,
    image_digest: str,
    database: TrivyDatabaseSnapshot,
) -> AnalyzerToolRegistration:
    if tool_version != TRIVY_TOOL_VERSION or database.tool_version != TRIVY_TOOL_VERSION:
        raise ValueError(f"only Trivy {TRIVY_TOOL_VERSION} is admitted")
    return AnalyzerToolRegistration.create(
        tool_id="analyzer.trivy",
        analyzer=AnalyzerKind.TRIVY,
        tool_version=tool_version,
        image_digest=image_digest,
        rules_digest=database.snapshot_id,
        adapter_id=TRIVY_ADAPTER_ID,
        adapter_digest=TRIVY_ADAPTER_DIGEST,
        argv=(
            "/usr/local/bin/trivy",
            "filesystem",
            "--cache-dir",
            "/workspace/analyzer-data",
            "--cache-backend",
            "memory",
            "--scanners",
            "vuln",
            "--pkg-types",
            "library",
            "--format",
            "json",
            "--quiet",
            "--no-progress",
            "--offline-scan",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--skip-vex-repo-update",
            "--skip-version-check",
            "--disable-telemetry",
            "--exit-code",
            "0",
            "/workspace/source",
        ),
        environment={"HOME": "/tmp", "TMPDIR": "/tmp"},
        output_mode=AnalyzerOutputMode.STDOUT,
        trivy_database=database,
    )


def validate_admitted_registration(
    target: TargetSnapshot,
    registration: AnalyzerToolRegistration,
) -> None:
    if registration.output_mode is not AnalyzerOutputMode.STDOUT:
        raise ValueError("real analyzer execution requires bounded stdout")
    if registration.analyzer is AnalyzerKind.CHECKOV:
        if registration.cwe_map is None or registration.trivy_database is not None:
            raise ValueError("real Checkov execution requires one sealed CWE map")
        expected = checkov_registration(
            tool_version=registration.tool_version,
            image_digest=registration.image_digest,
            rules_digest=registration.rules_digest,
            cwe_map=registration.cwe_map,
        )
    elif registration.analyzer is AnalyzerKind.KUBESEC:
        if registration.cwe_map is None or registration.trivy_database is not None:
            raise ValueError("real Kubesec execution requires one sealed CWE map")
        expected = kubesec_registration(
            target=target,
            input_paths=registration.input_paths,
            tool_version=registration.tool_version,
            image_digest=registration.image_digest,
            rules_digest=registration.rules_digest,
            cwe_map=registration.cwe_map,
        )
    elif registration.analyzer is AnalyzerKind.TRIVY:
        if registration.cwe_map is not None or registration.trivy_database is None:
            raise ValueError("real Trivy execution requires one sealed offline database")
        expected = trivy_registration(
            tool_version=registration.tool_version,
            image_digest=registration.image_digest,
            database=registration.trivy_database,
        )
    else:
        raise ValueError("only Checkov, Kubesec, and Trivy are admitted for real execution")
    if expected != registration:
        raise ValueError("analyzer registration does not match the admitted exact argv")
