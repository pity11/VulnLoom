"""Exact source-only registrations for admitted Checkov and Kubesec CLIs."""

from __future__ import annotations

from vulnloom.domain.models import StaticFileCategory, TargetSnapshot

from .analyzer_adapters import (
    CHECKOV_ADAPTER_DIGEST,
    CHECKOV_ADAPTER_ID,
    KUBESEC_ADAPTER_DIGEST,
    KUBESEC_ADAPTER_ID,
)
from .analyzer_execution_models import (
    AnalyzerOutputMode,
    AnalyzerToolRegistration,
)
from .analyzer_models import AnalyzerKind, AnalyzerResultFile


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


def validate_admitted_registration(
    target: TargetSnapshot,
    registration: AnalyzerToolRegistration,
) -> None:
    if registration.cwe_map is None or registration.output_mode is not AnalyzerOutputMode.STDOUT:
        raise ValueError("real Checkov/Kubesec execution requires sealed CWE map and stdout")
    if registration.analyzer is AnalyzerKind.CHECKOV:
        expected = checkov_registration(
            tool_version=registration.tool_version,
            image_digest=registration.image_digest,
            rules_digest=registration.rules_digest,
            cwe_map=registration.cwe_map,
        )
    elif registration.analyzer is AnalyzerKind.KUBESEC:
        expected = kubesec_registration(
            target=target,
            input_paths=registration.input_paths,
            tool_version=registration.tool_version,
            image_digest=registration.image_digest,
            rules_digest=registration.rules_digest,
            cwe_map=registration.cwe_map,
        )
    else:
        raise ValueError("only Checkov and Kubesec are admitted for real execution")
    if expected != registration:
        raise ValueError("analyzer registration does not match the admitted exact argv")
