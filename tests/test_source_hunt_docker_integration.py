from __future__ import annotations

import os

import pytest
from test_source_hunt import _execution_fixture

from vulnloom.runners import (
    DockerCliBackend,
    DockerEnginePolicy,
    DockerSandboxRunner,
    DockerTool,
    RegisteredObjectStore,
    RunnerOutputStore,
)
from vulnloom.source_hunt import (
    RunnerOutputEvidenceAdapter,
    SourceExecutionService,
    SourceExecutionStatus,
    SourceExecutionStore,
)


def _engine_policy() -> DockerEnginePolicy:
    if os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") == "1":
        return DockerEnginePolicy()
    return DockerEnginePolicy(require_rootless=False)


@pytest.mark.docker_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_DOCKER_INTEGRATION") != "1",
    reason="set VULNLOOM_DOCKER_INTEGRATION=1 to run real Source Hunt isolation",
)
def test_real_source_execution_chain_is_networkless_secretless_and_clean(
    tmp_path, approved_scope, now
):
    backend = DockerCliBackend()
    image = backend.inspect_image("alpine:3.22")["Id"]
    fixture = _execution_fixture(tmp_path, approved_scope, now, image=image)
    (
        hunt_store,
        index,
        scope,
        checkpoint,
        candidate,
        plan,
        approval,
        evidence_store,
        _,
    ) = fixture
    source = tmp_path / "objects" / "snapshots" / index.manifest_id
    outputs = RunnerOutputStore(tmp_path / "runner-outputs")
    probe = """
set -eu
[ "$(id -u)" = "65532" ]
grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status
grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status
! touch /workspace/source/must-remain-read-only
[ "$(wc -l < /proc/net/route)" = "1" ]
[ ! -S /var/run/docker.sock ]
[ -z "${VULNLOOM_MODEL_API_KEY+x}" ]
printf '{"stage":"__STAGE__","result":"completed"}'
""".strip()
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {index.manifest_id: source}),
        tuple(
            DockerTool(
                tool_id=f"source.{stage}",
                argv_prefix=(
                    "/bin/sh",
                    "-c",
                    probe.replace("__STAGE__", stage),
                    "source-hunt-stage",
                ),
            )
            for stage in ("build", "harness", "fuzz", "sanitizer", "pov_replay")
        ),
        engine_policy=_engine_policy(),
        output_store=outputs,
        captured_output_tools=frozenset(
            {
                "source.build",
                "source.harness",
                "source.fuzz",
                "source.sanitizer",
                "source.pov_replay",
            }
        ),
    )
    with SourceExecutionStore(tmp_path / "docker-execution.sqlite3") as store:
        outcome = SourceExecutionService(
            scope=scope,
            runner=runner,
            evidence_store=evidence_store,
            store=store,
            output_evidence_adapter=RunnerOutputEvidenceAdapter(
                output_store=outputs, evidence_store=evidence_store
            ),
        ).execute(
            plan=plan,
            index=index,
            investigation=checkpoint,
            candidate=candidate,
            approval=approval,
            now=now,
        )
    assert outcome.status is SourceExecutionStatus.COMPLETED
    assert outcome.reproducible_pov
    assert len(outcome.evidence_refs) == 5
    assert all(item.cleanup.complete for item in outcome.runner_results)
    assert runner.last_inspection is not None
    assert not backend.exists(runner.last_inspection["Id"])
    hunt_store.close()
