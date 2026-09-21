from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

import pytest
from test_project_recipes import _approval
from test_source_hunt import _indexed

from vulnloom.domain.models import ApprovalAction, ApprovalRequest, ApprovalStatus
from vulnloom.project_recipes import (
    ProjectRecipe,
    ProjectRecipeExecutionService,
    ProjectRecipePhase,
    ProjectRecipePlanningService,
    ProjectRecipeRegistry,
    ProjectRecipeRunStatus,
    ProjectRecipeRunStore,
    ProjectRecipeStep,
    project_recipe_approval_digest,
)
from vulnloom.runners import (
    DockerCliBackend,
    DockerEnginePolicy,
    DockerSandboxRunner,
    RegisteredObjectStore,
)
from vulnloom.source_hunt import BuildSystem


def _engine_policy() -> DockerEnginePolicy:
    if os.environ.get("VULNLOOM_ROOTLESS_QUALIFICATION") == "1":
        return DockerEnginePolicy()
    return DockerEnginePolicy(require_rootless=False, require_versioned_seccomp=False)


class _RecordingDockerBackend:
    def __init__(self):
        self.backend = DockerCliBackend()
        self.container_ids: list[str] = []

    def create(self, arguments):
        container_id = self.backend.create(arguments)
        self.container_ids.append(container_id)
        return container_id

    def __getattr__(self, name):
        return getattr(self.backend, name)


def _fixture_files() -> dict[str, str]:
    root = Path(__file__).parent / "fixtures" / "project_recipe_python"
    return {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.suffix in {".py", ".toml"}
    }


def _python_recipe(image_digest: str) -> ProjectRecipe:
    return ProjectRecipe.create(
        name="python-stdlib",
        version="1.0.0",
        required_build_systems=("pyproject",),
        image_digest=image_digest,
        steps=(
            ProjectRecipeStep.create(
                phase=ProjectRecipePhase.BUILD,
                tool_id="recipe.python-stdlib.build",
                argv=(
                    "/usr/local/bin/python",
                    "-m",
                    "compileall",
                    "-q",
                    "project_recipe_demo",
                    "checks",
                ),
                environment={
                    "HOME": "/tmp",
                    "TMPDIR": "/tmp",
                    "PYTHONPYCACHEPREFIX": "/workspace/output/pycache",
                },
                wall_seconds=30,
            ),
            ProjectRecipeStep.create(
                phase=ProjectRecipePhase.TEST,
                tool_id="recipe.python-stdlib.test",
                argv=(
                    "/usr/local/bin/python",
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    "checks",
                    "-p",
                    "check_*.py",
                    "-v",
                ),
                environment={
                    "HOME": "/tmp",
                    "TMPDIR": "/tmp",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                wall_seconds=30,
            ),
        ),
    )


def _runner(tmp_path, registry, index):
    backend = _RecordingDockerBackend()
    source = tmp_path / "objects" / "snapshots" / index.manifest_id
    runner = DockerSandboxRunner(
        backend,
        RegisteredObjectStore(tmp_path / "objects", {index.manifest_id: source}),
        registry.docker_tools,
        engine_policy=_engine_policy(),
    )
    return backend, runner


@pytest.mark.docker_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_PROJECT_RECIPE_INTEGRATION") != "1",
    reason="set VULNLOOM_PROJECT_RECIPE_INTEGRATION=1 for A1.2 local admission",
)
def test_registered_python_project_recipe_builds_and_tests_in_hardened_docker(
    tmp_path, approved_scope, now
):
    _hunt, hunt_store, index, scope = _indexed(
        tmp_path,
        approved_scope,
        now,
        extra_files=_fixture_files(),
    )
    backend = DockerCliBackend()
    image_digest = backend.inspect_image("vulnloom-project-recipe-python:local")["Id"]
    recipe = _python_recipe(image_digest)
    registry = ProjectRecipeRegistry((recipe,))
    plan = ProjectRecipePlanningService(registry=registry).prepare(
        recipe_id=recipe.recipe_id,
        index=index,
        scope=scope,
        now=now,
        deadline=now + timedelta(minutes=2),
        idempotency_key="a1.2:python-stdlib:success",
    )
    recording_backend, runner = _runner(tmp_path, registry, index)
    with ProjectRecipeRunStore(tmp_path / "project-recipes.sqlite3") as store:
        outcome = ProjectRecipeExecutionService(
            scope=scope,
            registry=registry,
            runner=runner,
            store=store,
        ).execute(
            plan=plan,
            index=index,
            approval=_approval(plan, scope, index, now),
            now=now,
        )

    assert outcome.status is ProjectRecipeRunStatus.COMPLETED
    assert len(outcome.runner_results) == 2
    assert all(result.cleanup.complete for result in outcome.runner_results)
    assert runner.last_inspection is not None
    inspection = runner.last_inspection
    assert inspection["Config"]["User"] == "65532:65532"
    assert inspection["HostConfig"]["ReadonlyRootfs"] is True
    assert inspection["HostConfig"]["NetworkMode"] == "none"
    assert set(inspection["HostConfig"]["CapDrop"]) == {"ALL"}
    assert all(mount["RW"] is False for mount in inspection["Mounts"])
    assert not any(mount["Destination"] == "/var/run/docker.sock" for mount in inspection["Mounts"])
    assert recording_backend.container_ids
    assert all(not recording_backend.exists(item) for item in recording_backend.container_ids)
    hunt_store.close()


@pytest.mark.docker_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_PROJECT_RECIPE_INTEGRATION") != "1",
    reason="set VULNLOOM_PROJECT_RECIPE_INTEGRATION=1 for A1.2 local admission",
)
def test_project_recipe_timeout_is_terminal_and_container_is_removed(
    tmp_path, approved_scope, now
):
    _hunt, hunt_store, index, scope = _indexed(
        tmp_path,
        approved_scope,
        now,
        extra_files=_fixture_files(),
    )
    backend = DockerCliBackend()
    image_digest = backend.inspect_image("vulnloom-project-recipe-python:local")["Id"]
    recipe = ProjectRecipe.create(
        name="python-timeout",
        version="1.0.0",
        required_build_systems=(BuildSystem.PYPROJECT,),
        image_digest=image_digest,
        steps=(
            ProjectRecipeStep.create(
                phase=ProjectRecipePhase.BUILD,
                tool_id="recipe.python-timeout.build",
                argv=(
                    "/usr/local/bin/python",
                    "-c",
                    "import time; time.sleep(2)",
                ),
                environment={"HOME": "/tmp", "TMPDIR": "/tmp"},
                wall_seconds=1,
            ),
            ProjectRecipeStep.create(
                phase=ProjectRecipePhase.TEST,
                tool_id="recipe.python-timeout.test",
                argv=("/usr/local/bin/python", "-c", "raise SystemExit(0)"),
                environment={"HOME": "/tmp", "TMPDIR": "/tmp"},
                wall_seconds=1,
            ),
        ),
    )
    registry = ProjectRecipeRegistry((recipe,))
    plan = ProjectRecipePlanningService(registry=registry).prepare(
        recipe_id=recipe.recipe_id,
        index=index,
        scope=scope,
        now=now,
        deadline=now + timedelta(minutes=2),
        idempotency_key="a1.2:python-timeout",
    )
    approval = ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=index.target_id,
        action=ApprovalAction.RUN_UNTRUSTED_BUILD,
        action_digest=project_recipe_approval_digest(plan),
        expected_side_effects=("run the sealed timeout admission recipe",),
        evidence_summary="A1.2 local timeout cleanup admission",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=2),
        status=ApprovalStatus.GRANTED,
        decided_by="integration-operator",
        decided_at=now,
    )
    recording_backend, runner = _runner(tmp_path, registry, index)
    with ProjectRecipeRunStore(tmp_path / "project-recipes-timeout.sqlite3") as store:
        outcome = ProjectRecipeExecutionService(
            scope=scope,
            registry=registry,
            runner=runner,
            store=store,
        ).execute(plan=plan, index=index, approval=approval, now=now)

    assert outcome.status is ProjectRecipeRunStatus.TIMED_OUT
    assert outcome.reason_code == "step_timed_out"
    assert len(outcome.runner_results) == 1
    assert outcome.runner_results[0].cleanup.complete
    assert recording_backend.container_ids
    assert all(not recording_backend.exists(item) for item in recording_backend.container_ids)
    hunt_store.close()


@pytest.mark.docker_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_PROJECT_RECIPE_INTEGRATION") != "1",
    reason="set VULNLOOM_PROJECT_RECIPE_INTEGRATION=1 for A1.2 local admission",
)
def test_project_recipe_rejects_inherited_image_environment_and_cleans_container(
    tmp_path, approved_scope, now
):
    _hunt, hunt_store, index, scope = _indexed(
        tmp_path,
        approved_scope,
        now,
        extra_files=_fixture_files(),
    )
    backend = DockerCliBackend()
    image_digest = backend.inspect_image("python:3.11-slim")["Id"]
    recipe = _python_recipe(image_digest)
    registry = ProjectRecipeRegistry((recipe,))
    plan = ProjectRecipePlanningService(registry=registry).prepare(
        recipe_id=recipe.recipe_id,
        index=index,
        scope=scope,
        now=now,
        deadline=now + timedelta(minutes=2),
        idempotency_key="a1.2:dirty-image:rejected",
    )
    recording_backend, runner = _runner(tmp_path, registry, index)
    with ProjectRecipeRunStore(tmp_path / "project-recipes-rejected.sqlite3") as store:
        outcome = ProjectRecipeExecutionService(
            scope=scope,
            registry=registry,
            runner=runner,
            store=store,
        ).execute(
            plan=plan,
            index=index,
            approval=_approval(plan, scope, index, now),
            now=now,
        )

        assert store.load(plan.plan_id) == outcome
    assert outcome.status is ProjectRecipeRunStatus.FAILED
    assert outcome.reason_code == "runner_rejected"
    assert not outcome.runner_results
    assert recording_backend.container_ids
    assert all(not recording_backend.exists(item) for item in recording_backend.container_ids)
    hunt_store.close()
