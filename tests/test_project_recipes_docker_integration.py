from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

import pytest
from test_project_recipes import _approval
from test_source_hunt import _indexed, _snapshot

from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    Candidate,
)
from vulnloom.project_recipes import (
    ProjectRecipe,
    ProjectRecipeCandidateBindingService,
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
from vulnloom.source_hunt import (
    BuildSystem,
    SourceHuntLimits,
    SourceHuntService,
    SourceHuntStore,
)


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


@pytest.mark.docker_integration
@pytest.mark.skipif(
    os.environ.get("VULNLOOM_PROJECT_RECIPE_LOCAL_PROJECT") != "1",
    reason="set VULNLOOM_PROJECT_RECIPE_LOCAL_PROJECT=1 for A1.3 local project admission",
)
def test_current_vulnloom_project_recipe_binds_a_real_indexed_candidate(
    tmp_path, approved_scope, now
):
    repository_root = Path(__file__).parents[1]
    paths = (repository_root / "pyproject.toml", *sorted((repository_root / "src").rglob("*.py")))
    files = {
        path.relative_to(repository_root).as_posix(): path.read_text(encoding="utf-8")
        for path in paths
    }
    snapshot, scope, object_root = _snapshot(tmp_path, approved_scope, files)
    hunt_store = SourceHuntStore(tmp_path / "a1.3-source-hunt.sqlite3")
    index = SourceHuntService(store=hunt_store).index_repository(
        snapshot=snapshot,
        store_root=object_root,
        scope=scope,
        limits=SourceHuntLimits(max_files_per_partition=100),
        now=now,
    )
    symbols = sorted(index.symbols, key=lambda item: item.qualified_name)
    assert symbols
    candidate = Candidate(
        target_id=index.target_id,
        target_version=index.target_version,
        source_graph_id=index.index_id,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        title="VulnLoom local repository admission candidate",
        cwe="CWE-20",
        entry_point=symbols[0].location,
        sink=symbols[-1].location,
        code_path=(symbols[0].location, symbols[-1].location),
        security_invariant="Only bounded indexed inputs enter validation",
        hypothesis="The local indexed project is ready for isolated validation",
        signal_ids=("a" * 64,),
        cheapest_disproof="Run the approval-gated validation chain",
        duplicate_fingerprint="d" * 64,
        confidence=0.5,
    )
    backend = DockerCliBackend()
    image_digest = backend.inspect_image("vulnloom-project-recipe-python312:local")["Id"]
    recipe = ProjectRecipe.create(
        name="vulnloom-local",
        version="1.0.0",
        required_build_systems=(BuildSystem.PYPROJECT,),
        image_digest=image_digest,
        steps=(
            ProjectRecipeStep.create(
                phase=ProjectRecipePhase.BUILD,
                tool_id="recipe.vulnloom-local.build",
                argv=(
                    "/usr/local/bin/python",
                    "-m",
                    "compileall",
                    "-q",
                    "src/vulnloom",
                ),
                environment={
                    "HOME": "/tmp",
                    "TMPDIR": "/tmp",
                    "PYTHONPYCACHEPREFIX": "/workspace/output/pycache",
                },
                wall_seconds=60,
            ),
            ProjectRecipeStep.create(
                phase=ProjectRecipePhase.TEST,
                tool_id="recipe.vulnloom-local.test",
                argv=(
                    "/usr/local/bin/python",
                    "-c",
                    "from pathlib import Path; "
                    "p=Path('pyproject.toml').read_text(); "
                    "assert '[project]' in p and 'vulnloom' in p.lower()",
                ),
                environment={"HOME": "/tmp", "TMPDIR": "/tmp"},
                wall_seconds=30,
            ),
        ),
    )
    registry = ProjectRecipeRegistry((recipe,))
    plan = ProjectRecipePlanningService(registry=registry).prepare(
        recipe_id=recipe.recipe_id,
        index=index,
        scope=scope,
        now=now,
        deadline=now + timedelta(minutes=3),
        idempotency_key="a1.3:vulnloom-local",
    )
    recording_backend, runner = _runner(tmp_path, registry, index)
    with ProjectRecipeRunStore(tmp_path / "a1.3-project-recipes.sqlite3") as store:
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
        assert outcome.status is ProjectRecipeRunStatus.COMPLETED, tuple(
            (result.status, result.error_codes) for result in outcome.runner_results
        )
        binding = ProjectRecipeCandidateBindingService(
            scope=scope, store=store
        ).bind(
            plan=plan,
            outcome=outcome,
            index=index,
            candidate=candidate,
            now=now,
        )

        assert store.load_candidate_binding(binding.binding_id) == binding
    assert outcome.status is ProjectRecipeRunStatus.COMPLETED
    assert binding.index_id == index.index_id
    assert binding.candidate_id == candidate.candidate_id
    assert all(result.cleanup.complete for result in outcome.runner_results)
    assert recording_backend.container_ids
    assert all(not recording_backend.exists(item) for item in recording_backend.container_ids)
    hunt_store.close()
