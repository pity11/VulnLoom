from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    Candidate,
    Scope,
    ScopeState,
    SourceLocation,
    utc_now,
)
from vulnloom.project_recipes import (
    ProjectRecipe,
    ProjectRecipeCandidateBindingService,
    ProjectRecipeExecutionService,
    ProjectRecipePhase,
    ProjectRecipePlanningService,
    ProjectRecipeRegistry,
    ProjectRecipeRegistryError,
    ProjectRecipeRejected,
    ProjectRecipeRunPlan,
    ProjectRecipeRunStatus,
    ProjectRecipeRunStep,
    ProjectRecipeRunStore,
    ProjectRecipeStep,
    project_recipe_approval_digest,
)
from vulnloom.runners import (
    OfflineSandboxRunner,
    OfflineScenario,
    RunnerCleanupFailed,
    RunnerRejected,
    SandboxRunRequest,
)
from vulnloom.source_hunt import BuildSystem, RepositoryIndex

IMAGE = "sha256:" + "1" * 64


def _recipe() -> ProjectRecipe:
    return ProjectRecipe.create(
        name="python-wheel",
        version="1.0.0",
        required_build_systems=(BuildSystem.PYPROJECT,),
        image_digest=IMAGE,
        steps=(
            ProjectRecipeStep.create(
                phase=ProjectRecipePhase.BUILD,
                tool_id="recipe.python-wheel.build",
                argv=("/usr/local/bin/python", "-m", "build", "--wheel", "--no-isolation"),
                environment={"HOME": "/tmp", "TMPDIR": "/tmp"},
                wall_seconds=120,
            ),
            ProjectRecipeStep.create(
                phase=ProjectRecipePhase.TEST,
                tool_id="recipe.python-wheel.test",
                argv=("/usr/local/bin/python", "-m", "pytest", "-q"),
                environment={"HOME": "/tmp", "TMPDIR": "/tmp"},
                wall_seconds=180,
            ),
        ),
    )


def _scope(now):
    return Scope(
        scope_id=uuid4(),
        engagement_id=uuid4(),
        authority_reference="local-fixture",
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(hours=1),
        approval_requirements=frozenset({ApprovalAction.RUN_UNTRUSTED_BUILD}),
        state=ScopeState.APPROVED,
        approved_by="reviewer",
        approved_at=now - timedelta(seconds=30),
    )


def _index(scope: Scope, *, build_systems=(BuildSystem.PYPROJECT,)) -> RepositoryIndex:
    return RepositoryIndex.create(
        target_id=uuid4(),
        target_version="fixture-v1",
        scope_id=scope.scope_id,
        scope_version=scope.version,
        manifest_id="2" * 64,
        adapter_versions={},
        source_files=(),
        files_indexed=(),
        symbols=(),
        references=(),
        build_systems=build_systems,
        partitions=(),
        skipped_files=(),
    )


def _approval(plan, scope, index, now):
    return ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=index.target_id,
        action=ApprovalAction.RUN_UNTRUSTED_BUILD,
        action_digest=project_recipe_approval_digest(plan),
        expected_side_effects=("execute sealed project recipe in isolated runner",),
        evidence_summary="Local fixture recipe review",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=10),
        status=ApprovalStatus.GRANTED,
        decided_by="reviewer",
        decided_at=now,
    )


def _plan(now):
    recipe = _recipe()
    registry = ProjectRecipeRegistry((recipe,))
    scope = _scope(now)
    index = _index(scope)
    plan = ProjectRecipePlanningService(registry=registry).prepare(
        recipe_id=recipe.recipe_id,
        index=index,
        scope=scope,
        now=now,
        deadline=now + timedelta(minutes=15),
        idempotency_key="recipe-run-1",
    )
    return recipe, registry, scope, index, plan


def _candidate(index: RepositoryIndex, scope: Scope) -> Candidate:
    location = SourceLocation(path="src/example.py", line=1, symbol="example")
    return Candidate(
        target_id=index.target_id,
        target_version=index.target_version,
        source_graph_id=index.index_id,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        title="Project recipe binding candidate",
        cwe="CWE-20",
        entry_point=location,
        sink=location,
        code_path=(location,),
        security_invariant="Input must be validated before use",
        hypothesis="The indexed project contains a bounded candidate path",
        signal_ids=("3" * 64,),
        cheapest_disproof="Run the isolated validation chain",
        duplicate_fingerprint="4" * 64,
        confidence=0.5,
    )


def test_registry_is_content_addressed_and_rejects_shells_or_duplicates():
    recipe = _recipe()
    registry = ProjectRecipeRegistry((recipe,))

    assert registry.require(recipe.recipe_id) == recipe
    assert tuple(tool.argv_prefix for tool in registry.docker_tools) == tuple(
        step.argv for step in recipe.steps
    )
    assert registry.digest == ProjectRecipeRegistry((recipe,)).digest

    with pytest.raises(ValidationError, match="non-shell"):
        ProjectRecipeStep.create(
            phase=ProjectRecipePhase.BUILD,
            tool_id="recipe.bad.build",
            argv=("/bin/sh", "-c", "make"),
        )
    with pytest.raises(ValidationError, match="non-shell"):
        ProjectRecipeStep.create(
            phase=ProjectRecipePhase.BUILD,
            tool_id="recipe.bad.path",
            argv=("/usr/local/../bin/make",),
        )
    with pytest.raises(ValidationError, match="credential-like"):
        ProjectRecipeStep.create(
            phase=ProjectRecipePhase.BUILD,
            tool_id="recipe.bad.secret",
            argv=("/usr/bin/make",),
            environment={"API_TOKEN": "forbidden"},
        )
    with pytest.raises(ProjectRecipeRegistryError, match="identity"):
        ProjectRecipeRegistry((recipe, recipe))


def test_planner_materializes_only_registered_networkless_commands():
    now = utc_now()
    recipe, registry, _, _, plan = _plan(now)

    assert plan.recipe_id == recipe.recipe_id
    assert plan.registry_digest == registry.digest
    assert tuple(step.step_id for step in plan.steps) == tuple(
        step.step_id for step in recipe.steps
    )
    for planned, registered in zip(plan.steps, recipe.steps, strict=True):
        assert planned.request.invocation.tool_id == registered.tool_id
        assert planned.request.invocation.arguments == ()
        assert planned.request.environment == registered.environment
        assert planned.request.profile.network_mode.value == "none"
        assert planned.request.profile.allowed_tools == {registered.tool_id}
        assert planned.request.task.budget.model_tokens == 0


def test_success_is_persisted_and_exact_retry_is_idempotent(tmp_path):
    now = utc_now()
    _, registry, scope, index, plan = _plan(now)
    runner = OfflineSandboxRunner(registry.tool_ids)
    with ProjectRecipeRunStore(tmp_path / "recipes.db") as store:
        service = ProjectRecipeExecutionService(
            scope=scope, registry=registry, runner=runner, store=store
        )
        approval = _approval(plan, scope, index, now)
        outcome = service.execute(
            plan=plan, index=index, approval=approval, now=now
        )
        replay = service.execute(
            plan=plan, index=index, approval=approval, now=now
        )

        assert outcome.status is ProjectRecipeRunStatus.COMPLETED
        assert outcome == replay == store.load(plan.plan_id)
        assert outcome.executed_step_ids == tuple(step.step_id for step in plan.steps)
        assert all(result.cleanup.complete for result in outcome.runner_results)


def test_successful_recipe_binds_exact_candidate_idempotently(tmp_path):
    now = utc_now()
    _, registry, scope, index, plan = _plan(now)
    candidate = _candidate(index, scope)
    with ProjectRecipeRunStore(tmp_path / "recipes.db") as store:
        outcome = ProjectRecipeExecutionService(
            scope=scope,
            registry=registry,
            runner=OfflineSandboxRunner(registry.tool_ids),
            store=store,
        ).execute(
            plan=plan,
            index=index,
            approval=_approval(plan, scope, index, now),
            now=now,
        )
        service = ProjectRecipeCandidateBindingService(scope=scope, store=store)
        binding = service.bind(
            plan=plan,
            outcome=outcome,
            index=index,
            candidate=candidate,
            now=now,
        )

        assert binding == service.bind(
            plan=plan,
            outcome=outcome,
            index=index,
            candidate=candidate,
            now=now,
        )
        assert store.load_candidate_binding(binding.binding_id) == binding
        assert binding.candidate_id == candidate.candidate_id
        assert binding.manifest_id == index.manifest_id

        changed_candidate = candidate.model_copy(update={"confidence": 0.6})
        with pytest.raises(ProjectRecipeRejected, match="authoritative state"):
            service.bind(
                plan=plan,
                outcome=outcome,
                index=index,
                candidate=changed_candidate,
                now=now,
            )


def test_incomplete_or_unavailable_recipe_cannot_bind_candidate(tmp_path):
    now = utc_now()
    _, registry, scope, index, plan = _plan(now)
    candidate = _candidate(index, scope)
    with ProjectRecipeRunStore(tmp_path / "failed.db") as store:
        outcome = ProjectRecipeExecutionService(
            scope=scope,
            registry=registry,
            runner=_ScenarioRunner(
                registry.tool_ids, OfflineScenario(wall_seconds=601)
            ),
            store=store,
        ).execute(
            plan=plan,
            index=index,
            approval=_approval(plan, scope, index, now),
            now=now,
        )
        with pytest.raises(ProjectRecipeRejected, match="provenance"):
            ProjectRecipeCandidateBindingService(scope=scope, store=store).bind(
                plan=plan,
                outcome=outcome,
                index=index,
                candidate=candidate,
                now=now,
            )

    with (
        ProjectRecipeRunStore(tmp_path / "missing.db") as store,
        pytest.raises(ProjectRecipeRejected, match="source is unavailable"),
    ):
        ProjectRecipeCandidateBindingService(scope=scope, store=store).bind(
            plan=plan,
            outcome=outcome,
            index=index,
            candidate=candidate,
            now=now,
        )


def test_missing_approval_and_build_system_mismatch_fail_closed(tmp_path):
    now = utc_now()
    recipe, registry, scope, index, plan = _plan(now)
    with ProjectRecipeRunStore(tmp_path / "recipes.db") as store:
        service = ProjectRecipeExecutionService(
            scope=scope,
            registry=registry,
            runner=OfflineSandboxRunner(registry.tool_ids),
            store=store,
        )
        pending = _approval(plan, scope, index, now).model_copy(
            update={"status": ApprovalStatus.PENDING, "decided_by": None, "decided_at": None}
        )
        with pytest.raises(ProjectRecipeRejected, match="exact untrusted-build approval"):
            service.execute(plan=plan, index=index, approval=pending, now=now)

    incompatible = _index(scope, build_systems=(BuildSystem.NPM,))
    with pytest.raises(ProjectRecipeRejected, match="planning preflight"):
        ProjectRecipePlanningService(registry=registry).prepare(
            recipe_id=recipe.recipe_id,
            index=incompatible,
            scope=scope,
            now=now,
            deadline=now + timedelta(minutes=5),
            idempotency_key="incompatible",
        )


def test_sealed_plan_drift_is_rejected_even_with_matching_approval(tmp_path):
    now = utc_now()
    _, registry, scope, index, plan = _plan(now)
    first = plan.steps[0]
    request_values = first.request.model_dump(mode="python")
    request_values["environment"] = {"HOME": "/workspace/output"}
    changed_request = SandboxRunRequest.model_validate(request_values)
    changed_steps = (
        ProjectRecipeRunStep(
            step_id=first.step_id, phase=first.phase, request=changed_request
        ),
        *plan.steps[1:],
    )
    plan_values = plan.model_dump(mode="python", exclude={"plan_id", "steps"})
    drifted = ProjectRecipeRunPlan.create(**plan_values, steps=changed_steps)

    with ProjectRecipeRunStore(tmp_path / "recipes.db") as store:
        service = ProjectRecipeExecutionService(
            scope=scope,
            registry=registry,
            runner=OfflineSandboxRunner(registry.tool_ids),
            store=store,
        )
        with pytest.raises(ProjectRecipeRejected, match="run plan drifted"):
            service.execute(
                plan=drifted,
                index=index,
                approval=_approval(drifted, scope, index, now),
                now=now,
            )


class _ScenarioRunner:
    def __init__(self, registered_tools, scenario):
        self.runner = OfflineSandboxRunner(registered_tools)
        self.scenario = scenario

    def execute(self, request, *, now):
        return self.runner.execute(request, now=now, scenario=self.scenario)


class _IncompleteCleanupRunner:
    def __init__(self, registered_tools):
        del registered_tools

    def execute(self, request, *, now):
        del request, now
        raise RunnerCleanupFailed("fixture cleanup cannot be proven")


class _RejectingRunner:
    def __init__(self, registered_tools):
        del registered_tools

    def execute(self, request, *, now):
        del request, now
        raise RunnerRejected("fixture image environment drifted")


@pytest.mark.parametrize(
    ("runner_factory", "expected_status", "reason"),
    [
        (
            lambda tools: _ScenarioRunner(
                tools, OfflineScenario(wall_seconds=601)
            ),
            ProjectRecipeRunStatus.TIMED_OUT,
            "step_timed_out",
        ),
        (
            _IncompleteCleanupRunner,
            ProjectRecipeRunStatus.FAILED,
            "cleanup_unverified",
        ),
        (
            _RejectingRunner,
            ProjectRecipeRunStatus.FAILED,
            "runner_rejected",
        ),
    ],
)
def test_timeout_and_cleanup_failure_are_terminal_and_persisted(
    tmp_path, runner_factory, expected_status, reason
):
    now = utc_now()
    _, registry, scope, index, plan = _plan(now)
    with ProjectRecipeRunStore(tmp_path / reason / "recipes.db") as store:
        outcome = ProjectRecipeExecutionService(
            scope=scope,
            registry=registry,
            runner=runner_factory(registry.tool_ids),
            store=store,
        ).execute(
            plan=plan,
            index=index,
            approval=_approval(plan, scope, index, now),
            now=now,
        )

        assert outcome.status is expected_status
        assert outcome.reason_code == reason
        assert store.load(plan.plan_id) == outcome
