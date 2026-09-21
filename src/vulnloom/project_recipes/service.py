"""Approval-gated planning and execution of trusted project recipes."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import NAMESPACE_URL, uuid5

from vulnloom.domain.models import ApprovalAction, ApprovalRequest, Scope, ScopeState
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.policy import PolicyEngine
from vulnloom.runners import (
    NetworkMode,
    RunnerCleanupFailed,
    RunnerRejected,
    SandboxProfile,
    SandboxRunRequest,
    SandboxRunResult,
    SandboxRunStatus,
    ToolInvocation,
    validation_profile,
)
from vulnloom.runners.models import invocation_digest, sandbox_profile_digest
from vulnloom.source_hunt.models import RepositoryIndex

from .models import (
    ProjectRecipe,
    ProjectRecipeRunOutcome,
    ProjectRecipeRunPlan,
    ProjectRecipeRunStatus,
    ProjectRecipeRunStep,
    project_recipe_approval_digest,
)
from .registry import ProjectRecipeRegistry, ProjectRecipeRegistryError
from .store import ProjectRecipeRunStore


class ProjectRecipeRejected(ValueError):
    pass


class ProjectRecipeRunner(Protocol):
    def execute(
        self, request: SandboxRunRequest, *, now: datetime
    ) -> SandboxRunResult: ...


class ProjectRecipePlanningService:
    def __init__(self, *, registry: ProjectRecipeRegistry):
        self.registry = registry

    def prepare(
        self,
        *,
        recipe_id: str,
        index: RepositoryIndex,
        scope: Scope,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> ProjectRecipeRunPlan:
        try:
            recipe = self.registry.require(recipe_id)
        except ProjectRecipeRegistryError as exc:
            raise ProjectRecipeRejected("project recipe is not admitted") from exc
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or not now < deadline <= scope.valid_until
            or index.scope_id != scope.scope_id
            or index.scope_version != scope.version
            or not set(recipe.required_build_systems) <= set(index.build_systems)
        ):
            raise ProjectRecipeRejected("project recipe planning preflight failed")

        steps = tuple(
            self._materialize_step(
                recipe=recipe,
                index=index,
                scope=scope,
                ordinal=ordinal,
                deadline=deadline,
                idempotency_key=idempotency_key,
            )
            for ordinal in range(len(recipe.steps))
        )
        return ProjectRecipeRunPlan.create(
            registry_digest=self.registry.digest,
            recipe_id=recipe.recipe_id,
            index_id=index.index_id,
            manifest_id=index.manifest_id,
            target_version=index.target_version,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            steps=steps,
            created_at=now,
            deadline=deadline,
            idempotency_key=idempotency_key,
        )

    def _materialize_step(
        self,
        *,
        recipe: ProjectRecipe,
        index: RepositoryIndex,
        scope: Scope,
        ordinal: int,
        deadline: datetime,
        idempotency_key: str,
    ) -> ProjectRecipeRunStep:
        step = recipe.steps[ordinal]
        base_profile = validation_profile(
            image_digest=recipe.image_digest, snapshot_id=index.manifest_id
        )
        profile = SandboxProfile.model_validate(
            base_profile.model_copy(
                update={"allowed_tools": frozenset({step.tool_id})}
            ).model_dump(mode="python")
        )
        stable_name = f"vulnloom:project-recipe:{idempotency_key}:{step.step_id}"
        task = TaskEnvelope(
            task_id=uuid5(NAMESPACE_URL, f"{stable_name}:task"),
            engagement_id=scope.engagement_id,
            target_id=index.target_id,
            target_version=index.target_version,
            scope_id=scope.scope_id,
            worker_role=WorkerRole.VALIDATOR,
            scope_version=scope.version,
            policy_digest=PolicyEngine(scope).policy_digest,
            sandbox_profile_digest=sandbox_profile_digest(profile),
            tool_registry_digest=self.registry.digest,
            input_refs=(
                f"snapshot:{index.manifest_id}",
                f"repository-index:{index.index_id}",
                f"project-recipe:{recipe.recipe_id}",
            ),
            allowed_tools=profile.allowed_tools,
            budget=TaskBudget(
                wall_seconds=step.wall_seconds, model_tokens=0, tool_calls=1
            ),
            deadline=deadline,
            idempotency_key=f"{idempotency_key}:{ordinal}:task",
        )
        return ProjectRecipeRunStep(
            step_id=step.step_id,
            phase=step.phase,
            request=SandboxRunRequest(
                run_id=uuid5(NAMESPACE_URL, f"{stable_name}:run"),
                task=task,
                profile=profile,
                invocation=ToolInvocation(
                    tool_id=step.tool_id,
                    arguments=(),
                    working_directory="source",
                ),
                environment=step.environment,
                idempotency_key=f"{idempotency_key}:{ordinal}:run",
            ),
        )


class ProjectRecipeExecutionService:
    def __init__(
        self,
        *,
        scope: Scope,
        registry: ProjectRecipeRegistry,
        runner: ProjectRecipeRunner,
        store: ProjectRecipeRunStore,
    ):
        self.scope = scope
        self.registry = registry
        self.runner = runner
        self.store = store

    def execute(
        self,
        *,
        plan: ProjectRecipeRunPlan,
        index: RepositoryIndex,
        approval: ApprovalRequest,
        now: datetime,
    ) -> ProjectRecipeRunOutcome:
        self._preflight(plan, index, approval, now=now)
        initial = ProjectRecipeRunOutcome(
            plan_id=plan.plan_id,
            status=ProjectRecipeRunStatus.RUNNING,
            executed_step_ids=(),
            runner_results=(),
            reason_code="execution_started",
            updated_at=now,
        )
        outcome = self.store.claim(plan, initial)
        if outcome.status is not ProjectRecipeRunStatus.RUNNING:
            return outcome
        for step in plan.steps[len(outcome.runner_results) :]:
            try:
                result = self.runner.execute(step.request, now=now)
            except RunnerCleanupFailed:
                failed = ProjectRecipeRunOutcome(
                    plan_id=plan.plan_id,
                    status=ProjectRecipeRunStatus.FAILED,
                    executed_step_ids=outcome.executed_step_ids,
                    runner_results=outcome.runner_results,
                    reason_code="cleanup_unverified",
                    updated_at=now,
                )
                self.store.save(plan, outcome, failed)
                return failed
            except RunnerRejected:
                failed = ProjectRecipeRunOutcome(
                    plan_id=plan.plan_id,
                    status=ProjectRecipeRunStatus.FAILED,
                    executed_step_ids=outcome.executed_step_ids,
                    runner_results=outcome.runner_results,
                    reason_code="runner_rejected",
                    updated_at=now,
                )
                self.store.save(plan, outcome, failed)
                return failed
            if (
                result.run_id != step.request.run_id
                or result.task_id != step.request.task.task_id
                or result.sandbox_profile_digest
                != sandbox_profile_digest(step.request.profile)
                or result.invocation_digest != invocation_digest(step.request.invocation)
            ):
                raise ProjectRecipeRejected("project recipe Runner provenance drifted")
            status, reason = self._status(result)
            next_outcome = ProjectRecipeRunOutcome(
                plan_id=plan.plan_id,
                status=status,
                executed_step_ids=(*outcome.executed_step_ids, step.step_id),
                runner_results=(*outcome.runner_results, result),
                reason_code=reason,
                updated_at=now,
            )
            self.store.save(plan, outcome, next_outcome)
            outcome = next_outcome
            if status is not ProjectRecipeRunStatus.RUNNING:
                return outcome
        final = ProjectRecipeRunOutcome(
            plan_id=plan.plan_id,
            status=ProjectRecipeRunStatus.COMPLETED,
            executed_step_ids=outcome.executed_step_ids,
            runner_results=outcome.runner_results,
            reason_code="recipe_completed",
            updated_at=now,
        )
        self.store.save(plan, outcome, final)
        return final

    def _preflight(
        self,
        plan: ProjectRecipeRunPlan,
        index: RepositoryIndex,
        approval: ApprovalRequest,
        *,
        now: datetime,
    ) -> None:
        try:
            recipe = self.registry.require(plan.recipe_id)
        except ProjectRecipeRegistryError as exc:
            raise ProjectRecipeRejected("project recipe is no longer registered") from exc
        if (
            self.scope.state is not ScopeState.APPROVED
            or not self.scope.valid_from <= now < self.scope.valid_until
            or now >= plan.deadline
            or plan.registry_digest != self.registry.digest
            or plan.index_id != index.index_id
            or plan.manifest_id != index.manifest_id
            or plan.target_version != index.target_version
            or plan.scope_id != self.scope.scope_id
            or plan.scope_version != self.scope.version
            or index.scope_id != self.scope.scope_id
            or index.scope_version != self.scope.version
            or not set(recipe.required_build_systems) <= set(index.build_systems)
        ):
            raise ProjectRecipeRejected("project recipe execution provenance drifted")
        if not approval.is_valid_for(
            action=ApprovalAction.RUN_UNTRUSTED_BUILD,
            digest=project_recipe_approval_digest(plan),
            now=now,
        ) or (
            approval.engagement_id != self.scope.engagement_id
            or approval.target_id != index.target_id
            or approval.policy_version != self.scope.version
            or approval.decided_by is None
            or approval.decided_at is None
        ):
            raise ProjectRecipeRejected(
                "project recipe requires exact untrusted-build approval"
            )
        expected = ProjectRecipePlanningService(registry=self.registry).prepare(
            recipe_id=recipe.recipe_id,
            index=index,
            scope=self.scope,
            now=plan.created_at,
            deadline=plan.deadline,
            idempotency_key=plan.idempotency_key,
        )
        if expected != plan:
            raise ProjectRecipeRejected("project recipe run plan drifted")
        for step in plan.steps:
            request = step.request
            if (
                request.profile.network_mode is not NetworkMode.NONE
                or not request.profile.execute_target_code
                or request.task.allowed_tools != frozenset({request.invocation.tool_id})
                or request.profile.allowed_tools != request.task.allowed_tools
                or request.invocation.arguments
            ):
                raise ProjectRecipeRejected("project recipe step escaped its sealed command")

    @staticmethod
    def _status(
        result: SandboxRunResult,
    ) -> tuple[ProjectRecipeRunStatus, str]:
        if not result.cleanup.complete:
            return ProjectRecipeRunStatus.FAILED, "cleanup_unverified"
        if result.status is SandboxRunStatus.COMPLETED:
            return ProjectRecipeRunStatus.RUNNING, "step_completed"
        if result.status is SandboxRunStatus.TIMED_OUT:
            return ProjectRecipeRunStatus.TIMED_OUT, "step_timed_out"
        if result.status is SandboxRunStatus.CANCELLED:
            return ProjectRecipeRunStatus.CANCELLED, "step_cancelled"
        return ProjectRecipeRunStatus.FAILED, "step_failed"
