from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.runners import (
    CleanupReport,
    NetworkGrant,
    OfflineOutcome,
    OfflineSandboxRunner,
    OfflineScenario,
    RunnerIdempotencyConflict,
    RunnerRejected,
    SandboxProfile,
    SandboxRunner,
    SandboxRunRequest,
    SandboxRunResult,
    SandboxRunStatus,
    ToolInvocation,
    report_profile,
    sandbox_profile_digest,
    static_profile,
    validation_profile,
)

IMAGE = "sha256:" + "1" * 64
SNAPSHOT = "2" * 64
EVIDENCE = "3" * 64


def _request(now, *, role=WorkerRole.SOURCE_MAPPER, profile=None, key="run:1"):
    profile = profile or static_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT)
    task = TaskEnvelope(
        engagement_id=uuid4(),
        target_id=uuid4(),
        target_version="4" * 40,
        scope_id=uuid4(),
        worker_role=role,
        scope_version=2,
        policy_digest="5" * 64,
        sandbox_profile_digest=sandbox_profile_digest(profile),
        tool_registry_digest="6" * 64,
        input_refs=("snapshot:" + SNAPSHOT,),
        allowed_tools=frozenset({"source.read"}),
        budget=TaskBudget(wall_seconds=60, model_tokens=0, tool_calls=2),
        deadline=now + timedelta(minutes=1),
        idempotency_key="task:source-map:2",
    )
    return SandboxRunRequest(
        task=task,
        profile=profile,
        invocation=ToolInvocation(
            tool_id="source.read", arguments=("app.py",), working_directory="source"
        ),
        environment={"VULNLOOM_TASK_ID": str(task.task_id)},
        idempotency_key=key,
    )


def test_profile_factories_are_hardened_and_deterministic():
    static = static_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT)
    validation = validation_profile(
        image_digest=IMAGE,
        snapshot_id=SNAPSHOT,
        network_grants=(
            NetworkGrant(
                host="app.example.test", ports=frozenset({443}), schemes=frozenset({"HTTPS"})
            ),
        ),
    )
    report = report_profile(image_digest=IMAGE, evidence_object_id=EVIDENCE)

    assert sandbox_profile_digest(static) == sandbox_profile_digest(static)
    assert static.network_mode.value == "none"
    assert validation.network_mode.value == "target_only"
    assert validation.network_grants[0].schemes == frozenset({"https"})
    assert report.network_mode.value == "none"
    assert not report.execute_target_code
    assert all(profile.run_as_uid != 0 for profile in (static, validation, report))
    assert all(
        profile.read_only_root and not profile.capabilities
        for profile in (static, validation, report)
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_as_uid", 0),
        ("read_only_root", False),
        ("no_new_privileges", False),
        ("capabilities", frozenset({"SYS_ADMIN"})),
        ("writable_paths", frozenset({"/workspace/output", "/host"})),
        ("execute_target_code", True),
    ],
)
def test_static_profile_cannot_weaken_security_invariants(field, value):
    raw = static_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT).model_dump(mode="python")
    raw[field] = value
    with pytest.raises(ValidationError):
        SandboxProfile.model_validate(raw)


def test_mount_contract_rejects_host_paths_and_report_source_mount():
    static = static_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT)
    raw = static.model_dump(mode="python")
    raw["mounts"][0]["destination"] = "/var/run/docker.sock"
    with pytest.raises(ValidationError, match="registered slot"):
        SandboxProfile.model_validate(raw)

    report = report_profile(image_digest=IMAGE, evidence_object_id=EVIDENCE)
    raw = report.model_dump(mode="python")
    raw["mounts"][0]["kind"] = "snapshot"
    raw["mounts"][0]["destination"] = "/workspace/source"
    with pytest.raises(ValidationError, match="report profile"):
        SandboxProfile.model_validate(raw)


def test_tool_invocation_has_no_shell_escape_field():
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ToolInvocation.model_validate(
            {
                "tool_id": "source.read",
                "arguments": (),
                "working_directory": "source",
                "shell": "cat /etc/passwd",
            }
        )
    with pytest.raises(ValidationError, match="NUL"):
        ToolInvocation(tool_id="source.read", arguments=("bad\x00arg",), working_directory="source")


def test_offline_runner_success_is_idempotent_and_always_clean(now):
    request = _request(now)
    runner = OfflineSandboxRunner(frozenset({"source.read"}))
    assert isinstance(runner, SandboxRunner)
    scenario = OfflineScenario(evidence_refs=("6" * 64,))
    first = runner.execute(request, now=now, scenario=scenario)
    repeated = runner.execute(
        request,
        now=now + timedelta(seconds=10),
        scenario=OfflineScenario(outcome=OfflineOutcome.FAILED),
    )

    assert first is repeated
    assert first.status is SandboxRunStatus.COMPLETED
    assert first.evidence_refs == ("6" * 64,)
    assert first.cleanup.complete
    assert first.budget_used.tool_calls == 1


@pytest.mark.parametrize(
    ("scenario", "status", "error"),
    [
        (OfflineScenario(wall_seconds=61), SandboxRunStatus.TIMED_OUT, "wall_time"),
        (
            OfflineScenario(outcome=OfflineOutcome.CANCELLED),
            SandboxRunStatus.CANCELLED,
            "cancelled",
        ),
        (
            OfflineScenario(peak_memory_bytes=1024 * 1024 * 1024),
            SandboxRunStatus.FAILED,
            "resource_limit",
        ),
        (
            OfflineScenario(outcome=OfflineOutcome.FAILED),
            SandboxRunStatus.FAILED,
            "offline_scenario",
        ),
    ],
)
def test_offline_runner_terminal_paths_are_clean(now, scenario, status, error):
    result = OfflineSandboxRunner(frozenset({"source.read"})).execute(
        _request(now), now=now, scenario=scenario
    )
    assert result.status is status
    assert any(error in item for item in result.error_codes)
    assert result.cleanup.complete
    assert result.evidence_refs == ()


def test_expired_task_times_out_without_running_tool(now):
    request = _request(now)
    expired_task = request.task.model_copy(update={"deadline": now})
    request = request.model_copy(update={"task": expired_task})
    result = OfflineSandboxRunner(frozenset({"source.read"})).execute(request, now=now)
    assert result.status is SandboxRunStatus.TIMED_OUT
    assert result.budget_used.tool_calls == 0
    assert result.cleanup.complete


@pytest.mark.parametrize("failure", ["digest", "role", "registry", "task", "budget"])
def test_runner_preflight_fails_before_allocating_resources(now, failure):
    request = _request(now)
    tools = frozenset({"source.read"})
    if failure == "digest":
        request = request.model_copy(
            update={"task": request.task.model_copy(update={"sandbox_profile_digest": "7" * 64})}
        )
    elif failure == "role":
        request = request.model_copy(
            update={"task": request.task.model_copy(update={"worker_role": WorkerRole.REPORTER})}
        )
    elif failure == "registry":
        tools = frozenset()
    elif failure == "task":
        request = request.model_copy(
            update={"task": request.task.model_copy(update={"allowed_tools": frozenset()})}
        )
    elif failure == "budget":
        budget = request.task.budget.model_copy(update={"tool_calls": 0})
        request = request.model_copy(
            update={"task": request.task.model_copy(update={"budget": budget})}
        )
    runner = OfflineSandboxRunner(tools)
    with pytest.raises(RunnerRejected):
        runner.execute(request, now=now)
    assert runner._results == {}


def test_runner_revalidates_objects_copied_past_pydantic_guards(now):
    request = _request(now)
    weakened = request.profile.model_copy(update={"capabilities": frozenset({"SYS_ADMIN"})})
    task = request.task.model_copy(
        update={"sandbox_profile_digest": sandbox_profile_digest(weakened)}
    )
    bypassed = request.model_copy(update={"profile": weakened, "task": task})
    runner = OfflineSandboxRunner(frozenset({"source.read"}))
    with pytest.raises(RunnerRejected, match="boundary validation"):
        runner.execute(bypassed, now=now)
    assert runner._results == {}


def test_runner_rejects_idempotency_conflict(now):
    runner = OfflineSandboxRunner(frozenset({"source.read"}))
    request = _request(now)
    runner.execute(request, now=now)
    changed = request.model_copy(
        update={"invocation": request.invocation.model_copy(update={"arguments": ("other.py",)})}
    )
    with pytest.raises(RunnerIdempotencyConflict):
        runner.execute(changed, now=now)


def test_checkpoint_resume_is_bound_to_exact_context(now):
    runner = OfflineSandboxRunner(frozenset({"source.read"}))
    first = _request(now)
    checkpointed = runner.execute(
        first, now=now, scenario=OfflineScenario(outcome=OfflineOutcome.CHECKPOINTED)
    )
    assert checkpointed.status is SandboxRunStatus.CHECKPOINTED
    assert checkpointed.checkpoint is not None

    resumed = first.model_copy(
        update={
            "run_id": uuid4(),
            "attempt": 2,
            "resume_from": checkpointed.checkpoint,
            "idempotency_key": "run:2",
        }
    )
    completed = runner.execute(resumed, now=now)
    assert completed.status is SandboxRunStatus.COMPLETED
    assert completed.cleanup.complete

    exhausted_request = resumed.model_copy(
        update={"run_id": uuid4(), "idempotency_key": "run:exhausted"}
    )
    exhausted = runner.execute(
        exhausted_request,
        now=now,
        scenario=OfflineScenario(outcome=OfflineOutcome.CHECKPOINTED),
    )
    assert exhausted.status is SandboxRunStatus.FAILED
    assert exhausted.error_codes == ("retry_limit_exhausted",)
    assert exhausted.cleanup.complete

    wrong_task = resumed.model_copy(
        update={
            "run_id": uuid4(),
            "task": resumed.task.model_copy(update={"target_version": "wrong"}),
            "idempotency_key": "run:wrong",
        }
    )
    with pytest.raises(RunnerRejected, match="checkpoint"):
        runner.execute(wrong_task, now=now)


def test_incomplete_cleanup_cannot_be_reported(now):
    result = OfflineSandboxRunner(frozenset({"source.read"})).execute(_request(now), now=now)
    raw = result.model_dump(mode="python")
    raw["cleanup"] = CleanupReport(
        processes_terminated=False,
        network_released=True,
        writable_layer_removed=True,
        temporary_mounts_removed=True,
    )
    with pytest.raises(ValidationError, match="complete cleanup"):
        SandboxRunResult.model_validate(raw)
