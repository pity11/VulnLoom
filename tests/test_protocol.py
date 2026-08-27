from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.domain.protocol import (
    TaskBudget,
    TaskEnvelope,
    WorkerClaim,
    WorkerResult,
    WorkerRole,
    WorkerStatus,
)


def test_worker_protocol_round_trip_is_typed_and_secret_free(now):
    task = TaskEnvelope(
        engagement_id=uuid4(),
        target_id=uuid4(),
        worker_role=WorkerRole.SOURCE_MAPPER,
        scope_version=1,
        policy_digest="a" * 64,
        input_refs=("source:commit:" + "b" * 40,),
        allowed_tools=frozenset({"source.read", "source.search"}),
        budget=TaskBudget(wall_seconds=60, model_tokens=10_000, tool_calls=100),
        deadline=now + timedelta(minutes=1),
        idempotency_key="mapper:target:v1",
    )
    result = WorkerResult(
        task_id=task.task_id,
        worker_role=task.worker_role,
        status=WorkerStatus.COMPLETED,
        confidence=0.8,
        claims=(WorkerClaim(statement="A route reaches an object lookup"),),
        budget_used=TaskBudget(wall_seconds=5, model_tokens=200, tool_calls=3),
    )
    assert result.task_id == task.task_id
    assert "api_key" not in TaskEnvelope.model_fields


def test_worker_protocol_rejects_prompt_injected_permission(now):
    with pytest.raises(ValidationError, match="extra_forbidden"):
        TaskEnvelope(
            engagement_id=uuid4(),
            target_id=uuid4(),
            worker_role="validator",
            scope_version=1,
            policy_digest="a" * 64,
            input_refs=(),
            allowed_tools=frozenset(),
            budget={"wall_seconds": 60, "model_tokens": 0, "tool_calls": 0},
            deadline=now + timedelta(minutes=1),
            idempotency_key="test",
            approval_granted_by_model=True,
        )
