from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.runners import (
    ResourcePressureProbeExpectation,
    ResourcePressureProbeKind,
    ResourcePressureProbeObservation,
    ResourcePressureQualificationOutcome,
    ResourcePressureQualificationPlan,
    ResourcePressureQualificationStatus,
    SandboxRunStatus,
    qualify_resource_pressure,
)

IMAGE = "sha256:" + "1" * 64
PROFILE = "2" * 64


def _terminal(kind: ResourcePressureProbeKind):
    if kind is ResourcePressureProbeKind.OUTPUT_LIMIT:
        return SandboxRunStatus.FAILED, ("output_capture_failed",)
    if kind is ResourcePressureProbeKind.MEMORY_LIMIT:
        return SandboxRunStatus.FAILED, ("memory_limit_exceeded",)
    if kind is ResourcePressureProbeKind.TIMEOUT_PROCESS_GROUP:
        return SandboxRunStatus.TIMED_OUT, ("wall_time_budget_exceeded",)
    return SandboxRunStatus.COMPLETED, ()


def _plan(now):
    probes = tuple(
        ResourcePressureProbeExpectation(
            kind=kind,
            run_id=uuid4(),
            task_id=uuid4(),
            sandbox_profile_digest=PROFILE,
            invocation_digest=f"{index + 3:064x}",
            expected_status=_terminal(kind)[0],
            expected_error_codes=_terminal(kind)[1],
        )
        for index, kind in enumerate(ResourcePressureProbeKind)
    )
    return ResourcePressureQualificationPlan.create(
        image_digest=IMAGE,
        created_at=now,
        expires_at=now + timedelta(minutes=10),
        probes=probes,
    )


def _observations(plan):
    return tuple(
        ResourcePressureProbeObservation(
            kind=probe.kind,
            run_id=probe.run_id,
            task_id=probe.task_id,
            sandbox_profile_digest=probe.sandbox_profile_digest,
            invocation_digest=probe.invocation_digest,
            status=probe.expected_status,
            error_codes=probe.expected_error_codes,
            boundary_observed=True,
            cleanup_verified=True,
            container_absent=True,
        )
        for probe in plan.probes
    )


def test_complete_content_bound_resource_pressure_probe_set_is_admitted(now):
    plan = _plan(now)

    outcome = qualify_resource_pressure(plan, _observations(plan), now=now)

    assert outcome.status is ResourcePressureQualificationStatus.ADMITTED
    assert outcome.denial_codes == ()
    assert len(outcome.observations) == 6
    reparsed = ResourcePressureQualificationOutcome.model_validate(
        outcome.model_dump(mode="python")
    )
    assert reparsed.outcome_id == outcome.outcome_id


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("missing", "missing_probe:pid_limit"),
        ("binding", "binding_mismatch:pid_limit"),
        ("terminal", "terminal_mismatch:pid_limit"),
        ("boundary", "boundary_unproven:pid_limit"),
        ("cleanup", "cleanup_unproven:pid_limit"),
    ),
)
def test_qualification_fails_closed_on_incomplete_or_drifted_probe(
    now, mutation, reason
):
    plan = _plan(now)
    observations = list(_observations(plan))
    index = next(
        index
        for index, item in enumerate(observations)
        if item.kind is ResourcePressureProbeKind.PID_LIMIT
    )
    if mutation == "missing":
        observations.pop(index)
    elif mutation == "binding":
        observations[index] = observations[index].model_copy(
            update={"invocation_digest": "f" * 64}
        )
    elif mutation == "terminal":
        observations[index] = observations[index].model_copy(
            update={"status": SandboxRunStatus.FAILED}
        )
    elif mutation == "boundary":
        observations[index] = observations[index].model_copy(
            update={"boundary_observed": False}
        )
    else:
        observations[index] = observations[index].model_copy(
            update={"cleanup_verified": False, "container_absent": False}
        )

    outcome = qualify_resource_pressure(plan, tuple(observations), now=now)

    assert outcome.status is ResourcePressureQualificationStatus.DENIED
    assert reason in outcome.denial_codes


def test_probe_terminal_semantics_cannot_be_weakened(now):
    plan = _plan(now)
    output = next(
        probe for probe in plan.probes if probe.kind is ResourcePressureProbeKind.OUTPUT_LIMIT
    )
    raw = output.model_dump(mode="python")
    raw["expected_status"] = SandboxRunStatus.COMPLETED
    raw["expected_error_codes"] = ()

    with pytest.raises(ValidationError, match="terminal semantics"):
        ResourcePressureProbeExpectation.model_validate(raw)


def test_expired_tampered_or_cleanup_unknown_plan_is_denied(now):
    plan = _plan(now)
    expired = qualify_resource_pressure(plan, _observations(plan), now=plan.expires_at)
    assert expired.status is ResourcePressureQualificationStatus.DENIED
    assert expired.denial_codes == ("plan_expired",)

    expectation = plan.probes[0]
    observations = [item for item in _observations(plan) if item.kind is not expectation.kind]
    observations.append(ResourcePressureProbeObservation.cleanup_unproven(expectation))
    denied = qualify_resource_pressure(plan, tuple(observations), now=now)
    assert f"cleanup_unproven:{expectation.kind.value}" in denied.denial_codes
    assert f"boundary_unproven:{expectation.kind.value}" in denied.denial_codes

    raw = plan.model_dump(mode="python")
    raw["image_digest"] = "sha256:" + "f" * 64
    with pytest.raises(ValidationError, match="plan id"):
        ResourcePressureQualificationPlan.model_validate(raw)


def test_resource_pressure_contract_cannot_carry_payloads_or_secrets(now):
    schema = ResourcePressureProbeObservation.model_json_schema()
    assert not (
        {"stdout", "stderr", "payload", "secret", "environment"}
        & set(schema["properties"])
    )

    raw = _observations(_plan(now))[0].model_dump(mode="python")
    raw["stdout"] = "FAKE_PROVIDER_TOKEN"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ResourcePressureProbeObservation.model_validate(raw)
