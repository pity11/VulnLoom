from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.runners import (
    HostileWorkerProbeExpectation,
    HostileWorkerProbeKind,
    HostileWorkerProbeObservation,
    HostileWorkerQualificationOutcome,
    HostileWorkerQualificationPlan,
    HostileWorkerQualificationStatus,
    SandboxRunStatus,
    qualify_hostile_worker,
)

IMAGE = "sha256:" + "1" * 64
PROFILE = "2" * 64


def _expected_status(kind: HostileWorkerProbeKind) -> SandboxRunStatus:
    if kind is HostileWorkerProbeKind.CRASH_CLEANUP:
        return SandboxRunStatus.FAILED
    if kind is HostileWorkerProbeKind.TIMEOUT_CLEANUP:
        return SandboxRunStatus.TIMED_OUT
    return SandboxRunStatus.COMPLETED


def _plan(now):
    probes = tuple(
        HostileWorkerProbeExpectation(
            kind=kind,
            run_id=uuid4(),
            task_id=uuid4(),
            sandbox_profile_digest=PROFILE,
            invocation_digest=f"{index + 3:064x}",
            expected_status=_expected_status(kind),
        )
        for index, kind in enumerate(HostileWorkerProbeKind)
    )
    return HostileWorkerQualificationPlan.create(
        image_digest=IMAGE,
        created_at=now,
        expires_at=now + timedelta(minutes=10),
        probes=probes,
    )


def _observations(plan):
    return tuple(
        HostileWorkerProbeObservation(
            kind=probe.kind,
            run_id=probe.run_id,
            task_id=probe.task_id,
            sandbox_profile_digest=probe.sandbox_profile_digest,
            invocation_digest=probe.invocation_digest,
            status=probe.expected_status,
            cleanup_verified=True,
            container_absent=True,
            error_codes=(
                ("worker_failed",)
                if probe.kind is HostileWorkerProbeKind.CRASH_CLEANUP
                else ("wall_time_budget_exceeded",)
                if probe.kind is HostileWorkerProbeKind.TIMEOUT_CLEANUP
                else ()
            ),
        )
        for probe in plan.probes
    )


def test_complete_content_bound_hostile_worker_probe_set_is_admitted(now):
    plan = _plan(now)

    outcome = qualify_hostile_worker(plan, _observations(plan), now=now)

    assert outcome.status is HostileWorkerQualificationStatus.ADMITTED
    assert outcome.denial_codes == ()
    assert len(outcome.observations) == 7
    reparsed = HostileWorkerQualificationOutcome.model_validate(
        outcome.model_dump(mode="python")
    )
    assert reparsed.outcome_id == outcome.outcome_id


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("missing", "missing_probe:secret_boundary"),
        ("binding", "binding_mismatch:secret_boundary"),
        ("status", "terminal_status_mismatch:secret_boundary"),
        ("cleanup", "cleanup_unproven:secret_boundary"),
    ),
)
def test_qualification_fails_closed_on_missing_drifted_or_unclean_probe(
    now, mutation, reason
):
    plan = _plan(now)
    observations = list(_observations(plan))
    index = next(
        index
        for index, item in enumerate(observations)
        if item.kind is HostileWorkerProbeKind.SECRET_BOUNDARY
    )
    if mutation == "missing":
        observations.pop(index)
    elif mutation == "binding":
        observations[index] = observations[index].model_copy(
            update={"invocation_digest": "f" * 64}
        )
    elif mutation == "status":
        observations[index] = observations[index].model_copy(
            update={"status": SandboxRunStatus.FAILED}
        )
    else:
        observations[index] = observations[index].model_copy(
            update={"cleanup_verified": False, "container_absent": False}
        )

    outcome = qualify_hostile_worker(plan, tuple(observations), now=now)

    assert outcome.status is HostileWorkerQualificationStatus.DENIED
    assert reason in outcome.denial_codes


def test_cleanup_exception_has_an_explicit_denied_observation(now):
    plan = _plan(now)
    expectation = next(
        probe
        for probe in plan.probes
        if probe.kind is HostileWorkerProbeKind.TIMEOUT_CLEANUP
    )
    observations = [
        item
        for item in _observations(plan)
        if item.kind is not HostileWorkerProbeKind.TIMEOUT_CLEANUP
    ]
    observations.append(HostileWorkerProbeObservation.cleanup_unproven(expectation))

    outcome = qualify_hostile_worker(plan, tuple(observations), now=now)

    assert outcome.status is HostileWorkerQualificationStatus.DENIED
    assert "cleanup_unproven:timeout_cleanup" in outcome.denial_codes
    assert "terminal_status_mismatch:timeout_cleanup" in outcome.denial_codes


def test_expired_or_tampered_qualification_cannot_be_admitted(now):
    plan = _plan(now)
    expired = qualify_hostile_worker(
        plan, _observations(plan), now=plan.expires_at
    )
    assert expired.status is HostileWorkerQualificationStatus.DENIED
    assert expired.denial_codes == ("plan_expired",)

    raw = plan.model_dump(mode="python")
    raw["image_digest"] = "sha256:" + "f" * 64
    with pytest.raises(ValidationError, match="plan id"):
        HostileWorkerQualificationPlan.model_validate(raw)


def test_qualification_contract_has_no_payload_or_secret_fields(now):
    schema = HostileWorkerProbeObservation.model_json_schema()
    fields = schema["properties"]
    assert not ({"stdout", "stderr", "payload", "secret", "environment"} & set(fields))

    plan = _plan(now)
    raw = _observations(plan)[0].model_dump(mode="python")
    raw["stdout"] = "FAKE_PROVIDER_TOKEN"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        HostileWorkerProbeObservation.model_validate(raw)
