from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.security import (
    REQUIRED_LEAKAGE_SURFACES,
    LeakageProbeExpectation,
    LeakageProbeObservation,
    LeakageQualificationOutcome,
    LeakageQualificationPlan,
    LeakageQualificationStatus,
    LeakageSurface,
    qualify_leakage_safety,
)


def _plan(now) -> LeakageQualificationPlan:
    probes = tuple(
        LeakageProbeExpectation(
            surface=surface,
            artifact_digest=canonical_digest({"fixture": surface.value}),
        )
        for surface in sorted(REQUIRED_LEAKAGE_SURFACES, key=lambda item: item.value)
    )
    return LeakageQualificationPlan.create(
        created_at=now,
        expires_at=now + timedelta(hours=1),
        probes=probes,
    )


def _observations(plan: LeakageQualificationPlan) -> tuple[LeakageProbeObservation, ...]:
    return tuple(
        LeakageProbeObservation(
            surface=item.surface,
            artifact_digest=item.artifact_digest,
            canary_absent=True,
            egress_boundary_enforced=True,
            size_boundary_enforced=True,
            cleanup_verified=True,
        )
        for item in plan.probes
    )


def test_all_bound_surfaces_produce_content_addressed_admission(now):
    plan = _plan(now)

    outcome = qualify_leakage_safety(plan, _observations(plan), now=now)

    assert outcome.status is LeakageQualificationStatus.ADMITTED
    assert outcome.denial_codes == ()
    assert LeakageQualificationOutcome.model_validate_json(outcome.model_dump_json()) == outcome


@pytest.mark.parametrize(
    ("surface", "field", "code"),
    (
        (LeakageSurface.WORKER_OUTPUT, "canary_absent", "canary_present"),
        (LeakageSurface.PROVIDER_TRANSPORT, "egress_boundary_enforced", "egress_unproven"),
        (LeakageSurface.EVIDENCE, "size_boundary_enforced", "size_boundary_unproven"),
        (LeakageSurface.REPORT, "cleanup_verified", "cleanup_unproven"),
    ),
)
def test_any_failed_surface_check_denies_qualification(now, surface, field, code):
    plan = _plan(now)
    observations = tuple(
        item.model_copy(update={field: False}) if item.surface is surface else item
        for item in _observations(plan)
    )

    outcome = qualify_leakage_safety(plan, observations, now=now)

    assert outcome.status is LeakageQualificationStatus.DENIED
    assert f"{code}:{surface.value}" in outcome.denial_codes


def test_missing_duplicate_drift_error_and_expiry_fail_closed(now):
    plan = _plan(now)
    observations = _observations(plan)
    missing = qualify_leakage_safety(plan, observations[:-1], now=now)
    assert missing.status is LeakageQualificationStatus.DENIED
    assert missing.denial_codes[0].startswith("missing_surface:")

    duplicate = qualify_leakage_safety(
        plan, observations + (observations[0],), now=now
    )
    assert "duplicate_surface:cli_api" in duplicate.denial_codes

    drifted = observations[0].model_copy(update={"artifact_digest": "f" * 64})
    drift = qualify_leakage_safety(plan, (drifted, *observations[1:]), now=now)
    assert "binding_mismatch:cli_api" in drift.denial_codes

    errored = observations[0].model_copy(update={"error_codes": ("probe_failed",)})
    failure = qualify_leakage_safety(plan, (errored, *observations[1:]), now=now)
    assert "probe_error:cli_api:probe_failed" in failure.denial_codes

    expired = qualify_leakage_safety(plan, observations, now=plan.expires_at)
    assert expired.denial_codes == ("plan_expired",)


def test_contract_models_cannot_carry_raw_secret_or_output(now):
    fields = LeakageProbeObservation.model_json_schema()["properties"]
    forbidden = {"secret", "canary", "stdout", "stderr", "payload", "environment"}
    assert not forbidden & set(fields)

    raw = _observations(_plan(now))[0].model_dump(mode="python")
    raw["stdout"] = "vl-canary-must-not-enter-contract"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        LeakageProbeObservation.model_validate(raw)

    plan = _plan(now)
    drifted = plan.model_dump(mode="python")
    drifted["probes"][0]["artifact_digest"] = "a" * 64
    with pytest.raises(ValidationError, match="plan id"):
        LeakageQualificationPlan.model_validate(drifted)
