"""Content-bound S1.3 secret-leakage and egress qualification contracts.

The protocol contains only digests and boolean safety observations. Raw canaries,
output, credentials, and exception text are intentionally not representable.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest


class LeakageSurface(StrEnum):
    WORKER_OUTPUT = "worker_output"
    PROVIDER_TRANSPORT = "provider_transport"
    EXCEPTION_CHAIN = "exception_chain"
    EVENT_LOG = "event_log"
    EVIDENCE = "evidence"
    REPORT = "report"
    CLI_API = "cli_api"
    MODEL_CONTEXT = "model_context"


REQUIRED_LEAKAGE_SURFACES = frozenset(LeakageSurface)
LEAKAGE_PROBE_CONTRACT_DIGEST = canonical_digest(
    {
        "contract": "vulnloom-secret-leakage-s1.3-v1",
        "surfaces": tuple(sorted(item.value for item in REQUIRED_LEAKAGE_SURFACES)),
        "secrets": "synthetic-canaries-only",
        "egress": "trusted-broker-or-provider-transport-only",
        "decision": "deterministic-structured-fail-closed",
    }
)


class LeakageProbeExpectation(DomainModel):
    surface: LeakageSurface
    artifact_digest: Digest
    probe_contract_digest: Digest = LEAKAGE_PROBE_CONTRACT_DIGEST

    @model_validator(mode="after")
    def admitted_contract_only(self) -> Self:
        if self.probe_contract_digest != LEAKAGE_PROBE_CONTRACT_DIGEST:
            raise ValueError("secret leakage probe contract is not admitted")
        return self


class LeakageQualificationPlan(DomainModel):
    plan_id: Digest
    created_at: AwareDatetime
    expires_at: AwareDatetime
    probes: Annotated[tuple[LeakageProbeExpectation, ...], Field(min_length=8, max_length=8)]

    @model_validator(mode="after")
    def content_addressed_and_complete(self) -> Self:
        surfaces = [probe.surface for probe in self.probes]
        if len(set(surfaces)) != len(surfaces) or set(surfaces) != REQUIRED_LEAKAGE_SURFACES:
            raise ValueError("secret leakage qualification requires every surface exactly once")
        if self.expires_at <= self.created_at:
            raise ValueError("secret leakage qualification plan must have a future expiry")
        expected = canonical_digest(self.model_dump(mode="python", exclude={"plan_id"}))
        if self.plan_id != expected:
            raise ValueError("secret leakage qualification plan id does not match its content")
        return self

    @classmethod
    def create(
        cls,
        *,
        created_at: datetime,
        expires_at: datetime,
        probes: tuple[LeakageProbeExpectation, ...],
    ) -> LeakageQualificationPlan:
        values = {"created_at": created_at, "expires_at": expires_at, "probes": probes}
        digest_values = {
            **values,
            "probes": tuple(item.model_dump(mode="python") for item in probes),
        }
        return cls(plan_id=canonical_digest(digest_values), **values)


class LeakageProbeObservation(DomainModel):
    surface: LeakageSurface
    artifact_digest: Digest
    canary_absent: bool
    egress_boundary_enforced: bool
    size_boundary_enforced: bool
    cleanup_verified: bool
    error_codes: Annotated[tuple[str, ...], Field(max_length=8)] = ()

    @model_validator(mode="after")
    def bounded_error_codes(self) -> Self:
        if any(not code or len(code) > 128 for code in self.error_codes):
            raise ValueError("secret leakage error codes must be bounded")
        return self


class LeakageQualificationStatus(StrEnum):
    ADMITTED = "admitted"
    DENIED = "denied"


class LeakageQualificationOutcome(DomainModel):
    outcome_id: Digest
    plan_id: Digest
    status: LeakageQualificationStatus
    observations: Annotated[tuple[LeakageProbeObservation, ...], Field(max_length=8)]
    denial_codes: Annotated[tuple[str, ...], Field(max_length=48)] = ()

    @model_validator(mode="after")
    def content_addressed_terminal_outcome(self) -> Self:
        if len({item.surface for item in self.observations}) != len(self.observations):
            raise ValueError("secret leakage observations must be unique")
        if (self.status is LeakageQualificationStatus.ADMITTED) == bool(self.denial_codes):
            raise ValueError("admitted outcome must be clean and denied outcome must explain why")
        expected = canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        if self.outcome_id != expected:
            raise ValueError("secret leakage outcome id does not match its content")
        return self


def qualify_leakage_safety(
    plan: LeakageQualificationPlan,
    observations: tuple[LeakageProbeObservation, ...],
    *,
    now: datetime,
) -> LeakageQualificationOutcome:
    """Reduce trusted surface checks into one deterministic admission result."""

    expected = {item.surface: item for item in plan.probes}
    actual: dict[LeakageSurface, LeakageProbeObservation] = {}
    denial_codes: list[str] = []
    if now >= plan.expires_at:
        denial_codes.append("plan_expired")
    for observation in observations:
        if observation.surface in actual:
            denial_codes.append(f"duplicate_surface:{observation.surface.value}")
            continue
        actual[observation.surface] = observation
    for surface in sorted(REQUIRED_LEAKAGE_SURFACES, key=lambda item: item.value):
        observation = actual.get(surface)
        if observation is None:
            denial_codes.append(f"missing_surface:{surface.value}")
            continue
        if observation.artifact_digest != expected[surface].artifact_digest:
            denial_codes.append(f"binding_mismatch:{surface.value}")
        checks = {
            "canary_present": observation.canary_absent,
            "egress_unproven": observation.egress_boundary_enforced,
            "size_boundary_unproven": observation.size_boundary_enforced,
            "cleanup_unproven": observation.cleanup_verified,
        }
        denial_codes.extend(
            f"{code}:{surface.value}" for code, passed in checks.items() if not passed
        )
        denial_codes.extend(
            f"probe_error:{surface.value}:{code}" for code in observation.error_codes
        )
    status = (
        LeakageQualificationStatus.DENIED
        if denial_codes
        else LeakageQualificationStatus.ADMITTED
    )
    ordered = tuple(actual[item] for item in sorted(actual, key=lambda item: item.value))
    values = {
        "plan_id": plan.plan_id,
        "status": status,
        "observations": ordered,
        "denial_codes": tuple(dict.fromkeys(denial_codes)),
    }
    digest_values = {
        **values,
        "observations": tuple(item.model_dump(mode="python") for item in ordered),
    }
    return LeakageQualificationOutcome(
        outcome_id=canonical_digest(digest_values), **values
    )
