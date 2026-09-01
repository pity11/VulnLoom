"""Operator-issued lifecycle for provider egress admissions."""

from __future__ import annotations

import os
import sqlite3
import stat
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Self

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel
from vulnloom.runners.models import Digest

from .transport import (
    AgentProviderTransportAdmission,
    AgentProviderTransportMode,
)


class AgentProviderEgressRejected(ValueError):
    pass


class AgentProviderEgressConflict(AgentProviderEgressRejected):
    pass


class AgentProviderEgressRecoveryRequired(RuntimeError):
    pass


class AgentProviderEgressTimedOut(TimeoutError):
    pass


class AgentProviderEgressPurpose(StrEnum):
    MODEL_INFERENCE = "model_inference"
    LOOPBACK_ADMISSION_PROBE = "loopback_admission_probe"


class AgentProviderEgressStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class AgentProviderEgressIssuerPolicy(DomainModel):
    policy_id: Digest
    issuer_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    allowed_provider_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=32)]
    allowed_modes: Annotated[
        tuple[AgentProviderTransportMode, ...], Field(min_length=1, max_length=2)
    ]
    max_lifetime_seconds: int = Field(ge=60, le=2_592_000)

    @model_validator(mode="after")
    def sealed_policy(self) -> Self:
        providers = tuple(sorted(set(self.allowed_provider_ids)))
        modes = tuple(sorted(set(self.allowed_modes), key=lambda item: item.value))
        if self.allowed_provider_ids != providers:
            raise ValueError("provider egress policy providers must be unique and sorted")
        if self.allowed_modes != modes or any(
            mode is AgentProviderTransportMode.ADMISSION_FAKE for mode in modes
        ):
            raise ValueError("provider egress policy modes must be networked and sorted")
        if self.policy_id != canonical_digest(
            self.model_dump(mode="python", exclude={"policy_id"})
        ):
            raise ValueError("provider egress issuer policy digest mismatch")
        return self

    @classmethod
    def create(
        cls,
        *,
        issuer_id: str,
        allowed_provider_ids: tuple[str, ...],
        allowed_modes: tuple[AgentProviderTransportMode, ...],
        max_lifetime_seconds: int,
    ) -> AgentProviderEgressIssuerPolicy:
        values = {
            "issuer_id": issuer_id,
            "allowed_provider_ids": tuple(sorted(set(allowed_provider_ids))),
            "allowed_modes": tuple(sorted(set(allowed_modes), key=lambda item: item.value)),
            "max_lifetime_seconds": max_lifetime_seconds,
        }
        return cls(policy_id=canonical_digest(values), **values)


class AgentProviderEgressGrant(DomainModel):
    grant_id: Digest
    admission_id: Digest
    provider_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    mode: AgentProviderTransportMode
    credential_reference_id: Digest
    adapter_digest: Digest
    issuer_policy_id: Digest
    issuer_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    purpose: AgentProviderEgressPurpose
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_grant(self) -> Self:
        if self.mode is AgentProviderTransportMode.ADMISSION_FAKE:
            raise ValueError("provider egress grant cannot authorize a no-network admission")
        if not self.issued_at < self.expires_at:
            raise ValueError("provider egress grant lifetime is invalid")
        if (
            self.mode is AgentProviderTransportMode.LOOPBACK_HTTPS_PROBE
        ) != (self.purpose is AgentProviderEgressPurpose.LOOPBACK_ADMISSION_PROBE):
            raise ValueError("provider egress grant purpose and mode mismatch")
        if "\x00" in self.idempotency_key:
            raise ValueError("provider egress idempotency key contains NUL")
        if self.grant_id != canonical_digest(
            self.model_dump(mode="python", exclude={"grant_id"})
        ):
            raise ValueError("provider egress grant digest mismatch")
        return self


class AgentProviderEgressRevocation(DomainModel):
    revocation_id: Digest
    grant_id: Digest
    issuer_policy_id: Digest
    issuer_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    reason_digest: Digest
    revoked_at: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed_revocation(self) -> Self:
        if "\x00" in self.idempotency_key:
            raise ValueError("provider egress idempotency key contains NUL")
        if self.revocation_id != canonical_digest(
            self.model_dump(mode="python", exclude={"revocation_id"})
        ):
            raise ValueError("provider egress revocation digest mismatch")
        return self


@dataclass(frozen=True)
class AgentProviderEgressClaim:
    created: bool


class AgentProviderEgressStore:
    """Read-only object store plus transactional lifecycle ledger."""

    def __init__(self, root: Path, *, max_object_bytes: int = 65_536):
        if max_object_bytes <= 0:
            raise ValueError("provider egress object size limit must be positive")
        self.root = root.resolve()
        self.objects = self.root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_object_bytes = max_object_bytes
        self.connection = sqlite3.connect(self.root / "ledger.sqlite3")
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS provider_egress_issuances (
                grant_id TEXT PRIMARY KEY,
                admission_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK(state IN ('started', 'completed')),
                status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
                started_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS provider_egress_revocations (
                revocation_id TEXT PRIMARY KEY,
                grant_id TEXT NOT NULL UNIQUE,
                idempotency_key TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK(state IN ('started', 'completed')),
                started_at TEXT NOT NULL,
                completed_at TEXT
            );
            """
        )
        self.connection.commit()

    def claim_issue(
        self, grant: AgentProviderEgressGrant, *, now: datetime
    ) -> AgentProviderEgressClaim:
        try:
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO provider_egress_issuances (
                        grant_id, admission_id, idempotency_key, state, status, started_at
                    ) VALUES (?, ?, ?, 'started', 'active', ?)
                    """,
                    (
                        grant.grant_id,
                        grant.admission_id,
                        grant.idempotency_key,
                        now.isoformat(),
                    ),
                )
            return AgentProviderEgressClaim(created=True)
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                """
                SELECT * FROM provider_egress_issuances
                WHERE grant_id = ? OR idempotency_key = ?
                """,
                (grant.grant_id, grant.idempotency_key),
            ).fetchone()
            if row is None:
                raise
            if row["grant_id"] != grant.grant_id:
                raise AgentProviderEgressConflict(
                    "provider egress issuance idempotency key was reused"
                ) from None
            if row["state"] == "started":
                raise AgentProviderEgressRecoveryRequired(
                    "provider egress issuance has an unfinished STARTED checkpoint"
                ) from None
            return AgentProviderEgressClaim(created=False)

    def complete_issue(self, grant: AgentProviderEgressGrant, *, now: datetime) -> None:
        with self.connection:
            changed = self.connection.execute(
                """
                UPDATE provider_egress_issuances
                SET state = 'completed', completed_at = ?
                WHERE grant_id = ? AND state = 'started'
                """,
                (now.isoformat(), grant.grant_id),
            ).rowcount
        if changed != 1:
            raise AgentProviderEgressRecoveryRequired(
                "provider egress issuance STARTED checkpoint is unavailable"
            )

    def claim_revoke(
        self, revocation: AgentProviderEgressRevocation
    ) -> AgentProviderEgressClaim:
        existing = self.connection.execute(
            """
            SELECT * FROM provider_egress_revocations
            WHERE revocation_id = ? OR grant_id = ? OR idempotency_key = ?
            """,
            (
                revocation.revocation_id,
                revocation.grant_id,
                revocation.idempotency_key,
            ),
        ).fetchone()
        if existing is not None:
            if existing["revocation_id"] != revocation.revocation_id:
                raise AgentProviderEgressConflict(
                    "provider egress revocation conflicts with existing content"
                )
            if existing["state"] == "started":
                raise AgentProviderEgressRecoveryRequired(
                    "provider egress revocation has an unfinished STARTED checkpoint"
                )
            return AgentProviderEgressClaim(created=False)
        issuance = self.connection.execute(
            "SELECT * FROM provider_egress_issuances WHERE grant_id = ?",
            (revocation.grant_id,),
        ).fetchone()
        if (
            issuance is None
            or issuance["state"] != "completed"
            or issuance["status"] != "active"
        ):
            raise AgentProviderEgressRejected("provider egress grant is not active")
        try:
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO provider_egress_revocations (
                        revocation_id, grant_id, idempotency_key, state, started_at
                    ) VALUES (?, ?, ?, 'started', ?)
                    """,
                    (
                        revocation.revocation_id,
                        revocation.grant_id,
                        revocation.idempotency_key,
                        revocation.revoked_at.isoformat(),
                    ),
                )
            return AgentProviderEgressClaim(created=True)
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                """
                SELECT * FROM provider_egress_revocations
                WHERE revocation_id = ? OR grant_id = ? OR idempotency_key = ?
                """,
                (
                    revocation.revocation_id,
                    revocation.grant_id,
                    revocation.idempotency_key,
                ),
            ).fetchone()
            if row is None:
                raise
            if row["revocation_id"] != revocation.revocation_id:
                raise AgentProviderEgressConflict(
                    "provider egress revocation conflicts with existing content"
                ) from None
            if row["state"] == "started":
                raise AgentProviderEgressRecoveryRequired(
                    "provider egress revocation has an unfinished STARTED checkpoint"
                ) from None
            return AgentProviderEgressClaim(created=False)

    def complete_revoke(
        self, revocation: AgentProviderEgressRevocation, *, now: datetime
    ) -> None:
        with self.connection:
            changed = self.connection.execute(
                """
                UPDATE provider_egress_revocations
                SET state = 'completed', completed_at = ?
                WHERE revocation_id = ? AND state = 'started'
                """,
                (now.isoformat(), revocation.revocation_id),
            ).rowcount
            issuance_changed = self.connection.execute(
                """
                UPDATE provider_egress_issuances SET status = 'revoked'
                WHERE grant_id = ? AND state = 'completed' AND status = 'active'
                """,
                (revocation.grant_id,),
            ).rowcount
            if changed != 1 or issuance_changed != 1:
                raise AgentProviderEgressRecoveryRequired(
                    "provider egress revocation checkpoint is unavailable"
                )

    def publish(
        self, value: AgentProviderEgressGrant | AgentProviderEgressRevocation
    ) -> Path:
        object_id = (
            value.grant_id
            if isinstance(value, AgentProviderEgressGrant)
            else value.revocation_id
        )
        encoded = (value.model_dump_json() + "\n").encode("utf-8")
        if len(encoded) > self.max_object_bytes:
            raise AgentProviderEgressRejected("provider egress object exceeds the store limit")
        destination = self.objects / object_id
        if os.path.lexists(destination):
            if self._read_bytes(object_id) != encoded:
                raise AgentProviderEgressRejected("provider egress object collision")
            return destination
        descriptor, temporary = tempfile.mkstemp(prefix="egress-", dir=self.objects)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            os.chmod(destination, 0o400)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        if self._read_bytes(object_id) != encoded:
            raise AgentProviderEgressRejected(
                "provider egress object integrity check failed"
            )
        return destination

    def read_grant(self, grant_id: str) -> AgentProviderEgressGrant:
        data = self._read_bytes(grant_id)
        try:
            grant = AgentProviderEgressGrant.model_validate_json(data)
        except ValueError as exc:
            raise AgentProviderEgressRejected("provider egress grant is invalid") from exc
        if grant.grant_id != grant_id:
            raise AgentProviderEgressRejected("provider egress grant identity mismatch")
        return grant

    def read_revocation(self, revocation_id: str) -> AgentProviderEgressRevocation:
        data = self._read_bytes(revocation_id)
        try:
            revocation = AgentProviderEgressRevocation.model_validate_json(data)
        except ValueError as exc:
            raise AgentProviderEgressRejected(
                "provider egress revocation is invalid"
            ) from exc
        if revocation.revocation_id != revocation_id:
            raise AgentProviderEgressRejected(
                "provider egress revocation identity mismatch"
            )
        return revocation

    def require_active(
        self,
        grant_id: str,
        *,
        admission: AgentProviderTransportAdmission,
        now: datetime,
    ) -> AgentProviderEgressGrant:
        status, grant = self.status_at(grant_id, now=now)
        if status is AgentProviderEgressStatus.REVOKED:
            raise AgentProviderEgressRejected("provider egress grant is revoked")
        if status is AgentProviderEgressStatus.EXPIRED:
            raise AgentProviderEgressRejected("provider egress grant is expired")
        if (
            grant.admission_id != admission.admission_id
            or grant.provider_id != admission.provider_id
            or grant.mode is not admission.mode
            or grant.credential_reference_id != admission.credential_reference_id
            or grant.adapter_digest != admission.adapter_digest
        ):
            raise AgentProviderEgressRejected("provider egress grant binding mismatch")
        return grant

    def status_at(
        self, grant_id: str, *, now: datetime
    ) -> tuple[AgentProviderEgressStatus, AgentProviderEgressGrant]:
        row = self.connection.execute(
            "SELECT * FROM provider_egress_issuances WHERE grant_id = ?", (grant_id,)
        ).fetchone()
        if row is None or row["state"] != "completed":
            raise AgentProviderEgressRejected("provider egress grant is not issued")
        pending = self.connection.execute(
            """
            SELECT 1 FROM provider_egress_revocations
            WHERE grant_id = ? AND state = 'started'
            """,
            (grant_id,),
        ).fetchone()
        if pending is not None:
            raise AgentProviderEgressRecoveryRequired(
                "provider egress revocation has an unfinished STARTED checkpoint"
            )
        grant = self.read_grant(grant_id)
        if row["status"] == AgentProviderEgressStatus.REVOKED.value:
            return AgentProviderEgressStatus.REVOKED, grant
        if now < grant.issued_at or now >= grant.expires_at:
            return AgentProviderEgressStatus.EXPIRED, grant
        return AgentProviderEgressStatus.ACTIVE, grant

    def _read_bytes(self, object_id: str) -> bytes:
        if len(object_id) != 64 or any(
            character not in "0123456789abcdef" for character in object_id
        ):
            raise AgentProviderEgressRejected("invalid provider egress object reference")
        if not hasattr(os, "O_NOFOLLOW"):
            raise AgentProviderEgressRejected(
                "platform cannot enforce no-follow provider egress reads"
            )
        try:
            descriptor = os.open(self.objects / object_id, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise AgentProviderEgressRejected(
                "provider egress object is unavailable or unsafe"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o222
                or metadata.st_size > self.max_object_bytes
            ):
                raise AgentProviderEgressRejected(
                    "provider egress object is unavailable or unsafe"
                )
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(self.max_object_bytes + 1)
        finally:
            os.close(descriptor)
        if len(data) > self.max_object_bytes:
            raise AgentProviderEgressRejected(
                "provider egress object exceeds the store limit"
            )
        return data

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AgentProviderEgressStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class AgentProviderEgressAuthority:
    def __init__(
        self,
        *,
        store: AgentProviderEgressStore,
        issuer_policies: tuple[AgentProviderEgressIssuerPolicy, ...],
        clock: Callable[[], float] = time.monotonic,
    ):
        policies = {policy.policy_id: policy for policy in issuer_policies}
        if not policies or len(policies) != len(issuer_policies):
            raise ValueError("provider egress issuer policies must be non-empty and unique")
        self.store = store
        self.policies = policies
        self.clock = clock

    def issue(
        self,
        *,
        admission: AgentProviderTransportAdmission,
        issuer_policy_id: str,
        purpose: AgentProviderEgressPurpose,
        now: datetime,
        expires_at: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AgentProviderEgressGrant:
        started = self.clock()
        if now >= deadline:
            raise AgentProviderEgressTimedOut("provider egress issuance deadline expired")
        policy = self._policy(issuer_policy_id)
        lifetime = (expires_at - now).total_seconds()
        if (
            admission.mode not in policy.allowed_modes
            or admission.provider_id not in policy.allowed_provider_ids
            or not 0 < lifetime <= policy.max_lifetime_seconds
        ):
            raise AgentProviderEgressRejected("provider egress issuance policy rejected")
        values = {
            "admission_id": admission.admission_id,
            "provider_id": admission.provider_id,
            "mode": admission.mode,
            "credential_reference_id": admission.credential_reference_id,
            "adapter_digest": admission.adapter_digest,
            "issuer_policy_id": policy.policy_id,
            "issuer_id": policy.issuer_id,
            "purpose": purpose,
            "issued_at": now,
            "expires_at": expires_at,
            "idempotency_key": idempotency_key,
        }
        grant = AgentProviderEgressGrant(
            grant_id=canonical_digest(values), **values
        )
        claim = self.store.claim_issue(grant, now=now)
        if not claim.created:
            return self.store.require_active(
                grant.grant_id, admission=admission, now=now
            )
        self._check_deadline(started, now=now, deadline=deadline)
        try:
            self.store.publish(grant)
        except OSError as exc:
            raise AgentProviderEgressRejected(
                "provider egress grant publication failed"
            ) from exc
        self._check_deadline(started, now=now, deadline=deadline)
        self.store.complete_issue(grant, now=now)
        return grant

    def revoke(
        self,
        *,
        grant_id: str,
        issuer_policy_id: str,
        reason_digest: str,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AgentProviderEgressRevocation:
        started = self.clock()
        if now >= deadline:
            raise AgentProviderEgressTimedOut("provider egress revocation deadline expired")
        policy = self._policy(issuer_policy_id)
        grant = self.store.read_grant(grant_id)
        if grant.issuer_policy_id != policy.policy_id or grant.issuer_id != policy.issuer_id:
            raise AgentProviderEgressRejected("provider egress revocation issuer mismatch")
        if now < grant.issued_at or now >= grant.expires_at:
            raise AgentProviderEgressRejected("provider egress grant is expired")
        values = {
            "grant_id": grant_id,
            "issuer_policy_id": policy.policy_id,
            "issuer_id": policy.issuer_id,
            "reason_digest": reason_digest,
            "revoked_at": now,
            "idempotency_key": idempotency_key,
        }
        revocation = AgentProviderEgressRevocation(
            revocation_id=canonical_digest(values), **values
        )
        claim = self.store.claim_revoke(revocation)
        if not claim.created:
            return self.store.read_revocation(revocation.revocation_id)
        self._check_deadline(started, now=now, deadline=deadline)
        try:
            self.store.publish(revocation)
        except OSError as exc:
            raise AgentProviderEgressRejected(
                "provider egress revocation publication failed"
            ) from exc
        self._check_deadline(started, now=now, deadline=deadline)
        self.store.complete_revoke(revocation, now=now)
        return revocation

    def _policy(self, policy_id: str) -> AgentProviderEgressIssuerPolicy:
        try:
            return self.policies[policy_id]
        except KeyError as exc:
            raise AgentProviderEgressRejected(
                "provider egress issuer policy is not trusted"
            ) from exc

    def _check_deadline(
        self, started: float, *, now: datetime, deadline: datetime
    ) -> None:
        if now >= deadline or self.clock() - started >= (deadline - now).total_seconds():
            raise AgentProviderEgressTimedOut("provider egress operation timed out")
