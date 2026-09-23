"""Offline-only Vault and isolated Session adapters for B4.2."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from vulnloom.domain.digests import canonical_digest

from .credential_session_models import CredentialSessionPlan


class CredentialSessionAdapterRejected(RuntimeError):
    pass


class CredentialLease:
    """A non-serializable, single-owner secret buffer."""

    __slots__ = ("_released", "_secret", "credential_ref", "expires_at")

    def __init__(self, *, credential_ref: str, secret: bytes, expires_at: datetime):
        if not secret or len(secret) > 16_384 or b"\x00" in secret:
            raise CredentialSessionAdapterRejected("credential material is invalid")
        self.credential_ref = credential_ref
        self.expires_at = expires_at
        self._secret = bytearray(secret)
        self._released = False

    @property
    def released(self) -> bool:
        return self._released

    @property
    def zeroed(self) -> bool:
        return self._released and not any(self._secret)

    def view(self, *, now: datetime) -> memoryview:
        if self._released or now >= self.expires_at:
            raise CredentialSessionAdapterRejected("credential lease is unavailable")
        return memoryview(self._secret).toreadonly()

    def close(self) -> None:
        if not self._released:
            self._secret[:] = b"\x00" * len(self._secret)
            self._released = True


class IsolatedSessionHandle:
    __slots__ = ("_material", "_released", "session_binding")

    def __init__(self, *, session_binding: str):
        self.session_binding = session_binding
        self._material = bytearray(b"fixture-isolated-session")
        self._released = False

    @property
    def released(self) -> bool:
        return self._released

    @property
    def zeroed(self) -> bool:
        return self._released and not any(self._material)

    def close(self) -> None:
        if not self._released:
            self._material[:] = b"\x00" * len(self._material)
            self._released = True


class CredentialVault(Protocol):
    def acquire(self, plan: CredentialSessionPlan, *, now: datetime) -> CredentialLease: ...


class IsolatedSessionAdapter(Protocol):
    def open(
        self,
        plan: CredentialSessionPlan,
        *,
        credential: memoryview,
    ) -> IsolatedSessionHandle: ...


class OfflineCredentialVault:
    """In-memory fixture Vault; deliberately rejects non-fixture material."""

    def __init__(self, fixtures: dict[str, bytes]):
        self._fixtures = dict(fixtures)
        self.acquisitions = 0
        self.last_lease: CredentialLease | None = None

    def acquire(self, plan: CredentialSessionPlan, *, now: datetime) -> CredentialLease:
        secret = self._fixtures.get(plan.credential_ref)
        if secret is None or not secret.startswith(b"fixture:"):
            raise CredentialSessionAdapterRejected("offline fixture credential unavailable")
        self.acquisitions += 1
        self.last_lease = CredentialLease(
            credential_ref=plan.credential_ref,
            secret=secret,
            expires_at=plan.lease_expires_at,
        )
        return self.last_lease


class OfflineIsolatedSessionAdapter:
    """Consumes a fixture lease once without authentication or network I/O."""

    def __init__(self, *, interrupt: bool = False):
        self.interrupt = interrupt
        self.opens = 0
        self.last_handle: IsolatedSessionHandle | None = None

    def open(
        self,
        plan: CredentialSessionPlan,
        *,
        credential: memoryview,
    ) -> IsolatedSessionHandle:
        if bytes(credential[:8]) != b"fixture:":
            raise CredentialSessionAdapterRejected("non-fixture credential rejected")
        self.opens += 1
        if self.interrupt:
            raise CredentialSessionAdapterRejected("isolated Session adapter interrupted")
        self.last_handle = IsolatedSessionHandle(
            session_binding=canonical_digest({"plan_id": plan.plan_id, "use": 1, "offline": True})
        )
        return self.last_handle
