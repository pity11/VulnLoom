"""Local-only authentication fixture adapter with logout proof."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime

from vulnloom.domain.digests import canonical_digest

from .credential_session_adapters import CredentialSessionAdapterRejected
from .credential_session_models import CredentialSessionPlan
from .role_observation_models import (
    LocalAuthenticationExecution,
    LocalAuthenticationObservation,
    OfflineRoleFixture,
    SessionLogoutProof,
)
from .test_identity_models import TestIdentityPurpose


class LocalAuthenticationExecutionUnavailable(RuntimeError):
    pass


class OfflineAuthenticatedSessionHandle:
    __slots__ = (
        "_access_allowed",
        "_material",
        "_released",
        "authentication_performed",
        "session_binding",
    )

    def __init__(self, *, session_binding: str, access_allowed: bool):
        self.session_binding = session_binding
        self.authentication_performed = True
        self._access_allowed = access_allowed
        self._material = bytearray(b"fixture-authenticated-session")
        self._released = False

    @property
    def released(self) -> bool:
        return self._released

    @property
    def zeroed(self) -> bool:
        return self._released and not any(self._material)

    def access_allowed(self) -> bool:
        if self._released:
            raise CredentialSessionAdapterRejected("logged-out Session cannot be reused")
        return self._access_allowed

    def close(self) -> None:
        if not self._released:
            self._material[:] = b"\x00" * len(self._material)
            self._released = True


class OfflineRoleAuthenticationAdapter:
    """Authenticates fixture material and observes one configured role decision."""

    def __init__(
        self,
        fixture: OfflineRoleFixture,
        *,
        credential_proofs: dict[str, bytes],
    ):
        if not credential_proofs or any(
            len(proof) != hashlib.sha256().digest_size for proof in credential_proofs.values()
        ):
            raise ValueError("local fixture credential proofs are invalid")
        self.fixture = fixture
        self._credential_proofs = dict(credential_proofs)
        self._runs: dict[
            str, tuple[LocalAuthenticationObservation, OfflineAuthenticatedSessionHandle]
        ] = {}
        self.opens = 0

    def open(
        self,
        plan: CredentialSessionPlan,
        *,
        credential: memoryview,
        now: datetime,
    ) -> OfflineAuthenticatedSessionHandle:
        if plan.purpose is not TestIdentityPurpose.READ_ONLY_ROLE_OBSERVATION:
            raise CredentialSessionAdapterRejected(
                "local role observation requires read-only purpose"
            )
        if bytes(credential[:8]) != b"fixture:":
            raise CredentialSessionAdapterRejected(
                "local authentication rejected non-fixture material"
            )
        expected_proof = self._credential_proofs.get(plan.credential_ref)
        observed_proof = hashlib.sha256(credential).digest()
        if expected_proof is None or not hmac.compare_digest(observed_proof, expected_proof):
            raise CredentialSessionAdapterRejected(
                "local authentication rejected fixture credential"
            )
        decision = next(
            (item.decision for item in self.fixture.decisions if item.role_ref == plan.role_ref),
            None,
        )
        if decision is None:
            raise CredentialSessionAdapterRejected(
                "role is unavailable in local authentication fixture"
            )
        if plan.plan_id in self._runs:
            raise CredentialSessionAdapterRejected(
                "local authentication Session Plan was already consumed"
            )
        session_binding = canonical_digest({"plan_id": plan.plan_id, "use": 1, "offline": True})
        handle = OfflineAuthenticatedSessionHandle(
            session_binding=session_binding,
            access_allowed=decision.value == "allowed",
        )
        handle.access_allowed()
        observation = LocalAuthenticationObservation.create(
            fixture_id=self.fixture.fixture_id,
            session_plan_id=plan.plan_id,
            identity_ref=plan.identity_ref,
            role_ref=plan.role_ref,
            action_intent_digest=plan.action_intent_digest,
            access_decision=decision,
            observed_at=now,
        )
        self._runs[plan.plan_id] = (observation, handle)
        self.opens += 1
        return handle

    def result(self, session_plan_id: str) -> LocalAuthenticationExecution:
        run = self._runs.get(session_plan_id)
        if run is None:
            raise LocalAuthenticationExecutionUnavailable(
                "local authentication execution is unavailable"
            )
        observation, handle = run
        if not handle.released or not handle.zeroed:
            raise LocalAuthenticationExecutionUnavailable(
                "local authentication Session cleanup is incomplete"
            )
        try:
            handle.access_allowed()
        except CredentialSessionAdapterRejected:
            reuse_rejected = True
        else:
            reuse_rejected = False
        if not reuse_rejected:
            raise LocalAuthenticationExecutionUnavailable("logged-out Session remained reusable")
        logout = SessionLogoutProof.create(
            session_plan_id=session_plan_id,
            session_binding=handle.session_binding,
            logged_out_at=observation.observed_at,
        )
        return LocalAuthenticationExecution.create(
            observation=observation,
            logout=logout,
        )
