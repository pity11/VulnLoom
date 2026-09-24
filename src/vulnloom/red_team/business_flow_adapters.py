"""Offline publication-flow adapter with compensating restoration proof."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime

from vulnloom.domain.digests import canonical_digest

from .business_flow_models import (
    BusinessInvariantVerdict,
    BusinessMutationObservation,
    BusinessStateSnapshot,
    LocalBusinessFlowExecution,
    OfflinePublicationFixture,
    PublicationState,
    StateRestorationProof,
)
from .credential_session_adapters import CredentialSessionAdapterRejected
from .credential_session_models import CredentialSessionPlan
from .test_identity_models import TestIdentityPurpose


class LocalBusinessFlowExecutionUnavailable(RuntimeError):
    pass


class _PublicationState:
    def __init__(self, fixture: OfflinePublicationFixture):
        self.fixture = fixture
        self.state = PublicationState.DRAFT
        self.revision = 1

    def snapshot(self, *, now: datetime) -> BusinessStateSnapshot:
        return BusinessStateSnapshot.create(
            fixture_id=self.fixture.fixture_id,
            resource_ref=self.fixture.resource_ref,
            state=self.state,
            revision=self.revision,
            observed_at=now,
        )


class OfflineBusinessFlowHandle:
    __slots__ = (
        "_adapter",
        "_material",
        "_released",
        "authentication_performed",
        "session_binding",
        "state_changed",
        "state_restored",
    )

    def __init__(self, *, adapter: OfflinePublicationFlowAdapter, session_binding: str):
        self._adapter = adapter
        self.session_binding = session_binding
        self.authentication_performed = True
        self.state_changed = True
        self.state_restored = False
        self._material = bytearray(b"fixture-business-flow-session")
        self._released = False

    @property
    def released(self) -> bool:
        return self._released

    @property
    def zeroed(self) -> bool:
        return self._released and not any(self._material)

    def close(self) -> None:
        if self._released:
            return
        try:
            self._adapter._restore()
            self.state_restored = True
        finally:
            self._material[:] = b"\x00" * len(self._material)
            self._released = True
        if self._adapter.fail_after_restoration:
            raise CredentialSessionAdapterRejected(
                "local restoration proof interrupted after state restoration"
            )


class OfflinePublicationFlowAdapter:
    """Mutates only one in-memory fixture and restores it when the Session closes."""

    ACTION_NAME = "fixture_publish_draft"

    def __init__(
        self,
        fixture: OfflinePublicationFixture,
        *,
        credential_proofs: dict[str, bytes],
        fail_after_restoration: bool = False,
    ):
        if not credential_proofs or any(
            len(proof) != hashlib.sha256().digest_size for proof in credential_proofs.values()
        ):
            raise ValueError("local fixture credential proofs are invalid")
        self.fixture = fixture
        self._credential_proofs = dict(credential_proofs)
        self._state = _PublicationState(fixture)
        self._runs: dict[
            str,
            tuple[
                BusinessStateSnapshot,
                BusinessStateSnapshot,
                BusinessMutationObservation,
                OfflineBusinessFlowHandle,
                BusinessStateSnapshot | None,
                StateRestorationProof | None,
            ],
        ] = {}
        self._active_plan_id: str | None = None
        self.fail_after_restoration = fail_after_restoration
        self.opens = 0

    def open(
        self,
        plan: CredentialSessionPlan,
        *,
        credential: memoryview,
        now: datetime,
    ) -> OfflineBusinessFlowHandle:
        if (
            plan.purpose is not TestIdentityPurpose.STATE_CHANGE_VALIDATION
            or not plan.mutates_state
            or plan.action_name != self.ACTION_NAME
        ):
            raise CredentialSessionAdapterRejected(
                "local publication flow requires the exact state-change action"
            )
        if bytes(credential[:8]) != b"fixture:":
            raise CredentialSessionAdapterRejected(
                "local publication flow rejected non-fixture material"
            )
        expected_proof = self._credential_proofs.get(plan.credential_ref)
        observed_proof = hashlib.sha256(credential).digest()
        if expected_proof is None or not hmac.compare_digest(observed_proof, expected_proof):
            raise CredentialSessionAdapterRejected(
                "local publication flow rejected fixture credential"
            )
        if plan.plan_id in self._runs or self._active_plan_id is not None:
            raise CredentialSessionAdapterRejected(
                "local publication fixture already has a consumed or active Session Plan"
            )
        if self._state.state is not PublicationState.DRAFT:
            raise CredentialSessionAdapterRejected("local publication fixture is not in draft")

        expected_authorized = plan.role_ref in self.fixture.publisher_roles
        if not expected_authorized and self.fixture.enforces_role_policy:
            raise CredentialSessionAdapterRejected(
                "local publication fixture enforced its role policy"
            )

        before = self._state.snapshot(now=now)
        self._state.state = PublicationState.PUBLISHED
        self._state.revision += 1
        mutated = self._state.snapshot(now=now)
        observation = BusinessMutationObservation.create(
            session_plan_id=plan.plan_id,
            fixture_id=self.fixture.fixture_id,
            resource_ref=self.fixture.resource_ref,
            actor_identity_ref=plan.identity_ref,
            actor_role_ref=plan.role_ref,
            action_intent_digest=plan.action_intent_digest,
            before_snapshot_id=before.snapshot_id,
            mutated_snapshot_id=mutated.snapshot_id,
            expected_authorized=expected_authorized,
            verdict=(
                BusinessInvariantVerdict.UPHELD
                if expected_authorized
                else BusinessInvariantVerdict.VIOLATED
            ),
            observed_at=now,
        )
        handle = OfflineBusinessFlowHandle(
            adapter=self,
            session_binding=canonical_digest(
                {"plan_id": plan.plan_id, "use": 1, "offline": True}
            ),
        )
        self._runs[plan.plan_id] = (before, mutated, observation, handle, None, None)
        self._active_plan_id = plan.plan_id
        self.opens += 1
        return handle

    def _restore(self) -> None:
        plan_id = self._active_plan_id
        if plan_id is None:
            raise CredentialSessionAdapterRejected("no active local mutation to restore")
        before, mutated, observation, handle, _, _ = self._runs[plan_id]
        self._state.state = before.state
        self._state.revision += 1
        restored = self._state.snapshot(now=observation.observed_at)
        proof = StateRestorationProof.create(
            session_plan_id=plan_id,
            before_snapshot_id=before.snapshot_id,
            mutated_snapshot_id=mutated.snapshot_id,
            restored_snapshot_id=restored.snapshot_id,
            before_semantic_digest=before.semantic_digest,
            restored_semantic_digest=restored.semantic_digest,
            before_revision=before.revision,
            mutated_revision=mutated.revision,
            restored_revision=restored.revision,
            restored_at=observation.observed_at,
        )
        self._runs[plan_id] = (before, mutated, observation, handle, restored, proof)
        self._active_plan_id = None

    def current_snapshot(self, *, now: datetime) -> BusinessStateSnapshot:
        return self._state.snapshot(now=now)

    def result(self, session_plan_id: str) -> LocalBusinessFlowExecution:
        run = self._runs.get(session_plan_id)
        if run is None:
            raise LocalBusinessFlowExecutionUnavailable(
                "local business-flow execution is unavailable"
            )
        before, mutated, observation, handle, restored, proof = run
        if (
            not handle.released
            or not handle.zeroed
            or not handle.state_restored
            or restored is None
            or proof is None
        ):
            raise LocalBusinessFlowExecutionUnavailable(
                "local business-flow restoration is incomplete"
            )
        return LocalBusinessFlowExecution.create(
            before=before,
            mutated=mutated,
            restored=restored,
            observation=observation,
            restoration=proof,
        )
