"""Transactional SQLite persistence for the trusted local Provider Center."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from pydantic import ValidationError

from vulnloom.domain.model_routing import CapabilityManifest, ModelRoute, ProviderProfile

from .models import (
    CapabilityProbeRequest,
    CapabilityProbeResult,
    ProviderAuditEvent,
    ProviderCenterView,
    ProviderHealthStatus,
    ProviderHealthView,
    ProviderMutationResult,
    ProviderReferenceBundle,
)


class ProviderCenterConflict(ValueError):
    pass


class ProviderCenterRecoveryRequired(RuntimeError):
    pass


class ProviderCenterStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS provider_center_operations (
              command_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
              command_json TEXT NOT NULL, state TEXT NOT NULL,
              result_type TEXT, result_json TEXT
            );
            CREATE TABLE IF NOT EXISTS provider_center_profiles (
              profile_digest TEXT PRIMARY KEY, provider_id TEXT NOT NULL,
              revision INTEGER NOT NULL, is_current INTEGER NOT NULL,
              profile_json TEXT NOT NULL, references_json TEXT NOT NULL,
              UNIQUE(provider_id, revision)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS provider_center_current_profile
              ON provider_center_profiles(provider_id) WHERE is_current=1;
            CREATE TABLE IF NOT EXISTS provider_center_manifests (
              manifest_digest TEXT PRIMARY KEY, provider_profile_digest TEXT NOT NULL,
              model_id TEXT NOT NULL, manifest_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS provider_center_routes (
              engine TEXT NOT NULL, agent_role TEXT NOT NULL,
              route_json TEXT NOT NULL, fallback_json TEXT NOT NULL,
              PRIMARY KEY(engine, agent_role)
            );
            CREATE TABLE IF NOT EXISTS provider_center_audit (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
              event_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS provider_center_probes (
              request_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
              request_json TEXT NOT NULL, state TEXT NOT NULL, result_json TEXT
            );
            """
        )
        self.connection.commit()

    def _replay(self, command_id: str, idempotency_key: str, command_json: str):
        row = self.connection.execute(
            "SELECT * FROM provider_center_operations WHERE command_id=? OR idempotency_key=?",
            (command_id, idempotency_key),
        ).fetchone()
        if row is None:
            return None
        if row["command_id"] != command_id or row["command_json"] != command_json:
            raise ProviderCenterConflict("Provider Center idempotency identity conflict")
        if row["state"] != "completed" or row["result_json"] is None:
            raise ProviderCenterRecoveryRequired("Provider Center operation requires recovery")
        try:
            if row["result_type"] == "mutation":
                return ProviderMutationResult.model_validate_json(row["result_json"])
        except ValidationError as exc:
            raise ProviderCenterRecoveryRequired("Provider Center result is invalid") from exc
        raise ProviderCenterRecoveryRequired("Provider Center result type is invalid")

    def mutation_replay(self, command) -> ProviderMutationResult | None:
        replay = self._replay(
            command.command_id, command.idempotency_key, command.model_dump_json()
        )
        if replay is None:
            return None
        return replay.model_copy(update={"applied": False})

    def apply_mutation(
        self,
        command,
        result: ProviderMutationResult,
        event: ProviderAuditEvent,
        mutation,
    ) -> ProviderMutationResult:
        command_json = command.model_dump_json()
        replay = self.mutation_replay(command)
        if replay is not None:
            return replay
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO provider_center_operations VALUES (?,?,?,'started',NULL,NULL)",
                    (command.command_id, command.idempotency_key, command_json),
                )
                mutation(self.connection)
                self.connection.execute(
                    "INSERT INTO provider_center_audit(event_id,event_json) VALUES (?,?)",
                    (event.event_id, event.model_dump_json()),
                )
                changed = self.connection.execute(
                    "UPDATE provider_center_operations SET "
                    "state='completed',result_type='mutation',"
                    "result_json=? WHERE command_id=? AND state='started'",
                    (result.model_dump_json(), command.command_id),
                ).rowcount
                if changed != 1:
                    raise ProviderCenterRecoveryRequired(
                        "Provider Center STARTED checkpoint unavailable"
                    )
        except sqlite3.IntegrityError as exc:
            raise ProviderCenterConflict("Provider Center concurrent mutation rejected") from exc
        return result

    def current_profile(self, provider_id: str) -> ProviderProfile:
        row = self.connection.execute(
            "SELECT profile_json FROM provider_center_profiles "
            "WHERE provider_id=? AND is_current=1",
            (provider_id,),
        ).fetchone()
        if row is None:
            raise ProviderCenterConflict("Provider Profile is unavailable")
        try:
            return ProviderProfile.model_validate_json(row[0])
        except ValidationError as exc:
            raise ProviderCenterRecoveryRequired("stored Provider Profile is invalid") from exc

    def references(self, profile_digest: str) -> ProviderReferenceBundle:
        row = self.connection.execute(
            "SELECT references_json FROM provider_center_profiles WHERE profile_digest=?",
            (profile_digest,),
        ).fetchone()
        if row is None:
            raise ProviderCenterConflict("Provider reference bundle is unavailable")
        try:
            return ProviderReferenceBundle.model_validate_json(row[0])
        except ValidationError as exc:
            raise ProviderCenterRecoveryRequired("stored Provider references are invalid") from exc

    def manifests_for(self, profile_digest: str) -> tuple[CapabilityManifest, ...]:
        rows = self.connection.execute(
            "SELECT manifest_json FROM provider_center_manifests "
            "WHERE provider_profile_digest=? ORDER BY model_id, manifest_digest",
            (profile_digest,),
        ).fetchall()
        try:
            return tuple(CapabilityManifest.model_validate_json(row[0]) for row in rows)
        except ValidationError as exc:
            raise ProviderCenterRecoveryRequired("stored Capability Manifest is invalid") from exc

    def route(self, engine: str, agent_role: str) -> ModelRoute | None:
        row = self.connection.execute(
            "SELECT route_json FROM provider_center_routes WHERE engine=? AND agent_role=?",
            (engine, agent_role),
        ).fetchone()
        if row is None:
            return None
        try:
            return ModelRoute.model_validate_json(row[0])
        except ValidationError as exc:
            raise ProviderCenterRecoveryRequired("stored Model Route is invalid") from exc

    def probe_replay(self, request: CapabilityProbeRequest) -> CapabilityProbeResult | None:
        row = self.connection.execute(
            "SELECT * FROM provider_center_probes WHERE request_id=? OR idempotency_key=?",
            (request.request_id, request.idempotency_key),
        ).fetchone()
        request_json = request.model_dump_json()
        if row is not None:
            if row["request_id"] != request.request_id or row["request_json"] != request_json:
                raise ProviderCenterConflict("capability probe identity conflict")
            if row["state"] != "completed" or row["result_json"] is None:
                raise ProviderCenterRecoveryRequired("capability probe requires recovery")
            try:
                return CapabilityProbeResult.model_validate_json(row["result_json"])
            except ValidationError as exc:
                raise ProviderCenterRecoveryRequired("capability probe result is invalid") from exc
        return None

    def claim_probe(self, request: CapabilityProbeRequest) -> None:
        if self.probe_replay(request) is not None:
            raise ProviderCenterConflict("completed capability probe cannot be claimed again")
        request_json = request.model_dump_json()
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO provider_center_probes VALUES (?,?,?,'started',NULL)",
                    (request.request_id, request.idempotency_key, request_json),
                )
        except sqlite3.IntegrityError as exc:
            raise ProviderCenterConflict("concurrent capability probe rejected") from exc

    def complete_probe(
        self,
        result: CapabilityProbeResult,
        expected_profile: ProviderProfile,
        profile: ProviderProfile,
        event: ProviderAuditEvent,
    ) -> None:
        with self.connection:
            row = self.connection.execute(
                "SELECT profile_json FROM provider_center_profiles "
                "WHERE profile_digest=? AND is_current=1",
                (expected_profile.profile_digest,),
            ).fetchone()
            if row is None or row[0] != expected_profile.model_dump_json():
                raise ProviderCenterRecoveryRequired(
                    "Provider lifecycle changed during capability probe"
                )
            if result.manifest is not None:
                self.connection.execute(
                    "INSERT INTO provider_center_manifests VALUES (?,?,?,?)",
                    (
                        result.manifest.manifest_digest,
                        result.manifest.provider_profile_digest,
                        result.manifest.provider_model_id,
                        result.manifest.model_dump_json(),
                    ),
                )
            profile_changed = self.connection.execute(
                "UPDATE provider_center_profiles SET profile_json=? WHERE profile_digest=?",
                (profile.model_dump_json(), profile.profile_digest),
            ).rowcount
            if profile_changed != 1:
                raise ProviderCenterRecoveryRequired("Provider Profile update failed")
            changed = self.connection.execute(
                "UPDATE provider_center_probes SET state='completed',result_json=? "
                "WHERE request_id=? AND state='started'",
                (result.model_dump_json(), result.request_id),
            ).rowcount
            if changed != 1:
                raise ProviderCenterRecoveryRequired("capability probe STARTED unavailable")
            self.connection.execute(
                "INSERT INTO provider_center_audit(event_id,event_json) VALUES (?,?)",
                (event.event_id, event.model_dump_json()),
            )

    def view(self, *, audit_limit: int = 50) -> ProviderCenterView:
        profile_rows = self.connection.execute(
            "SELECT profile_json FROM provider_center_profiles WHERE is_current=1 "
            "ORDER BY provider_id"
        ).fetchall()
        manifest_rows = self.connection.execute(
            "SELECT manifest_json FROM provider_center_manifests ORDER BY model_id, manifest_digest"
        ).fetchall()
        route_rows = self.connection.execute(
            "SELECT route_json FROM provider_center_routes ORDER BY engine, agent_role"
        ).fetchall()
        audit_rows = self.connection.execute(
            "SELECT event_json FROM provider_center_audit ORDER BY sequence DESC LIMIT ?",
            (audit_limit,),
        ).fetchall()
        probe_rows = self.connection.execute(
            "SELECT result_json FROM provider_center_probes WHERE state='completed' ORDER BY rowid"
        ).fetchall()
        try:
            profiles = tuple(ProviderProfile.model_validate_json(row[0]) for row in profile_rows)
            probe_results = tuple(
                CapabilityProbeResult.model_validate_json(row[0]) for row in probe_rows
            )
            latest_probe = {item.provider_profile_digest: item for item in probe_results}
            health = []
            for profile in profiles:
                probe = latest_probe.get(profile.profile_digest)
                if profile.state.value == "disabled":
                    status = ProviderHealthStatus.DISABLED
                elif probe is None:
                    status = ProviderHealthStatus.UNKNOWN
                elif probe.status.value == "passed":
                    status = ProviderHealthStatus.HEALTHY
                elif probe.status.value == "timed_out":
                    status = ProviderHealthStatus.TIMED_OUT
                else:
                    status = ProviderHealthStatus.FAILED
                health.append(
                    ProviderHealthView(
                        provider_id=profile.provider_id,
                        provider_profile_digest=profile.profile_digest,
                        status=status,
                        last_probe_at=None if probe is None else probe.completed_at,
                        cleanup_verified=None if probe is None else probe.cleanup_verified,
                        diagnostic_code=None if probe is None else probe.diagnostic_code,
                    )
                )
            return ProviderCenterView(
                profiles=profiles,
                health=tuple(health),
                capability_manifests=tuple(
                    CapabilityManifest.model_validate_json(row[0]) for row in manifest_rows
                ),
                default_routes=tuple(ModelRoute.model_validate_json(row[0]) for row in route_rows),
                recent_audit=tuple(
                    ProviderAuditEvent.model_validate_json(row[0]) for row in audit_rows
                ),
            )
        except ValidationError as exc:
            raise ProviderCenterRecoveryRequired("Provider Center registry is invalid") from exc

    def close(self) -> None:
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
