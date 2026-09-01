"""Crash-safe checkpoints and immutable artifacts for Agent session audits."""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .audit_models import (
    AgentSessionAuditArtifact,
    AgentSessionAuditBundle,
    AgentSessionAuditOutcome,
    AgentSessionAuditPlan,
)


class AgentSessionAuditIdempotencyConflict(ValueError):
    pass


class AgentSessionAuditSessionConflict(ValueError):
    pass


class AgentSessionAuditRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentSessionAuditClaim:
    created: bool
    outcome: AgentSessionAuditOutcome | None = None


class AgentSessionAuditStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_session_audits (
                audit_plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                session_id TEXT NOT NULL UNIQUE,
                session_outcome_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started', 'completed')),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(self, plan: AgentSessionAuditPlan, *, now: datetime) -> AgentSessionAuditClaim:
        existing = self.connection.execute(
            "SELECT * FROM agent_session_audits WHERE audit_plan_id = ? "
            "OR idempotency_key = ? OR session_id = ?",
            (plan.audit_plan_id, plan.idempotency_key, plan.session_id),
        ).fetchone()
        if existing is not None:
            if existing["audit_plan_id"] == plan.audit_plan_id:
                if existing["state"] == "started" or existing["outcome_json"] is None:
                    raise AgentSessionAuditRecoveryRequired(
                        "Agent session audit has an unfinished STARTED checkpoint"
                    )
                outcome = AgentSessionAuditOutcome.model_validate_json(
                    existing["outcome_json"]
                )
                if (
                    outcome.audit_plan_id != plan.audit_plan_id
                    or outcome.session_id != plan.session_id
                    or outcome.bundle.session_outcome_id
                    != existing["session_outcome_id"]
                ):
                    raise AgentSessionAuditRecoveryRequired(
                        "Agent session audit completed checkpoint binding mismatch"
                    )
                return AgentSessionAuditClaim(created=False, outcome=outcome)
            if existing["idempotency_key"] == plan.idempotency_key:
                raise AgentSessionAuditIdempotencyConflict(
                    "Agent session audit idempotency key was reused for different content"
                )
            raise AgentSessionAuditSessionConflict(
                "Agent session already has an audit bundle"
            )
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO agent_session_audits "
                    "(audit_plan_id, idempotency_key, session_id, session_outcome_id, "
                    "state, started_at) VALUES (?, ?, ?, ?, 'started', ?)",
                    (
                        plan.audit_plan_id,
                        plan.idempotency_key,
                        plan.session_id,
                        plan.session_outcome_id,
                        now.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise AgentSessionAuditSessionConflict(
                "Agent session audit checkpoint conflicted concurrently"
            ) from exc
        return AgentSessionAuditClaim(created=True)

    def complete(self, outcome: AgentSessionAuditOutcome) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE agent_session_audits SET state = 'completed', completed_at = ?, "
                "outcome_json = ? WHERE audit_plan_id = ? AND session_id = ? "
                "AND state = 'started'",
                (
                    outcome.completed_at.isoformat(),
                    outcome.model_dump_json(),
                    outcome.audit_plan_id,
                    outcome.session_id,
                ),
            ).rowcount
        if changed != 1:
            raise AgentSessionAuditRecoveryRequired(
                "Agent session audit STARTED checkpoint is unavailable"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AgentSessionAuditStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class AgentSessionAuditArtifactStore:
    def __init__(self, root: Path, *, max_artifact_bytes: int = 2 * 1024 * 1024):
        if max_artifact_bytes <= 0:
            raise ValueError("Agent session audit artifact size limit must be positive")
        self.root = root.resolve()
        self.objects = self.root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_artifact_bytes = max_artifact_bytes

    def put(self, bundle: AgentSessionAuditBundle) -> AgentSessionAuditArtifact:
        json_bytes = (bundle.model_dump_json(indent=2) + "\n").encode()
        markdown_bytes = render_agent_session_audit_markdown(bundle).encode()
        self._check_size(json_bytes)
        self._check_size(markdown_bytes)
        artifact = AgentSessionAuditArtifact(
            bundle_id=bundle.bundle_id,
            json_sha256=hashlib.sha256(json_bytes).hexdigest(),
            markdown_sha256=hashlib.sha256(markdown_bytes).hexdigest(),
            json_ref=f"objects/{bundle.bundle_id}/audit.json",
            markdown_ref=f"objects/{bundle.bundle_id}/audit.md",
        )
        destination = self.objects / bundle.bundle_id
        if destination.exists():
            self._verify(artifact)
            return artifact
        temporary = Path(tempfile.mkdtemp(prefix="audit-", dir=self.objects))
        try:
            self._write(temporary / "audit.json", json_bytes)
            self._write(temporary / "audit.md", markdown_bytes)
            os.chmod(temporary, 0o500)
            try:
                os.rename(temporary, destination)
            except FileExistsError:
                self._verify(artifact)
            self._verify(artifact)
            return artifact
        finally:
            if temporary.exists():
                os.chmod(temporary, 0o700)
                shutil.rmtree(temporary)

    def read_bundle(self, artifact: AgentSessionAuditArtifact) -> AgentSessionAuditBundle:
        self._verify(artifact)
        return AgentSessionAuditBundle.model_validate_json(
            self._read(self.root / artifact.json_ref)
        )

    def read_markdown(self, artifact: AgentSessionAuditArtifact) -> str:
        self._verify(artifact)
        return self._read(self.root / artifact.markdown_ref).decode()

    def _verify(self, artifact: AgentSessionAuditArtifact) -> None:
        directory = self.objects / artifact.bundle_id
        try:
            metadata = os.lstat(directory)
        except OSError as exc:
            raise ValueError(
                "Agent session audit object directory is unavailable or unsafe"
            ) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_mode & 0o222
            or {item.name for item in directory.iterdir()} != {"audit.json", "audit.md"}
        ):
            raise ValueError("Agent session audit object directory is unavailable or unsafe")
        json_bytes = self._read(self.root / artifact.json_ref)
        markdown_bytes = self._read(self.root / artifact.markdown_ref)
        if hashlib.sha256(json_bytes).hexdigest() != artifact.json_sha256:
            raise ValueError("Agent session audit JSON integrity check failed")
        if hashlib.sha256(markdown_bytes).hexdigest() != artifact.markdown_sha256:
            raise ValueError("Agent session audit Markdown integrity check failed")
        bundle = AgentSessionAuditBundle.model_validate_json(json_bytes)
        if bundle.bundle_id != artifact.bundle_id:
            raise ValueError("Agent session audit content identity mismatch")

    def _read(self, path: Path) -> bytes:
        if not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("platform cannot enforce no-follow Agent audit reads")
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise ValueError("Agent session audit artifact is unavailable or unsafe") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o222
                or metadata.st_size > self.max_artifact_bytes
            ):
                raise ValueError("Agent session audit artifact is unavailable or unsafe")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                content = handle.read(self.max_artifact_bytes + 1)
        finally:
            os.close(descriptor)
        self._check_size(content)
        return content

    def _check_size(self, content: bytes) -> None:
        if len(content) > self.max_artifact_bytes:
            raise ValueError("Agent session audit artifact exceeds its size limit")

    @staticmethod
    def _write(path: Path, content: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())


def render_agent_session_audit_markdown(bundle: AgentSessionAuditBundle) -> str:
    evidence = ", ".join(f"`{item}`" for item in bundle.evidence_refs)
    observations = ", ".join(f"`{item}`" for item in bundle.observation_ids)
    lines = (
        "# Agent session audit",
        "",
        f"Bundle ID: `{bundle.bundle_id}`  ",
        f"Session ID: `{bundle.session_id}`  ",
        f"Target ID: `{bundle.target_id}`  ",
        f"Target version digest: `{bundle.target_version_digest}`  ",
        f"Scope ID: `{bundle.scope_id}`  ",
        f"Scope version: `{bundle.scope_version}`",
        "",
        "## Deterministic recommendation",
        "",
        f"Disposition: `{bundle.recommendation.disposition.value}`  ",
        f"Reason: `{bundle.recommendation.reason_code.value}`",
        "",
        "## Verified chain",
        "",
        f"Observations: {observations}  ",
        f"Evidence: {evidence}  ",
        f"Provider attempts: `{bundle.budget.provider_attempts}`  ",
        f"Broker attempts: `{bundle.budget.broker_attempts}`  ",
        f"Consumed tool calls: `{bundle.budget.consumed_tool_calls}`",
        "",
        "This artifact contains digests and typed counts only; it is not a domain-state command.",
    )
    return "\n".join(lines) + "\n"
