"""Crash-safe checkpoints and immutable artifacts for Agent workflow regression."""

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

from vulnloom.domain.digests import canonical_digest

from .agent_workflow_models import (
    AgentWorkflowRegressionArtifact,
    AgentWorkflowRegressionOutcome,
    AgentWorkflowRegressionPlan,
    AgentWorkflowRegressionResult,
)


class AgentWorkflowRegressionConflict(ValueError):
    pass


class AgentWorkflowRegressionRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentWorkflowRegressionClaim:
    created: bool
    outcome: AgentWorkflowRegressionOutcome | None = None


class AgentWorkflowRegressionStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS agent_workflow_regressions (
            plan_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
            observation_id TEXT NOT NULL UNIQUE,
            state TEXT NOT NULL CHECK(state IN ('started','completed')),
            started_at TEXT NOT NULL, completed_at TEXT, outcome_json TEXT)"""
        )
        self.connection.commit()

    def claim(
        self, plan: AgentWorkflowRegressionPlan, *, now: datetime
    ) -> AgentWorkflowRegressionClaim:
        row = self.connection.execute(
            "SELECT * FROM agent_workflow_regressions WHERE plan_id=? "
            "OR idempotency_key=? OR observation_id=?",
            (plan.plan_id, plan.idempotency_key, plan.observation_id),
        ).fetchone()
        if row is not None:
            if row["plan_id"] != plan.plan_id:
                raise AgentWorkflowRegressionConflict(
                    "Agent workflow regression input or idempotency key was reused"
                )
            if row["state"] == "started":
                raise AgentWorkflowRegressionRecoveryRequired(
                    "Agent workflow regression has unfinished STARTED state"
                )
            return AgentWorkflowRegressionClaim(
                created=False,
                outcome=AgentWorkflowRegressionOutcome.model_validate_json(row["outcome_json"]),
            )
        with self.connection:
            self.connection.execute(
                "INSERT INTO agent_workflow_regressions "
                "(plan_id,idempotency_key,observation_id,state,started_at) "
                "VALUES (?,?,?,'started',?)",
                (plan.plan_id, plan.idempotency_key, plan.observation_id, now.isoformat()),
            )
        return AgentWorkflowRegressionClaim(created=True)

    def complete(self, outcome: AgentWorkflowRegressionOutcome, *, now: datetime) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE agent_workflow_regressions SET state='completed',completed_at=?,"
                "outcome_json=? WHERE plan_id=? AND state='started'",
                (now.isoformat(), outcome.model_dump_json(), outcome.plan_id),
            ).rowcount
        if changed != 1:
            raise AgentWorkflowRegressionRecoveryRequired(
                "Agent workflow regression STARTED checkpoint is unavailable"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AgentWorkflowRegressionStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class AgentWorkflowRegressionArtifactStore:
    def __init__(self, root: Path, *, max_artifact_bytes: int = 1024 * 1024):
        if max_artifact_bytes <= 0:
            raise ValueError("Agent workflow artifact size limit must be positive")
        self.root = root.resolve()
        self.objects = self.root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_artifact_bytes = max_artifact_bytes

    def put(self, result: AgentWorkflowRegressionResult) -> AgentWorkflowRegressionArtifact:
        result_digest = canonical_digest(result.model_dump(mode="python"))
        destination = self.objects / result_digest
        json_bytes = (result.model_dump_json(indent=2) + "\n").encode()
        markdown_bytes = _render_markdown(result).encode()
        self._check_size(json_bytes)
        self._check_size(markdown_bytes)
        artifact = AgentWorkflowRegressionArtifact(
            result_digest=result_digest,
            json_sha256=hashlib.sha256(json_bytes).hexdigest(),
            markdown_sha256=hashlib.sha256(markdown_bytes).hexdigest(),
            json_ref=f"objects/{result_digest}/result.json",
            markdown_ref=f"objects/{result_digest}/result.md",
        )
        if destination.exists():
            self._verify(artifact)
            return artifact
        temporary = Path(tempfile.mkdtemp(prefix="agent-workflow-", dir=self.objects))
        try:
            self._write(temporary / "result.json", json_bytes)
            self._write(temporary / "result.md", markdown_bytes)
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

    def read_result(
        self, artifact: AgentWorkflowRegressionArtifact
    ) -> AgentWorkflowRegressionResult:
        self._verify(artifact)
        return AgentWorkflowRegressionResult.model_validate_json(
            self._read(self.root / artifact.json_ref)
        )

    def _verify(self, artifact: AgentWorkflowRegressionArtifact) -> None:
        directory = self.objects / artifact.result_digest
        try:
            metadata = os.lstat(directory)
        except OSError as exc:
            raise ValueError("Agent workflow artifact directory is unsafe") from exc
        if not stat.S_ISDIR(metadata.st_mode) or {item.name for item in directory.iterdir()} != {
            "result.json",
            "result.md",
        }:
            raise ValueError("Agent workflow artifact directory is unsafe")
        json_bytes = self._read(self.root / artifact.json_ref)
        markdown_bytes = self._read(self.root / artifact.markdown_ref)
        if hashlib.sha256(json_bytes).hexdigest() != artifact.json_sha256:
            raise ValueError("Agent workflow JSON integrity check failed")
        if hashlib.sha256(markdown_bytes).hexdigest() != artifact.markdown_sha256:
            raise ValueError("Agent workflow Markdown integrity check failed")
        result = AgentWorkflowRegressionResult.model_validate_json(json_bytes)
        if canonical_digest(result.model_dump(mode="python")) != artifact.result_digest:
            raise ValueError("Agent workflow result content identity mismatch")

    def _read(self, path: Path) -> bytes:
        if not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("platform cannot enforce no-follow reads")
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise ValueError("Agent workflow artifact is unsafe") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > self.max_artifact_bytes:
                raise ValueError("Agent workflow artifact is unsafe")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                content = handle.read(self.max_artifact_bytes + 1)
        finally:
            os.close(descriptor)
        self._check_size(content)
        return content

    def _check_size(self, content: bytes) -> None:
        if len(content) > self.max_artifact_bytes:
            raise ValueError("Agent workflow artifact exceeds size limit")

    @staticmethod
    def _write(path: Path, content: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())


def _render_markdown(result: AgentWorkflowRegressionResult) -> str:
    metrics = result.metrics
    lines = [
        "# VulnLoom Agent Workflow Regression",
        "",
        f"- Gate: `{result.gate_status.value}`",
        f"- Stage completeness: `{metrics.stage_completeness:.9f}`",
        f"- Evidence refs: `{metrics.evidence_ref_count}`",
        f"- Human decisions: `{metrics.human_decision_count}`",
        f"- Exact Approvals: `{metrics.approval_count}`",
        f"- Forbidden effects: `{metrics.forbidden_effect_count}`",
        "",
    ]
    if result.violations:
        lines.extend(["## Violations", ""])
        lines.extend(f"- `{item.code}`" for item in result.violations)
        lines.append("")
    return "\n".join(lines)
