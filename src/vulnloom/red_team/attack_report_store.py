"""Transactional checkpoints and immutable artifacts for Attack Path Reports."""

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

from .attack_report_models import (
    AttackChainReport,
    AttackChainReportArtifact,
    AttackChainReportOutcome,
    AttackChainReportPlan,
    AttackReportState,
)


class AttackChainReportConflict(ValueError):
    pass


class AttackChainReportRecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AttackChainReportClaim:
    created: bool
    attempt: int
    outcome: AttackChainReportOutcome | None = None


class AttackChainReportStore:
    def __init__(self, path: Path):
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS attack_chain_reports (
                report_plan_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                chain_plan_id TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('started','completed','timed_out','failed')),
                attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                outcome_json TEXT
            )
            """
        )
        self.connection.commit()

    def claim(self, plan: AttackChainReportPlan, *, now: datetime) -> AttackChainReportClaim:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO attack_chain_reports VALUES (?,?,?,?,'started',1,?,NULL,NULL)",
                    (
                        plan.report_plan_id,
                        plan.idempotency_key,
                        plan.chain_plan_id,
                        plan.model_dump_json(),
                        now.isoformat(),
                    ),
                )
            return AttackChainReportClaim(created=True, attempt=1)
        except sqlite3.IntegrityError:
            row = self._identity(plan)
            self._same(row, plan)
            if row["state"] == "started":
                raise AttackChainReportRecoveryRequired(
                    "Attack Path Report has an unfinished STARTED checkpoint"
                ) from None
            return AttackChainReportClaim(
                created=False,
                attempt=row["attempt"],
                outcome=AttackChainReportOutcome.model_validate_json(row["outcome_json"]),
            )

    def recover(self, plan: AttackChainReportPlan, *, now: datetime) -> AttackChainReportClaim:
        exhausted = False
        with self.connection:
            row = self._identity(plan)
            self._same(row, plan)
            if row["state"] != "started":
                raise AttackChainReportRecoveryRequired(
                    "Attack Path Report is not awaiting recovery"
                )
            if row["attempt"] >= plan.max_attempts:
                outcome = AttackChainReportOutcome(
                    report_plan_id=plan.report_plan_id,
                    state=AttackReportState.FAILED,
                    attempt=row["attempt"],
                    chain_plan_id=plan.chain_plan_id,
                    reason_code="recovery_attempts_exhausted",
                    cleanup_complete=True,
                    completed_at=now,
                )
                self._finish(row, outcome)
                exhausted = True
            else:
                attempt = row["attempt"] + 1
                changed = self.connection.execute(
                    "UPDATE attack_chain_reports SET attempt=?,started_at=? "
                    "WHERE report_plan_id=? AND state='started' AND attempt=?",
                    (attempt, now.isoformat(), plan.report_plan_id, row["attempt"]),
                ).rowcount
                if changed != 1:
                    raise AttackChainReportRecoveryRequired("Attack Path Report recovery raced")
        if exhausted:
            raise AttackChainReportRecoveryRequired(
                "Attack Path Report recovery attempts are exhausted"
            )
        return AttackChainReportClaim(created=True, attempt=attempt)

    def finish(self, outcome: AttackChainReportOutcome) -> None:
        with self.connection:
            row = self.connection.execute(
                "SELECT * FROM attack_chain_reports WHERE report_plan_id=?",
                (outcome.report_plan_id,),
            ).fetchone()
            if row is None:
                raise AttackChainReportRecoveryRequired(
                    "Attack Path Report checkpoint is unavailable"
                )
            self._finish(row, outcome)

    def _finish(self, row: sqlite3.Row, outcome: AttackChainReportOutcome) -> None:
        changed = self.connection.execute(
            "UPDATE attack_chain_reports SET state=?,completed_at=?,outcome_json=? "
            "WHERE report_plan_id=? AND state='started' AND attempt=?",
            (
                outcome.state.value,
                outcome.completed_at.isoformat(),
                outcome.model_dump_json(),
                outcome.report_plan_id,
                outcome.attempt,
            ),
        ).rowcount
        if changed != 1 or row["chain_plan_id"] != outcome.chain_plan_id:
            raise AttackChainReportRecoveryRequired(
                "Attack Path Report STARTED checkpoint is unavailable"
            )

    def outcome(self, report_plan_id: str) -> AttackChainReportOutcome:
        row = self.connection.execute(
            "SELECT state,outcome_json FROM attack_chain_reports WHERE report_plan_id=?",
            (report_plan_id,),
        ).fetchone()
        if row is None or row["state"] == "started" or row["outcome_json"] is None:
            raise AttackChainReportRecoveryRequired(
                "terminal Attack Path Report outcome is unavailable"
            )
        outcome = AttackChainReportOutcome.model_validate_json(row["outcome_json"])
        if outcome.report_plan_id != report_plan_id or outcome.state.value != row["state"]:
            raise AttackChainReportRecoveryRequired("Attack Path Report outcome drifted")
        return outcome

    def state(self, report_plan_id: str) -> tuple[str, int] | None:
        row = self.connection.execute(
            "SELECT state,attempt FROM attack_chain_reports WHERE report_plan_id=?",
            (report_plan_id,),
        ).fetchone()
        return (row["state"], row["attempt"]) if row else None

    def _identity(self, plan: AttackChainReportPlan) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM attack_chain_reports WHERE report_plan_id=? "
            "OR idempotency_key=? OR chain_plan_id=?",
            (plan.report_plan_id, plan.idempotency_key, plan.chain_plan_id),
        ).fetchone()
        if row is None:
            raise AttackChainReportRecoveryRequired("Attack Path Report checkpoint is unavailable")
        return row

    @staticmethod
    def _same(row: sqlite3.Row, plan: AttackChainReportPlan) -> None:
        if (
            row["report_plan_id"] != plan.report_plan_id
            or row["plan_json"] != plan.model_dump_json()
        ):
            raise AttackChainReportConflict(
                "Attack Path Report identity was reused for different content"
            )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> AttackChainReportStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class AttackChainReportArtifactStore:
    def __init__(self, root: Path, *, max_artifact_bytes: int = 2 * 1024 * 1024):
        if max_artifact_bytes <= 0:
            raise ValueError("Attack Path Report artifact size limit must be positive")
        self.root = root.resolve()
        self.objects = self.root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_artifact_bytes = max_artifact_bytes

    def put(self, report: AttackChainReport) -> AttackChainReportArtifact:
        json_bytes = (report.model_dump_json(indent=2) + "\n").encode()
        markdown_bytes = self._markdown(report).encode()
        self._size(json_bytes)
        self._size(markdown_bytes)
        artifact = AttackChainReportArtifact(
            report_id=report.report_id,
            json_sha256=hashlib.sha256(json_bytes).hexdigest(),
            markdown_sha256=hashlib.sha256(markdown_bytes).hexdigest(),
            json_ref=f"objects/{report.report_id}/attack-report.json",
            markdown_ref=f"objects/{report.report_id}/attack-report.md",
        )
        destination = self.objects / report.report_id
        if destination.exists():
            self._verify(artifact)
            return artifact
        temporary = Path(tempfile.mkdtemp(prefix="attack-report-", dir=self.objects))
        try:
            self._write(temporary / "attack-report.json", json_bytes)
            self._write(temporary / "attack-report.md", markdown_bytes)
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

    def read_report(self, artifact: AttackChainReportArtifact) -> AttackChainReport:
        self._verify(artifact)
        return AttackChainReport.model_validate_json(self._read(self.root / artifact.json_ref))

    def read_markdown(self, artifact: AttackChainReportArtifact) -> str:
        self._verify(artifact)
        return self._read(self.root / artifact.markdown_ref).decode()

    def _verify(self, artifact: AttackChainReportArtifact) -> None:
        directory = self.objects / artifact.report_id
        try:
            metadata = os.lstat(directory)
        except OSError as exc:
            raise ValueError("Attack Path Report artifact is unavailable or unsafe") from exc
        if not stat.S_ISDIR(metadata.st_mode) or {item.name for item in directory.iterdir()} != {
            "attack-report.json",
            "attack-report.md",
        }:
            raise ValueError("Attack Path Report artifact is unavailable or unsafe")
        json_bytes = self._read(self.root / artifact.json_ref)
        markdown_bytes = self._read(self.root / artifact.markdown_ref)
        if hashlib.sha256(json_bytes).hexdigest() != artifact.json_sha256:
            raise ValueError("Attack Path Report JSON integrity check failed")
        if hashlib.sha256(markdown_bytes).hexdigest() != artifact.markdown_sha256:
            raise ValueError("Attack Path Report Markdown integrity check failed")
        report = AttackChainReport.model_validate_json(json_bytes)
        if (
            canonical_digest(report.model_dump(mode="python", exclude={"report_id"}))
            != report.report_id
        ):
            raise ValueError("Attack Path Report content identity mismatch")

    def _read(self, path: Path) -> bytes:
        if not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("platform cannot enforce no-follow Report reads")
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise ValueError("Attack Path Report artifact is unavailable or unsafe") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > self.max_artifact_bytes:
                raise ValueError("Attack Path Report artifact is unavailable or unsafe")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                content = handle.read(self.max_artifact_bytes + 1)
        finally:
            os.close(descriptor)
        self._size(content)
        return content

    def _write(self, path: Path, content: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)

    def _size(self, content: bytes) -> None:
        if len(content) > self.max_artifact_bytes:
            raise ValueError("Attack Path Report artifact exceeds its size limit")

    @staticmethod
    def _markdown(report: AttackChainReport) -> str:
        lines = [
            "# Authorized Attack Path Report",
            "",
            f"Report: `{report.report_id}`",
            f"Chain: `{report.chain_plan_id}`",
            f"Status: `{report.chain_status.value}`",
            "",
            "## Attack Path",
            "",
        ]
        lines.extend(
            f"{step.ordinal}. `{step.kind.value}` — evidence `{step.observation_id}`"
            for step in report.steps
        )
        lines.extend(("", "## Detection Opportunities", ""))
        lines.extend(
            f"- `{item.kind.value}` at action `{item.action_id}`"
            for item in report.detection_opportunities
        )
        lines.extend(("", "## Defensive Improvements", ""))
        lines.extend(f"- `{item.control.value}`" for item in report.defensive_improvements)
        return "\n".join(lines) + "\n"
