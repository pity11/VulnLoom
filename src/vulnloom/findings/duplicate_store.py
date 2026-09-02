"""Authoritative local store for sealed human duplicate-check proofs."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .models import FindingDuplicateCheck


class FindingDuplicateCheckConflict(ValueError):
    pass


class FindingDuplicateCheckStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS finding_duplicate_checks (
            check_id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL,
            checked_at TEXT NOT NULL, expires_at TEXT NOT NULL, proof_json TEXT NOT NULL)"""
        )
        self.connection.commit()

    def publish(self, proof: FindingDuplicateCheck) -> FindingDuplicateCheck:
        encoded = proof.model_dump_json()
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO finding_duplicate_checks VALUES (?,?,?,?,?)",
                    (
                        proof.check_id,
                        str(proof.candidate_id),
                        proof.checked_at.isoformat(),
                        proof.expires_at.isoformat(),
                        encoded,
                    ),
                )
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                "SELECT * FROM finding_duplicate_checks WHERE check_id=?", (proof.check_id,)
            ).fetchone()
            if row is None or row["proof_json"] != encoded:
                raise FindingDuplicateCheckConflict(
                    "duplicate-check identity was reused for different content"
                ) from None
        return self.load(proof.check_id)

    def load(self, check_id: str) -> FindingDuplicateCheck:
        row = self.connection.execute(
            "SELECT * FROM finding_duplicate_checks WHERE check_id=?", (check_id,)
        ).fetchone()
        if row is None:
            raise ValueError("Finding duplicate check is unavailable")
        proof = FindingDuplicateCheck.model_validate_json(row["proof_json"])
        if (
            proof.check_id != check_id
            or str(proof.candidate_id) != row["candidate_id"]
            or proof.checked_at.isoformat() != row["checked_at"]
            or proof.expires_at.isoformat() != row["expires_at"]
        ):
            raise FindingDuplicateCheckConflict("Finding duplicate-check checkpoint drifted")
        return proof

    def load_current(self, check_id: str) -> FindingDuplicateCheck:
        proof = self.load(check_id)
        rows = self.connection.execute(
            "SELECT proof_json FROM finding_duplicate_checks WHERE candidate_id=?",
            (str(proof.candidate_id),),
        ).fetchall()
        proofs = tuple(FindingDuplicateCheck.model_validate_json(row["proof_json"]) for row in rows)
        latest_at = max(item.checked_at for item in proofs)
        latest = tuple(item for item in proofs if item.checked_at == latest_at)
        if len(latest) != 1 or latest[0].check_id != check_id:
            raise FindingDuplicateCheckConflict(
                "Finding duplicate check is stale or has a conflicting successor"
            )
        return proof

    def close(self) -> None:
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
