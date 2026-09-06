"""Digest-only contracts for one human Candidate selection after pilot readiness."""

from __future__ import annotations

from typing import Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .models import Digest


class PilotCandidateSelectionCommand(DomainModel):
    command_id: Digest
    readiness_plan_id: Digest
    readiness_result_id: Digest
    readiness_result_digest: Digest
    readiness_artifact_digest: Digest
    pilot_manifest_id: Digest
    candidate_set_id: Digest
    candidate_set_digest: Digest
    candidate_id: UUID
    candidate_digest: Digest
    source_graph_id: Digest
    source_graph_digest: Digest
    target_manifest_id: Digest
    target_id: UUID
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    scope_digest: Digest
    reviewer: str = Field(min_length=1, max_length=256)
    decided_at: AwareDatetime
    expires_at: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.decided_at < self.expires_at:
            raise ValueError("pilot Candidate selection window is invalid")
        if "\x00" in self.reviewer or "\x00" in self.idempotency_key:
            raise ValueError("pilot Candidate selection text contains NUL")
        if self.command_id != pilot_candidate_selection_command_digest(self):
            raise ValueError("pilot Candidate selection command content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> PilotCandidateSelectionCommand:
        return cls(command_id=canonical_digest(values), **values)


def pilot_candidate_selection_command_digest(command: PilotCandidateSelectionCommand) -> str:
    return canonical_digest(command.model_dump(mode="python", exclude={"command_id"}))


class PilotCandidateSelectionRecord(DomainModel):
    record_id: Digest
    command_id: Digest
    readiness_plan_id: Digest
    readiness_result_id: Digest
    pilot_manifest_id: Digest
    candidate_set_id: Digest
    candidate_id: UUID
    candidate_digest: Digest
    target_id: UUID
    target_version_digest: Digest
    scope_id: UUID
    scope_version: int = Field(ge=1)
    reviewer: str = Field(min_length=1, max_length=256)
    decided_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if not self.decided_at < self.expires_at:
            raise ValueError("pilot Candidate selection record is expired")
        if self.record_id != pilot_candidate_selection_record_digest(self):
            raise ValueError("pilot Candidate selection record content digest mismatch")
        return self


def pilot_candidate_selection_record_digest(record: PilotCandidateSelectionRecord) -> str:
    return canonical_digest(record.model_dump(mode="python", exclude={"record_id"}))
