"""Content-addressed output of the static hypothesis stage."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Self
from uuid import UUID

from pydantic import Field, model_validator

from vulnloom.domain.models import Candidate, CandidateState, DomainModel


class CandidateSet(DomainModel):
    candidate_set_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_graph_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_id: UUID
    target_version: str = Field(min_length=1)
    scope_id: UUID
    scope_version: int = Field(ge=1)
    generator_version: str = Field(min_length=1)
    candidates: tuple[Candidate, ...]
    excluded_signal_ids: tuple[Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")], ...] = ()

    @model_validator(mode="after")
    def candidates_match_container(self) -> Self:
        candidate_ids = set()
        fingerprints = set()
        referenced_signals = set()
        for candidate in self.candidates:
            if (
                candidate.target_id != self.target_id
                or candidate.target_version != self.target_version
                or candidate.source_graph_id != self.source_graph_id
                or candidate.scope_id != self.scope_id
                or candidate.scope_version != self.scope_version
            ):
                raise ValueError("Candidate does not match its CandidateSet provenance")
            if candidate.state is not CandidateState.PROPOSED:
                raise ValueError("CandidateSet can contain only proposed Candidates")
            if candidate.candidate_id in candidate_ids:
                raise ValueError("CandidateSet contains a duplicate Candidate id")
            if candidate.duplicate_fingerprint in fingerprints:
                raise ValueError("CandidateSet contains an unmerged duplicate fingerprint")
            candidate_ids.add(candidate.candidate_id)
            fingerprints.add(candidate.duplicate_fingerprint)
            referenced_signals.update(candidate.signal_ids)
        if referenced_signals.intersection(self.excluded_signal_ids):
            raise ValueError("CandidateSet cannot both reference and exclude a StaticSignal")
        return self


def candidate_set_digest(candidate_set: CandidateSet) -> str:
    payload = candidate_set.model_dump(mode="json", exclude={"candidate_set_id"})
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()
