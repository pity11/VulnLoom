"""Trusted conversion of a completed investigation into proposed Candidates only."""

from __future__ import annotations

from typing import Annotated, Self
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Candidate, DomainModel, Scope, ScopeState
from vulnloom.hypotheses.models import CandidateSet, candidate_set_digest

from .models import (
    Digest,
    InvestigationCheckpoint,
    InvestigationStatus,
    RepositoryIndex,
)
from .store import SourceHuntStore


class SourceCandidateRejected(ValueError):
    pass


class SourceCandidateProposal(DomainModel):
    proposal_id: Digest
    entry_symbol_id: Digest
    sink_symbol_id: Digest
    code_path_symbol_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=128)]
    observation_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=64)]
    cwe: str = Field(pattern=r"^CWE-[1-9][0-9]*$")
    title: str = Field(min_length=1, max_length=512)
    preconditions: tuple[str, ...] = ()
    security_invariant: str = Field(min_length=1, max_length=8_192)
    hypothesis: str = Field(min_length=1, max_length=8_192)
    cheapest_disproof: str = Field(min_length=1, max_length=8_192)
    confidence: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if len(set(self.code_path_symbol_ids)) != len(self.code_path_symbol_ids):
            raise ValueError("Source Candidate code path contains duplicate symbols")
        if len(set(self.observation_ids)) != len(self.observation_ids):
            raise ValueError("Source Candidate observations must be unique")
        if self.proposal_id != canonical_digest(
            self.model_dump(mode="python", exclude={"proposal_id"})
        ):
            raise ValueError("SourceCandidateProposal content digest mismatch")
        return self

    @classmethod
    def create(cls, **values: object) -> SourceCandidateProposal:
        complete = {"preconditions": (), **values}
        return cls(proposal_id=canonical_digest(complete), **complete)


class SourceCandidateService:
    version = "source-hunt-observation-candidate-v1"

    def __init__(self, *, investigation_store: SourceHuntStore):
        self.investigation_store = investigation_store

    def materialize(
        self,
        *,
        proposal: SourceCandidateProposal,
        investigation: InvestigationCheckpoint,
        index: RepositoryIndex,
        scope: Scope,
        now,
    ) -> CandidateSet:
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or index.scope_id != scope.scope_id
            or index.scope_version != scope.version
            or investigation.index_id != index.index_id
            or investigation.status is not InvestigationStatus.READY_FOR_CANDIDATES
            or investigation.conclusion_digest != proposal.proposal_id
        ):
            raise SourceCandidateRejected("Source Candidate provenance or Scope is invalid")
        if not set(proposal.observation_ids) <= set(investigation.observation_ids):
            raise SourceCandidateRejected("Source Candidate cites an unavailable observation")
        observed_symbols = set()
        for query_digest in investigation.query_digests:
            observation = self.investigation_store.observation(
                investigation.plan_id, query_digest
            )
            if observation.observation_id in proposal.observation_ids:
                observed_symbols.update(item.symbol_id for item in observation.matched_symbols)
                observed_symbols.update(
                    item.resolved_symbol_id
                    for item in observation.matched_references
                    if item.resolved_symbol_id is not None
                )
        requested = {
            proposal.entry_symbol_id,
            proposal.sink_symbol_id,
            *proposal.code_path_symbol_ids,
        }
        if not requested <= observed_symbols:
            raise SourceCandidateRejected(
                "Source Candidate contains a symbol not returned by cited observations"
            )
        symbols = {item.symbol_id: item for item in index.symbols}
        if not requested <= set(symbols):
            raise SourceCandidateRejected("Source Candidate symbol is absent from the index")
        entry = symbols[proposal.entry_symbol_id].location
        sink = symbols[proposal.sink_symbol_id].location
        path = tuple(symbols[item].location for item in proposal.code_path_symbol_ids)
        fingerprint = canonical_digest(
            {
                "cwe": proposal.cwe,
                "entry": entry.model_dump(mode="python"),
                "sink": sink.model_dump(mode="python"),
                "path": tuple(item.model_dump(mode="python") for item in path),
            }
        )
        candidate = Candidate(
            candidate_id=uuid5(
                NAMESPACE_URL,
                f"vulnloom:source-candidate:{index.index_id}:{proposal.proposal_id}",
            ),
            target_id=index.target_id,
            target_version=index.target_version,
            source_graph_id=index.index_id,
            scope_id=index.scope_id,
            scope_version=index.scope_version,
            title=proposal.title,
            cwe=proposal.cwe,
            entry_point=entry,
            sink=sink,
            code_path=path,
            preconditions=proposal.preconditions,
            security_invariant=proposal.security_invariant,
            hypothesis=proposal.hypothesis,
            signal_ids=proposal.observation_ids,
            cheapest_disproof=proposal.cheapest_disproof,
            duplicate_fingerprint=fingerprint,
            confidence=proposal.confidence,
        )
        partial = CandidateSet(
            candidate_set_id="0" * 64,
            source_graph_id=index.index_id,
            target_id=index.target_id,
            target_version=index.target_version,
            scope_id=index.scope_id,
            scope_version=index.scope_version,
            generator_version=self.version,
            candidates=(candidate,),
        )
        return partial.model_copy(
            update={"candidate_set_id": candidate_set_digest(partial)}
        )

