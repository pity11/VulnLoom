"""Provider-neutral, observation-driven Source Hunt investigation loop."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, Self

from pydantic import model_validator

from vulnloom.domain.models import DomainModel, Scope
from vulnloom.hypotheses import CandidateSet

from .adapters import SourceContextReader
from .candidate import SourceCandidateProposal, SourceCandidateService
from .models import (
    InvestigationCheckpoint,
    InvestigationObservation,
    InvestigationPlan,
    InvestigationQuery,
    InvestigationStatus,
    RepositoryIndex,
)
from .service import SourceHuntService


class InvestigationDecisionKind(StrEnum):
    QUERY = "query"
    PROPOSE = "propose"
    ABANDON = "abandon"


class InvestigationTurn(DomainModel):
    plan_id: str
    index_id: str
    revision: int
    queries_remaining: int
    observations: tuple[InvestigationObservation, ...]


class InvestigationDecision(DomainModel):
    kind: InvestigationDecisionKind
    query: InvestigationQuery | None = None
    proposal: SourceCandidateProposal | None = None
    reason_code: str | None = None

    @model_validator(mode="after")
    def exact_payload(self) -> Self:
        if self.kind is InvestigationDecisionKind.QUERY:
            valid = self.query is not None and self.proposal is None and self.reason_code is None
        elif self.kind is InvestigationDecisionKind.PROPOSE:
            valid = self.query is None and self.proposal is not None and self.reason_code is None
        else:
            valid = (
                self.query is None
                and self.proposal is None
                and self.reason_code == "insufficient_evidence"
            )
        if not valid:
            raise ValueError("InvestigationDecision payload does not match its kind")
        return self


class SourceInvestigator(Protocol):
    """Trusted adapter interface; provider credentials stay behind its implementation."""

    def decide(self, turn: InvestigationTurn) -> InvestigationDecision: ...


class SourceHuntAgentRejected(ValueError):
    pass


class SourceHuntAgentOutcome(DomainModel):
    plan_id: str
    checkpoint: InvestigationCheckpoint
    candidate_set: CandidateSet | None = None


class SourceHuntAgentService:
    def __init__(
        self,
        *,
        investigation_service: SourceHuntService,
        candidate_service: SourceCandidateService,
        investigator: SourceInvestigator,
        source_reader: SourceContextReader | None = None,
    ):
        self.investigation_service = investigation_service
        self.candidate_service = candidate_service
        self.investigator = investigator
        self.source_reader = source_reader

    def run(
        self,
        *,
        plan: InvestigationPlan,
        index: RepositoryIndex,
        scope: Scope,
        now,
    ) -> SourceHuntAgentOutcome:
        checkpoint = self.investigation_service.store.latest(plan.plan_id)
        while checkpoint.status is InvestigationStatus.ACTIVE:
            observations = tuple(
                self.investigation_service.store.observation(plan.plan_id, digest)
                for digest in checkpoint.query_digests
            )
            turn = InvestigationTurn(
                plan_id=plan.plan_id,
                index_id=index.index_id,
                revision=checkpoint.revision,
                queries_remaining=plan.limits.max_queries - checkpoint.queries_used,
                observations=observations,
            )
            try:
                decision = InvestigationDecision.model_validate(
                    self.investigator.decide(turn).model_dump(mode="python")
                )
            except Exception as exc:
                raise SourceHuntAgentRejected(
                    "Source investigator returned an invalid typed decision"
                ) from exc
            if decision.kind is InvestigationDecisionKind.QUERY:
                assert decision.query is not None
                checkpoint, _ = self.investigation_service.query(
                    plan=plan,
                    index=index,
                    checkpoint=checkpoint,
                    query=decision.query,
                    scope=scope,
                    now=now,
                    source_reader=self.source_reader,
                )
                continue
            if decision.kind is InvestigationDecisionKind.ABANDON:
                checkpoint = self.investigation_service.cancel(
                    plan=plan,
                    index=index,
                    checkpoint=checkpoint,
                    scope=scope,
                    now=now,
                )
                return SourceHuntAgentOutcome(plan_id=plan.plan_id, checkpoint=checkpoint)
            assert decision.proposal is not None
            checkpoint = self.investigation_service.complete(
                plan=plan,
                index=index,
                checkpoint=checkpoint,
                conclusion_digest=decision.proposal.proposal_id,
                scope=scope,
                now=now,
            )
            candidate_set = self.candidate_service.materialize(
                proposal=decision.proposal,
                investigation=checkpoint,
                index=index,
                scope=scope,
                now=now,
            )
            return SourceHuntAgentOutcome(
                plan_id=plan.plan_id,
                checkpoint=checkpoint,
                candidate_set=candidate_set,
            )
        raise SourceHuntAgentRejected("Source Hunt Agent cannot resume a terminal investigation")
