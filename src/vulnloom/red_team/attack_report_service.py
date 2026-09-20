"""Deterministic Attack Path Report projection over authoritative chain Evidence."""

from __future__ import annotations

from datetime import datetime

from vulnloom.domain.models import Scope, ScopeState
from vulnloom.evidence import EvidenceStore

from .attack_models import AttackChainStatus, AttackNodeStatus
from .attack_report_models import (
    CONTROL_FOR_DETECTION,
    DETECTION_FOR_ACTION,
    AttackChainReport,
    AttackChainReportArtifact,
    AttackChainReportOutcome,
    AttackChainReportPlan,
    AttackDefensiveImprovement,
    AttackDetectionOpportunity,
    AttackPathStep,
    AttackReportState,
)
from .attack_report_store import (
    AttackChainReportArtifactStore,
    AttackChainReportStore,
)
from .attack_store import AttackChainStore


class AttackChainReportRejected(ValueError):
    pass


class AttackChainReportService:
    def __init__(
        self,
        *,
        chain_store: AttackChainStore,
        report_store: AttackChainReportStore,
        artifact_store: AttackChainReportArtifactStore,
        evidence_store: EvidenceStore,
    ) -> None:
        self.chain_store = chain_store
        self.report_store = report_store
        self.artifact_store = artifact_store
        self.evidence_store = evidence_store

    def prepare(
        self,
        *,
        chain_plan_id: str,
        scope: Scope,
        prepared_by: str,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> AttackChainReportPlan:
        chain_plan, checkpoint = self._source(chain_plan_id, scope=scope, now=now)
        if deadline <= now or deadline > scope.valid_until:
            raise AttackChainReportRejected("Attack Path Report deadline is invalid")
        return AttackChainReportPlan.create(
            chain_plan_id=chain_plan.chain_plan_id,
            graph_id=chain_plan.graph.graph_id,
            source_checkpoint_id=checkpoint.checkpoint_id,
            target_id=chain_plan.graph.target_id,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            prepared_by=prepared_by,
            created_at=now,
            deadline=deadline,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        plan: AttackChainReportPlan,
        *,
        scope: Scope,
        now: datetime,
        recover: bool = False,
    ) -> AttackChainReportOutcome:
        plan = AttackChainReportPlan.model_validate(plan.model_dump(mode="python"))
        chain_plan, checkpoint = self._source(plan.chain_plan_id, scope=scope, now=now)
        if (
            now < plan.created_at
            or plan.graph_id != chain_plan.graph.graph_id
            or plan.source_checkpoint_id != checkpoint.checkpoint_id
            or plan.target_id != chain_plan.graph.target_id
            or plan.scope_id != scope.scope_id
            or plan.scope_version != scope.version
        ):
            raise AttackChainReportRejected("Attack Path Report provenance drifted")
        if now >= plan.deadline:
            claim = (
                self.report_store.recover(plan, now=now)
                if recover
                else self.report_store.claim(plan, now=now)
            )
            if not claim.created:
                assert claim.outcome is not None
                return claim.outcome
            return self._terminal(
                plan,
                attempt=claim.attempt,
                state=AttackReportState.TIMED_OUT,
                reason_code="attack_report_deadline_elapsed",
                now=now,
            )
        steps = []
        opportunities = []
        for action, node in zip(chain_plan.graph.actions, checkpoint.nodes, strict=True):
            if (
                node.action_id != action.action_id
                or node.status is not AttackNodeStatus.SUCCEEDED
                or node.observation_id is None
            ):
                raise AttackChainReportRejected("Attack Path Report source path is incomplete")
            observation = self.chain_store.observation(node.observation_id)
            if (
                observation.action_id != action.action_id
                or not observation.evidence_refs
                or not all(self.evidence_store.contains(ref) for ref in observation.evidence_refs)
            ):
                raise AttackChainReportRejected(
                    "Attack Path Report Evidence is unavailable or corrupt"
                )
            # Force bounded no-follow reads before claiming the report checkpoint.
            for ref in observation.evidence_refs:
                self.evidence_store.read_text_ref(ref)
            step = AttackPathStep.create(
                ordinal=action.ordinal,
                action_id=action.action_id,
                kind=action.kind,
                phase=action.phase,
                impact=action.impact,
                outcome=observation.outcome,
                observation_id=observation.observation_id,
                evidence_refs=observation.evidence_refs,
            )
            opportunity = AttackDetectionOpportunity.create(
                action_id=action.action_id,
                kind=DETECTION_FOR_ACTION[action.kind],
                evidence_refs=observation.evidence_refs,
            )
            steps.append(step)
            opportunities.append(opportunity)
        improvements = tuple(
            AttackDefensiveImprovement.create(
                control=CONTROL_FOR_DETECTION[item.kind],
                opportunity_ids=(item.opportunity_id,),
            )
            for item in opportunities
        )
        report = AttackChainReport.create(
            report_plan_id=plan.report_plan_id,
            chain_plan_id=chain_plan.chain_plan_id,
            graph_id=chain_plan.graph.graph_id,
            source_checkpoint_id=checkpoint.checkpoint_id,
            target_id=chain_plan.graph.target_id,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            chain_status=checkpoint.status,
            objective_observation_id=checkpoint.objective_observation_id,
            steps=tuple(steps),
            detection_opportunities=tuple(opportunities),
            defensive_improvements=improvements,
            evidence_refs=tuple(sorted({ref for item in steps for ref in item.evidence_refs})),
            generated_at=plan.created_at,
        )
        claim = (
            self.report_store.recover(plan, now=now)
            if recover
            else self.report_store.claim(plan, now=now)
        )
        if not claim.created:
            assert claim.outcome is not None
            return claim.outcome
        artifact = self.artifact_store.put(report)
        return self._terminal(
            plan,
            attempt=claim.attempt,
            state=AttackReportState.COMPLETED,
            reason_code="attack_path_report_completed",
            now=now,
            report=report,
            artifact=artifact,
        )

    def _source(self, chain_plan_id: str, *, scope: Scope, now: datetime):
        try:
            chain_plan = self.chain_store.plan(chain_plan_id)
            checkpoint = self.chain_store.latest(chain_plan_id)
        except (ValueError, RuntimeError) as exc:
            raise AttackChainReportRejected("Attack Path Report source is unavailable") from exc
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or chain_plan.graph.scope_id != scope.scope_id
            or chain_plan.graph.scope_version != scope.version
            or checkpoint.status is not AttackChainStatus.GOAL_REACHED
            or checkpoint.objective_observation_id is None
            or checkpoint.stop_reason != "objective_evidence_and_cleanup_recorded"
        ):
            raise AttackChainReportRejected(
                "Attack Path Report requires a successful cleaned authoritative chain"
            )
        return chain_plan, checkpoint

    def _terminal(
        self,
        plan: AttackChainReportPlan,
        *,
        attempt: int,
        state: AttackReportState,
        reason_code: str,
        now: datetime,
        report: AttackChainReport | None = None,
        artifact: AttackChainReportArtifact | None = None,
    ) -> AttackChainReportOutcome:
        outcome = AttackChainReportOutcome(
            report_plan_id=plan.report_plan_id,
            state=state,
            attempt=attempt,
            chain_plan_id=plan.chain_plan_id,
            report=report,
            artifact=artifact,
            reason_code=reason_code,
            cleanup_complete=True,
            completed_at=now,
        )
        self.report_store.finish(outcome)
        return outcome
