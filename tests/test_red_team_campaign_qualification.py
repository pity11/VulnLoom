from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import ScopeState
from vulnloom.red_team.adaptive_qualification_models import (
    AdaptiveCoverageLedger,
    AdaptiveFlowQualificationOutcome,
    AdaptiveFlowQualificationPlan,
    AdaptiveQualificationLimits,
    AdaptiveRoundCoverage,
)
from vulnloom.red_team.adaptive_runtime_models import (
    AdaptiveRuntimeQualificationLimits,
    AdaptiveRuntimeQualificationOutcome,
    AdaptiveRuntimeQualificationPlan,
    RuntimeAssuranceLevel,
)
from vulnloom.red_team.campaign_models import (
    CampaignBudget,
    CampaignGoal,
    CampaignGoalKind,
    CampaignPhase,
    CampaignPhaseKind,
    CampaignQualificationLimits,
    CampaignQualificationState,
    CampaignStopConditions,
    GoalDrivenCampaignPlan,
)
from vulnloom.red_team.campaign_service import (
    CampaignFlowQualificationSource,
    CampaignQualificationRejected,
    CampaignQualificationTimedOut,
    GoalDrivenCampaignQualificationService,
)
from vulnloom.red_team.campaign_store import (
    CampaignQualificationRecoveryRequired,
    CampaignQualificationStore,
    CampaignQualificationStoreRejected,
)
from vulnloom.red_team.models import ReconOutcome, RedTeamActionKind
from vulnloom.workflows import AutonomyLevel

IMAGE = "sha256:" + "1" * 64
_CONNECTIONS: list[sqlite3.Connection] = []


@pytest.fixture(autouse=True)
def _close_campaign_connections():
    yield
    while _CONNECTIONS:
        _CONNECTIONS.pop().close()


def _store():
    connection = sqlite3.connect(":memory:")
    _CONNECTIONS.append(connection)
    return CampaignQualificationStore(connection)


def _flow_source(scope, now, *, seed, assurance=RuntimeAssuranceLevel.LOCAL_DOCKER):
    flow_id = f"{1_000 + seed:064x}"
    target_id = uuid4()
    rounds = tuple(
        AdaptiveRoundCoverage.create(
            ordinal=index,
            execution_receipt_id=f"{seed * 100 + 10 + index:064x}",
            admission_id=f"{seed * 100 + 20 + index:064x}",
            source_checkpoint_id=f"{seed * 100 + 30 + index:064x}",
            result_checkpoint_id=f"{seed * 100 + 40 + index:064x}",
            source_observation_ids=(f"{seed * 100 + 50 + index:064x}",),
            produced_observation_id=f"{seed * 100 + 60 + index:064x}",
            action_id=f"{seed * 100 + 70 + index:064x}",
            action_kind=(
                RedTeamActionKind.HTTP_HEAD
                if index == 1
                else RedTeamActionKind.TLS_INSPECT
            ),
            test_class="read_only",
            outcome=ReconOutcome.SUCCEEDED,
        )
        for index in (1, 2)
    )
    ledger = AdaptiveCoverageLedger.create(
        flow_plan_id=flow_id,
        final_checkpoint_id=f"{seed * 100 + 80:064x}",
        rounds=rounds,
        covered_action_kinds=tuple(
            sorted({item.action_kind for item in rounds}, key=str)
        ),
        covered_test_classes=("read_only",),
        source_observation_count=1,
        produced_observation_count=2,
    )
    adaptive_plan = AdaptiveFlowQualificationPlan.create(
        flow_plan_id=flow_id,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        target_id=target_id,
        target_url_digest=f"{seed * 100 + 81:064x}",
        final_checkpoint_id=ledger.final_checkpoint_id,
        replan_execution_receipt_ids=(
            f"{seed * 100 + 82:064x}",
            f"{seed * 100 + 83:064x}",
        ),
        limits=AdaptiveQualificationLimits(),
        created_at=now - timedelta(minutes=5),
        deadline=now + timedelta(minutes=5),
        idempotency_key=f"campaign-adaptive:{seed}",
    )
    adaptive_outcome = AdaptiveFlowQualificationOutcome.create(
        plan_id=adaptive_plan.plan_id,
        flow_plan_id=flow_id,
        coverage_ledger=ledger,
        attempt=1,
        completed_at=now - timedelta(minutes=4),
    )
    runtime_plan = AdaptiveRuntimeQualificationPlan.create(
        adaptive_plan_id=adaptive_plan.plan_id,
        adaptive_outcome_id=adaptive_outcome.outcome_id,
        adaptive_outcome_digest=canonical_digest(
            adaptive_outcome.model_dump(mode="python")
        ),
        flow_plan_id=flow_id,
        coverage_ledger_id=ledger.ledger_id,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        image_digest=IMAGE,
        sandbox_profile_digest=f"{seed * 100 + 84:064x}",
        hostile_worker_plan_id=f"{seed * 100 + 85:064x}",
        hostile_worker_outcome_id=f"{seed * 100 + 86:064x}",
        hostile_worker_outcome_digest=f"{seed * 100 + 87:064x}",
        resource_pressure_plan_id=f"{seed * 100 + 88:064x}",
        resource_pressure_outcome_id=f"{seed * 100 + 89:064x}",
        resource_pressure_outcome_digest=f"{seed * 100 + 90:064x}",
        limits=AdaptiveRuntimeQualificationLimits(),
        created_at=now - timedelta(minutes=3),
        deadline=now + timedelta(minutes=3),
        idempotency_key=f"campaign-runtime:{seed}",
    )
    runtime_outcome = AdaptiveRuntimeQualificationOutcome.create(
        plan_id=runtime_plan.plan_id,
        adaptive_outcome_id=adaptive_outcome.outcome_id,
        flow_plan_id=flow_id,
        coverage_ledger_id=ledger.ledger_id,
        probe_observation_ids=(
            f"{seed * 100 + 91:064x}",
            f"{seed * 100 + 92:064x}",
        ),
        assurance_level=assurance,
        attempt=1,
        completed_at=now - timedelta(minutes=2),
        production_runner_admitted=(
            assurance is RuntimeAssuranceLevel.ROOTLESS_PRODUCTION
        ),
    )
    return CampaignFlowQualificationSource(
        adaptive_plan=adaptive_plan,
        adaptive_outcome=adaptive_outcome,
        runtime_plan=runtime_plan,
        runtime_outcome=runtime_outcome,
    )


def _phases():
    phases = []
    previous = None
    for ordinal, kind in enumerate(CampaignPhaseKind, start=1):
        phase = CampaignPhase.create(
            ordinal=ordinal,
            kind=kind,
            prerequisite_phase_ids=(() if previous is None else (previous.phase_id,)),
            max_flow_materializations=1,
            max_actions=2,
            wall_seconds=60,
        )
        phases.append(phase)
        previous = phase
    return tuple(phases)


def _runtime(approved_scope, now, *, assurances=None):
    assurances = assurances or (
        RuntimeAssuranceLevel.LOCAL_DOCKER,
        RuntimeAssuranceLevel.LOCAL_DOCKER,
    )
    sources = tuple(
        _flow_source(approved_scope, now, seed=index, assurance=assurance)
        for index, assurance in enumerate(assurances, start=1)
    )
    service = GoalDrivenCampaignQualificationService(
        store=_store()
    )
    goal = CampaignGoal.create(
        kind=CampaignGoalKind.EVIDENCE_REQUIREMENT_SATISFACTION,
        statement_digest=canonical_digest("verify bounded authorized evidence"),
        required_evidence_classes=("critic_review", "independent_validation"),
    )
    plan = service.prepare(
        goal=goal,
        sources=sources,
        phases=_phases(),
        budget=CampaignBudget(
            max_flow_materializations=12,
            max_actions=24,
            wall_seconds=600,
            max_consecutive_failures=2,
        ),
        stop_conditions=CampaignStopConditions(),
        scope=approved_scope,
        limits=CampaignQualificationLimits(),
        now=now,
        deadline=now + timedelta(minutes=5),
        idempotency_key="goal-driven-campaign",
    )
    return service, plan, sources


def test_two_bound_a3_runtime_flows_qualify_a4_without_starting_campaign(
    approved_scope, now
):
    service, plan, sources = _runtime(approved_scope, now)
    outcome = service.execute(plan, sources=sources, scope=approved_scope, now=now)
    replay = service.execute(
        plan,
        sources=tuple(reversed(sources)),
        scope=approved_scope,
        now=now + timedelta(seconds=1),
    )

    assert replay == outcome
    assert outcome.qualified_autonomy is AutonomyLevel.GOAL_DRIVEN_CAMPAIGN
    assert outcome.qualified is True
    assert outcome.campaign_started is False
    assert outcome.execution_authority_granted is False
    assert outcome.dynamic_target_expansion_granted is False
    assert outcome.credential_access_granted is False
    assert outcome.submission_granted is False
    assert outcome.candidate_created is False
    assert outcome.finding_created is False
    assert len(outcome.flow_binding_ids) == 2
    assert len(outcome.target_ids) == 2
    assert service.store.state(plan.campaign_plan_id) == (
        CampaignQualificationState.COMPLETED,
        1,
    )


def test_campaign_requires_multiple_unique_authoritative_a3_runtime_flows(
    approved_scope, now
):
    source = _flow_source(approved_scope, now, seed=1)
    service = GoalDrivenCampaignQualificationService(
        store=_store()
    )
    with pytest.raises(CampaignQualificationRejected, match="could not be sealed"):
        service.prepare(
            goal=CampaignGoal.create(
                kind=CampaignGoalKind.COVERAGE_COMPLETION,
                statement_digest="a" * 64,
                required_evidence_classes=("coverage_ledger",),
            ),
            sources=(source,),
            phases=_phases(),
            budget=CampaignBudget(
                max_flow_materializations=12,
                max_actions=24,
                wall_seconds=600,
                max_consecutive_failures=2,
            ),
            stop_conditions=CampaignStopConditions(),
            scope=approved_scope,
            limits=CampaignQualificationLimits(),
            now=now,
            deadline=now + timedelta(minutes=5),
            idempotency_key="single-flow",
        )
    with pytest.raises(CampaignQualificationRejected, match="could not be sealed"):
        service.prepare(
            goal=CampaignGoal.create(
                kind=CampaignGoalKind.COVERAGE_COMPLETION,
                statement_digest="b" * 64,
                required_evidence_classes=("coverage_ledger",),
            ),
            sources=(source, source),
            phases=_phases(),
            budget=CampaignBudget(
                max_flow_materializations=12,
                max_actions=24,
                wall_seconds=600,
                max_consecutive_failures=2,
            ),
            stop_conditions=CampaignStopConditions(),
            scope=approved_scope,
            limits=CampaignQualificationLimits(),
            now=now,
            deadline=now + timedelta(minutes=5),
            idempotency_key="duplicate-flow",
        )
    assert service.store.connection.execute(
        "SELECT COUNT(*) FROM red_team_campaign_qualifications"
    ).fetchone()[0] == 0


def test_scope_revocation_or_runtime_provenance_drift_fails_before_checkpoint(
    approved_scope, now
):
    service, plan, sources = _runtime(approved_scope, now)
    revoked = approved_scope.model_copy(update={"state": ScopeState.REVOKED})
    with pytest.raises(CampaignQualificationRejected, match="current approved Scope"):
        service.execute(plan, sources=sources, scope=revoked, now=now)

    drifted_outcome = sources[0].runtime_outcome.model_copy(
        update={"flow_plan_id": "f" * 64}
    )
    drifted = replace(sources[0], runtime_outcome=drifted_outcome)
    with pytest.raises(CampaignQualificationRejected, match="source is invalid"):
        service.execute(
            plan,
            sources=(drifted, sources[1]),
            scope=approved_scope,
            now=now,
        )
    assert service.store.state(plan.campaign_plan_id) is None


def test_phase_graph_budget_and_authority_escalation_are_rejected(
    approved_scope, now
):
    _, plan, _ = _runtime(approved_scope, now)
    raw = plan.model_dump(mode="python")
    raw["execution_authority_requested"] = True
    raw["campaign_plan_id"] = "0" * 64
    with pytest.raises(ValidationError):
        GoalDrivenCampaignPlan.model_validate(raw)

    raw = plan.model_dump(mode="python")
    phases = list(raw["phases"])
    phases[2] = CampaignPhase.create(
        ordinal=raw["phases"][2]["ordinal"],
        kind=raw["phases"][2]["kind"],
        prerequisite_phase_ids=(),
        max_flow_materializations=raw["phases"][2]["max_flow_materializations"],
        max_actions=raw["phases"][2]["max_actions"],
        wall_seconds=raw["phases"][2]["wall_seconds"],
    ).model_dump(mode="python")
    raw["phases"] = tuple(phases)
    raw["campaign_plan_id"] = "0" * 64
    with pytest.raises(ValidationError, match="topology"):
        GoalDrivenCampaignPlan.model_validate(raw)

    raw = plan.model_dump(mode="python")
    raw["budget"]["max_actions"] = 6
    raw["campaign_plan_id"] = "0" * 64
    with pytest.raises(ValidationError, match="budget"):
        GoalDrivenCampaignPlan.model_validate(raw)


def test_mixed_runtime_assurance_reduces_to_lowest_campaign_assurance(
    approved_scope, now
):
    service, plan, sources = _runtime(
        approved_scope,
        now,
        assurances=(
            RuntimeAssuranceLevel.ROOTLESS_PRODUCTION,
            RuntimeAssuranceLevel.LOCAL_DOCKER,
        ),
    )
    outcome = service.execute(plan, sources=sources, scope=approved_scope, now=now)
    assert outcome.minimum_assurance_level is RuntimeAssuranceLevel.LOCAL_DOCKER


def test_timeout_keeps_started_and_recovery_is_bounded(approved_scope, now):
    service, plan, sources = _runtime(approved_scope, now)
    ticks = iter((0.0, 100.0, 0.0, 100.0, 0.0, 100.0))
    service.monotonic = lambda: next(ticks)
    with pytest.raises(CampaignQualificationTimedOut):
        service.execute(plan, sources=sources, scope=approved_scope, now=now)
    for offset in (1, 2):
        with pytest.raises(CampaignQualificationTimedOut):
            service.recover(
                plan,
                sources=sources,
                scope=approved_scope,
                now=now + timedelta(seconds=offset),
            )
    with pytest.raises(CampaignQualificationRecoveryRequired, match="exhausted"):
        service.recover(
            plan,
            sources=sources,
            scope=approved_scope,
            now=now + timedelta(seconds=3),
        )
    assert service.store.state(plan.campaign_plan_id) == (
        CampaignQualificationState.STARTED,
        3,
    )


def test_campaign_idempotency_key_reuse_with_different_content_is_rejected(
    approved_scope, now
):
    service, plan, sources = _runtime(approved_scope, now)
    original = service.execute(plan, sources=sources, scope=approved_scope, now=now)
    conflict = service.prepare(
        goal=CampaignGoal.create(
            kind=CampaignGoalKind.COVERAGE_COMPLETION,
            statement_digest="c" * 64,
            required_evidence_classes=("coverage_ledger",),
        ),
        sources=sources,
        phases=_phases(),
        budget=plan.budget,
        stop_conditions=plan.stop_conditions,
        scope=approved_scope,
        limits=plan.limits,
        now=now,
        deadline=plan.deadline,
        idempotency_key=plan.idempotency_key,
    )

    with pytest.raises(CampaignQualificationStoreRejected, match="different content"):
        service.execute(conflict, sources=sources, scope=approved_scope, now=now)
    assert service.execute(plan, sources=sources, scope=approved_scope, now=now) == original
    assert service.store.state(conflict.campaign_plan_id) is None


def test_campaign_ledger_and_schema_exclude_targets_secrets_and_execution_fields(
    approved_scope, now
):
    service, plan, sources = _runtime(approved_scope, now)
    service.execute(plan, sources=sources, scope=approved_scope, now=now)
    row = service.store.connection.execute(
        "SELECT plan_json,outcome_json FROM red_team_campaign_qualifications"
    ).fetchone()
    serialized = "".join(row).lower()
    schema = json.dumps(GoalDrivenCampaignPlan.model_json_schema()).lower()
    for forbidden in (
        "target_url",
        "hostname",
        "password",
        "cookie",
        "credential_value",
        "provider_token",
        "docker_socket",
        "submission_token",
        "payload",
        "command",
    ):
        assert forbidden not in serialized
        assert forbidden not in schema
