from __future__ import annotations

import hashlib
from datetime import timedelta
from uuid import uuid4

import pytest

from vulnloom.benchmark.pilot_readiness_fixture import PILOT_NOW, build_pilot_fixture
from vulnloom.cli import main
from vulnloom.critic import (
    CounterevidenceAngle,
    CounterevidenceAssessment,
    CounterevidenceDisposition,
    CriticPlan,
    CriticStore,
    DeterministicCritic,
    domain_object_digest,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalStatus,
    Artifact,
    ArtifactKind,
    Candidate,
    EvidenceKind,
    ReportChannel,
    ReportSection,
    ReportSectionKind,
    RepositoryScope,
    ScopeState,
    SnapshotFile,
    StaticFileCategory,
    Target,
    TargetKind,
    TargetManifest,
    TargetSnapshot,
)
from vulnloom.domain.protocol import TaskBudget, TaskEnvelope, WorkerRole
from vulnloom.evidence import EvidenceStore
from vulnloom.findings import DuplicateCheckResult, FindingDuplicateCheck
from vulnloom.policy import PolicyEngine
from vulnloom.reporting import (
    DeterministicReportService,
    ReportArtifactStore,
    ReportDraftPlan,
    ReportDraftStore,
)
from vulnloom.runners import (
    OfflineOutcome,
    OfflineSandboxRunner,
    OfflineScenario,
    SandboxRunRequest,
    ToolInvocation,
    sandbox_profile_digest,
)
from vulnloom.source_hunt import (
    SOURCE_FINDING_SIDE_EFFECTS,
    BuildSystem,
    InvestigationDecision,
    InvestigationDecisionKind,
    InvestigationQuery,
    InvestigationQueryKind,
    InvestigationStatus,
    SourceCandidateProposal,
    SourceCandidateRejected,
    SourceCandidateService,
    SourceExecutionPlan,
    SourceExecutionRejected,
    SourceExecutionService,
    SourceExecutionStage,
    SourceExecutionStatus,
    SourceExecutionStep,
    SourceExecutionStore,
    SourceExecutionValidationService,
    SourceFindingPromotionPlan,
    SourceFindingPromotionRejected,
    SourceFindingPromotionService,
    SourceFindingPromotionStore,
    SourceHuntAgentRejected,
    SourceHuntAgentService,
    SourceHuntLimits,
    SourceHuntRejected,
    SourceHuntService,
    SourceHuntStore,
    SourceHuntTimedOut,
    source_execution_approval_digest,
    source_execution_profile,
    source_finding_approval_digest,
)
from vulnloom.validation import candidate_content_digest


def _snapshot(tmp_path, scope, files):
    commit = "a" * 40
    repository_url = "https://example.test/source-hunt.git"
    scope = scope.model_copy(
        update={"repositories": (RepositoryScope(url=repository_url, commit=commit),)}
    )
    manifest_id = "b" * 64
    root = tmp_path / "objects" / "snapshots" / manifest_id
    root.mkdir(parents=True)
    entries = []
    for path, text in files.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        content = text.encode()
        entries.append(
            SnapshotFile(
                path=path,
                size=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
                category=StaticFileCategory.SOURCE,
            )
        )
    target = Target(
        target_id=uuid4(),
        engagement_id=scope.engagement_id,
        kind=TargetKind.REPOSITORY,
        source_ref=repository_url,
        version=commit,
    )
    artifact = Artifact(
        artifact_id="c" * 64,
        engagement_id=scope.engagement_id,
        kind=ArtifactKind.GIT_REPOSITORY,
        source_name="source-hunt",
        source_ref=repository_url,
        original_size=sum(item.size for item in entries),
        detected_format="git",
    )
    manifest = TargetManifest(
        manifest_id=manifest_id,
        artifact_id=artifact.artifact_id,
        target_id=target.target_id,
        target_version=commit,
        files=tuple(entries),
        total_size=sum(item.size for item in entries),
    )
    return (
        TargetSnapshot(
            target=target,
            artifact=artifact,
            manifest=manifest,
            root_ref=f"snapshots/{manifest_id}",
        ),
        scope,
        tmp_path / "objects",
    )


def _indexed(tmp_path, approved_scope, now, *, clock=None):
    snapshot, scope, root = _snapshot(
        tmp_path,
        approved_scope,
        {
            "api/routes.py": (
                "from core.service import load_user\n"
                "def route():\n    return load_user()\n"
            ),
            "core/service.py": (
                "def load_user():\n    return query_user()\n"
                "def query_user():\n    return 'Authorization: Bearer raw-secret'\n"
            ),
            "web/handler.ts": (
                "export function handler() { return lookupUser(); }\n"
                "export const lookupUser = (id) => database.find(id);\n"
            ),
            "package.json": "{}\n",
            "pyproject.toml": "[project]\nname='fixture'\n",
        },
    )
    store = SourceHuntStore(tmp_path / "source-hunt.sqlite3")
    service = SourceHuntService(
        store=store, **({"clock": clock} if clock else {})
    )
    index = service.index_repository(
        snapshot=snapshot,
        store_root=root,
        scope=scope,
        limits=SourceHuntLimits(max_files_per_partition=1),
        now=now,
    )
    return service, store, index, scope


def test_cross_language_index_and_observation_driven_resume(tmp_path, approved_scope, now):
    service, store, index, scope = _indexed(tmp_path, approved_scope, now)
    assert {BuildSystem.PYPROJECT, BuildSystem.NPM} <= set(index.build_systems)
    assert {item.location.path for item in index.symbols} >= {
        "api/routes.py",
        "core/service.py",
        "web/handler.ts",
    }
    assert len(index.partitions) == len(index.files_indexed)

    limits = SourceHuntLimits(max_queries=3, max_observations=3)
    plan, checkpoint = service.start(
        index=index,
        scope=scope,
        limits=limits,
        now=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="source-hunt:test:1",
    )
    plan_replay, checkpoint_replay = service.start(
        index=index,
        scope=scope,
        limits=limits,
        now=now + timedelta(seconds=1),
        deadline=now + timedelta(minutes=2),
        idempotency_key="source-hunt:test:1",
    )
    assert (plan_replay, checkpoint_replay) == (plan, checkpoint)

    query = InvestigationQuery(kind=InvestigationQueryKind.CALLERS, term="load_user")
    checkpoint, observation = service.query(
        plan=plan,
        index=index,
        checkpoint=checkpoint,
        query=query,
        scope=scope,
        now=now + timedelta(seconds=2),
    )
    assert observation.matched_references[0].location.path == "api/routes.py"
    replay_checkpoint, replay_observation = service.query(
        plan=plan,
        index=index,
        checkpoint=checkpoint,
        query=query,
        scope=scope,
        now=now + timedelta(seconds=3),
    )
    assert replay_checkpoint == checkpoint
    assert replay_observation == observation

    final = service.complete(
        plan=plan,
        index=index,
        checkpoint=checkpoint,
        conclusion_digest=canonical_digest({"candidate": "cross-file-call"}),
        scope=scope,
        now=now + timedelta(seconds=4),
    )
    assert final.status is InvestigationStatus.READY_FOR_CANDIDATES
    assert store.latest(plan.plan_id) == final
    persisted = (tmp_path / "source-hunt.sqlite3").read_bytes()
    assert b"raw-secret" not in persisted
    assert b"Authorization" not in persisted
    store.close()


def test_rejects_scope_drift_stale_checkpoint_and_completion_without_observation(
    tmp_path, approved_scope, now
):
    service, store, index, scope = _indexed(tmp_path, approved_scope, now)
    plan, checkpoint = service.start(
        index=index,
        scope=scope,
        limits=SourceHuntLimits(max_queries=2),
        now=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="source-hunt:test:reject",
    )
    with pytest.raises(SourceHuntRejected, match="without observations"):
        service.complete(
            plan=plan,
            index=index,
            checkpoint=checkpoint,
            conclusion_digest="d" * 64,
            scope=scope,
            now=now,
        )
    changed_scope = scope.model_copy(update={"version": scope.version + 1})
    with pytest.raises(SourceHuntRejected, match="binding"):
        service.query(
            plan=plan,
            index=index,
            checkpoint=checkpoint,
            query=InvestigationQuery(kind=InvestigationQueryKind.SYMBOL, term="route"),
            scope=changed_scope,
            now=now,
        )
    current, _ = service.query(
        plan=plan,
        index=index,
        checkpoint=checkpoint,
        query=InvestigationQuery(kind=InvestigationQueryKind.SYMBOL, term="route"),
        scope=scope,
        now=now,
    )
    with pytest.raises(SourceHuntRejected, match="stale"):
        service.query(
            plan=plan,
            index=index,
            checkpoint=checkpoint,
            query=InvestigationQuery(kind=InvestigationQueryKind.SYMBOL, term="handler"),
            scope=scope,
            now=now,
        )
    cancelled = service.cancel(
        plan=plan,
        index=index,
        checkpoint=current,
        scope=scope,
        now=now,
    )
    assert cancelled.status is InvestigationStatus.CANCELLED
    store.close()


def test_timeout_is_persisted_and_index_timeout_has_no_checkpoint(
    tmp_path, approved_scope, now
):
    service, store, index, scope = _indexed(tmp_path, approved_scope, now)
    plan, checkpoint = service.start(
        index=index,
        scope=scope,
        limits=SourceHuntLimits(),
        now=now,
        deadline=now + timedelta(seconds=1),
        idempotency_key="source-hunt:test:timeout",
    )
    with pytest.raises(SourceHuntTimedOut):
        service.query(
            plan=plan,
            index=index,
            checkpoint=checkpoint,
            query=InvestigationQuery(kind=InvestigationQueryKind.SYMBOL, term="route"),
            scope=scope,
            now=now + timedelta(seconds=2),
        )
    expired = service.expire(
        plan=plan, checkpoint=checkpoint, now=now + timedelta(seconds=2)
    )
    assert expired.status is InvestigationStatus.TIMED_OUT

    readings = iter((0.0, 2.0))
    timed_service, timed_store, _, timed_scope = _indexed(
        tmp_path / "timed", approved_scope, now
    )
    # Rebuild with a deterministic clock that expires during verified reads.
    timed_service.clock = lambda: next(readings)
    snapshot, timed_scope, root = _snapshot(
        tmp_path / "other", timed_scope, {"a.py": "def a():\n    pass\n"}
    )
    with pytest.raises(SourceHuntTimedOut, match="indexing"):
        timed_service.index_repository(
            snapshot=snapshot,
            store_root=root,
            scope=timed_scope,
            limits=SourceHuntLimits(timeout_seconds=1),
            now=now,
        )
    assert timed_store.connection.execute(
        "SELECT count(*) FROM source_hunt_plans"
    ).fetchone()[0] == 0
    timed_store.close()
    store.close()


def test_integrity_drift_and_revoked_scope_fail_closed(tmp_path, approved_scope, now):
    snapshot, scope, root = _snapshot(
        tmp_path, approved_scope, {"app.py": "def route():\n    return 1\n"}
    )
    path = root / snapshot.root_ref / "app.py"
    path.write_text("tampered\n", encoding="utf-8")
    with SourceHuntStore(tmp_path / "hunt.sqlite3") as store:
        service = SourceHuntService(store=store)
        with pytest.raises(SourceHuntRejected, match="integrity"):
            service.index_repository(
                snapshot=snapshot,
                store_root=root,
                scope=scope,
                limits=SourceHuntLimits(),
                now=now,
            )
        with pytest.raises(ValueError, match="approved Scope"):
            service.index_repository(
                snapshot=snapshot,
                store_root=root,
                scope=scope.model_copy(update={"state": ScopeState.REVOKED}),
                limits=SourceHuntLimits(),
                now=now,
            )


def test_source_hunt_cli_is_one_resumable_product_entry(tmp_path, capsys, monkeypatch):
    fixture = build_pilot_fixture(tmp_path / "fixture")
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(fixture.scope.model_dump_json(), encoding="utf-8")
    hunt_db = tmp_path / "hunt.sqlite3"
    monkeypatch.setattr("vulnloom.source_hunt.cli.utc_now", lambda: PILOT_NOW)
    assert main(
        [
            "source-hunt",
            "start",
            "--snapshot-id",
            fixture.snapshot.manifest.manifest_id,
            "--scope-file",
            str(scope_file),
            "--target-store",
            str(fixture.target_store_root),
            "--hunt-db",
            str(hunt_db),
            "--idempotency-key",
            "source-hunt:cli:1",
        ]
    ) == 0
    started = __import__("json").loads(capsys.readouterr().out)
    plan_id = started["plan"]["plan_id"]
    assert started["index_summary"]["languages"] == ["python"]

    assert main(
        [
            "source-hunt",
            "query",
            "--plan-id",
            plan_id,
            "--scope-file",
            str(scope_file),
            "--hunt-db",
            str(hunt_db),
            "--kind",
            "symbol",
            "--term",
            "handler",
        ]
    ) == 0
    queried = __import__("json").loads(capsys.readouterr().out)
    assert queried["checkpoint"]["queries_used"] == 1
    assert main(
        [
            "source-hunt",
            "status",
            "--plan-id",
            plan_id,
            "--hunt-db",
            str(hunt_db),
        ]
    ) == 0
    status = __import__("json").loads(capsys.readouterr().out)
    assert status["status"] == "active"
    assert status["observation_count"] == 1


class _ScriptedRunner:
    def __init__(self, scenarios, *, fail_after=None):
        self.delegate = OfflineSandboxRunner(
            frozenset(
                {
                    "source.build",
                    "source.harness",
                    "source.fuzz",
                    "source.sanitizer",
                    "source.pov_replay",
                }
            )
        )
        self.scenarios = iter(scenarios)
        self.calls = 0
        self.fail_after = fail_after

    def execute(self, request, *, now):
        if self.fail_after is not None and self.calls >= self.fail_after:
            raise RuntimeError("simulated control-plane interruption")
        self.calls += 1
        return self.delegate.execute(request, now=now, scenario=next(self.scenarios))


def _execution_fixture(tmp_path, approved_scope, now, *, image=None):
    service, hunt_store, index, scope = _indexed(tmp_path, approved_scope, now)
    investigation_plan, checkpoint = service.start(
        index=index,
        scope=scope,
        limits=SourceHuntLimits(),
        now=now,
        deadline=now + timedelta(minutes=10),
        idempotency_key="source-hunt:execution-investigation",
    )
    checkpoint, _ = service.query(
        plan=investigation_plan,
        index=index,
        checkpoint=checkpoint,
        query=InvestigationQuery(kind=InvestigationQueryKind.CALLERS, term="load_user"),
        scope=scope,
        now=now,
    )
    checkpoint = service.complete(
        plan=investigation_plan,
        index=index,
        checkpoint=checkpoint,
        conclusion_digest="e" * 64,
        scope=scope,
        now=now,
    )
    ordered_symbols = sorted(index.symbols, key=lambda item: item.qualified_name)
    entry, sink = ordered_symbols[0], ordered_symbols[-1]
    candidate = Candidate(
        target_id=index.target_id,
        target_version=index.target_version,
        source_graph_id=index.index_id,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        title="Authorized Source Hunt execution candidate",
        cwe="CWE-89",
        entry_point=entry.location,
        sink=sink.location,
        code_path=(entry.location, sink.location),
        security_invariant="Untrusted input cannot alter query structure",
        hypothesis="The bounded investigation identified a candidate path",
        signal_ids=checkpoint.observation_ids,
        cheapest_disproof="Replay the PoV under sanitizers",
        duplicate_fingerprint="d" * 64,
        confidence=0.7,
    )
    image = image or "sha256:" + "1" * 64
    profile = source_execution_profile(image_digest=image, snapshot_id=index.manifest_id)
    steps = []
    for stage in SourceExecutionStage:
        task = TaskEnvelope(
            engagement_id=scope.engagement_id,
            target_id=index.target_id,
            target_version=index.target_version,
            scope_id=scope.scope_id,
            worker_role=WorkerRole.VALIDATOR,
            scope_version=scope.version,
            policy_digest=PolicyEngine(scope).policy_digest,
            sandbox_profile_digest=sandbox_profile_digest(profile),
            tool_registry_digest="f" * 64,
            input_refs=(
                f"source-hunt:{checkpoint.checkpoint_id}",
                f"candidate:{candidate_content_digest(candidate)}",
            ),
            allowed_tools=profile.allowed_tools,
            budget=TaskBudget(wall_seconds=60, model_tokens=0, tool_calls=1),
            deadline=now + timedelta(minutes=5),
            idempotency_key=f"source-hunt:task:{stage.value}",
        )
        steps.append(
            SourceExecutionStep(
                stage=stage,
                request=SandboxRunRequest(
                    task=task,
                    profile=profile,
                    invocation=ToolInvocation(
                        tool_id=f"source.{stage.value}",
                        arguments=(),
                        working_directory="source",
                    ),
                    environment={"VULNLOOM_STAGE": stage.value},
                    idempotency_key=f"source-hunt:run:{stage.value}",
                ),
            )
        )
    plan = SourceExecutionPlan.create(
        investigation_plan_id=investigation_plan.plan_id,
        investigation_checkpoint_id=checkpoint.checkpoint_id,
        index_id=index.index_id,
        candidate_id=candidate.candidate_id,
        candidate_digest=candidate_content_digest(candidate),
        scope_id=scope.scope_id,
        scope_version=scope.version,
        target_version=index.target_version,
        steps=tuple(steps),
        created_at=now,
        deadline=now + timedelta(minutes=10),
        idempotency_key="source-hunt:execution:1",
    )
    approval = ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=index.target_id,
        action=ApprovalAction.RUN_UNTRUSTED_BUILD,
        action_digest=source_execution_approval_digest(plan),
        expected_side_effects=("execute target code in network-isolated sandbox",),
        evidence_summary="Human approved exact build and PoV validation plan",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=10),
        status=ApprovalStatus.GRANTED,
        decided_by="human-reviewer",
        decided_at=now,
    )
    evidence_store = EvidenceStore(tmp_path / "execution-evidence")
    evidence = tuple(
        evidence_store.capture_text(
            f"{stage.value} completed for authorized local fixture",
            kind=EvidenceKind.TEST,
            source_ref=f"source-execution:{stage.value}",
            producer="test.source-execution",
            target_version=index.target_version,
            summary=f"{stage.value} evidence",
        )
        for stage in SourceExecutionStage
    )
    return (
        hunt_store,
        index,
        scope,
        checkpoint,
        candidate,
        plan,
        approval,
        evidence_store,
        evidence,
    )


def test_source_execution_requires_approval_and_resumes_after_interruption(
    tmp_path, approved_scope, now
):
    (
        hunt_store,
        index,
        scope,
        checkpoint,
        candidate,
        plan,
        approval,
        evidence_store,
        evidence,
    ) = _execution_fixture(tmp_path, approved_scope, now)
    store = SourceExecutionStore(tmp_path / "executions.sqlite3")
    denied = approval.model_copy(update={"status": ApprovalStatus.DENIED})
    service = SourceExecutionService(
        scope=scope,
        runner=_ScriptedRunner(()),
        evidence_store=evidence_store,
        store=store,
    )
    with pytest.raises(SourceExecutionRejected, match="approval"):
        service.execute(
            plan=plan,
            index=index,
            investigation=checkpoint,
            candidate=candidate,
            approval=denied,
            now=now,
        )
    assert store.connection.execute("SELECT count(*) FROM source_executions").fetchone()[0] == 0

    interrupted = SourceExecutionService(
        scope=scope,
        runner=_ScriptedRunner(
            tuple(OfflineScenario(evidence_refs=(item.evidence_id,)) for item in evidence),
            fail_after=2,
        ),
        evidence_store=evidence_store,
        store=store,
    )
    with pytest.raises(RuntimeError, match="interruption"):
        interrupted.execute(
            plan=plan,
            index=index,
            investigation=checkpoint,
            candidate=candidate,
            approval=approval,
            now=now,
        )
    assert len(store.load(plan.plan_id).runner_results) == 2

    resumed = SourceExecutionService(
        scope=scope,
        runner=_ScriptedRunner(
            tuple(
                OfflineScenario(evidence_refs=(item.evidence_id,)) for item in evidence[2:]
            )
        ),
        evidence_store=evidence_store,
        store=store,
    ).execute(
        plan=plan,
        index=index,
        investigation=checkpoint,
        candidate=candidate,
        approval=approval,
        now=now + timedelta(seconds=1),
    )
    assert resumed.status is SourceExecutionStatus.COMPLETED
    assert resumed.reproducible_pov
    assert resumed.executed_stages == tuple(SourceExecutionStage)
    assert all(item.cleanup.complete for item in resumed.runner_results)
    binding_service = SourceExecutionValidationService(
        scope=scope, evidence_store=evidence_store, store=store
    )
    binding = binding_service.bind(
        plan=plan,
        candidate=candidate,
        outcome=resumed,
        evidence=evidence,
        now=now + timedelta(seconds=2),
    )
    assert binding.validated_candidate.state.value == "validated"
    assert binding.validation_run.result.value == "reproduced"
    assert binding_service.bind(
        plan=plan,
        candidate=candidate,
        outcome=resumed,
        evidence=evidence,
        now=now + timedelta(seconds=2),
    ) == binding
    hunt_store.close()
    store.close()


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (OfflineOutcome.CANCELLED, SourceExecutionStatus.CANCELLED),
        (OfflineOutcome.FAILED, SourceExecutionStatus.FAILED),
    ],
)
def test_source_execution_terminal_runner_paths_are_fail_closed(
    tmp_path, approved_scope, now, outcome, expected
):
    (
        hunt_store,
        index,
        scope,
        checkpoint,
        candidate,
        plan,
        approval,
        evidence_store,
        evidence,
    ) = _execution_fixture(tmp_path, approved_scope, now)
    scenarios = (
        OfflineScenario(outcome=outcome),
        *(OfflineScenario(evidence_refs=(item.evidence_id,)) for item in evidence[1:]),
    )
    with SourceExecutionStore(tmp_path / "terminal.sqlite3") as store:
        result = SourceExecutionService(
            scope=scope,
            runner=_ScriptedRunner(scenarios),
            evidence_store=evidence_store,
            store=store,
        ).execute(
            plan=plan,
            index=index,
            investigation=checkpoint,
            candidate=candidate,
            approval=approval,
            now=now,
        )
    assert result.status is expected
    assert not result.reproducible_pov
    assert result.runner_results[0].cleanup.complete
    hunt_store.close()


def test_source_execution_timeout_and_missing_evidence_do_not_claim_pov(
    tmp_path, approved_scope, now
):
    fixture = _execution_fixture(tmp_path, approved_scope, now)
    hunt_store, index, scope, checkpoint, candidate, plan, approval, evidence_store, _ = fixture
    with SourceExecutionStore(tmp_path / "timeout.sqlite3") as store:
        result = SourceExecutionService(
            scope=scope,
            runner=_ScriptedRunner((OfflineScenario(wall_seconds=61),)),
            evidence_store=evidence_store,
            store=store,
        ).execute(
            plan=plan,
            index=index,
            investigation=checkpoint,
            candidate=candidate,
            approval=approval,
            now=now,
        )
    assert result.status is SourceExecutionStatus.TIMED_OUT
    assert not result.reproducible_pov
    hunt_store.close()


def test_source_hunt_candidate_reaches_critic_finding_and_report(
    tmp_path, approved_scope, now
):
    fixture = _execution_fixture(tmp_path, approved_scope, now)
    hunt_store, index, scope, checkpoint, candidate, plan, approval, evidence_store, evidence = (
        fixture
    )
    with SourceExecutionStore(tmp_path / "closed-loop-execution.sqlite3") as execution_store:
        execution = SourceExecutionService(
            scope=scope,
            runner=_ScriptedRunner(
                tuple(OfflineScenario(evidence_refs=(item.evidence_id,)) for item in evidence)
            ),
            evidence_store=evidence_store,
            store=execution_store,
        ).execute(
            plan=plan,
            index=index,
            investigation=checkpoint,
            candidate=candidate,
            approval=approval,
            now=now + timedelta(seconds=1),
        )
        validation = SourceExecutionValidationService(
            scope=scope, evidence_store=evidence_store, store=execution_store
        ).bind(
            plan=plan,
            candidate=candidate,
            outcome=execution,
            evidence=evidence,
            now=now + timedelta(seconds=2),
        )

    assessments = tuple(
        CounterevidenceAssessment(
            angle=angle,
            disposition=CounterevidenceDisposition.RULED_OUT,
            evidence_refs=(evidence[0].evidence_id,),
            rationale_code=f"fixture_{angle.value}_ruled_out",
        )
        for angle in CounterevidenceAngle
    )
    critic_plan = CriticPlan.create(
        candidate_id=validation.validated_candidate.candidate_id,
        candidate_digest=domain_object_digest(validation.validated_candidate),
        validation_run_id=validation.validation_run.run_id,
        validation_run_digest=domain_object_digest(validation.validation_run),
        evidence_bundle_id=validation.evidence_bundle.bundle_id,
        evidence_bundle_digest=domain_object_digest(validation.evidence_bundle),
        scope_id=scope.scope_id,
        scope_version=scope.version,
        validation_context_id="1" * 64,
        review_context_id="2" * 64,
        validation_producer="source-hunt.validator",
        review_producer="source-hunt.critic",
        assessments=assessments,
        created_at=now + timedelta(seconds=3),
        deadline=now + timedelta(minutes=2),
        idempotency_key="source-hunt:critic:1",
    )
    with CriticStore(tmp_path / "closed-loop-critic.sqlite3") as critic_store:
        critic = DeterministicCritic(
            scope=scope, evidence_store=evidence_store, store=critic_store
        ).review(
            validation.validated_candidate,
            validation.validation_run,
            validation.evidence_bundle,
            evidence,
            critic_plan,
            now=now + timedelta(seconds=4),
        )

    duplicate = FindingDuplicateCheck.create(
        candidate_id=critic.candidate.candidate_id,
        candidate_digest=domain_object_digest(critic.candidate),
        target_version_digest=canonical_digest(critic.candidate.target_version),
        scope_id=scope.scope_id,
        scope_version=scope.version,
        result=DuplicateCheckResult.CLEAR,
        duplicate_family_id=None,
        checked_by="human-reviewer",
        checked_at=now + timedelta(seconds=5),
        expires_at=now + timedelta(minutes=3),
    )
    finding_id = uuid4()
    promotion_plan = SourceFindingPromotionPlan.create(
        validation_binding_id=validation.binding_id,
        validation_binding_digest=domain_object_digest(validation),
        critic_plan_id=critic.plan_id,
        critic_outcome_digest=domain_object_digest(critic),
        duplicate_check_id=duplicate.check_id,
        duplicate_check_digest=domain_object_digest(duplicate),
        candidate_id=critic.candidate.candidate_id,
        candidate_digest=domain_object_digest(critic.candidate),
        finding_id=finding_id,
        root_cause="Observed input reaches a query boundary without parameter binding",
        affected_versions=(index.target_version,),
        impact="An authorized fixture demonstrates query structure control",
        severity_assessment={"rating": "high", "score": 8.0},
        scope_id=scope.scope_id,
        scope_version=scope.version,
        created_at=now + timedelta(seconds=5),
        deadline=now + timedelta(minutes=3),
        idempotency_key="source-hunt:finding:1",
    )
    finding_approval = ApprovalRequest(
        engagement_id=scope.engagement_id,
        target_id=index.target_id,
        action=ApprovalAction.MUTATE_TARGET_STATE,
        action_digest=source_finding_approval_digest(promotion_plan),
        expected_side_effects=SOURCE_FINDING_SIDE_EFFECTS,
        evidence_summary="Human approved exact Source Hunt Finding promotion",
        policy_version=scope.version,
        expires_at=now + timedelta(minutes=3),
        status=ApprovalStatus.GRANTED,
        decided_by="human-approver",
        decided_at=now + timedelta(seconds=6),
    )
    with (
        SourceExecutionStore(tmp_path / "closed-loop-execution.sqlite3") as execution_store,
        CriticStore(tmp_path / "closed-loop-critic.sqlite3") as critic_store,
        SourceFindingPromotionStore(tmp_path / "closed-loop-finding.sqlite3") as store,
    ):
        promotion_service = SourceFindingPromotionService(
            scope=scope,
            execution_store=execution_store,
            critic_store=critic_store,
            store=store,
        )
        with pytest.raises(SourceFindingPromotionRejected, match="Approval"):
            promotion_service.execute(
                plan=promotion_plan,
                validation=validation,
                critic=critic,
                duplicate_check=duplicate,
                approval=finding_approval.model_copy(
                    update={"status": ApprovalStatus.DENIED}
                ),
                now=now + timedelta(seconds=7),
            )
        with pytest.raises(SourceFindingPromotionRejected, match="provenance"):
            promotion_service.execute(
                plan=promotion_plan,
                validation=validation,
                critic=critic,
                duplicate_check=duplicate,
                approval=finding_approval,
                now=promotion_plan.deadline,
            )
        assert store.connection.execute(
            "SELECT count(*) FROM source_finding_promotions"
        ).fetchone()[0] == 0
        promoted = promotion_service.execute(
            plan=promotion_plan,
            validation=validation,
            critic=critic,
            duplicate_check=duplicate,
            approval=finding_approval,
            now=now + timedelta(seconds=7),
        )
    sections = tuple(
        ReportSection(
            kind=kind,
            text=f"Authorized {kind.value} for the reproduced Source Hunt Finding",
            evidence_refs=(evidence[0].evidence_id,),
        )
        for kind in ReportSectionKind
    )
    report_plan = ReportDraftPlan.create(
        finding_id=promoted.finding.finding_id,
        finding_digest=domain_object_digest(promoted.finding),
        candidate_id=promoted.promoted_candidate.candidate_id,
        candidate_digest=domain_object_digest(promoted.promoted_candidate),
        evidence_bundle_id=validation.evidence_bundle.bundle_id,
        evidence_bundle_digest=domain_object_digest(validation.evidence_bundle),
        scope_id=scope.scope_id,
        scope_version=scope.version,
        channel=ReportChannel.GENERIC,
        title="Authorized Source Hunt Finding",
        sections=sections,
        prepared_by="source-hunt.reporter",
        created_at=now + timedelta(seconds=8),
        deadline=now + timedelta(minutes=3),
        idempotency_key="source-hunt:report:1",
    )
    with ReportDraftStore(tmp_path / "closed-loop-report.sqlite3") as report_store:
        report = DeterministicReportService(
            scope=scope,
            evidence_store=evidence_store,
            store=report_store,
            artifact_store=ReportArtifactStore(tmp_path / "closed-loop-reports"),
        ).draft(
            promoted.finding,
            promoted.promoted_candidate,
            validation.evidence_bundle,
            evidence,
            report_plan,
            now=now + timedelta(seconds=9),
        )
    assert report.report.finding_id == promoted.finding.finding_id
    assert report.report.review_status.value == "draft"
    assert promoted.promoted_candidate.state.value == "promoted"
    hunt_store.close()


def test_completed_observations_materialize_only_a_proposed_candidate(
    tmp_path, approved_scope, now
):
    service, store, index, scope = _indexed(tmp_path, approved_scope, now)
    plan, checkpoint = service.start(
        index=index,
        scope=scope,
        limits=SourceHuntLimits(max_queries=3),
        now=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="source-hunt:candidate:1",
    )
    checkpoint, route_observation = service.query(
        plan=plan,
        index=index,
        checkpoint=checkpoint,
        query=InvestigationQuery(kind=InvestigationQueryKind.SYMBOL, term="api.routes.route"),
        scope=scope,
        now=now,
    )
    checkpoint, service_observation = service.query(
        plan=plan,
        index=index,
        checkpoint=checkpoint,
        query=InvestigationQuery(kind=InvestigationQueryKind.SYMBOL, term="core.service"),
        scope=scope,
        now=now,
    )
    entry = route_observation.matched_symbols[0]
    load, sink = service_observation.matched_symbols
    proposal = SourceCandidateProposal.create(
        entry_symbol_id=entry.symbol_id,
        sink_symbol_id=sink.symbol_id,
        code_path_symbol_ids=(entry.symbol_id, load.symbol_id, sink.symbol_id),
        observation_ids=(
            route_observation.observation_id,
            service_observation.observation_id,
        ),
        cwe="CWE-89",
        title="Cross-file query construction may accept untrusted input",
        security_invariant="Request input cannot alter query structure",
        hypothesis="The observed call chain reaches the query builder",
        cheapest_disproof="Prove parameter binding on every observed path",
        confidence=0.7,
    )
    checkpoint = service.complete(
        plan=plan,
        index=index,
        checkpoint=checkpoint,
        conclusion_digest=proposal.proposal_id,
        scope=scope,
        now=now,
    )
    candidate_set = SourceCandidateService(investigation_store=store).materialize(
        proposal=proposal,
        investigation=checkpoint,
        index=index,
        scope=scope,
        now=now,
    )
    assert candidate_set.candidates[0].state.value == "proposed"
    assert candidate_set.candidates[0].code_path == (
        entry.location,
        load.location,
        sink.location,
    )
    drift = SourceCandidateProposal.create(
        **(
            proposal.model_dump(mode="python", exclude={"proposal_id", "entry_symbol_id"})
            | {"entry_symbol_id": "0" * 64}
        )
    )
    with pytest.raises(SourceCandidateRejected, match="provenance"):
        SourceCandidateService(investigation_store=store).materialize(
            proposal=drift,
            investigation=checkpoint,
            index=index,
            scope=scope,
            now=now,
        )
    store.close()


class _ObservationDrivenInvestigator:
    def __init__(self, index):
        self.index = index
        self.turns = []

    def decide(self, turn):
        self.turns.append(turn)
        if turn.revision == 0:
            return InvestigationDecision(
                kind=InvestigationDecisionKind.QUERY,
                query=InvestigationQuery(
                    kind=InvestigationQueryKind.SYMBOL, term="api.routes.route"
                ),
            )
        if turn.revision == 1:
            assert len(turn.observations) == 1
            return InvestigationDecision(
                kind=InvestigationDecisionKind.QUERY,
                query=InvestigationQuery(
                    kind=InvestigationQueryKind.SYMBOL, term="core.service"
                ),
            )
        matched = tuple(
            symbol for observation in turn.observations for symbol in observation.matched_symbols
        )
        by_name = {item.qualified_name: item for item in matched}
        route = by_name["api.routes.route"]
        load = by_name["core.service.load_user"]
        sink = by_name["core.service.query_user"]
        return InvestigationDecision(
            kind=InvestigationDecisionKind.PROPOSE,
            proposal=SourceCandidateProposal.create(
                entry_symbol_id=route.symbol_id,
                sink_symbol_id=sink.symbol_id,
                code_path_symbol_ids=(route.symbol_id, load.symbol_id, sink.symbol_id),
                observation_ids=tuple(item.observation_id for item in turn.observations),
                cwe="CWE-89",
                title="Observed cross-file query path",
                security_invariant="Inputs cannot alter query structure",
                hypothesis="Observed calls reach a query-building function",
                cheapest_disproof="Verify parameter binding across the observed path",
                confidence=0.7,
            ),
        )


def test_agent_loop_changes_queries_from_observations_and_is_resumable(
    tmp_path, approved_scope, now
):
    service, store, index, scope = _indexed(tmp_path, approved_scope, now)
    plan, _ = service.start(
        index=index,
        scope=scope,
        limits=SourceHuntLimits(max_queries=4),
        now=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="source-hunt:agent:1",
    )
    investigator = _ObservationDrivenInvestigator(index)
    outcome = SourceHuntAgentService(
        investigation_service=service,
        candidate_service=SourceCandidateService(investigation_store=store),
        investigator=investigator,
    ).run(plan=plan, index=index, scope=scope, now=now)
    assert outcome.checkpoint.status is InvestigationStatus.READY_FOR_CANDIDATES
    assert outcome.candidate_set is not None
    assert len(investigator.turns[1].observations) == 1
    assert len(investigator.turns[2].observations) == 2

    class BrokenInvestigator:
        def decide(self, _turn):
            raise TimeoutError("provider unavailable")

    second, checkpoint = service.start(
        index=index,
        scope=scope,
        limits=SourceHuntLimits(),
        now=now,
        deadline=now + timedelta(minutes=1),
        idempotency_key="source-hunt:agent:failure",
    )
    with pytest.raises(SourceHuntAgentRejected, match="invalid typed decision"):
        SourceHuntAgentService(
            investigation_service=service,
            candidate_service=SourceCandidateService(investigation_store=store),
            investigator=BrokenInvestigator(),
        ).run(plan=second, index=index, scope=scope, now=now)
    assert store.latest(second.plan_id) == checkpoint
    store.close()
