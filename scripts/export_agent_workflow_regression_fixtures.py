"""Generate the sealed M9.2 Agent workflow mutation corpus."""

from __future__ import annotations

from pathlib import Path

from vulnloom.benchmark import (
    REQUIRED_AGENT_WORKFLOW_STAGES,
    AgentWorkflowCheckpoint,
    AgentWorkflowEffectCounters,
    AgentWorkflowRegressionCorpus,
    AgentWorkflowRegressionObservation,
    AgentWorkflowRegressionPolicy,
)
from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import (
    CandidateState,
    CriticVerdict,
    ReportReviewStatus,
    ValidationResult,
)


def build_fixture() -> AgentWorkflowRegressionCorpus:
    checkpoints = tuple(
        AgentWorkflowCheckpoint(
            stage=stage,
            object_id=canonical_digest(f"m9.2:checkpoint:{stage.value}"),
            object_digest=canonical_digest(f"m9.2:object:{stage.value}"),
        )
        for stage in REQUIRED_AGENT_WORKFLOW_STAGES
    )
    observation = AgentWorkflowRegressionObservation.create(
        checkpoints=checkpoints,
        proposed_candidate_state=CandidateState.PROPOSED,
        critic_candidate_state=CandidateState.CRITIC_REVIEWED,
        promoted_candidate_state=CandidateState.PROMOTED,
        validation_result=ValidationResult.REPRODUCED,
        critic_verdict=CriticVerdict.ACCEPTED,
        draft_report_status=ReportReviewStatus.DRAFT,
        reviewed_report_status=ReportReviewStatus.HUMAN_APPROVED,
        exported_report_status=ReportReviewStatus.EXPORTED,
        evidence_refs=tuple(
            sorted(canonical_digest(f"m9.2:evidence:{index}") for index in range(2))
        ),
        human_decision_digests=tuple(
            sorted(canonical_digest(f"m9.2:human:{index}") for index in range(6))
        ),
        approval_digests=tuple(
            sorted(canonical_digest(f"m9.2:approval:{index}") for index in range(3))
        ),
        validation_effects=AgentWorkflowEffectCounters(
            provider_attempts=3,
            broker_calls=2,
            runner_calls=1,
            target_requests=2,
        ),
        export_effects=AgentWorkflowEffectCounters(
            provider_attempts=3,
            broker_calls=2,
            runner_calls=1,
            target_requests=2,
        ),
        public_network_calls=0,
        target_builds=0,
        automatic_approvals=0,
        submission_calls=0,
        exported_artifact_digest=canonical_digest("m9.2:exported-artifact"),
    )
    return AgentWorkflowRegressionCorpus.create(
        version="1",
        base_observation=observation,
        policy=AgentWorkflowRegressionPolicy(),
    )


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "benchmarks" / "m9_2"
    root.mkdir(parents=True, exist_ok=True)
    corpus = build_fixture()
    (root / "corpus.json").write_text(
        corpus.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
