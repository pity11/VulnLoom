"""Operator commands for previewing and running one Candidate recommendation call."""

import json
from datetime import timedelta
from pathlib import Path
from uuid import UUID

from vulnloom.adapters.model_credentials import EnvironmentModelCredentialProvider
from vulnloom.agent_runtime.provider_admission import AgentProviderEgressStore
from vulnloom.analyzers import SourceGraphStore
from vulnloom.domain.models import ApprovalRequest, Scope, utc_now
from vulnloom.hypotheses import CandidateSetStore
from vulnloom.review_assist.source import _read

from .generation_service import (
    CandidateRecommendationGenerationService,
    _digest,
    recommendation_generation_approval_request,
)
from .generation_store import CandidateRecommendationGenerationStore
from .provider import CandidateRecommendationGenerationPlan


def _load(path, model):
    path = Path(path)
    return model.model_validate_json(_read(path.parent, path.name))


def _service(args, scope, *, egress=None, store=None, credentials=None):
    return CandidateRecommendationGenerationService(
        scope=scope,
        graph_store=SourceGraphStore(Path(args.graph_store)),
        candidate_store=CandidateSetStore(Path(args.candidate_store)),
        egress_store=egress,
        store=store,
        credential_provider=credentials,
        now=utc_now,
    )


def handle_candidate_recommendation_generation(args):
    try:
        scope = _load(args.scope_file, Scope)
        if args.generation_mode == "approval":
            plan = _load(args.plan_file, CandidateRecommendationGenerationPlan)
            if plan.scope_digest != _digest(scope):
                raise ValueError("recommendation approval Scope mismatch")
            print(recommendation_generation_approval_request(plan, scope).model_dump_json(indent=2))
            return 0
        candidate_id = UUID(args.candidate_id) if hasattr(args, "candidate_id") else None
        if args.generation_mode == "preview":
            result = _service(args, scope).projection(
                candidate_set_id=args.candidate_set_id, candidate_id=candidate_id
            )
            print(result.model_dump_json(indent=2))
            return 0
        if args.generation_mode == "run" and not args.allow_provider_network:
            raise ValueError("recommendation model-network opt-in required")
        with AgentProviderEgressStore(Path(args.egress_store)) as egress:
            if args.generation_mode == "prepare":
                result = _service(args, scope, egress=egress).prepare(
                    candidate_set_id=args.candidate_set_id,
                    candidate_id=candidate_id,
                    grant_id=args.grant_id,
                    deadline=utc_now() + timedelta(seconds=args.ttl_seconds),
                    idempotency_key=args.idempotency_key,
                )
                print(result.model_dump_json(indent=2))
                return 0
            plan = _load(args.plan_file, CandidateRecommendationGenerationPlan)
            approval = _load(args.approval_file, ApprovalRequest)
            credentials = EnvironmentModelCredentialProvider(
                allowed_references=(plan.config.credential_reference,)
            )
            with CandidateRecommendationGenerationStore(Path(args.generation_db)) as store:
                result = _service(
                    args, scope, egress=egress, store=store, credentials=credentials
                ).execute(
                    plan=plan,
                    approval=approval,
                    allow_provider_network=args.allow_provider_network,
                )
            print(result.model_dump_json(indent=2))
            return 0 if result.status == "recommendation_ready" else 1
    except TimeoutError:
        print(
            json.dumps({"status": "timed_out", "error_code": "recommendation_generation_timed_out"})
        )
    except Exception:
        print(
            json.dumps({"status": "rejected", "error_code": "recommendation_generation_rejected"})
        )
    return 1


def register_candidate_recommendation_generation_commands(sub):
    commands = (
        ("candidate-recommendation-preview", "preview"),
        ("candidate-recommendation-generate-prepare", "prepare"),
        ("candidate-recommendation-generate-approval-request", "approval"),
        ("candidate-recommendation-generate-run", "run"),
    )
    for command, mode in commands:
        parser = sub.add_parser(command)
        parser.add_argument("--scope-file", required=True)
        if mode in {"preview", "prepare", "run"}:
            parser.add_argument("--graph-store", required=True)
            parser.add_argument("--candidate-store", required=True)
        if mode in {"preview", "prepare"}:
            parser.add_argument("--candidate-set-id", required=True)
            parser.add_argument("--candidate-id", required=True)
        if mode in {"prepare", "run"}:
            parser.add_argument("--egress-store", required=True)
        if mode == "prepare":
            parser.add_argument("--grant-id", required=True)
            parser.add_argument("--ttl-seconds", type=int, default=60)
            parser.add_argument("--idempotency-key", required=True)
        if mode in {"approval", "run"}:
            parser.add_argument("--plan-file", required=True)
        if mode == "run":
            parser.add_argument("--approval-file", required=True)
            parser.add_argument(
                "--generation-db", default=".vulnloom/candidate-recommendation-generations.db"
            )
            parser.add_argument("--allow-provider-network", action="store_true")
        parser.set_defaults(
            handler=handle_candidate_recommendation_generation,
            generation_mode=mode,
        )
