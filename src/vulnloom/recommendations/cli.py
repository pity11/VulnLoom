"""Local preparation and admission commands; no model or target network access."""

import json
from datetime import timedelta
from pathlib import Path

from vulnloom.agent_runtime.provider_probe_models import ProviderProbeResult
from vulnloom.analyzers import SourceGraphStore
from vulnloom.domain.models import Scope, utc_now
from vulnloom.hypotheses import CandidateSetStore
from vulnloom.review_assist.source import _read

from .generation_store import CandidateRecommendationGenerationStore
from .models import CandidateRecommendation, CandidateRecommendationAdmissionPlan
from .service import CandidateRecommendationAdmissionService
from .store import CandidateRecommendationStore


def _load(path, model):
    path = Path(path)
    return model.model_validate_json(_read(path.parent, path.name))


def handle_candidate_recommendation(args):
    try:
        scope = _load(args.scope_file, Scope)
        recommendation = _load(args.recommendation_file, CandidateRecommendation)
        provider_result = _load(args.provider_result_file, ProviderProbeResult)
        with CandidateRecommendationStore(Path(args.recommendation_db)) as store:
            service = CandidateRecommendationAdmissionService(
                scope=scope,
                graph_store=SourceGraphStore(Path(args.graph_store)),
                candidate_store=CandidateSetStore(Path(args.candidate_store)),
                store=store,
            )
            if args.recommendation_mode == "prepare":
                now = utc_now()
                result = service.prepare(
                    recommendation,
                    provider_result,
                    now=now,
                    deadline=now + timedelta(seconds=args.ttl_seconds),
                    idempotency_key=args.idempotency_key,
                )
            else:
                plan = _load(args.plan_file, CandidateRecommendationAdmissionPlan)
                result = service.admit(plan, recommendation, provider_result, now=utc_now())
        print(result.model_dump_json(indent=2))
        return 0
    except TimeoutError:
        print(json.dumps({"status": "timed_out", "error_code": "recommendation_timed_out"}))
    except Exception:
        print(json.dumps({"status": "rejected", "error_code": "recommendation_rejected"}))
    return 1


def handle_generated_candidate_recommendation(args):
    try:
        scope = _load(args.scope_file, Scope)
        with (
            CandidateRecommendationStore(Path(args.recommendation_db)) as store,
            CandidateRecommendationGenerationStore(Path(args.generation_db)) as generation_store,
        ):
            service = CandidateRecommendationAdmissionService(
                scope=scope,
                graph_store=SourceGraphStore(Path(args.graph_store)),
                candidate_store=CandidateSetStore(Path(args.candidate_store)),
                store=store,
                generation_store=generation_store,
            )
            if args.recommendation_mode == "generated-prepare":
                now = utc_now()
                result = service.prepare_generated(
                    generation_plan_id=args.generation_plan_id,
                    now=now,
                    deadline=now + timedelta(seconds=args.ttl_seconds),
                    idempotency_key=args.idempotency_key,
                )
            else:
                plan = _load(args.plan_file, CandidateRecommendationAdmissionPlan)
                result = service.admit_generated(plan, now=utc_now())
        print(result.model_dump_json(indent=2))
        return 0
    except TimeoutError:
        print(json.dumps({"status": "timed_out", "error_code": "recommendation_timed_out"}))
    except Exception:
        print(json.dumps({"status": "rejected", "error_code": "recommendation_rejected"}))
    return 1


def register_candidate_recommendation_commands(sub):
    for command, mode in (
        ("candidate-recommendation-prepare-local", "prepare"),
        ("candidate-recommendation-admit-local", "admit"),
    ):
        parser = sub.add_parser(command)
        parser.add_argument("--scope-file", required=True)
        parser.add_argument("--recommendation-file", required=True)
        parser.add_argument("--provider-result-file", required=True)
        parser.add_argument("--graph-store", required=True)
        parser.add_argument("--candidate-store", required=True)
        parser.add_argument("--recommendation-db", default=".vulnloom/recommendations.db")
        if mode == "prepare":
            parser.add_argument("--ttl-seconds", type=int, default=120)
            parser.add_argument("--idempotency-key", required=True)
        else:
            parser.add_argument("--plan-file", required=True)
        parser.set_defaults(
            handler=handle_candidate_recommendation,
            recommendation_mode=mode,
        )
    for command, mode in (
        ("candidate-recommendation-generated-prepare-local", "generated-prepare"),
        ("candidate-recommendation-generated-admit-local", "generated-admit"),
    ):
        parser = sub.add_parser(command)
        parser.add_argument("--scope-file", required=True)
        parser.add_argument("--generation-db", required=True)
        parser.add_argument("--graph-store", required=True)
        parser.add_argument("--candidate-store", required=True)
        parser.add_argument("--recommendation-db", default=".vulnloom/recommendations.db")
        if mode == "generated-prepare":
            parser.add_argument("--generation-plan-id", required=True)
            parser.add_argument("--ttl-seconds", type=int, default=120)
            parser.add_argument("--idempotency-key", required=True)
        else:
            parser.add_argument("--plan-file", required=True)
        parser.set_defaults(
            handler=handle_generated_candidate_recommendation,
            recommendation_mode=mode,
        )
    from .generation_cli import register_candidate_recommendation_generation_commands
    from .selection_cli import register_candidate_recommendation_selection_commands

    register_candidate_recommendation_generation_commands(sub)
    register_candidate_recommendation_selection_commands(sub)
