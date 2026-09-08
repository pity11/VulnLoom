"""Offline operator commands for Candidate recommendation selection."""

import json
from contextlib import ExitStack, suppress
from datetime import timedelta
from pathlib import Path

from vulnloom.analyzers import SourceGraphStore
from vulnloom.domain.models import Scope, utc_now
from vulnloom.hypotheses import CandidateSetStore
from vulnloom.review_assist.source import _read

from .generation_store import CandidateRecommendationGenerationStore
from .review_web import CandidateRecommendationReviewApplication, create_review_server
from .selection_models import CandidateRecommendationSelectionCommand
from .selection_service import CandidateRecommendationSelectionService
from .selection_store import CandidateRecommendationSelectionStore
from .store import CandidateRecommendationStore


def _load(path, model):
    path = Path(path)
    return model.model_validate_json(_read(path.parent, path.name))


def selection_service(args, stack):
    scope = _load(args.scope_file, Scope)
    recommendation_store = stack.enter_context(
        CandidateRecommendationStore(Path(args.recommendation_db))
    )
    generation_store = stack.enter_context(
        CandidateRecommendationGenerationStore(Path(args.generation_db))
    )
    selection_store = stack.enter_context(
        CandidateRecommendationSelectionStore(Path(args.selection_db))
    )
    return CandidateRecommendationSelectionService(
        scope=scope,
        graph_store=SourceGraphStore(Path(args.graph_store)),
        candidate_store=CandidateSetStore(Path(args.candidate_store)),
        recommendation_store=recommendation_store,
        generation_store=generation_store,
        selection_store=selection_store,
    )


def handle_candidate_recommendation_selection(args):
    try:
        with ExitStack() as stack:
            service = selection_service(args, stack)
            if args.selection_mode == "prepare":
                now = utc_now()
                result = service.prepare(
                    admission_record_id=args.admission_record_id,
                    decision=args.decision,
                    reviewer_id=args.reviewer_id,
                    decided_at=now,
                    expires_at=now + timedelta(seconds=args.ttl_seconds),
                    idempotency_key=args.idempotency_key,
                )
            else:
                command = _load(args.command_file, CandidateRecommendationSelectionCommand)
                result = service.record(command, now=utc_now())
        print(result.model_dump_json(indent=2))
        return 0
    except TimeoutError:
        print(json.dumps({"status": "timed_out", "error_code": "selection_timed_out"}))
    except Exception:
        print(json.dumps({"status": "rejected", "error_code": "selection_rejected"}))
    return 1


def handle_candidate_recommendation_review_web(args):
    try:
        if not 1024 <= args.port <= 65535:
            raise ValueError("review UI port rejected")
        with ExitStack() as stack:
            service = selection_service(args, stack)
            application = CandidateRecommendationReviewApplication(
                service, reviewer_id=args.reviewer_id
            )
            server = stack.enter_context(create_review_server(application, port=args.port))
            print(json.dumps({"status": "ready", "url": f"http://127.0.0.1:{args.port}/"}))
            with suppress(KeyboardInterrupt):
                server.serve_forever(poll_interval=0.25)
        return 0
    except Exception:
        print(json.dumps({"status": "rejected", "error_code": "review_ui_rejected"}))
        return 1


def _common(parser):
    parser.add_argument("--scope-file", required=True)
    parser.add_argument("--generation-db", required=True)
    parser.add_argument("--recommendation-db", required=True)
    parser.add_argument("--selection-db", required=True)
    parser.add_argument("--graph-store", required=True)
    parser.add_argument("--candidate-store", required=True)


def register_candidate_recommendation_selection_commands(sub):
    prepare = sub.add_parser("candidate-recommendation-selection-prepare-local")
    _common(prepare)
    prepare.add_argument("--admission-record-id", required=True)
    prepare.add_argument("--decision", choices=("accept", "reject", "defer"), required=True)
    prepare.add_argument("--reviewer-id", required=True)
    prepare.add_argument("--ttl-seconds", type=int, default=120)
    prepare.add_argument("--idempotency-key", required=True)
    prepare.set_defaults(
        handler=handle_candidate_recommendation_selection, selection_mode="prepare"
    )

    record = sub.add_parser("candidate-recommendation-selection-record-local")
    _common(record)
    record.add_argument("--command-file", required=True)
    record.set_defaults(handler=handle_candidate_recommendation_selection, selection_mode="record")

    web = sub.add_parser("candidate-recommendation-review-web")
    _common(web)
    web.add_argument("--reviewer-id", required=True)
    web.add_argument("--port", type=int, default=8765)
    web.set_defaults(handler=handle_candidate_recommendation_review_web)
