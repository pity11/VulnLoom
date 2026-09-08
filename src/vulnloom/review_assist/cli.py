"""Operator-selected review commands. Errors never print source or provider exceptions."""

import json
from datetime import timedelta
from pathlib import Path

from vulnloom.adapters.model_credentials import EnvironmentModelCredentialProvider
from vulnloom.agent_runtime.provider_admission import AgentProviderEgressStore
from vulnloom.domain.models import ApprovalRequest, Scope, utc_now
from vulnloom.ingestion import IngestionService

from .provider import CodeReviewPlan
from .service import CodeReviewService, approval_request
from .source import _read, select_snippet
from .store import CodeReviewStore


def _document(path, model):
    path = Path(path)
    return model.model_validate_json(_read(path.parent, path.name))


def handle_review(args):
    try:
        scope = _document(args.scope_file, Scope)
        if args.review_mode == "approval":
            plan = _document(args.plan_file, CodeReviewPlan)
            from .service import digest

            if plan.scope_digest != digest(scope):
                raise ValueError("review approval scope mismatch")
            print(approval_request(plan, scope).model_dump_json(indent=2))
            return 0
        ingestion = IngestionService(Path(args.store))
        if args.review_mode == "preview":
            snippet = select_snippet(
                ingestion=ingestion,
                snapshot=ingestion.load_snapshot(args.snapshot_id),
                scope=scope,
                path=args.source_path,
                start_line=args.start_line,
                end_line=args.end_line,
                now=utc_now(),
            )
            print(snippet.model_dump_json(indent=2))
            return 0
        if args.review_mode == "run" and not args.allow_provider_network:
            raise ValueError("review model-network opt-in required")
        with AgentProviderEgressStore(Path(args.egress_store)) as egress:
            if args.review_mode == "prepare":
                service = CodeReviewService(
                    ingestion=ingestion, scope=scope, egress_store=egress, store=None
                )
                plan = service.prepare(
                    snapshot_id=args.snapshot_id,
                    path=args.source_path,
                    start_line=args.start_line,
                    end_line=args.end_line,
                    grant_id=args.grant_id,
                    deadline=utc_now() + timedelta(seconds=args.ttl_seconds),
                    idempotency_key=args.idempotency_key,
                )
                print(plan.model_dump_json(indent=2))
                return 0
            plan = _document(args.plan_file, CodeReviewPlan)
            approval = _document(args.approval_file, ApprovalRequest)
            with CodeReviewStore(Path(args.review_db)) as store:
                service = CodeReviewService(
                    ingestion=ingestion,
                    scope=scope,
                    egress_store=egress,
                    store=store,
                    credential_provider=EnvironmentModelCredentialProvider(
                        allowed_references=(plan.config.credential_reference,),
                    ),
                )
                outcome = service.execute(
                    plan=plan,
                    approval=approval,
                    path=args.source_path,
                    allow_provider_network=args.allow_provider_network,
                )
            print(outcome.model_dump_json(indent=2))
            return 0 if outcome.status == "review_ready" else 1
    except TimeoutError:
        print(json.dumps({"status": "timed_out", "error_code": "code_review_timed_out"}))
    except Exception:
        print(json.dumps({"status": "rejected", "error_code": "code_review_rejected"}))
    return 1


def register_review_commands(sub):
    for command, mode in (
        ("code-review-preview", "preview"),
        ("code-review-prepare", "prepare"),
        ("code-review-approval-request", "approval"),
        ("code-review-run", "run"),
    ):
        parser = sub.add_parser(command)
        parser.add_argument("--scope-file", required=True)
        if mode in {"preview", "prepare", "run"}:
            parser.add_argument("--store", default=".vulnloom/targets")
            parser.add_argument("--source-path", required=True)
        if mode in {"preview", "prepare"}:
            parser.add_argument("--snapshot-id", required=True)
            parser.add_argument("--start-line", type=int, required=True)
            parser.add_argument("--end-line", type=int, required=True)
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
            parser.add_argument("--review-db", default=".vulnloom/code-reviews.db")
            parser.add_argument("--allow-provider-network", action="store_true")
        parser.set_defaults(handler=handle_review, review_mode=mode)
