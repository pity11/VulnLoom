"""One provider attempt per grant, including failures and interrupted attempts."""

import sqlite3
from pathlib import Path

from .provider_probe_fixture import CUC_PROBE_DIGEST, CUC_STRUCTURED_PROBE_DIGEST
from .provider_probe_models import ProviderProbePlan, ProviderProbeResult


class ProviderProbeRecoveryRequired(RuntimeError):
    pass


class ProviderProbeStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS provider_probes (plan_id TEXT PRIMARY KEY, "
            "idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, "
            "plan_json TEXT NOT NULL, state TEXT NOT NULL, result_json TEXT)"
        )
        self.connection.commit()

    def claim(self, plan: ProviderProbePlan) -> ProviderProbeResult | None:
        row = self.connection.execute(
            "SELECT * FROM provider_probes WHERE plan_id=? OR idempotency_key=? OR grant_id=?",
            (plan.plan_id, plan.idempotency_key, plan.grant_id),
        ).fetchone()
        if row is not None:
            if (
                row["plan_id"] != plan.plan_id
                or row["plan_json"] != plan.model_dump_json()
                or row["idempotency_key"] != plan.idempotency_key
                or row["grant_id"] != plan.grant_id
            ):
                raise ValueError("provider probe grant or key already consumed")
            if row["state"] != "completed" or row["result_json"] is None:
                raise ProviderProbeRecoveryRequired("provider probe requires explicit recovery")
            result = ProviderProbeResult.model_validate_json(row["result_json"])
            if (
                result.plan_id != plan.plan_id
                or result.completed_at < plan.created_at
                or (result.status == "passed" and result.completed_at >= plan.deadline)
                or (
                    plan.fixture_digest in {CUC_PROBE_DIGEST, CUC_STRUCTURED_PROBE_DIGEST}
                    and result.status == "passed"
                    and result.response_model is None
                )
                or (
                    plan.fixture_digest not in {CUC_PROBE_DIGEST, CUC_STRUCTURED_PROBE_DIGEST}
                    and result.response_model is not None
                )
            ):
                raise ProviderProbeRecoveryRequired("provider probe result drifted")
            return result
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO provider_probes VALUES (?,?,?,?,'started',NULL)",
                    (plan.plan_id, plan.idempotency_key, plan.grant_id, plan.model_dump_json()),
                )
        except sqlite3.IntegrityError as exc:
            raise ProviderProbeRecoveryRequired("concurrent provider probe claim") from exc
        return None

    def complete(self, result: ProviderProbeResult):
        with self.connection:
            changed = self.connection.execute(
                "UPDATE provider_probes SET state='completed',result_json=? "
                "WHERE plan_id=? AND state='started'",
                (result.model_dump_json(), result.plan_id),
            ).rowcount
        if changed != 1:
            raise ProviderProbeRecoveryRequired("provider probe STARTED unavailable")

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
