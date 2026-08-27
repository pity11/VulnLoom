from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from vulnloom.domain.models import (
    Candidate,
    NetworkTargetScope,
    RepositoryScope,
    Scope,
    ScopeState,
    SourceLocation,
)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 8, 27, 12, 0, tzinfo=UTC)


@pytest.fixture
def engagement_id():
    return uuid4()


@pytest.fixture
def approved_scope(now, engagement_id) -> Scope:
    return Scope(
        engagement_id=engagement_id,
        authority_reference="signed-authorization-42",
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=1),
        repositories=(RepositoryScope(url="https://example.test/app.git", commit="a" * 40),),
        network_targets=(NetworkTargetScope(host="app.example.test", ports=frozenset({443})),),
        allowed_test_classes=frozenset({"read_only", "idor"}),
        state=ScopeState.APPROVED,
        approved_by="security-owner",
        approved_at=now,
    )


@pytest.fixture
def candidate() -> Candidate:
    signal_id = uuid4()
    return Candidate(
        target_id=uuid4(),
        title="Object lookup omits ownership predicate",
        cwe="CWE-639",
        entry_point=SourceLocation(path="app/routes.py", line=10, symbol="get_invoice"),
        sink=SourceLocation(path="app/models.py", line=41, symbol="Invoice.get"),
        code_path=(
            SourceLocation(path="app/routes.py", line=10, symbol="get_invoice"),
            SourceLocation(path="app/models.py", line=41, symbol="Invoice.get"),
        ),
        security_invariant="A caller can only read invoices owned by its tenant",
        hypothesis="The route loads an invoice by identifier without a tenant predicate",
        signal_ids=(signal_id,),
        cheapest_disproof="Show a mandatory tenant filter on every reachable lookup path",
        duplicate_fingerprint="cwe639:invoice:get-without-tenant",
    )
