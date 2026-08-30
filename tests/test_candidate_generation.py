from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from uuid import uuid4

import pytest

from vulnloom.analyzers import PythonWebSourceMapper
from vulnloom.analyzers.models import source_graph_digest
from vulnloom.domain.models import ArtifactKind, ArtifactScope, ScopeState
from vulnloom.hypotheses import (
    CandidateGenerationError,
    CandidateGenerator,
    CandidateGeneratorLimits,
    CandidateSet,
    CandidateSetStore,
)
from vulnloom.ingestion import IngestionService


def _graph(tmp_path: Path, approved_scope, files: dict[str, str]):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        for name, content in files.items():
            handle.writestr(name, content)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    scope = approved_scope.model_copy(
        update={
            "artifacts": (
                ArtifactScope(
                    kind=ArtifactKind.SOURCE_ARCHIVE,
                    sha256=digest,
                    source_name=archive.name,
                ),
            )
        }
    )
    target_store = tmp_path / "targets"
    snapshot = IngestionService(target_store).ingest_archive(archive, scope=scope)
    return PythonWebSourceMapper().analyze(snapshot, target_store, scope=scope), scope


def test_candidate_generation_merges_signals_and_is_deterministic(tmp_path, approved_scope, now):
    graph, scope = _graph(
        tmp_path,
        approved_scope,
        {
            "shop/app.py": """
from flask import Flask
from .service import load_invoice
app = Flask(__name__)
@app.get('/invoice/<invoice_id>')
def invoice(invoice_id):
    return load_invoice(invoice_id)
""",
            "shop/service.py": """
def load_invoice(invoice_id):
    return Invoice.query.get(invoice_id)
""",
            "broken.py": "def invalid(:\n",
        },
    )
    generator = CandidateGenerator()
    first = generator.generate(graph, scope=scope, now=now)
    second = generator.generate(graph, scope=scope, now=now)

    assert first == second
    assert len(first.candidates) == 1
    candidate = first.candidates[0]
    assert candidate.cwe == "CWE-639"
    assert candidate.source_graph_id == graph.graph_id
    assert candidate.target_version == graph.target_version
    assert candidate.scope_id == scope.scope_id
    assert len(candidate.signal_ids) == 2
    assert candidate.entry_point.path == "shop/app.py"
    assert candidate.sink.path == "shop/service.py"
    assert "ownership" in candidate.cheapest_disproof
    assert len(first.excluded_signal_ids) == 1


def test_guarded_object_lookup_is_not_promoted_to_candidate(tmp_path, approved_scope, now):
    graph, scope = _graph(
        tmp_path,
        approved_scope,
        {
            "app.py": """
from flask import Flask
app = Flask(__name__)
@app.get('/item/<item_id>')
def item(item_id):
    value = Item.query.get(item_id)
    if value.owner_id != current_user.id:
        raise PermissionError()
    return value
""",
        },
    )
    result = CandidateGenerator().generate(graph, scope=scope, now=now)
    assert result.candidates == ()
    assert set(result.excluded_signal_ids) == {item.signal_id for item in graph.signals}


@pytest.mark.parametrize("failure", ["draft", "expired", "scope", "digest", "signal"])
def test_candidate_generation_fails_closed(tmp_path, approved_scope, now, failure):
    graph, scope = _graph(
        tmp_path,
        approved_scope,
        {
            "app.py": """
from flask import Flask
app = Flask(__name__)
@app.get('/fetch')
def fetch():
    return Item.query.get(request.args.get('id'))
""",
        },
    )
    if failure == "draft":
        scope = scope.model_copy(update={"state": ScopeState.DRAFT})
    elif failure == "expired":
        now = scope.valid_until
    elif failure == "scope":
        scope = scope.model_copy(update={"scope_id": uuid4()})
    elif failure == "digest":
        graph = graph.model_copy(update={"analyzer_version": "forged"})
    elif failure == "signal":
        bad_signal = graph.signals[0].model_copy(update={"target_id": uuid4()})
        partial = graph.model_copy(update={"graph_id": "0" * 64, "signals": (bad_signal,)})
        graph = partial.model_copy(update={"graph_id": source_graph_digest(partial)})

    with pytest.raises(CandidateGenerationError):
        CandidateGenerator().generate(graph, scope=scope, now=now)


def test_candidate_generation_limits_and_timeout(tmp_path, approved_scope, now, monkeypatch):
    graph, scope = _graph(
        tmp_path,
        approved_scope,
        {
            "app.py": """
from flask import Flask
app = Flask(__name__)
@app.get('/fetch')
def fetch():
    return Item.query.get(request.args.get('id'))
""",
        },
    )
    with pytest.raises(CandidateGenerationError, match="signal count"):
        CandidateGenerator(CandidateGeneratorLimits(max_signals=1)).generate(
            graph, scope=scope, now=now
        )

    many_root = tmp_path / "many"
    many_root.mkdir()
    many_graph, many_scope = _graph(
        many_root,
        approved_scope,
        {
            "app.py": """
from flask import Flask
app = Flask(__name__)
@app.get('/a/<name>')
def first(name):
    return open(name).read()
@app.get('/b/<name>')
def second(name):
    return open(name).read()
""",
        },
    )
    with pytest.raises(CandidateGenerationError, match="Candidate count"):
        CandidateGenerator(CandidateGeneratorLimits(max_candidates=1)).generate(
            many_graph, scope=many_scope, now=now
        )

    ticks = iter((0.0, 2.0))
    monkeypatch.setattr("vulnloom.hypotheses.generator.time.monotonic", lambda: next(ticks))
    with pytest.raises(CandidateGenerationError, match="timed out"):
        CandidateGenerator(CandidateGeneratorLimits(timeout_seconds=1)).generate(
            graph, scope=scope, now=now
        )


def test_candidate_set_store_is_immutable_idempotent_and_cleans_up(tmp_path, approved_scope, now):
    graph, scope = _graph(
        tmp_path,
        approved_scope,
        {
            "app.py": """
from flask import Flask
app = Flask(__name__)
@app.get('/file/<name>')
def download(name):
    return open(name).read()
""",
        },
    )
    candidate_set = CandidateGenerator().generate(graph, scope=scope, now=now)
    raw = candidate_set.model_dump(mode="python")
    raw["candidates"][0]["target_id"] = uuid4()
    with pytest.raises(ValueError, match="provenance"):
        CandidateSet.model_validate(raw)

    store = CandidateSetStore(tmp_path / "candidates")
    path, created = store.put(candidate_set)
    repeated_path, repeated_created = store.put(candidate_set)

    assert created is True
    assert repeated_created is False
    assert repeated_path == path
    assert store.load(candidate_set.candidate_set_id) == candidate_set
    assert list((tmp_path / "candidates").glob("candidates-*")) == []
    with pytest.raises(ValueError, match="invalid"):
        store.load("../escape")

    outside = tmp_path / "outside.json"
    outside.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(outside)
    with pytest.raises(ValueError, match="unsafe"):
        store.load(candidate_set.candidate_set_id)

    small_store = CandidateSetStore(tmp_path / "small", max_set_bytes=1)
    with pytest.raises(ValueError, match="size limit"):
        small_store.put(candidate_set)
    assert list((tmp_path / "small").iterdir()) == []
