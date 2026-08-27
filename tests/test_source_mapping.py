from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

import pytest

from vulnloom.analyzers import (
    AnalyzerAdapterError,
    PythonWebSourceMapper,
    SemgrepAdapter,
    SourceGraphStore,
    SourceMapperLimits,
    SourceMappingError,
)
from vulnloom.analyzers.models import GuardKind, SignalKind, SinkKind, WebFramework
from vulnloom.domain.models import ArtifactKind, ArtifactScope
from vulnloom.ingestion import IngestionError, IngestionService


def _snapshot(tmp_path: Path, approved_scope, files: dict[str, str]):
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
    store = tmp_path / "targets"
    snapshot = IngestionService(store).ingest_archive(archive, scope=scope)
    return snapshot, store


def test_flask_cross_file_route_call_taint_and_object_lookup(tmp_path, approved_scope):
    snapshot, store = _snapshot(
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
from .models import Invoice

def load_invoice(invoice_id):
    return Invoice.query.get(invoice_id)
""",
            "shop/models.py": "class Invoice: pass\n",
        },
    )

    graph = PythonWebSourceMapper().analyze(snapshot, store)

    assert graph.routes[0].framework is WebFramework.FLASK
    assert graph.routes[0].input_names == ("invoice_id",)
    assert any(edge.resolved_symbol == "shop.service.load_invoice" for edge in graph.calls)
    assert graph.sinks[0].kind is SinkKind.OBJECT_LOOKUP
    assert graph.flows[0].call_chain == ("shop.app.invoice", "shop.service.load_invoice")
    assert graph.flows[0].source_names == ("invoice_id",)
    assert {signal.kind for signal in graph.signals} == {
        SignalKind.TAINTED_SINK,
        SignalKind.OBJECT_LOOKUP_WITHOUT_VISIBLE_AUTHORIZATION,
    }
    assert PythonWebSourceMapper().analyze(snapshot, store) == graph


def test_fastapi_dependencies_are_guards_not_taint_sources(tmp_path, approved_scope):
    snapshot, store = _snapshot(
        tmp_path,
        approved_scope,
        {
            "api.py": """
from fastapi import APIRouter, Depends
router = APIRouter()

def get_current_user(): pass
def get_db(): pass

@router.get('/items/{item_id}')
def item(item_id, user=Depends(get_current_user), db=Depends(get_db)):
    return db.query.get(item_id)
""",
        },
    )

    graph = PythonWebSourceMapper().analyze(snapshot, store)

    route = graph.routes[0]
    assert route.framework is WebFramework.FASTAPI
    assert route.input_names == ("item_id",)
    assert route.dependency_names == ("api.get_current_user", "api.get_db")
    assert {guard.kind for guard in graph.guards} == {GuardKind.AUTHENTICATION}
    assert graph.flows[0].source_names == ("item_id",)
    assert SignalKind.OBJECT_LOOKUP_WITHOUT_VISIBLE_AUTHORIZATION in {
        signal.kind for signal in graph.signals
    }


def test_django_urlpatterns_and_ownership_guard(tmp_path, approved_scope):
    snapshot, store = _snapshot(
        tmp_path,
        approved_scope,
        {
            "docs/urls.py": """
from django.urls import path
from . import views
urlpatterns = [path('doc/<int:doc_id>/', views.detail)]
""",
            "docs/views.py": """
from django.shortcuts import get_object_or_404

def detail(request, doc_id):
    document = get_object_or_404(Document, id=doc_id)
    if document.owner_id != request.user.id:
        raise PermissionError()
    return document
""",
        },
    )

    graph = PythonWebSourceMapper().analyze(snapshot, store)

    assert graph.routes[0].framework is WebFramework.DJANGO
    assert graph.routes[0].handler_symbol == "docs.views.detail"
    assert any(guard.kind is GuardKind.OWNERSHIP for guard in graph.guards)
    assert any(sink.kind is SinkKind.OBJECT_LOOKUP for sink in graph.sinks)
    assert SignalKind.OBJECT_LOOKUP_WITHOUT_VISIBLE_AUTHORIZATION not in {
        signal.kind for signal in graph.signals
    }


def test_request_source_parse_failure_integrity_and_limits(tmp_path, approved_scope):
    snapshot, store = _snapshot(
        tmp_path,
        approved_scope,
        {
            "app.py": """
from flask import Flask, request
import requests
app = Flask(__name__)
@app.get('/fetch')
def fetch():
    return requests.get(request.args.get('url'))
""",
            "broken.py": "def nope(:\n",
        },
    )
    graph = PythonWebSourceMapper().analyze(snapshot, store)
    assert graph.flows[0].source_names == ("request.args.get",)
    assert any(signal.kind is SignalKind.PARSE_FAILURE for signal in graph.signals)

    source = store / snapshot.root_ref / "app.py"
    source.chmod(0o600)
    source.write_text("pass\n", encoding="utf-8")
    with pytest.raises(SourceMappingError, match="integrity"):
        PythonWebSourceMapper().analyze(snapshot, store)
    with pytest.raises(SourceMappingError, match="count limit"):
        PythonWebSourceMapper(SourceMapperLimits(max_python_files=1)).analyze(snapshot, store)


def test_source_mapper_timeout_fails_closed(tmp_path, approved_scope):
    snapshot, store = _snapshot(tmp_path, approved_scope, {"app.py": "def f(): pass\n"})
    with pytest.raises(SourceMappingError, match="timed out"):
        PythonWebSourceMapper(SourceMapperLimits(timeout_seconds=1e-12)).analyze(snapshot, store)


def test_snapshot_loader_revalidates_identifier_and_files(tmp_path, approved_scope):
    snapshot, store = _snapshot(tmp_path, approved_scope, {"app.py": "pass\n"})
    service = IngestionService(store)
    assert service.load_snapshot(snapshot.manifest.manifest_id) == snapshot
    with pytest.raises(IngestionError, match="identifier"):
        service.load_snapshot("../snapshot")

    source = store / snapshot.root_ref / "app.py"
    source.chmod(0o600)
    source.write_text("changed\n", encoding="utf-8")
    with pytest.raises(IngestionError, match="integrity"):
        service.load_snapshot(snapshot.manifest.manifest_id)


def test_source_graph_store_is_immutable_and_idempotent(tmp_path, approved_scope):
    snapshot, target_store = _snapshot(tmp_path, approved_scope, {"app.py": "def f(): pass\n"})
    graph = PythonWebSourceMapper().analyze(snapshot, target_store)
    store = SourceGraphStore(tmp_path / "graphs")
    path, created = store.put(graph)
    repeated_path, repeated_created = store.put(graph)

    assert created is True
    assert repeated_created is False
    assert repeated_path == path
    assert store.load(graph.graph_id) == graph
    with pytest.raises(ValueError, match="invalid"):
        store.load("../escape")
    forged = graph.model_copy(update={"graph_id": "0" * 64})
    with pytest.raises(ValueError, match="digest mismatch"):
        store.put(forged)


def test_semgrep_adapter_uses_trusted_config_minimal_env_and_sanitizes_output(
    tmp_path, approved_scope, monkeypatch
):
    snapshot, store = _snapshot(tmp_path, approved_scope, {"app.py": "pass\n"})
    executable = tmp_path / "semgrep"
    executable.write_text("binary", encoding="utf-8")
    config = tmp_path / "rules.yml"
    config.write_text("rules: []\n", encoding="utf-8")
    captured = {}

    def fake_run(command, **kwargs):
        captured.update({"command": command, **kwargs})
        output = {
            "results": [
                {
                    "check_id": "python.example",
                    "path": "app.py",
                    "start": {"line": 1},
                    "extra": {"message": "  candidate   match  ", "severity": "WARNING"},
                }
            ]
        }
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(output), stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    root = store / snapshot.root_ref
    signals = SemgrepAdapter(executable, {"web": config}).analyze(snapshot, root, "web")

    assert signals[0].kind is SignalKind.EXTERNAL_ANALYZER
    assert signals[0].summary == "candidate match"
    assert set(captured["env"]) == {
        "LANG",
        "LC_ALL",
        "SEMGREP_SEND_METRICS",
        "SEMGREP_ENABLE_VERSION_CHECK",
    }
    assert "shell" not in captured
    with pytest.raises(AnalyzerAdapterError, match="unknown"):
        SemgrepAdapter(executable, {"web": config}).analyze(snapshot, root, "other")


def test_semgrep_adapter_rejects_timeout_bad_output_and_escaped_path(
    tmp_path, approved_scope, monkeypatch
):
    snapshot, store = _snapshot(tmp_path, approved_scope, {"app.py": "pass\n"})
    executable = tmp_path / "semgrep"
    executable.write_text("binary", encoding="utf-8")
    config = tmp_path / "rules.yml"
    config.write_text("rules: []\n", encoding="utf-8")
    adapter = SemgrepAdapter(executable, {"web": config}, max_output_bytes=100)
    root = store / snapshot.root_ref

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("semgrep", 1)

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(AnalyzerAdapterError, match="timed out"):
        adapter.analyze(snapshot, root, "web")

    def escaped(command, **_kwargs):
        output = {
            "results": [
                {
                    "check_id": "escape",
                    "path": "../outside.py",
                    "start": {"line": 1},
                    "extra": {},
                }
            ]
        }
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(output), stderr="")

    monkeypatch.setattr(subprocess, "run", escaped)
    with pytest.raises(AnalyzerAdapterError, match="escapes"):
        adapter.analyze(snapshot, root, "web")

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, stdout=json.dumps({"results": []}) + "x" * 101, stderr=""
        ),
    )
    with pytest.raises(AnalyzerAdapterError, match="output exceeds"):
        adapter.analyze(snapshot, root, "web")
