"""Structured output of source mapping; none of these objects is a Finding."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from uuid import UUID

from pydantic import Field

from vulnloom.domain.models import DomainModel, SourceLocation


class WebFramework(StrEnum):
    FLASK = "flask"
    FASTAPI = "fastapi"
    DJANGO = "django"
    STARLETTE = "starlette"
    UNKNOWN = "unknown"


class GuardKind(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    OWNERSHIP = "ownership"
    INPUT_VALIDATION = "input_validation"
    CSRF = "csrf"


class SinkKind(StrEnum):
    OBJECT_LOOKUP = "object_lookup"
    SQL = "sql"
    COMMAND = "command"
    FILE = "file"
    NETWORK = "network"
    TEMPLATE = "template"
    DESERIALIZATION = "deserialization"
    REDIRECT = "redirect"


class SignalKind(StrEnum):
    TAINTED_SINK = "tainted_sink"
    OBJECT_LOOKUP_WITHOUT_VISIBLE_AUTHORIZATION = "object_lookup_without_visible_authorization"
    PARSE_FAILURE = "parse_failure"
    EXTERNAL_ANALYZER = "external_analyzer"


class FunctionNode(DomainModel):
    symbol: str = Field(min_length=1)
    location: SourceLocation
    parameters: tuple[str, ...]
    decorators: tuple[str, ...] = ()


class RouteNode(DomainModel):
    route_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    framework: WebFramework
    http_methods: tuple[str, ...]
    path: str
    handler_symbol: str
    location: SourceLocation
    input_names: tuple[str, ...]
    dependency_names: tuple[str, ...] = ()


class CallEdge(DomainModel):
    caller_symbol: str
    callee: str
    resolved_symbol: str | None = None
    location: SourceLocation


class GuardNode(DomainModel):
    guard_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    function_symbol: str
    kind: GuardKind
    mechanism: str
    location: SourceLocation


class SinkNode(DomainModel):
    sink_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    function_symbol: str
    kind: SinkKind
    callee: str
    location: SourceLocation


class DataFlowPath(DomainModel):
    flow_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    route_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_names: tuple[str, ...]
    call_chain: tuple[str, ...]
    sink_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    guard_ids: tuple[str, ...] = ()
    confidence: float = Field(ge=0, le=1)


class ParseFailure(DomainModel):
    path: str
    line: int | None = Field(default=None, ge=1)
    error_type: str


class StaticSignal(DomainModel):
    signal_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_id: UUID
    kind: SignalKind
    rule_id: str
    summary: str
    locations: tuple[SourceLocation, ...]
    route_id: str | None = None
    sink_id: str | None = None
    flow_id: str | None = None
    confidence: float = Field(ge=0, le=1)
    limitations: tuple[str, ...] = ()


class SourceGraph(DomainModel):
    graph_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_id: UUID
    target_version: str
    scope_id: UUID
    scope_version: int = Field(ge=1)
    manifest_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    analyzer_version: str
    files_analyzed: tuple[str, ...]
    functions: tuple[FunctionNode, ...]
    routes: tuple[RouteNode, ...]
    calls: tuple[CallEdge, ...]
    guards: tuple[GuardNode, ...]
    sinks: tuple[SinkNode, ...]
    flows: tuple[DataFlowPath, ...]
    signals: tuple[StaticSignal, ...]
    parse_failures: tuple[ParseFailure, ...] = ()


def source_graph_digest(graph: SourceGraph) -> str:
    payload = graph.model_dump(mode="json", exclude={"graph_id"})
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()
