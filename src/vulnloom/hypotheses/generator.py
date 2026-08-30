"""Fail-closed, deterministic Candidate generation from a trusted SourceGraph."""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from datetime import datetime
from uuid import UUID, uuid5

from pydantic import Field

from vulnloom.analyzers.models import (
    SignalKind,
    SinkKind,
    SourceGraph,
    StaticSignal,
    source_graph_digest,
)
from vulnloom.domain.models import Candidate, DomainModel, Scope, ScopeState

from .models import CandidateSet, candidate_set_digest


class CandidateGenerationError(ValueError):
    """The graph cannot safely or completely be converted into Candidates."""


class CandidateGeneratorLimits(DomainModel):
    max_signals: int = Field(default=10_000, ge=1)
    max_candidates: int = Field(default=2_000, ge=1)
    timeout_seconds: float = Field(default=30.0, gt=0)


_NAMESPACE = UUID("47d4b18d-05bf-5d58-9c3d-d8753e364cee")
_GENERATOR_VERSION = "python-web-hypothesis-v1"

_SINK_DETAILS: dict[SinkKind, tuple[str, str, str, str]] = {
    SinkKind.SQL: (
        "CWE-89",
        "User-controlled input reaches a SQL execution sink",
        "Untrusted request values must not alter SQL query structure",
        "Confirm that the query uses parameter binding for every traced input",
    ),
    SinkKind.COMMAND: (
        "CWE-78",
        "User-controlled input reaches an OS command sink",
        "Request values must not control executable command syntax",
        "Confirm that no shell is used and every argument is fixed or strictly allowlisted",
    ),
    SinkKind.FILE: (
        "CWE-22",
        "User-controlled input reaches a filesystem sink",
        "Request values must resolve only inside the intended filesystem root",
        "Confirm canonical-path containment after all decoding and link resolution",
    ),
    SinkKind.NETWORK: (
        "CWE-918",
        "User-controlled input reaches a server-side network sink",
        "Request values must not select unauthorized outbound destinations",
        "Confirm destination validation after redirects and DNS resolution",
    ),
    SinkKind.TEMPLATE: (
        "CWE-1336",
        "User-controlled input reaches a template evaluation sink",
        "Untrusted input must be rendered as data rather than template syntax",
        "Confirm that the template source is fixed and only values are interpolated",
    ),
    SinkKind.DESERIALIZATION: (
        "CWE-502",
        "User-controlled input reaches an unsafe deserialization sink",
        "Untrusted bytes must not instantiate attacker-selected objects",
        "Confirm that the parser accepts only a non-executable schema and safe types",
    ),
    SinkKind.REDIRECT: (
        "CWE-601",
        "User-controlled input reaches a redirect sink",
        "Redirect destinations must remain within an explicitly trusted origin set",
        "Confirm canonical destination validation for absolute, relative, and encoded URLs",
    ),
}


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


class CandidateGenerator:
    def __init__(self, limits: CandidateGeneratorLimits | None = None):
        self.limits = limits or CandidateGeneratorLimits()

    def generate(
        self,
        graph: SourceGraph,
        *,
        scope: Scope,
        now: datetime,
    ) -> CandidateSet:
        started = time.monotonic()
        self._authorize(graph, scope, now)
        if len(graph.signals) > self.limits.max_signals:
            raise CandidateGenerationError("SourceGraph exceeds the signal count limit")

        routes = {item.route_id: item for item in graph.routes}
        sinks = {item.sink_id: item for item in graph.sinks}
        flows = {item.flow_id: item for item in graph.flows}
        functions = {item.symbol: item.location for item in graph.functions}
        grouped: dict[tuple[str, str], list[StaticSignal]] = defaultdict(list)
        excluded: set[str] = set()
        for signal in graph.signals:
            self._deadline(started)
            if signal.target_id != graph.target_id:
                raise CandidateGenerationError("StaticSignal belongs to another Target")
            if not signal.route_id or not signal.sink_id or not signal.flow_id:
                excluded.add(signal.signal_id)
                continue
            if signal.route_id not in routes or signal.sink_id not in sinks:
                raise CandidateGenerationError("StaticSignal references a missing graph node")
            flow = flows.get(signal.flow_id)
            if flow is None or flow.route_id != signal.route_id or flow.sink_id != signal.sink_id:
                raise CandidateGenerationError("StaticSignal and DataFlowPath disagree")
            grouped[(signal.route_id, signal.sink_id)].append(signal)

        candidates = []
        for key in sorted(grouped):
            self._deadline(started)
            route = routes[key[0]]
            sink = sinks[key[1]]
            signals = grouped[key]
            flow = min(
                (flows[item.flow_id] for item in signals if item.flow_id),
                key=lambda item: item.flow_id,
            )
            candidate = self._candidate(graph, route, sink, flow, signals, functions)
            if candidate is None:
                excluded.update(item.signal_id for item in signals)
                continue
            candidates.append(candidate)
            if len(candidates) > self.limits.max_candidates:
                raise CandidateGenerationError("Candidate count exceeds the configured limit")

        candidates.sort(key=lambda item: (item.duplicate_fingerprint, str(item.candidate_id)))
        partial = CandidateSet(
            candidate_set_id="0" * 64,
            source_graph_id=graph.graph_id,
            target_id=graph.target_id,
            target_version=graph.target_version,
            scope_id=graph.scope_id,
            scope_version=graph.scope_version,
            generator_version=_GENERATOR_VERSION,
            candidates=tuple(candidates),
            excluded_signal_ids=tuple(sorted(excluded)),
        )
        return partial.model_copy(update={"candidate_set_id": candidate_set_digest(partial)})

    @staticmethod
    def _authorize(graph: SourceGraph, scope: Scope, now: datetime) -> None:
        if source_graph_digest(graph) != graph.graph_id:
            raise CandidateGenerationError("SourceGraph content digest mismatch")
        if scope.state is not ScopeState.APPROVED:
            raise CandidateGenerationError("Candidate generation requires an approved Scope")
        if not scope.valid_from <= now < scope.valid_until:
            raise CandidateGenerationError(
                "Candidate generation is outside the Scope validity window"
            )
        if graph.scope_id != scope.scope_id or graph.scope_version != scope.version:
            raise CandidateGenerationError("SourceGraph is bound to another Scope version")

    def _deadline(self, started: float) -> None:
        if time.monotonic() - started > self.limits.timeout_seconds:
            raise CandidateGenerationError("Candidate generation timed out")

    @staticmethod
    def _candidate(graph, route, sink, flow, signals, functions) -> Candidate | None:
        kinds = {item.kind for item in signals}
        if sink.kind is SinkKind.OBJECT_LOOKUP:
            if SignalKind.OBJECT_LOOKUP_WITHOUT_VISIBLE_AUTHORIZATION not in kinds:
                return None
            details = (
                "CWE-639",
                "Object lookup may omit an ownership or authorization constraint",
                "A caller may access only objects authorized for its identity or tenant",
                "Show a mandatory ownership or authorization predicate on every "
                "reachable lookup path",
            )
        else:
            details = _SINK_DETAILS.get(sink.kind)
            if details is None or SignalKind.TAINTED_SINK not in kinds:
                return None
        cwe, title, invariant, disproof = details
        fingerprint = _digest(
            {
                "cwe": cwe,
                "route": {"methods": route.http_methods, "path": route.path},
                "sink": {"kind": sink.kind.value, "callee": sink.callee},
                "chain": flow.call_chain,
            }
        )
        signal_ids = tuple(sorted(item.signal_id for item in signals))
        candidate_id = uuid5(_NAMESPACE, f"{graph.graph_id}:{fingerprint}:{','.join(signal_ids)}")
        path = [route.location]
        path.extend(functions[symbol] for symbol in flow.call_chain if symbol in functions)
        path.append(sink.location)
        code_path = tuple(dict.fromkeys(path))
        sources = ", ".join(flow.source_names)
        return Candidate(
            candidate_id=candidate_id,
            target_id=graph.target_id,
            target_version=graph.target_version,
            source_graph_id=graph.graph_id,
            scope_id=graph.scope_id,
            scope_version=graph.scope_version,
            title=title,
            cwe=cwe,
            entry_point=route.location,
            sink=sink.location,
            code_path=code_path,
            preconditions=(
                f"The route {','.join(route.http_methods)} {route.path} is reachable",
                f"Attacker-controlled input reaches the sink through: {sources}",
            ),
            security_invariant=invariant,
            hypothesis=(
                f"Route {route.path} propagates {sources} to {sink.kind.value} sink "
                f"{sink.callee}; static analysis does not prove exploitability"
            ),
            signal_ids=signal_ids,
            cheapest_disproof=disproof,
            duplicate_fingerprint=fingerprint,
            confidence=min(item.confidence for item in signals),
        )
