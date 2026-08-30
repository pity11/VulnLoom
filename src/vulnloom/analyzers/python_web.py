"""Deterministic Python Web source mapper.

The mapper parses a verified M1 Target Snapshot with the standard-library AST.
It never imports or executes target code. Results are security signals and
trace hypotheses, not vulnerability Findings.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import Field

from vulnloom.domain.models import DomainModel, Scope, SourceLocation, TargetSnapshot
from vulnloom.ingestion import IngestionService

from .models import (
    CallEdge,
    DataFlowPath,
    FunctionNode,
    GuardKind,
    GuardNode,
    ParseFailure,
    RouteNode,
    SignalKind,
    SinkKind,
    SinkNode,
    SourceGraph,
    StaticSignal,
    WebFramework,
)

ANALYZER_VERSION = "python-web-ast-v1"
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "websocket"}
_AUTH_WORDS = ("auth", "login", "current_user", "authenticated", "jwt", "token")
_AUTHZ_WORDS = ("permission", "authorize", "authorise", "allowed", "has_perm", "require_role")
_OWNERSHIP_WORDS = ("owner", "tenant", "organization", "organisation", "account_id")


class SourceMappingError(ValueError):
    pass


class SourceMapperLimits(DomainModel):
    max_python_files: int = Field(default=5_000, gt=0)
    max_single_file_bytes: int = Field(default=2 * 1024 * 1024, gt=0)
    max_total_bytes: int = Field(default=50 * 1024 * 1024, gt=0)
    max_call_depth: int = Field(default=12, gt=0, le=100)
    timeout_seconds: float = Field(default=60, gt=0, le=3600)


@dataclass
class _ModuleInfo:
    path: str
    name: str
    tree: ast.Module
    imports: dict[str, str]
    framework_bindings: dict[str, WebFramework]


@dataclass
class _FunctionInfo:
    symbol: str
    module: _ModuleInfo
    node: ast.FunctionDef | ast.AsyncFunctionDef
    class_name: str | None
    parameters: tuple[str, ...]
    dependency_parameters: tuple[str, ...]
    dependency_names: tuple[str, ...]
    decorators: tuple[str, ...]


@dataclass
class _StaticIndex:
    functions: dict[str, _FunctionInfo] = field(default_factory=dict)
    routes: list[RouteNode] = field(default_factory=list)
    calls: list[CallEdge] = field(default_factory=list)
    guards: list[GuardNode] = field(default_factory=list)
    sinks: list[SinkNode] = field(default_factory=list)
    sink_by_site: dict[tuple[str, int, int], SinkNode] = field(default_factory=dict)
    guard_ids_by_function: dict[str, tuple[str, ...]] = field(default_factory=dict)


class _Deadline:
    def __init__(self, seconds: float):
        self.ends_at = time.monotonic() + seconds

    def check(self) -> None:
        if time.monotonic() >= self.ends_at:
            raise SourceMappingError("source mapping timed out")


class PythonWebSourceMapper:
    def __init__(self, limits: SourceMapperLimits | None = None):
        self.limits = limits or SourceMapperLimits()

    def analyze(
        self,
        snapshot: TargetSnapshot,
        store_root: Path,
        *,
        scope: Scope,
        now=None,
    ) -> SourceGraph:
        deadline = _Deadline(self.limits.timeout_seconds)
        IngestionService.require_snapshot_scope(snapshot, scope, now)
        root = self._snapshot_root(snapshot, store_root)
        modules, failures, files = self._parse_modules(snapshot, root, deadline)
        index = self._build_index(modules, deadline)
        flows = _FlowTracer(index, self.limits, deadline).trace()
        signals = self._signals(snapshot, index, flows, failures)
        functions = tuple(
            FunctionNode(
                symbol=info.symbol,
                location=_location(info.module.path, info.node, info.symbol),
                parameters=info.parameters,
                decorators=info.decorators,
            )
            for info in sorted(index.functions.values(), key=lambda item: item.symbol)
        )
        payload: dict[str, Any] = {
            "target_id": str(snapshot.target.target_id),
            "target_version": snapshot.target.version,
            "scope_id": str(scope.scope_id),
            "scope_version": scope.version,
            "manifest_id": snapshot.manifest.manifest_id,
            "analyzer_version": ANALYZER_VERSION,
            "files_analyzed": files,
            "functions": [item.model_dump(mode="json") for item in functions],
            "routes": [item.model_dump(mode="json") for item in index.routes],
            "calls": [item.model_dump(mode="json") for item in index.calls],
            "guards": [item.model_dump(mode="json") for item in index.guards],
            "sinks": [item.model_dump(mode="json") for item in index.sinks],
            "flows": [item.model_dump(mode="json") for item in flows],
            "signals": [item.model_dump(mode="json") for item in signals],
            "parse_failures": [item.model_dump(mode="json") for item in failures],
        }
        graph_id = _digest(payload)
        return SourceGraph(graph_id=graph_id, **payload)

    @staticmethod
    def _snapshot_root(snapshot: TargetSnapshot, store_root: Path) -> Path:
        if snapshot.root_ref is None:
            raise SourceMappingError("source mapping requires a filesystem Target Snapshot")
        store_root = store_root.resolve()
        root = (store_root / snapshot.root_ref).resolve()
        if root == store_root or store_root not in root.parents or not root.is_dir():
            raise SourceMappingError("Target Snapshot root is unavailable or escapes the store")
        return root

    def _parse_modules(
        self,
        snapshot: TargetSnapshot,
        root: Path,
        deadline: _Deadline,
    ) -> tuple[tuple[_ModuleInfo, ...], tuple[ParseFailure, ...], tuple[str, ...]]:
        python_files = tuple(
            item for item in snapshot.manifest.files if item.path.casefold().endswith(".py")
        )
        if len(python_files) > self.limits.max_python_files:
            raise SourceMappingError("snapshot exceeds Python file count limit")
        total = 0
        modules = []
        failures = []
        analyzed = []
        for item in sorted(python_files, key=lambda value: value.path):
            deadline.check()
            if item.size > self.limits.max_single_file_bytes:
                raise SourceMappingError(f"Python source exceeds single-file limit: {item.path}")
            total += item.size
            if total > self.limits.max_total_bytes:
                raise SourceMappingError("snapshot exceeds total Python source size limit")
            path = root.joinpath(*PurePosixPath(item.path).parts)
            content = self._read_verified(path, item.size, item.sha256)
            analyzed.append(item.path)
            try:
                text = content.decode("utf-8", "strict")
                tree = ast.parse(text, filename=item.path, type_comments=True)
            except UnicodeDecodeError:
                failures.append(ParseFailure(path=item.path, error_type="UnicodeDecodeError"))
                continue
            except SyntaxError as exc:
                failures.append(
                    ParseFailure(
                        path=item.path,
                        line=exc.lineno,
                        error_type="SyntaxError",
                    )
                )
                continue
            module_name = _module_name(item.path)
            imports = _imports(tree, module_name, item.path)
            modules.append(
                _ModuleInfo(
                    path=item.path,
                    name=module_name,
                    tree=tree,
                    imports=imports,
                    framework_bindings=_framework_bindings(tree, imports),
                )
            )
        return tuple(modules), tuple(failures), tuple(analyzed)

    @staticmethod
    def _read_verified(path: Path, expected_size: int, expected_digest: str) -> bytes:
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise SourceMappingError("manifest source file is unavailable") from exc
        if not stat.S_ISREG(mode) or path.is_symlink():
            raise SourceMappingError("manifest source path is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise SourceMappingError("manifest source file cannot be opened safely") from exc
        with os.fdopen(fd, "rb") as handle:
            content = handle.read(expected_size + 1)
        if len(content) != expected_size or hashlib.sha256(content).hexdigest() != expected_digest:
            raise SourceMappingError("manifest source file failed integrity check")
        return content

    def _build_index(self, modules: tuple[_ModuleInfo, ...], deadline: _Deadline) -> _StaticIndex:
        index = _StaticIndex()
        for module in modules:
            deadline.check()
            for info in _module_functions(module):
                index.functions[info.symbol] = info

        resolver = _SymbolResolver(index.functions)
        for module in modules:
            deadline.check()
            index.routes.extend(_decorated_routes(module, index.functions))
            index.routes.extend(_django_routes(module, resolver))

        for info in index.functions.values():
            deadline.check()
            calls = _function_calls(info.node)
            for call in calls:
                raw = _dotted(call.func)
                normalized = _normalize_name(raw, info.module.imports)
                resolved = resolver.resolve(info, normalized)
                index.calls.append(
                    CallEdge(
                        caller_symbol=info.symbol,
                        callee=normalized or raw or "<dynamic>",
                        resolved_symbol=resolved,
                        location=_location(info.module.path, call, info.symbol),
                    )
                )
                sink_kind = _sink_kind(normalized or raw)
                if sink_kind is not None:
                    sink = SinkNode(
                        sink_id=_digest(
                            {
                                "symbol": info.symbol,
                                "path": info.module.path,
                                "line": call.lineno,
                                "column": call.col_offset,
                                "kind": sink_kind.value,
                                "callee": normalized or raw,
                            }
                        ),
                        function_symbol=info.symbol,
                        kind=sink_kind,
                        callee=normalized or raw,
                        location=_location(info.module.path, call, info.symbol),
                    )
                    index.sinks.append(sink)
                    index.sink_by_site[(info.symbol, call.lineno, call.col_offset)] = sink
            index.guards.extend(_function_guards(info))

        index.routes.sort(key=lambda item: (item.location.path, item.location.line, item.path))
        index.calls.sort(
            key=lambda item: (item.location.path, item.location.line, item.location.symbol or "")
        )
        index.guards.sort(
            key=lambda item: (item.location.path, item.location.line, item.kind.value)
        )
        index.sinks.sort(key=lambda item: (item.location.path, item.location.line, item.kind.value))
        grouped: dict[str, list[str]] = defaultdict(list)
        for guard in index.guards:
            grouped[guard.function_symbol].append(guard.guard_id)
        index.guard_ids_by_function = {
            symbol: tuple(
                sorted(
                    guard.guard_id
                    for guard in index.guards
                    if guard.function_symbol == symbol
                    and guard.mechanism.startswith(("decorator:", "dependency:"))
                )
            )
            for symbol in grouped
        }
        return index

    @staticmethod
    def _signals(
        snapshot: TargetSnapshot,
        index: _StaticIndex,
        flows: tuple[DataFlowPath, ...],
        failures: tuple[ParseFailure, ...],
    ) -> tuple[StaticSignal, ...]:
        routes = {item.route_id: item for item in index.routes}
        sinks = {item.sink_id: item for item in index.sinks}
        guards = {item.guard_id: item for item in index.guards}
        signals = []
        for flow in flows:
            route = routes[flow.route_id]
            sink = sinks[flow.sink_id]
            locations = (route.location, sink.location)
            signals.append(
                StaticSignal(
                    signal_id=_digest({"rule": "web.tainted-sink.v1", "flow": flow.flow_id}),
                    target_id=snapshot.target.target_id,
                    kind=SignalKind.TAINTED_SINK,
                    rule_id="web.tainted-sink.v1",
                    summary=(
                        f"Route {route.path} has a statically traced input path to "
                        f"{sink.kind.value} sink {sink.callee}"
                    ),
                    locations=locations,
                    route_id=route.route_id,
                    sink_id=sink.sink_id,
                    flow_id=flow.flow_id,
                    confidence=flow.confidence,
                    limitations=(
                        "Static taint does not prove exploitability or missing runtime validation.",
                    ),
                )
            )
            visible_guard_kinds = {
                guards[guard_id].kind for guard_id in flow.guard_ids if guard_id in guards
            }
            if sink.kind is SinkKind.OBJECT_LOOKUP and not visible_guard_kinds.intersection(
                {GuardKind.AUTHORIZATION, GuardKind.OWNERSHIP}
            ):
                signals.append(
                    StaticSignal(
                        signal_id=_digest(
                            {"rule": "web.object-lookup-no-visible-authz.v1", "flow": flow.flow_id}
                        ),
                        target_id=snapshot.target.target_id,
                        kind=SignalKind.OBJECT_LOOKUP_WITHOUT_VISIBLE_AUTHORIZATION,
                        rule_id="web.object-lookup-no-visible-authz.v1",
                        summary=(
                            f"Route {route.path} reaches object lookup {sink.callee} without a "
                            "visible ownership or authorization guard on the traced call chain"
                        ),
                        locations=locations,
                        route_id=route.route_id,
                        sink_id=sink.sink_id,
                        flow_id=flow.flow_id,
                        confidence=min(flow.confidence, 0.72),
                        limitations=(
                            "Framework middleware, model managers, or runtime policy may "
                            "enforce access.",
                        ),
                    )
                )
        for failure in failures:
            location = SourceLocation(path=failure.path, line=failure.line or 1)
            signals.append(
                StaticSignal(
                    signal_id=_digest(
                        {
                            "rule": "source.parse-failure.v1",
                            "path": failure.path,
                            "line": failure.line,
                        }
                    ),
                    target_id=snapshot.target.target_id,
                    kind=SignalKind.PARSE_FAILURE,
                    rule_id="source.parse-failure.v1",
                    summary=f"Python source could not be parsed: {failure.error_type}",
                    locations=(location,),
                    confidence=1.0,
                    limitations=("The affected file is absent from call and data-flow analysis.",),
                )
            )
        return tuple(sorted(signals, key=lambda item: item.signal_id))


class _SymbolResolver:
    def __init__(self, functions: dict[str, _FunctionInfo]):
        self.functions = functions
        suffixes: dict[str, list[str]] = defaultdict(list)
        for symbol in functions:
            suffixes[symbol.rsplit(".", 1)[-1]].append(symbol)
        self.unique_suffix = {
            name: values[0] for name, values in suffixes.items() if len(values) == 1
        }

    def resolve(self, caller: _FunctionInfo, name: str) -> str | None:
        if not name:
            return None
        if name.startswith("self.") and caller.class_name:
            candidate = f"{caller.module.name}.{caller.class_name}.{name.removeprefix('self.')}"
            if candidate in self.functions:
                return candidate
        if "." not in name:
            candidate = f"{caller.module.name}.{name}"
            if candidate in self.functions:
                return candidate
        if name in self.functions:
            return name
        return self.unique_suffix.get(name.rsplit(".", 1)[-1])


class _FlowTracer:
    def __init__(self, index: _StaticIndex, limits: SourceMapperLimits, deadline: _Deadline):
        self.index = index
        self.limits = limits
        self.deadline = deadline
        self.resolver = _SymbolResolver(index.functions)
        self.flows: dict[str, DataFlowPath] = {}

    def trace(self) -> tuple[DataFlowPath, ...]:
        for route in self.index.routes:
            info = self.index.functions.get(route.handler_symbol)
            if info is None:
                continue
            environment = {name: frozenset({name}) for name in route.input_names}
            self._function(
                route,
                info,
                environment,
                (info.symbol,),
                frozenset(),
                frozenset(),
            )
        return tuple(sorted(self.flows.values(), key=lambda item: item.flow_id))

    def _function(
        self,
        route: RouteNode,
        info: _FunctionInfo,
        environment: dict[str, frozenset[str]],
        chain: tuple[str, ...],
        inherited_guards: frozenset[str],
        active: frozenset[str],
    ) -> None:
        self.deadline.check()
        if len(chain) > self.limits.max_call_depth or info.symbol in active:
            return
        guards = inherited_guards.union(self.index.guard_ids_by_function.get(info.symbol, ()))
        self._block(
            route,
            info,
            info.node.body,
            dict(environment),
            chain,
            guards,
            active.union({info.symbol}),
            dominant_sequence=True,
        )

    def _block(
        self,
        route: RouteNode,
        info: _FunctionInfo,
        statements: list[ast.stmt],
        environment: dict[str, frozenset[str]],
        chain: tuple[str, ...],
        guards: frozenset[str],
        active: frozenset[str],
        *,
        dominant_sequence: bool,
    ) -> dict[str, frozenset[str]]:
        current_guards = guards
        for statement in statements:
            self.deadline.check()
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                value = statement.value
                self._expression(route, info, value, environment, chain, current_guards, active)
                dependencies = _expr_dependencies(value, environment)
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                for target in targets:
                    for name in _assigned_names(target):
                        environment[name] = dependencies
            elif isinstance(statement, ast.AugAssign):
                dependencies = environment.get(_dotted(statement.target), frozenset()).union(
                    _expr_dependencies(statement.value, environment)
                )
                for name in _assigned_names(statement.target):
                    environment[name] = frozenset(dependencies)
                self._expression(
                    route, info, statement.value, environment, chain, current_guards, active
                )
            elif isinstance(statement, ast.If):
                self._expression(
                    route, info, statement.test, environment, chain, current_guards, active
                )
                branch_guards = current_guards.union(
                    _guard_ids_at_line(self.index, info.symbol, statement.lineno)
                )
                left = self._block(
                    route,
                    info,
                    statement.body,
                    dict(environment),
                    chain,
                    branch_guards,
                    active,
                    dominant_sequence=False,
                )
                right = self._block(
                    route,
                    info,
                    statement.orelse,
                    dict(environment),
                    chain,
                    current_guards,
                    active,
                    dominant_sequence=False,
                )
                environment = _merge_environments(left, right)
                if dominant_sequence and _denial_branch_guards_following_code(statement):
                    current_guards = current_guards.union(branch_guards)
                    self._add_guards_to_existing_flows(chain, branch_guards)
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                self._expression(
                    route, info, statement.iter, environment, chain, current_guards, active
                )
                dependencies = _expr_dependencies(statement.iter, environment)
                loop_environment = dict(environment)
                for name in _assigned_names(statement.target):
                    loop_environment[name] = dependencies
                loop_environment = self._block(
                    route,
                    info,
                    statement.body,
                    loop_environment,
                    chain,
                    current_guards,
                    active,
                    dominant_sequence=False,
                )
                environment = _merge_environments(environment, loop_environment)
            elif isinstance(statement, ast.While):
                self._expression(
                    route, info, statement.test, environment, chain, current_guards, active
                )
                loop_environment = self._block(
                    route,
                    info,
                    statement.body,
                    dict(environment),
                    chain,
                    current_guards,
                    active,
                    dominant_sequence=False,
                )
                environment = _merge_environments(environment, loop_environment)
            elif isinstance(statement, ast.Try):
                branches = [
                    self._block(
                        route,
                        info,
                        statement.body,
                        dict(environment),
                        chain,
                        current_guards,
                        active,
                        dominant_sequence=False,
                    )
                ]
                branches.extend(
                    self._block(
                        route,
                        info,
                        handler.body,
                        dict(environment),
                        chain,
                        current_guards,
                        active,
                        dominant_sequence=False,
                    )
                    for handler in statement.handlers
                )
                environment = _merge_many(branches)
                environment = self._block(
                    route,
                    info,
                    statement.finalbody,
                    environment,
                    chain,
                    current_guards,
                    active,
                    dominant_sequence=False,
                )
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    self._expression(
                        route,
                        info,
                        item.context_expr,
                        environment,
                        chain,
                        current_guards,
                        active,
                    )
                environment = self._block(
                    route,
                    info,
                    statement.body,
                    environment,
                    chain,
                    current_guards,
                    active,
                    dominant_sequence=False,
                )
            else:
                for expression in _statement_expressions(statement):
                    self._expression(
                        route, info, expression, environment, chain, current_guards, active
                    )
            if not isinstance(statement, ast.If):
                current_guards = current_guards.union(
                    _guard_ids_at_line(
                        self.index,
                        info.symbol,
                        max(1, getattr(statement, "lineno", 1)),
                    )
                )
            if isinstance(statement, (ast.Return, ast.Raise)):
                break
        return environment

    def _add_guards_to_existing_flows(
        self, chain: tuple[str, ...], guard_ids: frozenset[str]
    ) -> None:
        for old_id, flow in tuple(self.flows.items()):
            if flow.call_chain[: len(chain)] != chain:
                continue
            combined = tuple(sorted(set(flow.guard_ids).union(guard_ids)))
            new_id = _digest(
                {
                    "route": flow.route_id,
                    "sources": sorted(flow.source_names),
                    "chain": flow.call_chain,
                    "sink": flow.sink_id,
                    "guards": list(combined),
                }
            )
            self.flows.pop(old_id)
            self.flows[new_id] = flow.model_copy(update={"flow_id": new_id, "guard_ids": combined})

    def _expression(
        self,
        route: RouteNode,
        info: _FunctionInfo,
        expression: ast.AST,
        environment: dict[str, frozenset[str]],
        chain: tuple[str, ...],
        guards: frozenset[str],
        active: frozenset[str],
    ) -> None:
        for child in ast.iter_child_nodes(expression):
            if not isinstance(child, (ast.Load, ast.Store, ast.Del, ast.expr_context)):
                self._expression(route, info, child, environment, chain, guards, active)
        if not isinstance(expression, ast.Call):
            return
        dependencies = frozenset().union(
            *(_expr_dependencies(arg, environment) for arg in expression.args),
            *(_expr_dependencies(keyword.value, environment) for keyword in expression.keywords),
        )
        raw = _dotted(expression.func)
        normalized = _normalize_name(raw, info.module.imports)
        site = (info.symbol, expression.lineno, expression.col_offset)
        sink = self.index.sink_by_site.get(site)
        if sink is not None and dependencies:
            flow_id = _digest(
                {
                    "route": route.route_id,
                    "sources": sorted(dependencies),
                    "chain": chain,
                    "sink": sink.sink_id,
                    "guards": sorted(guards),
                }
            )
            self.flows[flow_id] = DataFlowPath(
                flow_id=flow_id,
                route_id=route.route_id,
                source_names=tuple(sorted(dependencies)),
                call_chain=chain,
                sink_id=sink.sink_id,
                guard_ids=tuple(sorted(guards)),
                confidence=0.84 if len(chain) == 1 else 0.78,
            )
        resolved = self.resolver.resolve(info, normalized)
        if resolved is None or resolved not in self.index.functions:
            return
        callee = self.index.functions[resolved]
        child_environment: dict[str, frozenset[str]] = {}
        for position, argument in enumerate(expression.args):
            if position < len(callee.parameters):
                child_environment[callee.parameters[position]] = _expr_dependencies(
                    argument, environment
                )
        for keyword in expression.keywords:
            if keyword.arg in callee.parameters:
                child_environment[keyword.arg] = _expr_dependencies(keyword.value, environment)
        self._function(
            route,
            callee,
            child_environment,
            (*chain, callee.symbol),
            guards,
            active,
        )


def _module_name(path: str) -> str:
    value = PurePosixPath(path).with_suffix("").as_posix().replace("/", ".")
    return value.removesuffix(".__init__") or "__init__"


def _imports(tree: ast.Module, module_name: str, path: str) -> dict[str, str]:
    result = {}
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                result[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(statement, ast.ImportFrom):
            if statement.level:
                package = (
                    module_name.split(".")
                    if path.endswith("/__init__.py") or path == "__init__.py"
                    else module_name.split(".")[:-1]
                )
                ascend = statement.level - 1
                base = package[: max(0, len(package) - ascend)]
                module = ".".join((*base, *(statement.module or "").split("."))).strip(".")
            else:
                module = statement.module or ""
            for alias in statement.names:
                if alias.name != "*":
                    result[alias.asname or alias.name] = f"{module}.{alias.name}".strip(".")
    return result


def _framework_bindings(tree: ast.Module, imports: dict[str, str]) -> dict[str, WebFramework]:
    result = {}
    for statement in tree.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        value = statement.value
        if not isinstance(value, ast.Call):
            continue
        name = _normalize_name(_dotted(value.func), imports).casefold()
        framework = None
        if name.endswith(("flask.flask", "flask.blueprint")):
            framework = WebFramework.FLASK
        elif name.endswith(("fastapi.fastapi", "fastapi.apirouter")):
            framework = WebFramework.FASTAPI
        elif name.endswith("starlette.starlette"):
            framework = WebFramework.STARLETTE
        if framework is None:
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        for target in targets:
            if isinstance(target, ast.Name):
                result[target.id] = framework
    return result


def _module_functions(module: _ModuleInfo) -> tuple[_FunctionInfo, ...]:
    output = []
    for statement in module.tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            output.append(_function_info(module, statement, None))
        elif isinstance(statement, ast.ClassDef):
            for child in statement.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    output.append(_function_info(module, child, statement.name))
    return tuple(output)


def _function_info(
    module: _ModuleInfo,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    class_name: str | None,
) -> _FunctionInfo:
    parameters = tuple(
        argument.arg
        for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
        if argument.arg not in {"self", "cls"}
    )
    defaults = [None] * (len(node.args.args) - len(node.args.defaults)) + list(node.args.defaults)
    default_by_name = {
        argument.arg: default for argument, default in zip(node.args.args, defaults, strict=True)
    }
    default_by_name.update(
        {
            argument.arg: default
            for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True)
        }
    )
    dependency_parameters = []
    dependencies = []
    for name, default in default_by_name.items():
        if (
            name in parameters
            and isinstance(default, ast.Call)
            and _dotted(default.func).rsplit(".", 1)[-1].casefold() == "depends"
            and default.args
        ):
            dependency_parameters.append(name)
            dependency = _normalize_name(_dotted(default.args[0]), module.imports)
            dependencies.append(dependency if "." in dependency else f"{module.name}.{dependency}")
    symbol = ".".join(filter(None, (module.name, class_name, node.name)))
    decorators = tuple(
        _normalize_name(_dotted(_decorator_target(item)), module.imports)
        for item in node.decorator_list
    )
    return _FunctionInfo(
        symbol=symbol,
        module=module,
        node=node,
        class_name=class_name,
        parameters=parameters,
        dependency_parameters=tuple(dependency_parameters),
        dependency_names=tuple(dependencies),
        decorators=decorators,
    )


def _decorated_routes(
    module: _ModuleInfo, functions: dict[str, _FunctionInfo]
) -> tuple[RouteNode, ...]:
    routes = []
    for info in functions.values():
        if info.module is not module:
            continue
        for decorator in info.node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            raw = _dotted(decorator.func)
            parts = raw.split(".")
            method_name = parts[-1].casefold() if parts else ""
            binding = parts[0] if parts else ""
            framework = module.framework_bindings.get(binding, WebFramework.UNKNOWN)
            if method_name == "route":
                methods = _keyword_string_list(decorator, "methods") or ("GET",)
                if framework is WebFramework.UNKNOWN:
                    framework = WebFramework.FLASK
            elif method_name in _HTTP_METHODS:
                methods = (method_name.upper(),)
                if framework is WebFramework.UNKNOWN:
                    framework = _framework_from_imports(module.imports)
            else:
                continue
            path = _literal_string(decorator.args[0]) if decorator.args else None
            if path is None:
                continue
            dependency_names = set(info.dependency_names)
            dependency_names.update(_decorator_dependencies(decorator))
            input_names = tuple(
                name
                for name in info.parameters
                if name not in info.dependency_parameters and name not in {"self", "cls"}
            )
            route_id = _digest(
                {
                    "framework": framework.value,
                    "methods": methods,
                    "path": path,
                    "handler": info.symbol,
                }
            )
            routes.append(
                RouteNode(
                    route_id=route_id,
                    framework=framework,
                    http_methods=tuple(sorted(set(methods))),
                    path=path,
                    handler_symbol=info.symbol,
                    location=_location(module.path, info.node, info.symbol),
                    input_names=input_names,
                    dependency_names=tuple(sorted(dependency_names)),
                )
            )
    return tuple(routes)


def _django_routes(module: _ModuleInfo, resolver: _SymbolResolver) -> tuple[RouteNode, ...]:
    routes = []
    for statement in module.tree.body:
        if not isinstance(statement, ast.Assign) or not any(
            isinstance(target, ast.Name) and target.id == "urlpatterns"
            for target in statement.targets
        ):
            continue
        if not isinstance(statement.value, (ast.List, ast.Tuple)):
            continue
        for item in statement.value.elts:
            if not isinstance(item, ast.Call):
                continue
            callee = _normalize_name(_dotted(item.func), module.imports)
            if callee.rsplit(".", 1)[-1] not in {"path", "re_path"} or len(item.args) < 2:
                continue
            path = _literal_string(item.args[0])
            handler_name = _normalize_name(_dotted(item.args[1]), module.imports)
            if path is None or not handler_name:
                continue
            resolved = (
                handler_name
                if handler_name in resolver.functions
                else resolver.unique_suffix.get(handler_name.rsplit(".", 1)[-1])
            )
            if resolved is None:
                continue
            info = resolver.functions[resolved]
            routes.append(
                RouteNode(
                    route_id=_digest(
                        {
                            "framework": "django",
                            "methods": ("ANY",),
                            "path": path,
                            "handler": resolved,
                        }
                    ),
                    framework=WebFramework.DJANGO,
                    http_methods=("ANY",),
                    path=path,
                    handler_symbol=resolved,
                    location=_location(module.path, item, resolved),
                    input_names=info.parameters,
                    dependency_names=(),
                )
            )
    return tuple(routes)


def _function_calls(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[ast.Call, ...]:
    collector = _BodyCollector(ast.Call)
    for statement in node.body:
        collector.visit(statement)
    return tuple(collector.items)


class _BodyCollector(ast.NodeVisitor):
    def __init__(self, kind: type[ast.AST]):
        self.kind = kind
        self.items: list[Any] = []

    def generic_visit(self, node: ast.AST) -> None:
        if isinstance(node, self.kind):
            self.items.append(node)
        super().generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return None

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return None


def _function_guards(info: _FunctionInfo) -> tuple[GuardNode, ...]:
    guards: dict[str, GuardNode] = {}
    for decorator in info.decorators:
        kind = _guard_kind(decorator)
        if kind is not None:
            guard = _guard(info, kind, f"decorator:{decorator}", info.node)
            guards[guard.guard_id] = guard
    for dependency in info.dependency_names:
        kind = _guard_kind(dependency)
        if kind is not None:
            guard = _guard(info, kind, f"dependency:{dependency}", info.node)
            guards[guard.guard_id] = guard
    for call in _function_calls(info.node):
        callee = _normalize_name(_dotted(call.func), info.module.imports)
        kind = _guard_kind(callee)
        if kind is not None:
            guard = _guard(info, kind, f"call:{callee}", call)
            guards[guard.guard_id] = guard
    collector = _BodyCollector(ast.If)
    for statement in info.node.body:
        collector.visit(statement)
    for condition in collector.items:
        names = " ".join(_dotted(node) for node in ast.walk(condition.test)).casefold()
        if any(word in names for word in _OWNERSHIP_WORDS) and any(
            word in names for word in ("user", "tenant", "account")
        ):
            guard = _guard(info, GuardKind.OWNERSHIP, "conditional:ownership", condition)
            guards[guard.guard_id] = guard
    return tuple(guards.values())


def _guard(
    info: _FunctionInfo,
    kind: GuardKind,
    mechanism: str,
    node: ast.AST,
) -> GuardNode:
    identity = {
        "symbol": info.symbol,
        "kind": kind.value,
        "mechanism": mechanism,
        "path": info.module.path,
        "line": getattr(node, "lineno", info.node.lineno),
    }
    return GuardNode(
        guard_id=_digest(identity),
        function_symbol=info.symbol,
        kind=kind,
        mechanism=mechanism,
        location=_location(info.module.path, node, info.symbol),
    )


def _guard_kind(name: str) -> GuardKind | None:
    lowered = name.casefold()
    if "csrf" in lowered:
        return GuardKind.CSRF
    if any(word in lowered for word in _OWNERSHIP_WORDS):
        return GuardKind.OWNERSHIP
    if any(word in lowered for word in _AUTHZ_WORDS):
        return GuardKind.AUTHORIZATION
    if any(word in lowered for word in _AUTH_WORDS):
        return GuardKind.AUTHENTICATION
    if any(word in lowered for word in ("validate", "schema", "parse_obj", "model_validate")):
        return GuardKind.INPUT_VALIDATION
    return None


def _sink_kind(name: str) -> SinkKind | None:
    lowered = name.casefold()
    tail = lowered.rsplit(".", 1)[-1]
    if lowered in {"eval", "exec", "os.system"} or lowered.startswith("subprocess."):
        return SinkKind.COMMAND
    if lowered.startswith(("requests.", "httpx.", "aiohttp.")) or lowered.endswith(
        "urllib.request.urlopen"
    ):
        return SinkKind.NETWORK
    if tail in {"open", "read_text", "write_text", "send_file"} or lowered.endswith("fileresponse"):
        return SinkKind.FILE
    if tail in {"execute", "executemany", "raw"} or lowered.endswith("sqlalchemy.text"):
        return SinkKind.SQL
    if (
        ".objects.get" in lowered
        or ".query.get" in lowered
        or tail in {"get_object_or_404", "get_or_404"}
    ):
        return SinkKind.OBJECT_LOOKUP
    if tail in {"render_template_string", "mark_safe"}:
        return SinkKind.TEMPLATE
    if lowered.startswith(("pickle.", "marshal.")) or lowered.endswith("yaml.load"):
        return SinkKind.DESERIALIZATION
    if tail == "redirect":
        return SinkKind.REDIRECT
    return None


def _expr_dependencies(
    node: ast.AST | None, environment: dict[str, frozenset[str]]
) -> frozenset[str]:
    if node is None:
        return frozenset()
    if isinstance(node, ast.Name):
        if node.id == "request":
            return frozenset({"request"})
        return environment.get(node.id, frozenset())
    if isinstance(node, ast.Attribute):
        dotted = _dotted(node).casefold()
        if dotted.startswith("request."):
            return frozenset({dotted})
        return _expr_dependencies(node.value, environment)
    if isinstance(node, ast.Call):
        dotted = _dotted(node.func).casefold()
        dependencies = frozenset().union(
            *(_expr_dependencies(item, environment) for item in node.args),
            *(_expr_dependencies(item.value, environment) for item in node.keywords),
        )
        if dotted.startswith("request."):
            return dependencies.union({dotted})
        return dependencies
    if isinstance(node, ast.Constant):
        return frozenset()
    dependencies = frozenset()
    for child in ast.iter_child_nodes(node):
        dependencies = dependencies.union(_expr_dependencies(child, environment))
    return dependencies


def _assigned_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(name for item in node.elts for name in _assigned_names(item))
    return ()


def _statement_expressions(statement: ast.stmt) -> tuple[ast.AST, ...]:
    if isinstance(statement, ast.Expr):
        return (statement.value,)
    if isinstance(statement, ast.Return) and statement.value is not None:
        return (statement.value,)
    if isinstance(statement, ast.Raise) and statement.exc is not None:
        return (statement.exc,)
    if isinstance(statement, ast.Assert):
        return (statement.test,)
    return ()


def _merge_environments(
    left: dict[str, frozenset[str]], right: dict[str, frozenset[str]]
) -> dict[str, frozenset[str]]:
    keys = set(left).union(right)
    return {key: left.get(key, frozenset()).union(right.get(key, frozenset())) for key in keys}


def _merge_many(values: list[dict[str, frozenset[str]]]) -> dict[str, frozenset[str]]:
    output: dict[str, frozenset[str]] = {}
    for value in values:
        output = _merge_environments(output, value)
    return output


def _guard_ids_at_line(index: _StaticIndex, symbol: str, line: int) -> frozenset[str]:
    return frozenset(
        item.guard_id
        for item in index.guards
        if item.function_symbol == symbol and item.location.line == line
    )


def _denial_branch_guards_following_code(statement: ast.If) -> bool:
    """Recognize a top-level negative guard whose denied branch terminates.

    For example, after ``if object.owner_id != user.id: raise``, the normal
    continuation is ownership-checked. Positive branches such as
    ``if is_owner: return object`` must not authorize the fall-through path.
    """
    if statement.orelse or not statement.body:
        return False
    terminates = isinstance(statement.body[-1], (ast.Raise, ast.Return))
    if not terminates:
        return False
    test = statement.test
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return True
    return isinstance(test, ast.Compare) and any(
        isinstance(operator, (ast.NotEq, ast.IsNot, ast.NotIn)) for operator in test.ops
    )


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _normalize_name(name: str, imports: dict[str, str]) -> str:
    if not name:
        return ""
    first, separator, rest = name.partition(".")
    replacement = imports.get(first)
    if replacement:
        return replacement + (separator + rest if rest else "")
    return name


def _decorator_target(node: ast.AST) -> ast.AST:
    return node.func if isinstance(node, ast.Call) else node


def _literal_string(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _keyword_string_list(call: ast.Call, name: str) -> tuple[str, ...]:
    for keyword in call.keywords:
        if keyword.arg == name and isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
            return tuple(
                item.value.upper()
                for item in keyword.value.elts
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            )
    return ()


def _decorator_dependencies(call: ast.Call) -> tuple[str, ...]:
    output = []
    for keyword in call.keywords:
        if keyword.arg != "dependencies" or not isinstance(keyword.value, (ast.List, ast.Tuple)):
            continue
        for item in keyword.value.elts:
            if isinstance(item, ast.Call) and item.args:
                output.append(_dotted(item.args[0]))
    return tuple(output)


def _framework_from_imports(imports: dict[str, str]) -> WebFramework:
    values = " ".join(imports.values()).casefold()
    if "fastapi" in values:
        return WebFramework.FASTAPI
    if "flask" in values:
        return WebFramework.FLASK
    if "starlette" in values:
        return WebFramework.STARLETTE
    return WebFramework.UNKNOWN


def _location(path: str, node: ast.AST, symbol: str | None = None) -> SourceLocation:
    return SourceLocation(path=path, line=max(1, getattr(node, "lineno", 1)), symbol=symbol)


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()
