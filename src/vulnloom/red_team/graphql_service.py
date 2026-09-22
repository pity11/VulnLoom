"""Trusted offline reducer for one authoritative sealed GraphQL SDL GET."""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from vulnloom.domain.models import Scope, ScopeState
from vulnloom.evidence import EvidenceStore

from .graphql_models import (
    GraphQlQueryFieldDiscovery,
    GraphQlSchemaObservation,
    GraphQlSchemaObservationLimits,
    GraphQlSchemaObservationOutcome,
    GraphQlSchemaObservationPlan,
)
from .graphql_store import GraphQlSchemaObservationStore
from .models import ReconOutcome, RedTeamActionKind
from .seed_models import EndpointReconOutcomeKind
from .seed_store import EndpointReconStore
from .store import RedTeamStore


class GraphQlSchemaObservationRejected(ValueError):
    pass


class GraphQlSchemaObservationTimedOut(TimeoutError):
    pass


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]):
        self.seconds = seconds
        self.clock = clock
        self.started = clock()

    def check(self) -> None:
        if self.clock() - self.started >= self.seconds:
            raise GraphQlSchemaObservationTimedOut(
                "GraphQL schema observation timed out"
            )


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    value: str


@dataclass(frozen=True, slots=True)
class _SchemaSummary:
    query_root: str
    query_fields: tuple[tuple[str, str], ...]
    type_count: int
    mutation_fields: int
    subscription_fields: int
    directive_uses: int


_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_OPEN_TO_CLOSE = {"(": ")", "[": "]", "{": "}"}
_CLOSE_TO_OPEN = {value: key for key, value in _OPEN_TO_CLOSE.items()}
_TYPE_KEYWORDS = {"type", "interface", "input", "enum", "scalar", "union"}
_EXECUTABLE_KEYWORDS = {"query", "mutation", "subscription", "fragment"}


class GraphQlSchemaObservationService:
    def __init__(
        self,
        *,
        red_team_store: RedTeamStore,
        endpoint_recon_store: EndpointReconStore,
        observation_store: GraphQlSchemaObservationStore,
        evidence_store: EvidenceStore,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.red_team_store = red_team_store
        self.endpoint_recon_store = endpoint_recon_store
        self.observation_store = observation_store
        self.evidence_store = evidence_store
        self.monotonic = monotonic

    def prepare(
        self,
        *,
        endpoint_recon_plan_id: str,
        scope: Scope,
        limits: GraphQlSchemaObservationLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
    ) -> GraphQlSchemaObservationPlan:
        source = self._source(endpoint_recon_plan_id, scope=scope, now=now)
        stop_at = min(deadline, scope.valid_until, source["flow"].deadline)
        if stop_at <= now:
            raise GraphQlSchemaObservationRejected(
                "GraphQL schema observation deadline is invalid"
            )
        web = source["observation"].web_response
        assert web is not None
        return GraphQlSchemaObservationPlan.create(
            endpoint_recon_plan_id=endpoint_recon_plan_id,
            flow_plan_id=source["flow"].plan_id,
            source_checkpoint_id=source["checkpoint"].checkpoint_id,
            source_observation_id=source["observation"].observation_id,
            web_response_snapshot_id=web.snapshot_id,
            evidence_ref=web.evidence_refs[0],
            response_body_sha256=web.response_body_sha256,
            target_id=source["flow"].target.target_id,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            limits=limits,
            created_at=now,
            deadline=stop_at,
            idempotency_key=idempotency_key,
        )

    def execute(
        self,
        plan: GraphQlSchemaObservationPlan,
        *,
        scope: Scope,
        now: datetime,
    ) -> GraphQlSchemaObservationOutcome:
        authoritative = GraphQlSchemaObservationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        observation = self._observe(authoritative, scope=scope, now=now)
        claim = self.observation_store.claim(authoritative, now=now)
        if not claim.created:
            if claim.outcome is None or claim.outcome.observation != observation:
                raise GraphQlSchemaObservationRejected(
                    "completed GraphQL schema observation outcome drifted"
                )
            return claim.outcome
        return self._complete(
            authoritative,
            observation,
            attempt=claim.attempt,
            scope=scope,
            now=now,
        )

    def recover(
        self,
        plan: GraphQlSchemaObservationPlan,
        *,
        scope: Scope,
        now: datetime,
    ) -> GraphQlSchemaObservationOutcome:
        authoritative = GraphQlSchemaObservationPlan.model_validate(
            plan.model_dump(mode="python")
        )
        observation = self._observe(authoritative, scope=scope, now=now)
        claim = self.observation_store.recover(authoritative, now=now)
        return self._complete(
            authoritative,
            observation,
            attempt=claim.attempt,
            scope=scope,
            now=now,
        )

    def _complete(self, plan, observation, *, attempt, scope, now):
        self._plan_binding(plan, scope=scope, now=now)
        if not self.evidence_store.contains(plan.evidence_ref):
            raise GraphQlSchemaObservationRejected(
                "GraphQL source Evidence changed before completion"
            )
        outcome = GraphQlSchemaObservationOutcome(
            plan_id=plan.plan_id,
            observation=observation,
            attempt=attempt,
        )
        self.observation_store.complete(outcome, completed_at=now)
        return outcome

    def _observe(self, plan, *, scope, now):
        self._plan_binding(plan, scope=scope, now=now)
        deadline = _Deadline(plan.limits.timeout_seconds, self.monotonic)
        deadline.check()
        body = self._document_body(self.evidence_store.read_text_ref(plan.evidence_ref))
        if len(body.encode("utf-8")) > plan.limits.max_document_bytes:
            raise GraphQlSchemaObservationRejected(
                "GraphQL SDL exceeds its byte budget"
            )
        tokens = self._lex(body, plan.limits, deadline)
        summary = self._summarize(tokens, plan.limits, deadline)
        deadline.check()
        discoveries = tuple(
            sorted(
                (
                    GraphQlQueryFieldDiscovery.create(
                        field_name=field_name,
                        return_named_type=return_type,
                    )
                    for field_name, return_type in summary.query_fields
                ),
                key=lambda item: item.discovery_id,
            )
        )
        try:
            return GraphQlSchemaObservation.create(
                plan_id=plan.plan_id,
                endpoint_recon_plan_id=plan.endpoint_recon_plan_id,
                source_observation_id=plan.source_observation_id,
                web_response_snapshot_id=plan.web_response_snapshot_id,
                evidence_ref=plan.evidence_ref,
                response_body_sha256=plan.response_body_sha256,
                query_root_type=summary.query_root,
                query_fields=discoveries,
                type_count=summary.type_count,
                mutation_fields_ignored=summary.mutation_fields,
                subscription_fields_ignored=summary.subscription_fields,
                directive_uses_ignored=summary.directive_uses,
                observed_at=plan.created_at,
            )
        except ValueError as exc:
            raise GraphQlSchemaObservationRejected(
                "GraphQL schema observation could not be sealed"
            ) from exc

    @staticmethod
    def _document_body(text: str) -> str:
        stripped = text.lstrip("\ufeff \t\r\n")
        if not stripped.startswith(("method:", "url_sha256:", "status:")):
            return stripped
        _, separator, body = text.partition("\n\n")
        body = body.lstrip("\ufeff \t\r\n")
        if not separator or not body:
            raise GraphQlSchemaObservationRejected(
                "GraphQL Evidence does not contain an SDL document"
            )
        return body

    @staticmethod
    def _lex(
        body: str, limits: GraphQlSchemaObservationLimits, deadline: _Deadline
    ) -> tuple[_Token, ...]:
        tokens: list[_Token] = []
        stack: list[str] = []
        index = 0
        while index < len(body):
            deadline.check()
            char = body[index]
            if char.isspace() or char == "," or char == "\ufeff":
                index += 1
                continue
            if char == "#":
                newline = body.find("\n", index + 1)
                index = len(body) if newline < 0 else newline + 1
                continue
            if body.startswith('"""', index):
                end = body.find('"""', index + 3)
                if end < 0:
                    raise GraphQlSchemaObservationRejected(
                        "GraphQL SDL contains an unterminated block string"
                    )
                tokens.append(_Token("string", ""))
                index = end + 3
            elif char == '"':
                index += 1
                while index < len(body):
                    if body[index] in "\r\n":
                        raise GraphQlSchemaObservationRejected(
                            "GraphQL SDL contains an invalid string"
                        )
                    if body[index] == "\\":
                        index += 2
                    elif index < len(body) and body[index] == '"':
                        index += 1
                        break
                    else:
                        index += 1
                else:
                    raise GraphQlSchemaObservationRejected(
                        "GraphQL SDL contains an unterminated string"
                    )
                tokens.append(_Token("string", ""))
            else:
                name = _NAME.match(body, index)
                number = _NUMBER.match(body, index)
                if name is not None:
                    value = name.group(0)
                    if len(value) > 128:
                        raise GraphQlSchemaObservationRejected(
                            "GraphQL SDL name exceeds its budget"
                        )
                    tokens.append(_Token("name", value))
                    index = name.end()
                elif number is not None:
                    tokens.append(_Token("number", ""))
                    index = number.end()
                elif body.startswith("...", index):
                    tokens.append(_Token("punct", "..."))
                    index += 3
                elif char in "!$&():=@[]{|}":
                    if char in _OPEN_TO_CLOSE:
                        stack.append(char)
                        if len(stack) > limits.max_depth:
                            raise GraphQlSchemaObservationRejected(
                                "GraphQL SDL nesting budget exceeded"
                            )
                    elif char in _CLOSE_TO_OPEN:
                        if not stack or stack.pop() != _CLOSE_TO_OPEN[char]:
                            raise GraphQlSchemaObservationRejected(
                                "GraphQL SDL delimiters are unbalanced"
                            )
                    tokens.append(_Token("punct", char))
                    index += 1
                else:
                    raise GraphQlSchemaObservationRejected(
                        "GraphQL SDL contains an unsupported token"
                    )
            if len(tokens) > limits.max_tokens:
                raise GraphQlSchemaObservationRejected(
                    "GraphQL SDL token budget exceeded"
                )
        if stack:
            raise GraphQlSchemaObservationRejected(
                "GraphQL SDL delimiters are unbalanced"
            )
        if not tokens:
            raise GraphQlSchemaObservationRejected("GraphQL SDL is empty")
        return tuple(tokens)

    @classmethod
    def _summarize(cls, tokens, limits, deadline):
        matching = cls._matching(tokens)
        objects: dict[str, dict[str, str]] = {}
        type_names: set[str] = set()
        extensions: list[tuple[str, dict[str, str]]] = []
        roots: dict[str, str] = {}
        directive_uses = sum(token.value == "@" for token in tokens)
        index = 0
        while index < len(tokens):
            deadline.check()
            token = tokens[index]
            if token.kind == "string":
                index += 1
                continue
            if token.kind != "name":
                raise GraphQlSchemaObservationRejected(
                    "GraphQL SDL has an invalid top-level definition"
                )
            keyword = token.value
            if keyword in _EXECUTABLE_KEYWORDS:
                raise GraphQlSchemaObservationRejected(
                    "executable GraphQL documents are not admissible"
                )
            extended = keyword == "extend"
            if extended:
                index += 1
                if index >= len(tokens) or tokens[index].kind != "name":
                    raise GraphQlSchemaObservationRejected(
                        "GraphQL SDL extension is invalid"
                    )
                keyword = tokens[index].value
            if keyword == "schema":
                start = cls._find_block(tokens, index + 1)
                values = cls._schema_roots(tokens, start + 1, matching[start])
                for name, value in values.items():
                    if name in roots:
                        raise GraphQlSchemaObservationRejected(
                            "GraphQL SDL repeats a schema root"
                        )
                    roots[name] = value
                index = matching[start] + 1
                continue
            if keyword in _TYPE_KEYWORDS:
                name_index = index + 1
                if name_index >= len(tokens) or tokens[name_index].kind != "name":
                    raise GraphQlSchemaObservationRejected(
                        "GraphQL SDL type name is missing"
                    )
                name = tokens[name_index].value
                if not extended:
                    if name in type_names:
                        raise GraphQlSchemaObservationRejected(
                            "GraphQL SDL repeats a type definition"
                        )
                    type_names.add(name)
                    if len(type_names) > limits.max_types:
                        raise GraphQlSchemaObservationRejected(
                            "GraphQL SDL type budget exceeded"
                        )
                if keyword in {"type", "interface", "input", "enum"}:
                    start = cls._find_block(tokens, name_index + 1)
                    fields = (
                        cls._object_fields(tokens, start + 1, matching[start])
                        if keyword == "type"
                        else {}
                    )
                    if keyword == "type":
                        if extended:
                            extensions.append((name, fields))
                        else:
                            objects[name] = fields
                    index = matching[start] + 1
                    continue
                index = cls._next_definition(tokens, name_index + 1)
                continue
            if keyword == "directive":
                index = cls._next_definition(tokens, index + 1)
                continue
            raise GraphQlSchemaObservationRejected(
                "GraphQL SDL has an unsupported top-level definition"
            )
        for name, fields in extensions:
            if name not in objects:
                raise GraphQlSchemaObservationRejected(
                    "GraphQL SDL extends an undefined object type"
                )
            if set(objects[name]).intersection(fields):
                raise GraphQlSchemaObservationRejected(
                    "GraphQL SDL repeats an extended field"
                )
            objects[name].update(fields)
        query_root = roots.get("query", "Query")
        if any(name not in objects for name in roots.values()) or len(
            set(roots.values())
        ) != len(roots):
            raise GraphQlSchemaObservationRejected(
                "GraphQL SDL schema roots are invalid"
            )
        if query_root not in objects or not objects[query_root]:
            raise GraphQlSchemaObservationRejected(
                "GraphQL SDL query root is missing or empty"
            )
        query_fields = objects[query_root]
        if len(query_fields) > limits.max_query_fields:
            raise GraphQlSchemaObservationRejected(
                "GraphQL SDL query field budget exceeded"
            )
        mutation_fields = cls._ignored_root_count(
            objects, roots.get("mutation", "Mutation"), limits
        )
        subscription_fields = cls._ignored_root_count(
            objects, roots.get("subscription", "Subscription"), limits
        )
        return _SchemaSummary(
            query_root=query_root,
            query_fields=tuple(sorted(query_fields.items())),
            type_count=len(type_names),
            mutation_fields=mutation_fields,
            subscription_fields=subscription_fields,
            directive_uses=directive_uses,
        )

    @staticmethod
    def _matching(tokens) -> dict[int, int]:
        stack: list[tuple[str, int]] = []
        result: dict[int, int] = {}
        for index, token in enumerate(tokens):
            if token.value in _OPEN_TO_CLOSE:
                stack.append((token.value, index))
            elif token.value in _CLOSE_TO_OPEN:
                opener, start = stack.pop()
                if opener != _CLOSE_TO_OPEN[token.value]:
                    raise GraphQlSchemaObservationRejected(
                        "GraphQL SDL delimiters are unbalanced"
                    )
                result[start] = index
        return result

    @staticmethod
    def _find_block(tokens, start: int) -> int:
        for index in range(start, len(tokens)):
            if tokens[index].value == "{":
                return index
            if tokens[index].kind == "name" and tokens[index].value in (
                _TYPE_KEYWORDS | {"schema", "directive", "extend"}
            ):
                break
        raise GraphQlSchemaObservationRejected(
            "GraphQL SDL definition block is missing"
        )

    @staticmethod
    def _schema_roots(tokens, start: int, end: int) -> dict[str, str]:
        result: dict[str, str] = {}
        index = start
        while index < end:
            if (
                index + 2 >= end
                or tokens[index].kind != "name"
                or tokens[index + 1].value != ":"
                or tokens[index + 2].kind != "name"
                or tokens[index].value not in {"query", "mutation", "subscription"}
            ):
                raise GraphQlSchemaObservationRejected(
                    "GraphQL SDL schema root mapping is invalid"
                )
            name = tokens[index].value
            if name.startswith("__"):
                raise GraphQlSchemaObservationRejected(
                    "GraphQL SDL reserved fields are not admissible"
                )
            if name in result:
                raise GraphQlSchemaObservationRejected(
                    "GraphQL SDL repeats a schema root"
                )
            result[name] = tokens[index + 2].value
            index += 3
        return result

    @classmethod
    def _object_fields(cls, tokens, start: int, end: int) -> dict[str, str]:
        matching = cls._matching(tokens)
        result: dict[str, str] = {}
        index = start
        while index < end:
            while index < end and tokens[index].kind == "string":
                index += 1
            if index >= end or tokens[index].kind != "name":
                raise GraphQlSchemaObservationRejected(
                    "GraphQL SDL object field is invalid"
                )
            name = tokens[index].value
            index += 1
            if index < end and tokens[index].value == "(":
                index = matching[index] + 1
            if index >= end or tokens[index].value != ":":
                raise GraphQlSchemaObservationRejected(
                    "GraphQL SDL object field type is missing"
                )
            return_type, index = cls._type_reference(tokens, index + 1, end, matching)
            while index < end and tokens[index].value == "@":
                index += 1
                if index >= end or tokens[index].kind != "name":
                    raise GraphQlSchemaObservationRejected(
                        "GraphQL SDL directive use is invalid"
                    )
                index += 1
                if index < end and tokens[index].value == "(":
                    index = matching[index] + 1
            if name in result:
                raise GraphQlSchemaObservationRejected(
                    "GraphQL SDL repeats an object field"
                )
            result[name] = return_type
        return result

    @classmethod
    def _type_reference(cls, tokens, index, end, matching):
        if index >= end:
            raise GraphQlSchemaObservationRejected(
                "GraphQL SDL field type is invalid"
            )
        if tokens[index].value == "[":
            close = matching[index]
            name, nested_end = cls._type_reference(tokens, index + 1, close, matching)
            if nested_end != close:
                raise GraphQlSchemaObservationRejected(
                    "GraphQL SDL list type is invalid"
                )
            index = close + 1
        elif tokens[index].kind == "name":
            name = tokens[index].value
            index += 1
        else:
            raise GraphQlSchemaObservationRejected(
                "GraphQL SDL field type is invalid"
            )
        if index < end and tokens[index].value == "!":
            index += 1
        return name, index

    @staticmethod
    def _next_definition(tokens, start: int) -> int:
        depth = 0
        for index in range(start, len(tokens)):
            value = tokens[index].value
            if value in _OPEN_TO_CLOSE:
                depth += 1
            elif value in _CLOSE_TO_OPEN:
                depth -= 1
            elif (
                depth == 0
                and tokens[index].kind == "name"
                and value
                in (_TYPE_KEYWORDS | {"schema", "directive", "extend"})
            ):
                return index
        return len(tokens)

    @staticmethod
    def _ignored_root_count(objects, name, limits):
        count = len(objects.get(name, {}))
        if count > limits.max_query_fields:
            raise GraphQlSchemaObservationRejected(
                "GraphQL SDL ignored root field budget exceeded"
            )
        return count

    def _plan_binding(self, plan, *, scope, now):
        if not plan.created_at <= now < plan.deadline:
            raise GraphQlSchemaObservationRejected(
                "GraphQL schema observation plan is not active"
            )
        source = self._source(plan.endpoint_recon_plan_id, scope=scope, now=now)
        web = source["observation"].web_response
        assert web is not None
        if (
            source["flow"].plan_id != plan.flow_plan_id
            or source["checkpoint"].checkpoint_id != plan.source_checkpoint_id
            or source["observation"].observation_id != plan.source_observation_id
            or web.snapshot_id != plan.web_response_snapshot_id
            or web.evidence_refs != (plan.evidence_ref,)
            or web.response_body_sha256 != plan.response_body_sha256
            or source["flow"].target.target_id != plan.target_id
            or scope.scope_id != plan.scope_id
            or scope.version != plan.scope_version
        ):
            raise GraphQlSchemaObservationRejected(
                "GraphQL schema observation binding drifted"
            )

    def _source(self, endpoint_recon_plan_id, *, scope, now):
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
        ):
            raise GraphQlSchemaObservationRejected(
                "GraphQL schema observation requires a current approved Scope"
            )
        endpoint_plan = self.endpoint_recon_store.plan(endpoint_recon_plan_id)
        outcome = self.endpoint_recon_store.outcome(endpoint_recon_plan_id)
        flow = self.red_team_store.plan(endpoint_plan.flow_plan_id)
        checkpoint = self.red_team_store.latest(flow.plan_id)
        if (
            len(endpoint_plan.steps) != 1
            or endpoint_plan.steps[0].method != "GET"
            or outcome.outcome is not EndpointReconOutcomeKind.SUCCEEDED
            or not outcome.cleanup_complete
            or len(outcome.results) != 1
            or outcome.results[0].step_id != endpoint_plan.steps[0].step_id
            or outcome.results[0].web_response_snapshot_id is None
            or endpoint_plan.target_id != flow.target.target_id
            or endpoint_plan.scope_id != scope.scope_id
            or endpoint_plan.scope_version != scope.version
            or flow.rules.scope_id != scope.scope_id
            or flow.rules.scope_version != scope.version
            or flow.deadline > scope.valid_until
        ):
            raise GraphQlSchemaObservationRejected(
                "GraphQL schema observation requires one authoritative sealed GET"
            )
        matches = []
        for observation_id in checkpoint.observation_ids:
            observation = self.red_team_store.observation(observation_id)
            web = observation.web_response
            if (
                web is not None
                and web.snapshot_id == outcome.results[0].web_response_snapshot_id
            ):
                matches.append(observation)
        if len(matches) != 1:
            raise GraphQlSchemaObservationRejected(
                "GraphQL source Observation is unavailable or ambiguous"
            )
        observation = matches[0]
        action = self.red_team_store.action(observation.action_id)
        web = observation.web_response
        assert web is not None
        step = endpoint_plan.steps[0]
        if (
            observation.outcome is not ReconOutcome.SUCCEEDED
            or not observation.cleanup_complete
            or not observation.sensitive_data_redacted
            or action.kind is not RedTeamActionKind.HTTP_GET
            or action.plan_id != flow.plan_id
            or hashlib.sha256(action.target_url.encode()).hexdigest()
            != step.target_url_digest
            or web.plan_id != flow.plan_id
            or web.action_id != action.action_id
            or web.target_id != flow.target.target_id
            or web.scope_id != scope.scope_id
            or web.scope_version != scope.version
            or web.requested_url_digest != step.target_url_digest
            or web.final_url_digest != step.target_url_digest
            or web.snapshot_id != outcome.results[0].web_response_snapshot_id
            or outcome.results[0].response_body_sha256 != web.response_body_sha256
            or outcome.results[0].response_bytes != web.response_bytes
            or web.evidence_refs != outcome.results[0].evidence_refs
            or len(web.evidence_refs) != 1
            or not self.evidence_store.contains(web.evidence_refs[0])
        ):
            raise GraphQlSchemaObservationRejected(
                "GraphQL source provenance is invalid"
            )
        return {
            "endpoint_plan": endpoint_plan,
            "flow": flow,
            "checkpoint": checkpoint,
            "observation": observation,
        }
