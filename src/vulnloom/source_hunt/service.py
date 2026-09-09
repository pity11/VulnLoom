"""Fail-closed repository indexing and observation-driven investigation service."""

from __future__ import annotations

import hashlib
import os
import stat
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime
from pathlib import Path, PurePosixPath
from time import monotonic

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import Scope, ScopeState, TargetSnapshot
from vulnloom.ingestion import IngestionService

from .adapters import (
    JavaScriptLanguageAdapter,
    LanguageAdapter,
    PythonLanguageAdapter,
    SourceContextReader,
    SourceDocument,
    detect_build_systems,
)
from .models import (
    InvestigationCheckpoint,
    InvestigationObservation,
    InvestigationPlan,
    InvestigationQuery,
    InvestigationQueryKind,
    InvestigationStatus,
    RepositoryIndex,
    SourceFileRecord,
    SourceHuntLimits,
    SourceLanguage,
    SourcePartition,
)
from .store import SourceHuntStore


class SourceHuntRejected(ValueError):
    pass


class SourceHuntTimedOut(TimeoutError):
    pass


class SourceHuntService:
    def __init__(
        self,
        *,
        store: SourceHuntStore,
        adapters: tuple[LanguageAdapter, ...] | None = None,
        clock: Callable[[], float] = monotonic,
    ):
        self.store = store
        self.adapters = adapters or (PythonLanguageAdapter(), JavaScriptLanguageAdapter())
        self.clock = clock
        extensions = [suffix for adapter in self.adapters for suffix in adapter.extensions]
        if len(extensions) != len(set(extensions)):
            raise SourceHuntRejected("LanguageAdapter extensions overlap")

    def index_repository(
        self,
        *,
        snapshot: TargetSnapshot,
        store_root: Path,
        scope: Scope,
        limits: SourceHuntLimits,
        now: datetime,
    ) -> RepositoryIndex:
        IngestionService.require_snapshot_scope(snapshot, scope, now)
        if snapshot.root_ref is None:
            raise SourceHuntRejected("Source Hunt requires a filesystem snapshot")
        root = self._root(snapshot, store_root)
        started = self.clock()
        supported = {
            suffix: adapter for adapter in self.adapters for suffix in adapter.extensions
        }
        selected = tuple(
            item
            for item in sorted(snapshot.manifest.files, key=lambda value: value.path)
            if PurePosixPath(item.path).suffix.casefold() in supported
        )
        if len(selected) > limits.max_files:
            raise SourceHuntRejected("repository exceeds Source Hunt file limit")
        total = sum(item.size for item in selected)
        if total > limits.max_total_bytes:
            raise SourceHuntRejected("repository exceeds Source Hunt byte limit")
        grouped: dict[LanguageAdapter, list[SourceDocument]] = defaultdict(list)
        for item in selected:
            self._deadline(started, limits)
            if item.size > limits.max_single_file_bytes:
                raise SourceHuntRejected("source file exceeds Source Hunt single-file limit")
            adapter = supported[PurePosixPath(item.path).suffix.casefold()]
            content = self._read_verified(root, item.path, item.size, item.sha256)
            try:
                text = content.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise SourceHuntRejected("source file is not valid UTF-8") from exc
            # Raw source remains transient at the trusted adapter boundary.
            grouped[adapter].append(SourceDocument(item.path, item.sha256, text))
        symbols = []
        references = []
        versions = {}
        for adapter in self.adapters:
            documents = tuple(grouped.get(adapter, ()))
            if not documents:
                continue
            self._deadline(started, limits)
            result = adapter.index(documents)
            symbols.extend(result.symbols)
            references.extend(result.references)
            versions[adapter.language] = adapter.version
        self._deadline(started, limits)
        files = tuple(item.path for item in selected)
        skipped = tuple(
            item.path
            for item in sorted(snapshot.manifest.files, key=lambda value: value.path)
            if item.path not in set(files)
        )
        return RepositoryIndex.create(
            target_id=snapshot.target.target_id,
            target_version=snapshot.target.version,
            scope_id=scope.scope_id,
            scope_version=scope.version,
            manifest_id=snapshot.manifest.manifest_id,
            adapter_versions=versions,
            source_files=tuple(
                SourceFileRecord(
                    path=item.path,
                    language=(
                        SourceLanguage.TYPESCRIPT
                        if PurePosixPath(item.path).suffix.casefold() in {".ts", ".tsx"}
                        else supported[
                            PurePosixPath(item.path).suffix.casefold()
                        ].language
                    ),
                    size=item.size,
                    sha256=item.sha256,
                )
                for item in selected
            ),
            files_indexed=files,
            symbols=tuple(sorted(symbols, key=lambda item: item.symbol_id)),
            references=tuple(sorted(references, key=lambda item: item.reference_id)),
            build_systems=detect_build_systems(
                tuple(item.path for item in snapshot.manifest.files)
            ),
            partitions=self._partitions(selected, limits.max_files_per_partition),
            skipped_files=skipped,
        )

    def start(
        self,
        *,
        index: RepositoryIndex,
        scope: Scope,
        limits: SourceHuntLimits,
        now: datetime,
        deadline: datetime,
        idempotency_key: str,
        seed_signal_ids: tuple[str, ...] = (),
    ) -> tuple[InvestigationPlan, InvestigationCheckpoint]:
        self._scope(index, scope, now)
        existing = self.store.plan_by_idempotency_key(idempotency_key)
        if existing is not None:
            if (
                existing.index_id != index.index_id
                or existing.limits != limits
                or existing.seed_signal_ids != seed_signal_ids
            ):
                raise SourceHuntRejected("Source Hunt idempotency collision")
            return existing, self.store.latest(existing.plan_id)
        plan = InvestigationPlan.create(
            index_id=index.index_id,
            target_id=index.target_id,
            target_version=index.target_version,
            scope_id=index.scope_id,
            scope_version=index.scope_version,
            seed_signal_ids=seed_signal_ids,
            limits=limits,
            created_at=now,
            deadline=min(deadline, scope.valid_until),
            idempotency_key=idempotency_key,
        )
        checkpoint = InvestigationCheckpoint.create(
            plan_id=plan.plan_id,
            index_id=index.index_id,
            status=InvestigationStatus.ACTIVE,
            revision=0,
            queries_used=0,
            observation_ids=(),
            query_digests=(),
            updated_at=now,
        )
        return plan, self.store.start(index=index, plan=plan, checkpoint=checkpoint)

    def query(
        self,
        *,
        plan: InvestigationPlan,
        index: RepositoryIndex,
        checkpoint: InvestigationCheckpoint,
        query: InvestigationQuery,
        scope: Scope,
        now: datetime,
        source_reader: SourceContextReader | None = None,
    ) -> tuple[InvestigationCheckpoint, InvestigationObservation]:
        self._preflight(plan, index, checkpoint, scope, now)
        query_digest = canonical_digest(query.model_dump(mode="python"))
        if query_digest in checkpoint.query_digests:
            return self.store.latest(plan.plan_id), self.store.observation(
                plan.plan_id, query_digest
            )
        if checkpoint.queries_used >= plan.limits.max_queries:
            raise SourceHuntRejected("Source Hunt query budget exhausted")
        if len(checkpoint.observation_ids) >= plan.limits.max_observations:
            raise SourceHuntRejected("Source Hunt observation budget exhausted")
        symbols, references = self._matches(index, query)
        excerpts = ()
        if query.kind is InvestigationQueryKind.SOURCE_WINDOW:
            if source_reader is None:
                raise SourceHuntRejected(
                    "Source Hunt source-window query requires a trusted reader"
                )
            files = {item.path: item for item in index.source_files}
            excerpts = tuple(
                source_reader.read_window(
                    source=files[item.location.path],
                    symbol_id=item.symbol_id,
                    line=item.location.line,
                )
                for item in symbols[: query.max_results]
            )
        limit = query.max_results
        truncated = len(symbols) + len(references) > limit
        symbols = symbols[:limit]
        references = references[: max(0, limit - len(symbols))]
        observation = InvestigationObservation.create(
            query_digest=query_digest,
            kind=query.kind,
            matched_symbols=symbols,
            matched_references=references,
            source_excerpts=excerpts,
            truncated=truncated,
        )
        advanced = InvestigationCheckpoint.create(
            plan_id=plan.plan_id,
            index_id=index.index_id,
            status=InvestigationStatus.ACTIVE,
            revision=checkpoint.revision + 1,
            queries_used=checkpoint.queries_used + 1,
            observation_ids=(*checkpoint.observation_ids, observation.observation_id),
            query_digests=(*checkpoint.query_digests, query_digest),
            updated_at=now,
        )
        stored, stored_observation = self.store.advance(
            previous=checkpoint, checkpoint=advanced, observation=observation
        )
        assert stored_observation is not None
        return stored, stored_observation

    def complete(
        self,
        *,
        plan: InvestigationPlan,
        index: RepositoryIndex,
        checkpoint: InvestigationCheckpoint,
        conclusion_digest: str,
        scope: Scope,
        now: datetime,
    ) -> InvestigationCheckpoint:
        self._preflight(plan, index, checkpoint, scope, now)
        if not checkpoint.observation_ids:
            raise SourceHuntRejected("Source Hunt cannot complete without observations")
        advanced = InvestigationCheckpoint.create(
            plan_id=plan.plan_id,
            index_id=index.index_id,
            status=InvestigationStatus.READY_FOR_CANDIDATES,
            revision=checkpoint.revision + 1,
            queries_used=checkpoint.queries_used,
            observation_ids=checkpoint.observation_ids,
            query_digests=checkpoint.query_digests,
            conclusion_digest=conclusion_digest,
            reason_code="investigation_completed",
            updated_at=now,
        )
        return self.store.advance(previous=checkpoint, checkpoint=advanced)[0]

    def cancel(
        self,
        *,
        plan: InvestigationPlan,
        index: RepositoryIndex,
        checkpoint: InvestigationCheckpoint,
        scope: Scope,
        now: datetime,
    ) -> InvestigationCheckpoint:
        self._preflight(plan, index, checkpoint, scope, now, allow_expired=True)
        advanced = InvestigationCheckpoint.create(
            plan_id=plan.plan_id,
            index_id=index.index_id,
            status=InvestigationStatus.CANCELLED,
            revision=checkpoint.revision + 1,
            queries_used=checkpoint.queries_used,
            observation_ids=checkpoint.observation_ids,
            query_digests=checkpoint.query_digests,
            reason_code="cancelled_by_operator",
            updated_at=now,
        )
        return self.store.advance(previous=checkpoint, checkpoint=advanced)[0]

    def expire(
        self,
        *,
        plan: InvestigationPlan,
        checkpoint: InvestigationCheckpoint,
        now: datetime,
    ) -> InvestigationCheckpoint:
        if now < plan.deadline:
            raise SourceHuntRejected("Source Hunt plan has not expired")
        if checkpoint.status is not InvestigationStatus.ACTIVE:
            return checkpoint
        advanced = InvestigationCheckpoint.create(
            plan_id=plan.plan_id,
            index_id=plan.index_id,
            status=InvestigationStatus.TIMED_OUT,
            revision=checkpoint.revision + 1,
            queries_used=checkpoint.queries_used,
            observation_ids=checkpoint.observation_ids,
            query_digests=checkpoint.query_digests,
            reason_code="deadline_expired",
            updated_at=now,
        )
        return self.store.advance(previous=checkpoint, checkpoint=advanced)[0]

    @staticmethod
    def _matches(index: RepositoryIndex, query: InvestigationQuery):
        term = query.term.casefold()
        if query.kind in {
            InvestigationQueryKind.SYMBOL,
            InvestigationQueryKind.SOURCE_WINDOW,
        }:
            symbols = tuple(
                item for item in index.symbols if term in item.qualified_name.casefold()
            )
            return symbols, ()
        if query.kind is InvestigationQueryKind.CALLERS:
            refs = tuple(
                item for item in index.references if term in item.target_name.casefold()
            )
            return (), refs
        if query.kind is InvestigationQueryKind.CALLEES:
            refs = tuple(
                item for item in index.references if term in item.source_symbol.casefold()
            )
            return (), refs
        refs = tuple(
            item
            for item in index.references
            if term in item.target_name.casefold() or term in item.source_symbol.casefold()
        )
        return (), refs

    @staticmethod
    def _root(snapshot: TargetSnapshot, store_root: Path) -> Path:
        root_store = store_root.resolve()
        root = (root_store / snapshot.root_ref).resolve()  # type: ignore[arg-type]
        if root == root_store or root_store not in root.parents or not root.is_dir():
            raise SourceHuntRejected("Source Hunt snapshot root is unavailable or unsafe")
        return root

    @staticmethod
    def _read_verified(
        root: Path, relative: str, size: int, digest: str
    ) -> bytes:
        path = root.joinpath(*PurePosixPath(relative).parts)
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise SourceHuntRejected("manifest source file is unavailable") from exc
        if not stat.S_ISREG(mode) or path.is_symlink():
            raise SourceHuntRejected("manifest source path is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise SourceHuntRejected("manifest source file cannot be opened safely") from exc
        with os.fdopen(descriptor, "rb") as handle:
            content = handle.read(size + 1)
        if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
            raise SourceHuntRejected("manifest source file failed integrity check")
        return content

    @staticmethod
    def _partitions(files, maximum: int) -> tuple[SourcePartition, ...]:
        grouped = defaultdict(list)
        for item in files:
            parts = PurePosixPath(item.path).parts
            grouped[parts[0] if len(parts) > 1 else "."].append(item)
        partitions = []
        ordinal = 0
        for group in sorted(grouped):
            items = grouped[group]
            for offset in range(0, len(items), maximum):
                chunk = items[offset : offset + maximum]
                partitions.append(
                    SourcePartition.create(
                        ordinal=ordinal,
                        paths=tuple(item.path for item in chunk),
                        total_bytes=sum(item.size for item in chunk),
                    )
                )
                ordinal += 1
        return tuple(partitions)

    @staticmethod
    def _scope(index: RepositoryIndex, scope: Scope, now: datetime) -> None:
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
            or index.scope_id != scope.scope_id
            or index.scope_version != scope.version
        ):
            raise SourceHuntRejected("Source Hunt requires the bound approved Scope")

    def _preflight(
        self, plan, index, checkpoint, scope, now, *, allow_expired: bool = False
    ) -> None:
        if (
            scope.state is not ScopeState.APPROVED
            or index.scope_id != scope.scope_id
            or index.scope_version != scope.version
            or plan.index_id != index.index_id
            or plan.target_id != index.target_id
            or plan.target_version != index.target_version
            or checkpoint.plan_id != plan.plan_id
            or checkpoint.index_id != index.index_id
        ):
            raise SourceHuntRejected("Source Hunt provenance or Scope binding mismatch")
        if checkpoint.status is not InvestigationStatus.ACTIVE:
            raise SourceHuntRejected("Source Hunt investigation is terminal")
        if not allow_expired and (
            not scope.valid_from <= now < scope.valid_until or now >= plan.deadline
        ):
            raise SourceHuntTimedOut("Source Hunt investigation deadline expired")
        current = self.store.latest(plan.plan_id)
        if current.checkpoint_id != checkpoint.checkpoint_id:
            raise SourceHuntRejected("Source Hunt checkpoint is stale")

    def _deadline(self, started: float, limits: SourceHuntLimits) -> None:
        if self.clock() - started >= limits.timeout_seconds:
            raise SourceHuntTimedOut("Source Hunt indexing exceeded its wall budget")
