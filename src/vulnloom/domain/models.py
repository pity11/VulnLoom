"""Immutable domain objects.

LLM and Worker output must be parsed into these objects before it can influence
trusted state. Models reject unknown fields so prose cannot silently become a
permission or workflow transition.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, HttpUrl, field_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


NonEmpty = Annotated[str, Field(min_length=1)]


class DomainModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class EngagementState(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    CLOSED = "closed"


class ScopeState(StrEnum):
    DRAFT = "draft"
    APPROVED = "approved"
    REVOKED = "revoked"


class TargetKind(StrEnum):
    REPOSITORY = "repository"
    CONTAINER_IMAGE = "container_image"
    TEST_SERVICE = "test_service"
    IAC_BUNDLE = "iac_bundle"


class ArtifactKind(StrEnum):
    SOURCE_ARCHIVE = "source_archive"
    IAC_BUNDLE = "iac_bundle"
    GIT_REPOSITORY = "git_repository"
    OCI_IMAGE = "oci_image"


class StaticFileCategory(StrEnum):
    SOURCE = "source"
    KUBERNETES = "kubernetes"
    HELM = "helm"
    TERRAFORM = "terraform"
    DOCKERFILE = "dockerfile"
    COMPOSE = "compose"
    CONFIG = "config"
    DOCUMENTATION = "documentation"
    OTHER = "other"


class CandidateState(StrEnum):
    PROPOSED = "proposed"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    VALIDATION_PENDING = "validation_pending"
    VALIDATION_RUNNING = "validation_running"
    VALIDATED = "validated"
    INCONCLUSIVE = "inconclusive"
    CRITIC_REVIEWED = "critic_reviewed"
    PROMOTED = "promoted"


class ValidationResult(StrEnum):
    REPRODUCED = "reproduced"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"
    POLICY_STOPPED = "policy_stopped"
    TIMED_OUT = "timed_out"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"
    REVOKED = "revoked"


class ApprovalAction(StrEnum):
    RUN_UNTRUSTED_BUILD = "run_untrusted_build"
    MUTATE_TARGET_STATE = "mutate_target_state"
    USE_REAL_CREDENTIALS = "use_real_credentials"
    EXTERNAL_CALLBACK = "external_callback"
    SUBMIT_REPORT = "submit_report"


class EvidenceKind(StrEnum):
    SOURCE = "source"
    HTTP = "http"
    LOG = "log"
    SCREENSHOT = "screenshot"
    TEST = "test"
    POLICY = "policy"


class ReportChannel(StrEnum):
    GENERIC = "generic"
    EDUSRC = "edusrc"
    CNVD = "cnvd"
    VENDOR = "vendor"
    CVE_DRAFT = "cve-draft"


class Engagement(DomainModel):
    engagement_id: UUID = Field(default_factory=uuid4)
    authority_reference: NonEmpty
    name: NonEmpty
    state: EngagementState = EngagementState.DRAFT
    created_at: AwareDatetime = Field(default_factory=utc_now)


class RepositoryScope(DomainModel):
    url: NonEmpty
    commit: Annotated[str, Field(pattern=r"^[0-9a-fA-F]{7,64}$")]


class ArtifactScope(DomainModel):
    kind: ArtifactKind
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    source_name: NonEmpty


class NetworkTargetScope(DomainModel):
    host: NonEmpty
    ports: frozenset[Annotated[int, Field(ge=1, le=65535)]]
    schemes: frozenset[str] = frozenset({"https"})

    @field_validator("schemes")
    @classmethod
    def supported_schemes(cls, value: frozenset[str]) -> frozenset[str]:
        normalized = frozenset(item.lower() for item in value)
        if not normalized or not normalized <= {"http", "https"}:
            raise ValueError("schemes must be a non-empty subset of http/https")
        return normalized


class Scope(DomainModel):
    scope_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    version: Annotated[int, Field(ge=1)] = 1
    authority_reference: NonEmpty
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    repositories: tuple[RepositoryScope, ...] = ()
    artifacts: tuple[ArtifactScope, ...] = ()
    network_targets: tuple[NetworkTargetScope, ...] = ()
    allowed_identities: frozenset[str] = frozenset()
    allowed_test_classes: frozenset[str] = frozenset()
    denied_actions: frozenset[str] = frozenset()
    rate_limits: dict[str, Annotated[int, Field(ge=1)]] = Field(default_factory=dict)
    approval_requirements: frozenset[ApprovalAction] = frozenset()
    state: ScopeState = ScopeState.DRAFT
    approved_by: str | None = None
    approved_at: AwareDatetime | None = None

    @field_validator("valid_until")
    @classmethod
    def validity_window_is_ordered(cls, value: datetime, info: Any) -> datetime:
        start = info.data.get("valid_from")
        if start is not None and value <= start:
            raise ValueError("valid_until must be after valid_from")
        return value


class Target(DomainModel):
    target_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    kind: TargetKind
    source_ref: NonEmpty
    version: NonEmpty
    ingested_at: AwareDatetime = Field(default_factory=utc_now)


class Artifact(DomainModel):
    artifact_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    engagement_id: UUID
    kind: ArtifactKind
    source_name: NonEmpty
    source_ref: NonEmpty
    original_size: Annotated[int, Field(ge=0)]
    detected_format: NonEmpty
    quarantine_ref: str | None = None
    captured_at: AwareDatetime = Field(default_factory=utc_now)


class SnapshotFile(DomainModel):
    path: NonEmpty
    size: Annotated[int, Field(ge=0)]
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    category: StaticFileCategory


class TargetManifest(DomainModel):
    manifest_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    artifact_id: NonEmpty
    target_id: UUID
    target_version: NonEmpty
    files: tuple[SnapshotFile, ...]
    total_size: Annotated[int, Field(ge=0)]
    created_at: AwareDatetime = Field(default_factory=utc_now)


class TargetSnapshot(DomainModel):
    target: Target
    artifact: Artifact
    manifest: TargetManifest
    root_ref: str | None = None


class SourceLocation(DomainModel):
    path: NonEmpty
    line: Annotated[int, Field(ge=1)]
    symbol: str | None = None


class Candidate(DomainModel):
    candidate_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    target_version: NonEmpty
    source_graph_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    scope_id: UUID
    scope_version: Annotated[int, Field(ge=1)]
    title: NonEmpty
    cwe: Annotated[str, Field(pattern=r"^CWE-[1-9][0-9]*$")]
    entry_point: SourceLocation
    sink: SourceLocation
    code_path: Annotated[tuple[SourceLocation, ...], Field(min_length=1)]
    preconditions: tuple[str, ...] = ()
    security_invariant: NonEmpty
    hypothesis: NonEmpty
    signal_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")], ...],
        Field(min_length=1),
    ]
    cheapest_disproof: NonEmpty
    duplicate_fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    confidence: float = Field(ge=0, le=1)
    state: CandidateState = CandidateState.PROPOSED


class ApprovalRequest(DomainModel):
    approval_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    target_id: UUID | None = None
    action: ApprovalAction
    action_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    expected_side_effects: tuple[str, ...]
    evidence_summary: NonEmpty
    policy_version: Annotated[int, Field(ge=1)]
    expires_at: AwareDatetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: str | None = None
    decided_at: AwareDatetime | None = None

    def is_valid_for(self, *, action: ApprovalAction, digest: str, now: datetime) -> bool:
        return (
            self.status is ApprovalStatus.GRANTED
            and self.action is action
            and self.action_digest == digest
            and now < self.expires_at
        )


class ValidationRun(DomainModel):
    run_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID
    target_version: NonEmpty
    scope_version: Annotated[int, Field(ge=1)]
    sandbox_image_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    policy_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    plan: tuple[str, ...]
    started_at: AwareDatetime
    finished_at: AwareDatetime
    result: ValidationResult
    side_effects: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    resource_usage: dict[str, int | float] = Field(default_factory=dict)

    @field_validator("finished_at")
    @classmethod
    def run_time_is_ordered(cls, value: datetime, info: Any) -> datetime:
        started = info.data.get("started_at")
        if started is not None and value < started:
            raise ValueError("finished_at cannot be before started_at")
        return value


class Evidence(DomainModel):
    evidence_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    kind: EvidenceKind
    source_ref: NonEmpty
    captured_at: AwareDatetime = Field(default_factory=utc_now)
    producer: NonEmpty
    target_version: NonEmpty
    redaction_policy: NonEmpty
    content_ref: NonEmpty
    summary: NonEmpty


class EvidenceBundle(DomainModel):
    bundle_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID
    evidence_refs: tuple[Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")], ...]
    sealed_at: AwareDatetime = Field(default_factory=utc_now)


class CriticReview(DomainModel):
    review_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID
    accepted: bool
    counterevidence_refs: tuple[str, ...] = ()
    rationale: NonEmpty
    reviewed_at: AwareDatetime = Field(default_factory=utc_now)


class Finding(DomainModel):
    finding_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID
    root_cause: NonEmpty
    affected_versions: tuple[str, ...]
    preconditions: tuple[str, ...]
    impact: NonEmpty
    severity_assessment: dict[str, str | float]
    validation_run_ids: tuple[UUID, ...]
    evidence_bundle_id: UUID
    duplicate_family_id: UUID | None = None
    state: str = "verified"


class ProductIdentity(DomainModel):
    vendor: NonEmpty
    product: NonEmpty
    component: str | None = None
    ecosystem: str | None = None
    repository_url: HttpUrl | None = None


class Report(DomainModel):
    report_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    channel: ReportChannel
    version: Annotated[int, Field(ge=1)] = 1
    title: NonEmpty
    summary: NonEmpty
    reproduction: tuple[str, ...]
    impact: NonEmpty
    remediation: NonEmpty
    evidence_refs: tuple[str, ...]
    redaction_status: str = "passed"
    review_status: str = "draft"


class DisclosureCase(DomainModel):
    disclosure_case_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    product: ProductIdentity | None = None
    intended_channel: ReportChannel
    eligibility_rationale: NonEmpty
    report_ids: tuple[UUID, ...] = ()
    external_reference: str | None = None
    status: str = "draft"
