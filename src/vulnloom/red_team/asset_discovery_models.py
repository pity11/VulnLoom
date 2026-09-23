"""Typed contracts for authorization-derived passive asset discovery."""

from __future__ import annotations

import ipaddress
import re
from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

from .models import Digest


class AssetDiscoverySource(StrEnum):
    FOFA = "fofa"
    QUAKE = "quake"
    SHODAN = "shodan"
    PASSIVE_DNS = "passive_dns"
    CERTIFICATE_TRANSPARENCY = "certificate_transparency"
    ICP_REGISTRY = "icp_registry"
    OPERATOR_IMPORT = "operator_import"


class AssetDiscoverySelectorKind(StrEnum):
    DOMAIN = "domain"
    ICP_REGISTRATION = "icp_registration"
    EXACT_HOST = "exact_host"


class AssetAuthorizationMode(StrEnum):
    EXACT_ASSIGNMENT = "exact_assignment"
    ENTITY_BOUND = "entity_bound"
    PLATFORM_CATEGORY = "platform_category"
    SUPPLY_CHAIN_WITH_APPROVAL = "supply_chain_with_approval"


class AssetLocatorKind(StrEnum):
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"


class AssetAttributionKind(StrEnum):
    AUTHORIZED_ROOT_DOMAIN = "authorized_root_domain"
    ICP_REGISTRATION_MATCH = "icp_registration_match"
    OPERATOR_INVENTORY_MATCH = "operator_inventory_match"
    CERTIFICATE_NAME_MATCH = "certificate_name_match"
    OFFICIAL_LINK = "official_link"
    PRODUCT_FINGERPRINT = "product_fingerprint"
    CROSS_LEGAL_ENTITY = "cross_legal_entity"
    EXPLICIT_EXCLUSION = "explicit_exclusion"


class AttributionVerdict(StrEnum):
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class AssetAdmissionVerdict(StrEnum):
    ADMITTED = "admitted"
    APPROVAL_REQUIRED = "approval_required"
    REJECTED = "rejected"


class AssetDiscoveryState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"


_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def canonical_hostname(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    if len(host) > 253 or "." not in host or any(
        not _HOST_LABEL.fullmatch(label) for label in host.split(".")
    ):
        raise ValueError("hostname is not canonical")
    return host


def canonical_ip(value: str) -> str:
    address = ipaddress.ip_address(value.strip())
    if address.is_unspecified or address.is_multicast:
        raise ValueError("IP address is not a discoverable unicast address")
    return address.compressed


class AssetDiscoveryAuthorization(DomainModel):
    authorization_id: Digest
    authorization_version: Literal[1] = 1
    scope_id: UUID
    scope_version: int = Field(ge=1)
    authority_reference_digest: Digest
    mode: AssetAuthorizationMode
    exact_hosts: tuple[str, ...] = ()
    exact_endpoints: tuple[
        Annotated[str, Field(pattern=r"^https?://[a-z0-9.-]{3,253}:[1-9][0-9]{0,4}$")],
        ...,
    ] = ()
    root_domains: tuple[str, ...] = ()
    icp_registration_digests: tuple[Digest, ...] = ()
    excluded_domain_suffixes: tuple[str, ...] = ()
    allowed_sources: Annotated[
        tuple[AssetDiscoverySource, ...], Field(min_length=1, max_length=8)
    ]
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    created_at: AwareDatetime

    @field_validator("exact_hosts", "root_domains", "excluded_domain_suffixes")
    @classmethod
    def canonical_domains(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(canonical_hostname(item) for item in value)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            not self.valid_from < self.valid_until
            or not self.valid_from <= self.created_at < self.valid_until
            or not self.exact_hosts
            and not self.root_domains
            and not self.icp_registration_digests
            or self.exact_hosts != tuple(sorted(set(self.exact_hosts)))
            or self.exact_endpoints != tuple(sorted(set(self.exact_endpoints)))
            or any(
                endpoint.split("://", 1)[1].rsplit(":", 1)[0]
                not in self.exact_hosts
                for endpoint in self.exact_endpoints
            )
            or self.root_domains != tuple(sorted(set(self.root_domains)))
            or self.icp_registration_digests
            != tuple(sorted(set(self.icp_registration_digests)))
            or self.excluded_domain_suffixes
            != tuple(sorted(set(self.excluded_domain_suffixes)))
            or self.allowed_sources
            != tuple(sorted(set(self.allowed_sources), key=lambda item: item.value))
            or self.authorization_id
            != canonical_digest(
                self.model_dump(mode="python", exclude={"authorization_id"})
            )
        ):
            raise ValueError("asset discovery authorization binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> AssetDiscoveryAuthorization:
        normalized = dict(values)
        for name in ("exact_hosts", "root_domains", "excluded_domain_suffixes"):
            normalized[name] = tuple(
                sorted({canonical_hostname(item) for item in normalized.get(name, ())})
            )
        normalized["icp_registration_digests"] = tuple(
            sorted(set(normalized.get("icp_registration_digests", ())))
        )
        normalized["exact_endpoints"] = tuple(
            sorted(set(normalized.get("exact_endpoints", ())))
        )
        normalized["allowed_sources"] = tuple(
            sorted(set(normalized["allowed_sources"]), key=lambda item: item.value)
        )
        expanded = cls.model_construct(
            authorization_id="0" * 64, **normalized
        ).model_dump(mode="python", exclude={"authorization_id"})
        return cls(authorization_id=canonical_digest(expanded), **expanded)


class AssetDiscoveryQuery(DomainModel):
    query_id: Digest
    source: AssetDiscoverySource
    selector_kind: AssetDiscoverySelectorKind
    selector: str = Field(min_length=1, max_length=253)
    selector_digest: Digest
    result_limit: int = Field(ge=1, le=1_000)
    raw_query_authorized: Literal[False] = False

    @field_validator("selector")
    @classmethod
    def canonical_selector(cls, value: str, info) -> str:
        kind = info.data.get("selector_kind")
        if kind in {
            AssetDiscoverySelectorKind.DOMAIN,
            AssetDiscoverySelectorKind.EXACT_HOST,
        }:
            return canonical_hostname(value)
        candidate = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9\u4e00-\u9fff._ -]{3,128}", candidate):
            raise ValueError("ICP selector contains unsupported characters")
        return candidate

    @model_validator(mode="after")
    def sealed(self) -> Self:
        identity = self.model_dump(mode="python", exclude={"query_id"})
        if (
            self.selector_digest != canonical_digest(self.selector)
            or self.raw_query_authorized
            or self.query_id != canonical_digest(identity)
        ):
            raise ValueError("asset discovery query binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> AssetDiscoveryQuery:
        selector = str(values["selector"])
        if values["selector_kind"] in {
            AssetDiscoverySelectorKind.DOMAIN,
            AssetDiscoverySelectorKind.EXACT_HOST,
        }:
            selector = canonical_hostname(selector)
        else:
            selector = selector.strip()
        expanded = {**values, "selector_digest": canonical_digest(selector)}
        expanded["selector"] = selector
        identity = cls.model_construct(query_id="0" * 64, **expanded).model_dump(
            mode="python", exclude={"query_id"}
        )
        return cls(query_id=canonical_digest(identity), **identity)


class AssetDiscoveryLimits(DomainModel):
    max_queries: int = Field(default=16, ge=1, le=64)
    max_records: int = Field(default=500, ge=1, le=5_000)
    max_evidence_per_asset: int = Field(default=16, ge=1, le=32)
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=3, ge=1, le=3)


class AssetDiscoveryPlan(DomainModel):
    plan_id: Digest
    authorization: AssetDiscoveryAuthorization
    queries: Annotated[tuple[AssetDiscoveryQuery, ...], Field(min_length=1, max_length=64)]
    limits: AssetDiscoveryLimits
    created_at: AwareDatetime
    deadline: AwareDatetime
    idempotency_key: str = Field(min_length=1, max_length=256)
    adapter_credential_ref: None = None
    worker_execution_authorized: Literal[False] = False
    active_scanning_authorized: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        query_ids = tuple(item.query_id for item in self.queries)
        if (
            not self.created_at < self.deadline <= self.authorization.valid_until
            or len(self.queries) > self.limits.max_queries
            or sum(item.result_limit for item in self.queries) > self.limits.max_records
            or query_ids != tuple(sorted(set(query_ids)))
            or any(item.source not in self.authorization.allowed_sources for item in self.queries)
            or self.adapter_credential_ref is not None
            or self.worker_execution_authorized
            or self.active_scanning_authorized
            or self.plan_id
            != canonical_digest(self.model_dump(mode="python", exclude={"plan_id"}))
        ):
            raise ValueError("asset discovery plan binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> AssetDiscoveryPlan:
        normalized = dict(values)
        normalized["queries"] = tuple(
            sorted(normalized["queries"], key=lambda item: item.query_id)
        )
        expanded = cls.model_construct(plan_id="0" * 64, **normalized).model_dump(
            mode="python", exclude={"plan_id"}
        )
        return cls(plan_id=canonical_digest(expanded), **expanded)


class DiscoveredAsset(DomainModel):
    asset_id: Digest
    plan_id: Digest
    query_id: Digest
    source: AssetDiscoverySource
    locator_kind: AssetLocatorKind
    locator: str
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"]
    observed_at: AwareDatetime
    source_record_ref: str = Field(
        min_length=1, max_length=256, pattern=r"^[a-z][a-z0-9:._-]{0,255}$"
    )
    source_evidence_digest: Digest
    active_observation: Literal[False] = False
    test_execution_authorized: Literal[False] = False

    @field_validator("locator")
    @classmethod
    def canonical_locator(cls, value: str, info) -> str:
        if info.data.get("locator_kind") is AssetLocatorKind.HOSTNAME:
            return canonical_hostname(value)
        return canonical_ip(value)

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.active_observation
            or self.test_execution_authorized
            or self.asset_id
            != canonical_digest(self.model_dump(mode="python", exclude={"asset_id"}))
        ):
            raise ValueError("discovered asset binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> DiscoveredAsset:
        normalized = dict(values)
        if values["locator_kind"] is AssetLocatorKind.HOSTNAME:
            normalized["locator"] = canonical_hostname(str(values["locator"]))
        else:
            normalized["locator"] = canonical_ip(str(values["locator"]))
        expanded = cls.model_construct(asset_id="0" * 64, **normalized).model_dump(
            mode="python", exclude={"asset_id"}
        )
        return cls(asset_id=canonical_digest(expanded), **expanded)


class AssetAttributionEvidence(DomainModel):
    attribution_id: Digest
    asset_id: Digest
    kind: AssetAttributionKind
    verdict: AttributionVerdict
    evidence_ref: Digest
    subject_digest: Digest
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if self.attribution_id != canonical_digest(
            self.model_dump(mode="python", exclude={"attribution_id"})
        ):
            raise ValueError("asset attribution evidence binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> AssetAttributionEvidence:
        expanded = cls.model_construct(attribution_id="0" * 64, **values).model_dump(
            mode="python", exclude={"attribution_id"}
        )
        return cls(attribution_id=canonical_digest(expanded), **expanded)


class AssetDiscoveryObservation(DomainModel):
    asset: DiscoveredAsset
    attribution: Annotated[
        tuple[AssetAttributionEvidence, ...], Field(max_length=32)
    ] = ()

    @model_validator(mode="after")
    def bound(self) -> Self:
        ids = tuple(item.attribution_id for item in self.attribution)
        if (
            ids != tuple(sorted(set(ids)))
            or len({item.kind for item in self.attribution}) != len(self.attribution)
            or any(item.asset_id != self.asset.asset_id for item in self.attribution)
        ):
            raise ValueError("asset discovery attribution binding is invalid")
        return self


class AssetDiscoveryBatch(DomainModel):
    query_id: Digest
    observations: tuple[AssetDiscoveryObservation, ...]
    raw_response_retained: Literal[False] = False
    credential_material_absent: Literal[True] = True
    adapter_session_closed: Literal[True] = True


class AssetAdmissionDecision(DomainModel):
    decision_id: Digest
    authorization_id: Digest
    asset_id: Digest
    verdict: AssetAdmissionVerdict
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    attribution_ids: tuple[Digest, ...]
    decided_at: AwareDatetime
    active_testing_authorized: Literal[False] = False
    finding_authorized: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            self.attribution_ids != tuple(sorted(set(self.attribution_ids)))
            or self.active_testing_authorized
            or self.finding_authorized
            or self.decision_id
            != canonical_digest(self.model_dump(mode="python", exclude={"decision_id"}))
        ):
            raise ValueError("asset admission decision binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> AssetAdmissionDecision:
        normalized = dict(values)
        normalized["attribution_ids"] = tuple(sorted(set(values["attribution_ids"])))
        expanded = cls.model_construct(decision_id="0" * 64, **normalized).model_dump(
            mode="python", exclude={"decision_id"}
        )
        return cls(decision_id=canonical_digest(expanded), **expanded)


class AuthorizedAsset(DomainModel):
    authorized_asset_id: Digest
    authorization_id: Digest
    decision_id: Digest
    asset: DiscoveredAsset
    admitted_at: AwareDatetime
    target_materialization_authorized: Literal[True] = True
    active_testing_authorized: Literal[False] = False
    finding_authorized: Literal[False] = False

    @model_validator(mode="after")
    def sealed(self) -> Self:
        if (
            not self.target_materialization_authorized
            or self.active_testing_authorized
            or self.finding_authorized
            or self.authorized_asset_id
            != canonical_digest(
                self.model_dump(mode="python", exclude={"authorized_asset_id"})
            )
        ):
            raise ValueError("authorized asset binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> AuthorizedAsset:
        expanded = cls.model_construct(
            authorized_asset_id="0" * 64, **values
        ).model_dump(mode="python", exclude={"authorized_asset_id"})
        return cls(authorized_asset_id=canonical_digest(expanded), **expanded)


class AssetDiscoveryOutcome(DomainModel):
    outcome_id: Digest
    plan_id: Digest
    observation_count: int = Field(ge=0, le=5_000)
    decisions: tuple[AssetAdmissionDecision, ...]
    authorized_asset_ids: tuple[Digest, ...]
    attempt: int = Field(ge=1, le=3)
    completed_at: AwareDatetime
    cleanup_complete: Literal[True] = True

    @model_validator(mode="after")
    def sealed(self) -> Self:
        decision_ids = tuple(item.decision_id for item in self.decisions)
        if (
            decision_ids != tuple(sorted(set(decision_ids)))
            or self.observation_count != len(self.decisions)
            or len({item.asset_id for item in self.decisions}) != len(self.decisions)
            or self.authorized_asset_ids != tuple(sorted(set(self.authorized_asset_ids)))
            or self.outcome_id
            != canonical_digest(self.model_dump(mode="python", exclude={"outcome_id"}))
        ):
            raise ValueError("asset discovery outcome binding is invalid")
        return self

    @classmethod
    def create(cls, **values: object) -> AssetDiscoveryOutcome:
        normalized = dict(values)
        normalized["decisions"] = tuple(
            sorted(values["decisions"], key=lambda item: item.decision_id)
        )
        normalized["authorized_asset_ids"] = tuple(
            sorted(set(values["authorized_asset_ids"]))
        )
        expanded = cls.model_construct(outcome_id="0" * 64, **normalized).model_dump(
            mode="python", exclude={"outcome_id"}
        )
        return cls(outcome_id=canonical_digest(expanded), **expanded)
