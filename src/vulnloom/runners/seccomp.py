"""Versioned seccomp qualification contract for untrusted Workers."""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from vulnloom.domain.digests import canonical_digest
from vulnloom.domain.models import DomainModel

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class SeccompContractMode(StrEnum):
    RUNTIME_DEFAULT = "runtime_default"


class SeccompContract(DomainModel):
    contract_id: Digest
    schema_version: Literal[1]
    name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")]
    mode: SeccompContractMode
    engine_versions: Annotated[frozenset[str], Field(min_length=1, max_length=8)]
    required_engine_security_option: str = Field(min_length=1, max_length=128)
    forbidden_container_security_options: Annotated[
        frozenset[str], Field(min_length=1, max_length=8)
    ]
    required_linux_seccomp_mode: Literal[2]

    @model_validator(mode="after")
    def content_addressed_and_fail_closed(self) -> Self:
        if self.required_engine_security_option != "name=seccomp,profile=builtin":
            raise ValueError("seccomp contract must require the admitted builtin profile")
        if "seccomp=unconfined" not in self.forbidden_container_security_options:
            raise ValueError("seccomp contract must forbid unconfined containers")
        if any(not item or len(item) > 64 for item in self.engine_versions):
            raise ValueError("seccomp contract engine versions must be bounded")
        expected = canonical_digest(self.model_dump(mode="python", exclude={"contract_id"}))
        if self.contract_id != expected:
            raise ValueError("seccomp contract id does not match its content")
        return self

    @classmethod
    def create(cls, **values: object) -> SeccompContract:
        return cls(contract_id=canonical_digest(values), **values)


def load_worker_seccomp_contract() -> SeccompContract:
    path = Path(__file__).with_name("contracts") / "worker-seccomp-v1.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("seccomp contract document must be an object")
    return SeccompContract.create(**payload)


WORKER_SECCOMP_CONTRACT = load_worker_seccomp_contract()
