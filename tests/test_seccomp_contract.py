from __future__ import annotations

from importlib.resources import files

import pytest
from pydantic import ValidationError

from vulnloom.runners import (
    WORKER_SECCOMP_CONTRACT,
    SandboxProfile,
    SeccompContract,
    SeccompContractMode,
    load_worker_seccomp_contract,
    static_profile,
)

IMAGE = "sha256:" + "1" * 64
SNAPSHOT = "2" * 64


def test_worker_seccomp_contract_is_packaged_versioned_and_content_addressed():
    contract = load_worker_seccomp_contract()

    assert contract == WORKER_SECCOMP_CONTRACT
    assert contract.mode is SeccompContractMode.RUNTIME_DEFAULT
    assert contract.engine_versions == {"29.7.2"}
    assert contract.required_linux_seccomp_mode == 2
    assert contract.required_engine_security_option == "name=seccomp,profile=builtin"
    assert "seccomp=unconfined" in contract.forbidden_container_security_options
    resource = files("vulnloom.runners").joinpath("contracts/worker-seccomp-v1.json")
    assert resource.is_file()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("required_engine_security_option", "name=seccomp,profile=unknown", "builtin"),
        ("forbidden_container_security_options", {"apparmor=unconfined"}, "unconfined"),
        ("contract_id", "f" * 64, "contract id"),
    ),
)
def test_seccomp_contract_rejects_weakened_or_tampered_content(field, value, message):
    raw = WORKER_SECCOMP_CONTRACT.model_dump(mode="python")
    raw[field] = value

    with pytest.raises(ValidationError, match=message):
        SeccompContract.model_validate(raw)


def test_every_sandbox_profile_binds_the_admitted_seccomp_contract():
    profile = static_profile(image_digest=IMAGE, snapshot_id=SNAPSHOT)
    assert profile.seccomp_contract_digest == WORKER_SECCOMP_CONTRACT.contract_id

    raw = profile.model_dump(mode="python")
    raw["seccomp_contract_digest"] = "f" * 64
    with pytest.raises(ValidationError, match="seccomp contract"):
        SandboxProfile.model_validate(raw)
