"""External-system adapter contracts."""

from .model_credentials import (
    EnvironmentModelCredentialProvider,
    ModelCredentialLease,
    ModelCredentialProvider,
    ModelCredentialReference,
    ModelCredentialUnavailable,
)
from .model_endpoints import ModelEndpointReference

__all__ = [
    "EnvironmentModelCredentialProvider",
    "ModelCredentialLease",
    "ModelCredentialProvider",
    "ModelCredentialReference",
    "ModelCredentialUnavailable",
    "ModelEndpointReference",
]
