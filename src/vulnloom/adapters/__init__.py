"""External-system adapter contracts."""

from .model_credentials import (
    EnvironmentModelCredentialProvider,
    ModelCredentialLease,
    ModelCredentialProvider,
    ModelCredentialReference,
    ModelCredentialUnavailable,
)
from .model_endpoints import (
    EnvironmentModelEndpointProvider,
    ModelEndpointProvider,
    ModelEndpointReference,
    ModelEndpointUnavailable,
    ResolvedModelEndpoint,
)

__all__ = [
    "EnvironmentModelCredentialProvider",
    "EnvironmentModelEndpointProvider",
    "ModelCredentialLease",
    "ModelCredentialProvider",
    "ModelCredentialReference",
    "ModelCredentialUnavailable",
    "ModelEndpointReference",
    "ModelEndpointProvider",
    "ModelEndpointUnavailable",
    "ResolvedModelEndpoint",
]
