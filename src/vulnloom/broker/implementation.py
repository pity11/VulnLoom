"""Stable identities for trusted Broker tool implementations."""

from __future__ import annotations

import hashlib

OFFLINE_HTTP_IMPLEMENTATION_DIGEST = hashlib.sha256(
    b"vulnloom:offline-http:v1"
).hexdigest()
PINNED_HTTP_IMPLEMENTATION_DIGEST = hashlib.sha256(
    b"vulnloom:pinned-http:v1"
).hexdigest()
