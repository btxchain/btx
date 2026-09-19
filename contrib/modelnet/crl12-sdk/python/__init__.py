# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Cognitive Reserve Layer v1.2 Python SDK."""

from __future__ import annotations

try:
    from .btx_crl12 import (
        ANALYTICS_SCOPES,
        AUTOMATIC_SPEND_ATOMS,
        Crl12Client,
        Crl12Error,
        CrlClient,
        CognitiveReserveLayerClient,
        OBJECT_TYPES,
        OPERATION_IDS,
        OPERATIONS,
        analytics_client,
        body_id,
        canonical_body,
        contains_secrets,
    )
    from .desktop_context import CONTEXT_TYPE, apply_desktop_context
except ImportError:  # directory on sys.path as loose modules
    from btx_crl12 import (
        ANALYTICS_SCOPES,
        AUTOMATIC_SPEND_ATOMS,
        Crl12Client,
        Crl12Error,
        CrlClient,
        CognitiveReserveLayerClient,
        OBJECT_TYPES,
        OPERATION_IDS,
        OPERATIONS,
        analytics_client,
        body_id,
        canonical_body,
        contains_secrets,
    )
    from desktop_context import CONTEXT_TYPE, apply_desktop_context

__all__ = (
    "ANALYTICS_SCOPES",
    "AUTOMATIC_SPEND_ATOMS",
    "CONTEXT_TYPE",
    "Crl12Client",
    "Crl12Error",
    "CrlClient",
    "CognitiveReserveLayerClient",
    "OBJECT_TYPES",
    "OPERATION_IDS",
    "OPERATIONS",
    "analytics_client",
    "apply_desktop_context",
    "body_id",
    "canonical_body",
    "contains_secrets",
)
