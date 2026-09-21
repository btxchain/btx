# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Cognitive Reserve v1.1 Python SDK. Additive HCP/1 extension.

Decimal atom strings, HTTP 202 is UNKNOWN, automatic_spend_atoms stays 0.
Not a wallet. No /rpc passthrough.
"""

from __future__ import annotations

try:
    from .btx_cr11 import (
        AUTOMATIC_SPEND_ATOMS,
        CognitiveReserveClient,
        Cr11Error,
        OBJECT_TYPES,
        OPERATION_IDS,
        OPERATIONS,
        body_id,
        canonical_body,
    )
except ImportError:  # directory on sys.path as loose modules
    from btx_cr11 import (
        AUTOMATIC_SPEND_ATOMS,
        CognitiveReserveClient,
        Cr11Error,
        OBJECT_TYPES,
        OPERATION_IDS,
        OPERATIONS,
        body_id,
        canonical_body,
    )

__all__ = (
    "AUTOMATIC_SPEND_ATOMS",
    "CognitiveReserveClient",
    "Cr11Error",
    "OBJECT_TYPES",
    "OPERATION_IDS",
    "OPERATIONS",
    "body_id",
    "canonical_body",
)
