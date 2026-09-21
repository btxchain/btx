# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Compatibility export of the typed CRL/1.2 client (no generic RPC)."""

from __future__ import annotations

try:
    from .btx_crl12 import Crl12Client as CrlClient
    from .btx_crl12 import Crl12Error as ClientError
except ImportError:
    from btx_crl12 import Crl12Client as CrlClient
    from btx_crl12 import Crl12Error as ClientError

__all__ = ("ClientError", "CrlClient")
