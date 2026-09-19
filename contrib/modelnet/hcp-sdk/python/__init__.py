# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""HCP/1 Python SDK.

Decimal atom strings, no auto-submit on timeout, MCP wrapper that never
forwards OAuth tokens to child tools. Not a wallet.
"""

from __future__ import annotations

try:
    from .btx_hcp import HcpClient, HcpError, body_id, canonical_body
    from .mcp_wrapper import (
        Effect,
        HcpMcpWrapper,
        McpTool,
        TokenPassthroughError,
        child_environ,
        child_headers,
        declared_effect,
        list_tools,
    )
except ImportError:  # directory on sys.path as loose modules
    from btx_hcp import HcpClient, HcpError, body_id, canonical_body
    from mcp_wrapper import (
        Effect,
        HcpMcpWrapper,
        McpTool,
        TokenPassthroughError,
        child_environ,
        child_headers,
        declared_effect,
        list_tools,
    )

__all__ = (
    "Effect",
    "HcpClient",
    "HcpError",
    "HcpMcpWrapper",
    "McpTool",
    "TokenPassthroughError",
    "body_id",
    "canonical_body",
    "child_environ",
    "child_headers",
    "declared_effect",
    "list_tools",
)
