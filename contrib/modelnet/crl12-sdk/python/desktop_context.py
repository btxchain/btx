# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Desktop context is view/draft only. Never HTTP, never localhost execute."""

from __future__ import annotations

from typing import Any

CONTEXT_TYPE = "btx.cognitiveReserve.v1_2"
VIEW_PURPOSES = frozenset({"INSPECT", "COMPARE"})
DRAFT_PURPOSES = frozenset(
    {
        "DRAFT",
        "DRAFT_RESERVE_ALLOCATION",
        "DRAFT_RESEARCH_COMMITMENT",
        "DRAFT_CAPABILITY_ACQUISITION",
        "DRAFT_PRODUCT_REFERRAL",
    }
)
ALLOWED_PURPOSES = VIEW_PURPOSES | DRAFT_PURPOSES

_FORBIDDEN_KEYS = frozenset(
    {
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "private_key",
        "secret",
        "mnemonic",
        "wallet_rpc",
        "prompt",
        "private_prompt",
        "local_path",
        "cwd",
        "automatic_spend_atoms",
        "grand_total",
        "combined_aum_auc",
        "invented_aum",
        "invented_auc",
    }
)
_FORBIDDEN_SUBSTR = (
    "127.0.0.1",
    "localhost",
    "/capital/allocations/",
    "/execute",
    "BEGIN PRIVATE KEY",
)


class DesktopContextError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


def _walk(value: Any) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            lk = str(k).lower()
            if lk in _FORBIDDEN_KEYS or lk.endswith("_secret"):
                if v not in (None, "", [], {}):
                    raise DesktopContextError("SECRET_INLINE", f"context must not carry {k}")
            if isinstance(v, str):
                low = v.lower()
                for needle in _FORBIDDEN_SUBSTR:
                    if needle.lower() in low:
                        raise DesktopContextError("LOCALHOST_EXECUTE_FORBIDDEN", needle)
            _walk(v)
    elif isinstance(value, list):
        for item in value:
            _walk(item)
    elif isinstance(value, str):
        low = value.lower()
        for needle in _FORBIDDEN_SUBSTR:
            if needle.lower() in low:
                raise DesktopContextError("LOCALHOST_EXECUTE_FORBIDDEN", needle)


def apply_desktop_context(ctx: dict[str, Any]) -> dict[str, Any]:
    """Map an application context to typed HCP view/draft operations. No HTTP."""
    if not isinstance(ctx, dict):
        raise DesktopContextError("INVALID_CONTEXT", "object required")
    _walk(ctx)
    if ctx.get("type") != CONTEXT_TYPE:
        raise DesktopContextError("UNKNOWN_CONTEXT_TYPE", str(ctx.get("type")))
    btx = ctx.get("btx")
    if not isinstance(btx, dict):
        raise DesktopContextError("MISSING_BTX", "btx object required")
    purpose = str(btx.get("purpose", ""))
    if purpose not in ALLOWED_PURPOSES:
        raise DesktopContextError("VIEW_DRAFT_ONLY", purpose or "missing purpose")
    ops: list[dict[str, Any]] = []
    asset = btx.get("asset_ref")
    projection = btx.get("projection_ref")
    if purpose in VIEW_PURPOSES:
        if isinstance(asset, str) and asset:
            ops.append(
                {
                    "operation_id": "getInstitutionalAsset",
                    "method": "GET",
                    "path": {"id": asset},
                }
            )
        if isinstance(projection, str) and projection:
            ops.append(
                {
                    "operation_id": "getPortfolioProjection",
                    "method": "GET",
                    "path": {"id": projection},
                }
            )
        if purpose == "COMPARE":
            ops.append({"operation_id": "listInstitutionalMetrics", "method": "GET"})
    else:
        body: dict[str, Any] = {
            "requested_action": purpose if purpose != "DRAFT" else "DRAFT_RESERVE_ALLOCATION",
            "execute": False,
        }
        if isinstance(projection, str) and projection:
            body["source_projection_ref"] = projection
        ops.append(
            {
                "operation_id": "preparePortfolioInstruction",
                "method": "POST",
                "body": body,
            }
        )
    for op in ops:
        oid = op["operation_id"]
        if oid == "executeAllocation" or "execute" in oid.lower():
            raise DesktopContextError("VIEW_DRAFT_ONLY", oid)
        path = str(op.get("path", "")) + str(op)
        if "/execute" in path or "127.0.0.1" in path:
            raise DesktopContextError("LOCALHOST_EXECUTE_FORBIDDEN", path)
    return {
        "type": CONTEXT_TYPE,
        "purpose": purpose,
        "operations": ops,
        "http": False,
        "localhost": False,
        "execute": False,
        "view_or_draft": True,
    }


__all__ = (
    "ALLOWED_PURPOSES",
    "CONTEXT_TYPE",
    "DRAFT_PURPOSES",
    "DesktopContextError",
    "VIEW_PURPOSES",
    "apply_desktop_context",
)
