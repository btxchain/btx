# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Cognitive Reserve v1.1 Python SDK. Additive HCP/1 extension (50 ops, 18 types).

Not a wallet. Does not call native wallet RPC, sign spends, or set
automatic_spend_atoms away from 0. Typed operations only; no /rpc passthrough.
HTTP 202 is UNKNOWN — never auto-submit or retry financial actions.
Default origin is HTTPS. Loopback http://127.0.0.1 is REGTEST lab only via
an explicit lab_origin flag.
"""

from __future__ import annotations

import hashlib
import json
import struct
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

AUTOMATIC_SPEND_ATOMS = 0

# Exact reviewed V1_1 object types. Underscores are not a general charset relaxation.
OBJECT_TYPES: tuple[str, ...] = (
    "ReserveExtensionProfileV1_1",
    "EntityLinkV1_1",
    "PortfolioV1_1",
    "ReservePolicyV1_1",
    "ReserveSnapshotV1_1",
    "WorkloadProfileV1_1",
    "TCOComparisonV1_1",
    "CapitalPlanV1_1",
    "AllocationPlanV1_1",
    "ApprovalRuleV1_1",
    "ApprovalRequestV1_1",
    "ApprovalDecisionV1_1",
    "CapabilityPositionV1_1",
    "ResearchProgramV1_1",
    "ProgramMembershipV1_1",
    "ProductOfferV1_1",
    "CapitalExecutionReceiptV1_1",
    "ReserveReportV1_1",
)

_CATALOG_PATH = Path(__file__).resolve().parents[1] / "schemas" / "operations-v1.1.json"


def _load_catalog() -> list[dict[str, Any]]:
    data = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    ops = data["operations"]
    if not isinstance(ops, list) or len(ops) != 50:
        raise RuntimeError("CRF v1.1 catalog must contain exactly 50 operations")
    ids = [o["operation_id"] for o in ops]
    if len(set(ids)) != 50:
        raise RuntimeError("CRF v1.1 catalog operation_id values must be unique")
    return ops


OPERATIONS: tuple[dict[str, Any], ...] = tuple(_load_catalog())
OPERATION_IDS: tuple[str, ...] = tuple(o["operation_id"] for o in OPERATIONS)


class Cr11Error(RuntimeError):
    def __init__(self, code: str, message: str, status: int = 0):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.status = status
        self.unknown = status == 202 or code == "UNKNOWN"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None


def canonical_body(body: dict) -> bytes:
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def body_id(object_type: str, body: dict) -> str:
    """body_id = SHA384(UTF8("BTX/HCP/"+object_type+"/v1") || 0x00 || LE64(len) || canonical_body)."""
    if object_type not in OBJECT_TYPES:
        raise ValueError(f"unsupported object_type {object_type!r}")
    b = canonical_body(body)
    return hashlib.sha384(
        f"BTX/HCP/{object_type}/v1".encode("utf-8") + b"\0" + struct.pack("<Q", len(b)) + b
    ).hexdigest()


def _is_loopback_lab_http(origin: str) -> bool:
    u = urllib.parse.urlsplit(origin)
    if u.scheme != "http":
        return False
    if u.username or u.password or u.query or u.fragment:
        return False
    if u.path not in ("", "/"):
        return False
    # Explicit 127.0.0.1 only — not localhost, not decimal/hex IP aliases.
    return u.hostname == "127.0.0.1"


def _validate_origin(origin: str, lab_origin: bool | str) -> None:
    u = urllib.parse.urlsplit(origin)
    if lab_origin:
        if isinstance(lab_origin, str):
            if not _is_loopback_lab_http(lab_origin):
                raise ValueError("lab_origin must be http://127.0.0.1 for REGTEST lab")
            flag = urllib.parse.urlsplit(lab_origin)
            if flag.port is not None and u.port != flag.port:
                raise ValueError("origin port must match lab_origin")
        if not _is_loopback_lab_http(origin):
            raise ValueError("lab_origin allows only http://127.0.0.1 for REGTEST lab")
        return
    if (
        u.scheme != "https"
        or u.username
        or u.password
        or u.path not in ("", "/")
        or u.query
        or u.fragment
        or not u.hostname
    ):
        raise ValueError("Use an independently enrolled HTTPS origin")


def _unknown_202(raw: bytes) -> dict[str, Any]:
    # UNKNOWN / accepted async — never auto-submit or retry a financial action.
    if not raw:
        return {"status": 202, "unknown": True}
    try:
        value: Any = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"status": 202, "unknown": True}
    if isinstance(value, dict):
        out = dict(value)
        out["unknown"] = True
        out.setdefault("status", 202)
        return out
    return {"status": 202, "unknown": True, "detail": value}


class CognitiveReserveClient:
    """Typed-contract HTTP client. No automatic financial retries or signatures."""

    def __init__(
        self,
        origin: str,
        auth_headers: Callable[[str, str], dict[str, str]],
        validate: Callable[[str, Any], None],
        timeout: float = 30,
        *,
        lab_origin: bool | str = False,
    ):
        _validate_origin(origin, lab_origin)
        self.origin = origin.rstrip("/")
        self.auth = auth_headers
        self.validate = validate
        self.timeout = timeout
        self.lab_origin = lab_origin
        self.automatic_spend_atoms = AUTOMATIC_SPEND_ATOMS
        self.opener = urllib.request.build_opener(NoRedirect())
        self.operations = {o["operation_id"]: o for o in OPERATIONS}
        for op_id in OPERATION_IDS:
            setattr(self, op_id, self._bind(op_id))

    def _bind(self, operation: str) -> Callable[..., Any]:
        def _fn(
            *,
            object_id: str | None = None,
            body: Any = None,
            idempotency_key: str | None = None,
        ) -> Any:
            return self.call(operation, object_id=object_id, body=body, idempotency_key=idempotency_key)

        _fn.__name__ = operation
        _fn.__qualname__ = f"CognitiveReserveClient.{operation}"
        return _fn

    def call(
        self,
        operation: str,
        *,
        object_id: str | None = None,
        body: Any = None,
        idempotency_key: str | None = None,
    ) -> Any:
        if operation not in self.operations:
            raise ValueError(f"unknown operation {operation!r}")
        o = self.operations[operation]
        path = o["path"]
        if "{id}" in path:
            if not object_id:
                raise ValueError("object_id required")
            path = path.replace("{id}", urllib.parse.quote(object_id, safe=""))
        if not path.startswith("/btx/hcp/v1/") or path == "/rpc" or path.startswith("/rpc"):
            raise ValueError("GENERIC_RPC_DISABLED")
        url = self.origin + path
        if o["method"] == "POST" and not idempotency_key:
            raise ValueError("stable idempotency_key required")
        if o["request_schema"]:
            self.validate(o["request_schema"], body)
        encoded = (
            None
            if body is None
            else json.dumps(body, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        )
        if encoded is not None and len(encoded) > 1048576:
            raise ValueError("request too large")
        headers = {**self.auth(o["method"], url), "Accept": "application/json"}
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        request = urllib.request.Request(url, data=encoded, headers=headers, method=o["method"])
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(4194305)
                status = response.status
        except TimeoutError as e:
            raise Cr11Error("UNKNOWN", "timeout", 0) from e
        except urllib.error.HTTPError as e:
            raw = e.read(4194305)
            status = e.code
        except urllib.error.URLError as e:
            reason = e.reason
            if isinstance(reason, TimeoutError) or "timed out" in str(e).lower():
                raise Cr11Error("UNKNOWN", "timeout", 0) from e
            raise
        if len(raw) > 4194304:
            raise ValueError("response too large")
        if status == 202:
            # UNKNOWN — return as-is. Never auto-submit / authorize / execute / cancel.
            return _unknown_202(raw)
        value = json.loads(raw.decode("utf-8"))
        self.validate(o["response_schema"] if 200 <= status < 300 else "Error", value)
        if not 200 <= status < 300:
            raise Cr11Error("HTTP", json.dumps(value, separators=(",", ":")), status)
        return value


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
