# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Cognitive Reserve Layer v1.2 Python SDK. Additive HCP/1 extension (43 ops).

Typed catalogue paths only. No generic RPC, wallet signing, brand dispatch,
remote inference, or invented AUM/AUC totals. Import is not custody credit.
automatic_spend_atoms stays 0. executeAllocation is not a v1.2 route.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

AUTOMATIC_SPEND_ATOMS = 0

# Exact engine object types (src/modelnet/hcp_types.h). Underscores are not a
# general charset relaxation.
OBJECT_TYPES: tuple[str, ...] = (
    "LayerExtensionProfileV1_2",
    "ProviderRoleManifestV1_2",
    "ServiceBindingV1_2",
    "AdapterCapabilityReportV1_2",
    "InstitutionalAssetV1_2",
    "AssetRightsV1_2",
    "PositionObservationV1_2",
    "ValuationObservationV1_2",
    "ExposureLinkV1_2",
    "PortfolioProjectionV1_2",
    "MetricDefinitionV1_2",
    "ExportManifestV1_2",
    "ImportManifestV1_2",
    "ReconciliationBreakV1_2",
    "PortfolioInstructionV1_2",
    "InstitutionalScenarioResultV1_2",
    "LayerConformanceClaimV1_2",
    "LayerJobV1_2",
)

ANALYTICS_SCOPES: tuple[str, ...] = (
    "catalog:read",
    "capital:read",
    "capital:prepare",
    "projections:read",
    "metrics:read",
    "assets:read",
    "positions:read",
)

_SECRET_KEYS = frozenset(
    {
        "secret",
        "access_token",
        "refresh_token",
        "private_key",
        "password",
        "mnemonic",
        "client_secret",
        "wallet_rpc",
        "api_key",
        "bearer",
        "prompt",
        "private_prompt",
        "id_token",
        "session_token",
    }
)
_INVENTED_TOTAL_KEYS = frozenset(
    {
        "grand_total",
        "combined_aum_auc",
        "invented_aum",
        "invented_auc",
        "unlabeled_combined_total",
    }
)
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_CATALOG_PATH = Path(__file__).resolve().parents[1] / "schemas" / "operations-v1.2.json"


def _load_catalog() -> list[dict[str, Any]]:
    data = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    ops = data["operations"]
    if not isinstance(ops, list) or len(ops) != 43:
        raise RuntimeError("CRL v1.2 catalog must contain exactly 43 operations")
    ids = [o["operation_id"] for o in ops]
    if len(set(ids)) != 43:
        raise RuntimeError("CRL v1.2 catalog operation_id values must be unique")
    for o in ops:
        path = o["path"]
        if not path.startswith("/btx/hcp/v1/") or path == "/rpc" or path.startswith("/rpc"):
            raise RuntimeError(f"catalogue path is not a typed HCP route: {path}")
    return ops


OPERATIONS: tuple[dict[str, Any], ...] = tuple(_load_catalog())
OPERATION_IDS: tuple[str, ...] = tuple(o["operation_id"] for o in OPERATIONS)


class Crl12Error(RuntimeError):
    def __init__(self, code: str, message: str, status: int = 0):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.status = status
        self.unknown = status == 202 or code == "UNKNOWN"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        raise Crl12Error("REDIRECT_REQUIRES_EXPLICIT_PROVIDER_POLICY", newurl or "")


def canonical_body(body: dict) -> bytes:
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def body_id(object_type: str, body: dict) -> str:
    """body_id = SHA384(UTF8("BTX/HCP/"+object_type+"/v1") || 0x00 || LE64(len) || canonical_body)."""
    if object_type not in OBJECT_TYPES:
        raise ValueError(f"unsupported object_type {object_type!r}")
    if not isinstance(body, dict):
        raise ValueError("body must be an object")
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


def _walk_keys(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            out.append(str(k))
            out.extend(_walk_keys(v))
    elif isinstance(value, list):
        for item in value:
            out.extend(_walk_keys(item))
    return out


def contains_secrets(value: Any) -> bool:
    if isinstance(value, dict):
        for k, v in value.items():
            lk = str(k).lower()
            if lk in _SECRET_KEYS or lk.endswith("_secret"):
                if v not in (None, "", [], {}):
                    return True
            if isinstance(v, str) and "BEGIN PRIVATE KEY" in v:
                return True
            if contains_secrets(v):
                return True
    elif isinstance(value, list):
        return any(contains_secrets(x) for x in value)
    elif isinstance(value, str) and "BEGIN PRIVATE KEY" in value:
        return True
    return False


def _reject_body_policy(operation: str, body: Any) -> None:
    if body is None:
        return
    if not isinstance(body, (dict, list)):
        return
    if contains_secrets(body):
        if operation == "createInstitutionalExport":
            raise Crl12Error("SECRET_INLINE", "export must not include secrets or tokens")
        if operation in ("createServiceBinding", "publishProviderRoles"):
            raise Crl12Error("SECRET_INLINE", "use secret_ref; never inline credentials")
        raise Crl12Error("SECRET_INLINE", "typed HCP bodies must not carry reusable secrets")
    keys = {k.lower() for k in _walk_keys(body)}
    if keys & _INVENTED_TOTAL_KEYS:
        raise Crl12Error("INVENTED_TOTAL", "never invent combined AUM/AUC")
    if isinstance(body, dict):
        if body.get("remote_inference") is True:
            raise Crl12Error("REMOTE_INFERENCE_FORBIDDEN", "no public prompt routing")
        if operation == "commitInstitutionalImport" and body.get("custody_credit") is True:
            raise Crl12Error("IMPORT_NOT_CUSTODY", "import is not custody credit")
        if body.get("brand_dispatch") or body.get("provider_brand_route"):
            raise Crl12Error("BRAND_DISPATCH", "generic fixtures only")


def _unknown_202(raw: bytes) -> dict[str, Any]:
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


class Crl12Client:
    """Typed-contract HTTP client over the 43 CRL/1.2 operations. No /rpc."""

    def __init__(
        self,
        origin: str,
        auth_headers: Callable[[str, str, bytes], Mapping[str, str]] | None = None,
        validate: Callable[[str, Any], None] | None = None,
        timeout: float = 30,
        *,
        lab_origin: bool | str = False,
        scopes: Sequence[str] | None = None,
        verify_statement: Callable[[Mapping[str, Any]], None] | None = None,
    ):
        _validate_origin(origin, lab_origin)
        self.origin = origin.rstrip("/")
        self.auth = auth_headers or (lambda _m, _u, _b: {})
        self.validate = validate or (lambda _schema, _value: None)
        self.verifier = verify_statement
        self.timeout = timeout
        self.lab_origin = lab_origin
        self.scopes = tuple(scopes) if scopes is not None else ()
        self.automatic_spend_atoms = AUTOMATIC_SPEND_ATOMS
        self.opener = urllib.request.build_opener(NoRedirect())
        self.operations = {o["operation_id"]: o for o in OPERATIONS}
        for op_id in OPERATION_IDS:
            setattr(self, op_id, self._bind(op_id))

    def _has_execute_scope(self) -> bool:
        if not self.scopes:
            return False
        return "capital:execute" in self.scopes or "account:admin" in self.scopes

    def executeAllocation(self, *args: Any, **kwargs: Any) -> Any:  # noqa: ARG002
        raise Crl12Error(
            "SCOPE_DENIED",
            "CRL/1.2 SDK has no executeAllocation route; analytics cannot execute",
        )

    def _bind(self, operation: str) -> Callable[..., Any]:
        def _fn(
            *,
            path: Mapping[str, str] | None = None,
            query: Mapping[str, str] | None = None,
            body: Any = None,
            idempotency_key: str | None = None,
            object_id: str | None = None,
            chunk_id: str | None = None,
        ) -> Any:
            params: dict[str, str] = dict(path or {})
            if object_id is not None:
                params.setdefault("id", object_id)
            if chunk_id is not None:
                params.setdefault("chunk_id", chunk_id)
            return self.call(
                operation,
                path=params or None,
                query=query,
                body=body,
                idempotency_key=idempotency_key,
            )

        _fn.__name__ = operation
        _fn.__qualname__ = f"Crl12Client.{operation}"
        return _fn

    def call(
        self,
        operation: str,
        *,
        path: Mapping[str, str] | None = None,
        query: Mapping[str, str] | None = None,
        body: Any = None,
        idempotency_key: str | None = None,
    ) -> Any:
        if operation in ("executeAllocation", "submitFinanceIntent", "genericRpc", "/rpc"):
            raise Crl12Error("SCOPE_DENIED", f"{operation} is not a CRL/1.2 typed route")
        if operation not in self.operations:
            raise ValueError(f"unknown operation {operation!r}")
        if self.scopes and set(self.scopes) <= set(ANALYTICS_SCOPES) and not self._has_execute_scope():
            if operation == "executeAllocation":
                raise Crl12Error("SCOPE_DENIED", "analytics cannot executeAllocation")
        o = self.operations[operation]
        relative = o["path"]
        if not relative.startswith("/btx/hcp/v1/") or relative == "/rpc" or relative.startswith("/rpc"):
            raise ValueError("GENERIC_RPC_DISABLED")
        needed = set(re.findall(r"\{([^}]+)\}", relative))
        params = dict(path or {})
        if set(params) != needed:
            raise ValueError("Path parameters must exactly match the operation.")
        for k, v in params.items():
            if not _ID_RE.fullmatch(v):
                raise ValueError("Invalid opaque path identifier")
            relative = relative.replace("{" + k + "}", urllib.parse.quote(v, safe=""))
        if "/execute" in relative:
            raise Crl12Error("SCOPE_DENIED", "CRL/1.2 client does not call execute paths")
        url = self.origin + relative
        if query:
            url += "?" + urllib.parse.urlencode(query)
        _reject_body_policy(operation, body)
        if o.get("request_schema"):
            self.validate(o["request_schema"], body)
        method = o["method"]
        if method == "POST" and (
            not idempotency_key or not _ID_RE.fullmatch(idempotency_key)
        ):
            raise ValueError("A stable Idempotency-Key is required for every POST.")
        if o["request_schema"] == "BINARY":
            if not isinstance(body, (bytes, bytearray)) or not 0 < len(body) <= 16 * 1024 * 1024:
                raise ValueError("Binary chunk must contain 1..16 MiB.")
            data = bytes(body)
            content_type = "application/octet-stream"
        else:
            data = (
                b""
                if body is None
                else json.dumps(body, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
            )
            if len(data) > 1048576:
                raise ValueError("JSON body exceeds 1 MiB.")
            content_type = "application/json"
        headers = dict(self.auth(method, url, data))
        headers["Accept"] = "application/json" if o["response_schema"] != "BINARY" else "application/octet-stream"
        headers["Content-Type"] = content_type
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        if o["request_schema"] == "BINARY":
            headers["X-Content-SHA384"] = hashlib.sha384(data).hexdigest()
        request = urllib.request.Request(
            url, data=data if method == "POST" else None, headers=headers, method=method
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                limit = 16 * 1024 * 1024 if o["response_schema"] == "BINARY" else 4194304
                raw = response.read(limit + 1)
                status = getattr(response, "status", 200)
        except TimeoutError as e:
            raise Crl12Error("UNKNOWN", "timeout", 0) from e
        except urllib.error.HTTPError as e:
            raw = e.read(4194305)
            status = e.code
        except urllib.error.URLError as e:
            reason = e.reason
            if isinstance(reason, TimeoutError) or "timed out" in str(e).lower():
                raise Crl12Error("UNKNOWN", "timeout", 0) from e
            raise
        if len(raw) > (16 * 1024 * 1024 if o["response_schema"] == "BINARY" else 4194304):
            raise Crl12Error("RESPONSE_TOO_LARGE", "bounded read")
        if status == 202:
            return _unknown_202(raw)
        if o["response_schema"] == "BINARY":
            if not 200 <= status < 300:
                raise Crl12Error("HTTP", raw[:512].decode("utf-8", errors="replace"), status)
            return raw
        value = json.loads(raw.decode("utf-8"))
        self.validate(o["response_schema"] if 200 <= status < 300 else "Error", value)
        if not 200 <= status < 300:
            raise Crl12Error("HTTP", json.dumps(value, separators=(",", ":")), status)
        if isinstance(value, dict) and "object_type" in value and self.verifier:
            self.verifier(value)
        return value


CognitiveReserveLayerClient = Crl12Client
CrlClient = Crl12Client


def analytics_client(
    origin: str,
    auth_headers: Callable[[str, str, bytes], Mapping[str, str]] | None = None,
    **kwargs: Any,
) -> Crl12Client:
    kwargs.setdefault("scopes", ANALYTICS_SCOPES)
    return Crl12Client(origin, auth_headers, **kwargs)


__all__ = (
    "ANALYTICS_SCOPES",
    "AUTOMATIC_SPEND_ATOMS",
    "Crl12Client",
    "Crl12Error",
    "CrlClient",
    "CognitiveReserveLayerClient",
    "OBJECT_TYPES",
    "OPERATION_IDS",
    "OPERATIONS",
    "analytics_client",
    "body_id",
    "canonical_body",
    "contains_secrets",
)
