# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tiny MCP-style HCP wrapper: declared READ vs SUBMIT, no OAuth passthrough.

The wrapper is an agent-facing tool list, not a wallet and not an MCP server.
Remote tools may search or prepare. Local ensure stays on a separate grant.
Tool descriptions do not confer financial or execution authority. Child tools
never receive the customer's exchange token, DPoP proof, or Authorization
header (spec §6.4 / §21, HCP-AUTH-03, R18). automatic_spend_atoms stays 0.
HTTP 202 remains UNKNOWN; this module never auto-submits on timeout.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, urlparse

# Keys that must never appear on a child tool, in env, headers, argv, or URI.
_TOKEN_KEYS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "access_token",
        "refresh_token",
        "id_token",
        "oauth_token",
        "oauth",
        "bearer",
        "bearer_token",
        "dpop",
        "dpop_proof",
        "client_secret",
        "client_assertion",
        "id_token_hint",
        "x-access-token",
        "hcp_access_token",
        "hcp_oauth_token",
    }
)
_TOKEN_ENV_NEEDLES = (
    "ACCESS_TOKEN",
    "REFRESH_TOKEN",
    "ID_TOKEN",
    "OAUTH",
    "CLIENT_SECRET",
    "CLIENT_ASSERTION",
    "DPOP",
    "BEARER",
    "AUTHORIZATION",
)


class Effect(str, Enum):
    """Declared tool effect. READ cannot submit. SUBMIT is never implied."""

    READ = "READ"
    SUBMIT = "SUBMIT"


class TokenPassthroughError(RuntimeError):
    """OAuth/Bearer material would have reached a child tool or URI."""


@dataclass(frozen=True)
class McpTool:
    name: str
    description: str
    effect: Effect
    audience: str  # tool-specific resource audience, not the CEX customer token


# Ranking text is catalogue product copy, not a protocol fact.
# SUBMIT does not grant spend merely by being listed.
TOOLS: tuple[McpTool, ...] = (
    McpTool(
        "hcp_get_profile",
        "Read the hosted provider profile. Not a wallet and not consensus.",
        Effect.READ,
        "hcp.catalog",
    ),
    McpTool(
        "hcp_search",
        "Search the hosted catalogue. Ranking annotations are not protocol facts.",
        Effect.READ,
        "hcp.catalog",
    ),
    McpTool(
        "hcp_poll_operation",
        "Poll an HCP operation. HTTP 202 stays UNKNOWN; never auto-submit.",
        Effect.READ,
        "hcp.catalog",
    ),
    McpTool(
        "hcp_submit_intent",
        "Submit an already-authorized finance intent. Explicit SUBMIT only; "
        "tool text confers no spend or local-execution authority.",
        Effect.SUBMIT,
        "hcp.finance",
    ),
)


def list_tools() -> list[dict[str, str]]:
    return [
        {
            "name": t.name,
            "description": t.description,
            "effect": t.effect.value,
            "audience": t.audience,
            "confers_authority": "false",
        }
        for t in TOOLS
    ]


def declared_effect(name: str) -> Effect:
    for t in TOOLS:
        if t.name == name:
            return t.effect
    raise KeyError(name)


def _norm_key(key: str) -> str:
    return key.strip().lower().replace("-", "_")


def _is_token_key(key: str) -> bool:
    return _norm_key(key) in _TOKEN_KEYS


def _is_token_env_key(key: str) -> bool:
    k = key.upper().replace("-", "_")
    return any(n in k for n in _TOKEN_ENV_NEEDLES)


def _bearerish(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    v = value.strip()
    return v.lower().startswith("bearer ") or v.lower().startswith("dpop ")


def assert_no_oauth_material(value: Any, *, where: str) -> None:
    """Fail closed if token-shaped keys or Bearer values appear in public payload."""
    if value is None:
        return
    if isinstance(value, Mapping):
        for k, v in value.items():
            ks = str(k)
            if _is_token_key(ks) or _is_token_env_key(ks) or _bearerish(ks):
                raise TokenPassthroughError(f"oauth material in {where} key {ks!r}")
            if _bearerish(v):
                raise TokenPassthroughError(f"oauth material in {where} value for {ks!r}")
            assert_no_oauth_material(v, where=where)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            assert_no_oauth_material(item, where=where)
            if _bearerish(item):
                raise TokenPassthroughError(f"oauth material in {where} list")
        return
    if _bearerish(value):
        raise TokenPassthroughError(f"oauth material in {where}")


def assert_no_token_in_uri(uri: str) -> None:
    """J11 / portal rule: tokens stay out of query, fragment, and userinfo."""
    parsed = urlparse(uri)
    if parsed.username or parsed.password:
        raise TokenPassthroughError("oauth material in URI userinfo")
    for bucket in (parsed.query, parsed.fragment):
        for k, v in parse_qsl(bucket, keep_blank_values=True):
            if _is_token_key(k) or _is_token_env_key(k) or _bearerish(v):
                raise TokenPassthroughError(f"oauth material in URI parameter {k!r}")


def child_environ(source: Mapping[str, str] | None) -> dict[str, str]:
    """Copy an environment for a child process with OAuth variables removed.

    Parent secrets are dropped, never rewritten into the child. No Authorization
    or access-token variable is added.
    """
    out: dict[str, str] = {}
    if source is None:
        return out
    for k, v in source.items():
        if _is_token_env_key(k) or _is_token_key(k) or _bearerish(v):
            continue
        out[k] = v
    return out


def child_headers(source: Mapping[str, str] | None) -> dict[str, str]:
    """Headers for a downstream tool: Authorization / DPoP stripped."""
    out: dict[str, str] = {}
    if source is None:
        return out
    for k, v in source.items():
        if _is_token_key(k) or _is_token_env_key(k) or _bearerish(v):
            continue
        out[k] = v
    return out


ChildFn = Callable[[dict[str, Any]], Any]


class HcpMcpWrapper:
    """Binds an HcpClient for this resource server only.

    ``client.access_token`` / ``dpop`` stay inside that client. They are never
    copied into child env, headers, argv, URI, or tool arguments.
    """

    def __init__(self, client: Any | None = None, *, allow_submit: bool = False):
        self._client = client
        self._allow_submit = allow_submit
        self._by_name = {t.name: t for t in TOOLS}

    def list_tools(self) -> list[dict[str, str]]:
        return list_tools()

    def _client_secret_material(self) -> tuple[str, ...]:
        if self._client is None:
            return ()
        bits = []
        for attr in ("access_token", "dpop"):
            val = getattr(self._client, attr, None)
            if isinstance(val, str) and val:
                bits.append(val)
        return tuple(bits)

    def _reject_client_leak(self, payload: Any, *, where: str) -> None:
        secrets = self._client_secret_material()
        if not secrets:
            return

        def walk(obj: Any) -> None:
            if obj is None:
                return
            if isinstance(obj, str):
                for s in secrets:
                    if s and s in obj:
                        raise TokenPassthroughError(f"client oauth material leaked into {where}")
                return
            if isinstance(obj, Mapping):
                for k, v in obj.items():
                    walk(str(k))
                    walk(v)
                return
            if isinstance(obj, (list, tuple, set)):
                for item in obj:
                    walk(item)

        walk(payload)

    def invoke_child(
        self,
        child: ChildFn,
        arguments: Mapping[str, Any] | None = None,
        *,
        env: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        uri: str | None = None,
    ) -> Any:
        """Run a downstream tool with OAuth material stripped/refused.

        The child's callable receives only ``arguments``. Env/headers are
        sanitized so a naive ``os.environ`` copy cannot carry the CEX token.
        """
        args = dict(arguments or {})
        assert_no_oauth_material(args, where="child.arguments")
        self._reject_client_leak(args, where="child.arguments")
        if uri is not None:
            assert_no_token_in_uri(uri)
            self._reject_client_leak(uri, where="child.uri")
        safe_env = child_environ(env)
        safe_headers = child_headers(headers)
        self._reject_client_leak(safe_env, where="child.env")
        self._reject_client_leak(safe_headers, where="child.headers")
        # Children do not get a side-channel token bag.
        child_payload = dict(args)
        child_payload.pop("env", None)
        child_payload.pop("headers", None)
        child_payload.pop("authorization", None)
        return child(child_payload)

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        child: ChildFn | None = None,
        child_env: Mapping[str, str] | None = None,
        child_headers_map: Mapping[str, str] | None = None,
        child_uri: str | None = None,
        allow_submit: bool | None = None,
    ) -> Any:
        tool = self._by_name.get(name)
        if tool is None:
            raise KeyError(name)
        args = dict(arguments or {})
        assert_no_oauth_material(args, where=f"tool.{name}.arguments")
        self._reject_client_leak(args, where=f"tool.{name}.arguments")

        if child is not None:
            # Downstream MCP/resource servers get a distinct audience and no
            # customer exchange token, even when this tool's effect is SUBMIT.
            return self.invoke_child(
                child,
                args,
                env=child_env,
                headers=child_headers_map,
                uri=child_uri,
            )

        submit_ok = self._allow_submit if allow_submit is None else allow_submit
        if tool.effect is Effect.SUBMIT:
            if not submit_ok:
                raise PermissionError(
                    "SUBMIT requires explicit allow_submit; listing the tool confers no authority"
                )
            # This wrapper does not auto-POST /finance/intents/{id}/submit.
            # Timeouts stay UNKNOWN. A caller supplies an audience-bound
            # finance transport separately; we still never forward tokens.
            raise PermissionError(
                "SUBMIT is declared only; this wrapper does not auto-submit or pass tokens"
            )

        if self._client is None:
            raise RuntimeError("no HCP client bound for READ")
        if name == "hcp_get_profile":
            return self._client.get_profile()
        if name == "hcp_search":
            return self._client.search(str(args.get("q") or ""))
        if name == "hcp_poll_operation":
            return self._client.poll_operation(str(args["operation_id"]))
        raise KeyError(name)


def _self_check() -> None:
    effects = {t["name"]: t["effect"] for t in list_tools()}
    assert effects["hcp_search"] == Effect.READ.value
    assert effects["hcp_submit_intent"] == Effect.SUBMIT.value
    assert all(t["confers_authority"] == "false" for t in list_tools())

    dirty = {
        "PATH": "/usr/bin",
        "ACCESS_TOKEN": "sentinel-oauth",
        "HTTP_AUTHORIZATION": "Bearer sentinel-oauth",
        "DPOP": "sentinel-dpop",
        "HOME": "/tmp",
    }
    clean = child_environ(dirty)
    assert clean == {"PATH": "/usr/bin", "HOME": "/tmp"}
    assert "ACCESS_TOKEN" not in clean
    assert child_headers({"Authorization": "Bearer x", "Accept": "application/json"}) == {
        "Accept": "application/json"
    }

    class _Stub:
        access_token = "sentinel-oauth"
        dpop = "sentinel-dpop"

        def search(self, q: str) -> dict:
            return {"q": q, "ranking": "sponsored"}

    w = HcpMcpWrapper(_Stub())
    leaked = False
    try:
        w.call_tool("hcp_search", {"q": "m", "access_token": "sentinel-oauth"})
    except TokenPassthroughError:
        leaked = True
    assert leaked

    seen: dict[str, Any] = {}

    def child(payload: dict[str, Any]) -> dict[str, Any]:
        seen.update(payload)
        return {"ok": True}

    out = w.invoke_child(
        child,
        {"package_core_id": "abc"},
        env=dirty,
        headers={"Authorization": "Bearer sentinel-oauth", "Accept": "application/json"},
        uri="https://device.example/pair?device=1",
    )
    assert out == {"ok": True}
    assert seen == {"package_core_id": "abc"}
    assert "sentinel-oauth" not in str(seen)

    uri_blocked = False
    try:
        w.invoke_child(child, {}, uri="https://x.example/?access_token=sentinel-oauth")
    except TokenPassthroughError:
        uri_blocked = True
    assert uri_blocked

    submit_blocked = False
    try:
        w.call_tool("hcp_submit_intent", {"intent_id": "i1"})
    except PermissionError:
        submit_blocked = True
    assert submit_blocked
    print("mcp_wrapper self-check PASS")


if __name__ == "__main__":
    _self_check()
