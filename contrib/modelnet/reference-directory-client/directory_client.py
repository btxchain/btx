#!/usr/bin/env python3
"""Minimal third-party model directory explorer via btx-modeld unix JSON-RPC only."""

from __future__ import annotations

import json
import os
import socket
import sys
from typing import Any

EXPECTED_SCHEMA_VERSION = 2
DEFAULT_LIMIT = 32


def _sock_path() -> str:
    path = os.environ.get("MODELD_SOCK", "").strip()
    if not path:
        raise RuntimeError("MODELD_SOCK is not set (path to btx-modeld unix RPC socket)")
    return path


def rpc(method: str, params: list[Any] | None = None, *, timeout: float = 30.0) -> Any:
    """One JSON line {jsonrpc,id,method,params} — same shape as contrib/modelnet e2e scripts."""
    payload = {
        "jsonrpc": "1.0",
        "id": 1,
        "method": method,
        "params": params if params is not None else [],
    }
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(_sock_path())
    sock.sendall(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
    sock.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    sock.close()
    if not data:
        raise RuntimeError(f"{method}: empty reply")
    reply = json.loads(data.decode())
    if reply.get("error"):
        err = reply["error"]
        if isinstance(err, dict):
            code = err.get("code", err.get("message", err))
            raise RuntimeError(f"{method}: {code}")
        raise RuntimeError(f"{method}: {err}")
    result = reply.get("result")
    _warn_schema_version(method, result)
    return result


def _warn_schema_version(method: str, result: Any) -> None:
    if not isinstance(result, dict):
        return
    sv = result.get("schema_version")
    if sv is not None and sv != EXPECTED_SCHEMA_VERSION:
        print(
            f"warning: {method} schema_version={sv!r} (expected {EXPECTED_SCHEMA_VERSION})",
            file=sys.stderr,
        )


def _results_list(page: dict[str, Any]) -> list[dict[str, Any]]:
    """Helper pages use results[]; accept legacy models[] fallback."""
    for key in ("results", "models", "entries", "records"):
        items = page.get(key)
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
    return []


def _availability(entry: dict[str, Any]) -> dict[str, Any]:
    av = entry.get("availability")
    if isinstance(av, dict):
        return av
    # Legacy flat fields on directory entries
    legacy: dict[str, Any] = {}
    for k in (
        "class",
        "providers_total",
        "reconstructable",
        "providers_complete",
        "providers_partial",
    ):
        if k in entry:
            legacy[k] = entry[k]
    if "swarm_health" in entry and "class" not in legacy:
        legacy["class"] = entry.get("swarm_health")
    return legacy


def _publisher(entry: dict[str, Any]) -> dict[str, Any]:
    pub = entry.get("publisher")
    if isinstance(pub, dict):
        return pub
    out: dict[str, Any] = {}
    if entry.get("publisher_display_name"):
        out["display_name"] = entry["publisher_display_name"]
    if entry.get("publisher_identity"):
        out["id"] = entry["publisher_identity"]
    return out


def _card_name(entry: dict[str, Any]) -> str:
    name = entry.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    sr = entry.get("search_record")
    if isinstance(sr, dict):
        for key in ("display_name", "canonical_name", "title"):
            val = sr.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    for key in ("display_name", "canonical_name", "label"):
        val = entry.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    mid = entry.get("model_id")
    if isinstance(mid, str) and mid:
        return mid
    return "(unnamed)"


def _card_uri(entry: dict[str, Any]) -> str:
    val = entry.get("uri")
    if isinstance(val, str) and val:
        return val
    val = entry.get("model_uri")
    if isinstance(val, str) and val:
        return val
    sr = entry.get("search_record")
    if isinstance(sr, dict) and isinstance(sr.get("uri"), str):
        return sr["uri"]
    return ""


def print_card_line(entry: dict[str, Any]) -> None:
    av = _availability(entry)
    pub = _publisher(entry)
    klass = av.get("class", "UNKNOWN")
    if isinstance(klass, dict):
        klass = klass.get("name", "UNKNOWN")
    recon = av.get("reconstructable")
    if recon is None:
        recon_s = "?"
    else:
        recon_s = "yes" if recon else "no"
    providers = av.get("providers_total")
    if providers is None:
        providers = av.get("observed_provider_count", "?")
    pub_name = pub.get("display_name") or pub.get("title") or "?"
    print(
        "\t".join(
            [
                _card_name(entry),
                str(providers),
                str(klass),
                recon_s,
                str(pub_name),
                _card_uri(entry),
            ]
        )
    )


def _print_card_header() -> None:
    print("name\tproviders_total\tavailability_class\treconstructable\tpublisher\turi")


def _print_publisher_header() -> None:
    print("id\tdisplay_name\tmodel_count_observed")


def print_publisher_line(pub: dict[str, Any]) -> None:
    pid = pub.get("id") or pub.get("publisher_id") or ""
    name = pub.get("display_name") or pub.get("title") or pub.get("label") or "?"
    count = pub.get("model_count_observed", "?")
    print("\t".join([str(pid), str(name), str(count)]))


def print_peercount_line(result: dict[str, Any]) -> None:
    print(
        "\t".join(
            [
                str(result.get("total", "?")),
                str(result.get("complete", "?")),
                str(result.get("partial", "?")),
            ]
        )
    )


def _model_id_arg(model_id: str) -> list[Any]:
    return [model_id]


def _paged(method: str, body: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Follow opaque cursor tokens when the helper returns them."""
    params_obj = dict(body or {})
    if "limit" not in params_obj:
        params_obj["limit"] = DEFAULT_LIMIT
    collected: list[dict[str, Any]] = []
    while True:
        page = rpc(method, [params_obj])
        if not isinstance(page, dict):
            break
        collected.extend(_results_list(page))
        for key in ("publishers", "collections"):
            items = page.get(key)
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        collected.append(item)
        cursor = page.get("cursor")
        if not cursor or cursor in ("", "0", 0):
            break
        if page.get("truncated") is False and not cursor:
            break
        params_obj["cursor"] = cursor
    return collected


def _print_result_pages(method: str, first: dict[str, Any], body: dict[str, Any] | None) -> None:
    _print_card_header()
    for m in _results_list(first):
        print_card_line(m)
    cursor = first.get("cursor")
    if cursor:
        for m in _paged(method, {**(body or {}), "cursor": cursor}):
            print_card_line(m)


def search(text: str, *, scope: str | None = None) -> dict[str, Any]:
    """RPC: searchmodels — local + optional network/indexer search (coverage incomplete)."""
    q: dict[str, Any] = {"text": text, "limit": DEFAULT_LIMIT}
    if scope:
        q["scope"] = scope
    first = rpc("searchmodels", [q])
    if isinstance(first, dict):
        _print_result_pages("searchmodels", first, q)
    return first if isinstance(first, dict) else {"raw": first}


def browse() -> dict[str, Any]:
    """RPC: browsemodels — paged partial directory browse view."""
    body = {"limit": DEFAULT_LIMIT}
    first = rpc("browsemodels", [body])
    if isinstance(first, dict):
        _print_result_pages("browsemodels", first, body)
    return first if isinstance(first, dict) else {"raw": first}


def new_models() -> dict[str, Any]:
    """RPC: getnewmodels — newest search records in local partial index."""
    body = {"limit": DEFAULT_LIMIT}
    first = rpc("getnewmodels", [body])
    if isinstance(first, dict):
        _print_result_pages("getnewmodels", first, body)
    return first if isinstance(first, dict) else {"raw": first}


def model_detail(model_id: str) -> dict[str, Any]:
    """RPC: getmodeldirectoryentry — one directory entry for a model id or btx:// URI."""
    result = rpc("getmodeldirectoryentry", _model_id_arg(model_id))
    _print_card_header()
    if isinstance(result, dict):
        print_card_line(result)
    return result if isinstance(result, dict) else {"raw": result}


def availability(model_id: str) -> dict[str, Any]:
    """RPC: getmodelavailability — swarm snapshot (class/providers_* at top level)."""
    result = rpc("getmodelavailability", _model_id_arg(model_id))
    print("model_id\tproviders_total\tclass\treconstructable")
    if isinstance(result, dict):
        av = _availability(result)
        print(
            "\t".join(
                [
                    str(result.get("model_id", model_id)),
                    str(av.get("providers_total", result.get("providers_total", "?"))),
                    str(av.get("class", result.get("class", "UNKNOWN"))),
                    str(av.get("reconstructable", result.get("reconstructable", "?"))),
                ]
            )
        )
    return result if isinstance(result, dict) else {"raw": result}


def peercount(model_id: str) -> dict[str, Any]:
    """RPC: getmodelpeercount — total / complete / partial for this node's view."""
    result = rpc("getmodelpeercount", _model_id_arg(model_id))
    print("total\tcomplete\tpartial")
    if isinstance(result, dict):
        print_peercount_line(result)
    return result if isinstance(result, dict) else {"raw": result}


def providers(model_id: str) -> dict[str, Any]:
    """RPC: getmodelproviders — observed provider records (cap 32)."""
    result = rpc("getmodelproviders", _model_id_arg(model_id))
    print("providers_returned\treconstructable")
    if isinstance(result, dict):
        provs = result.get("providers")
        n = len(provs) if isinstance(provs, list) else 0
        recon = result.get("reconstructable", "?")
        print(f"{n}\t{recon}")
    return result if isinstance(result, dict) else {"raw": result}


def publishers(text: str) -> dict[str, Any]:
    """RPC: searchpublishers — text search over publisher identity cards."""
    body = {"text": text, "limit": DEFAULT_LIMIT}
    first = rpc("searchpublishers", [body])
    _print_publisher_header()
    if isinstance(first, dict):
        pubs = first.get("publishers")
        if isinstance(pubs, list):
            for p in pubs:
                if isinstance(p, dict):
                    print_publisher_line(p)
        cursor = first.get("cursor")
        if cursor:
            for p in _paged("searchpublishers", {**body, "cursor": cursor}):
                print_publisher_line(p)
    return first if isinstance(first, dict) else {"raw": first}


def collections(text: str) -> dict[str, Any]:
    """RPC: searchcollections — text search over signed collections."""
    body = {"text": text, "limit": DEFAULT_LIMIT}
    first = rpc("searchcollections", [body])
    _print_publisher_header()
    if isinstance(first, dict):
        cols = first.get("collections")
        if isinstance(cols, list):
            for c in cols:
                if not isinstance(c, dict):
                    continue
                print(
                    "\t".join(
                        [
                            str(c.get("collection_id", "")),
                            str(c.get("title", c.get("display_name", "?"))),
                            "-",
                        ]
                    )
                )
    return first if isinstance(first, dict) else {"raw": first}


def network_stats() -> dict[str, Any]:
    """RPC: getnetworkmodelstats — aggregates over this node's local view only."""
    result = rpc("getnetworkmodelstats", [])
    if isinstance(result, dict):
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result)
    return result if isinstance(result, dict) else {"raw": result}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(
            "usage: directory_client.py "
            "<search|browse|new|detail|availability|peercount|providers|publishers|collections|stats> [arg]",
            file=sys.stderr,
        )
        return 2
    cmd, *rest = argv
    try:
        if cmd == "search":
            search(rest[0] if rest else "")
        elif cmd == "browse":
            browse()
        elif cmd == "new":
            new_models()
        elif cmd == "detail":
            if not rest:
                raise SystemExit("detail requires model id or btx:// URI")
            model_detail(rest[0])
        elif cmd == "availability":
            if not rest:
                raise SystemExit("availability requires model id or btx:// URI")
            availability(rest[0])
        elif cmd == "peercount":
            if not rest:
                raise SystemExit("peercount requires model id or btx:// URI")
            peercount(rest[0])
        elif cmd == "providers":
            if not rest:
                raise SystemExit("providers requires model id or btx:// URI")
            providers(rest[0])
        elif cmd == "publishers":
            publishers(rest[0] if rest else "")
        elif cmd == "collections":
            collections(rest[0] if rest else "")
        elif cmd == "stats":
            network_stats()
        else:
            print(f"unknown command: {cmd}", file=sys.stderr)
            return 2
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
