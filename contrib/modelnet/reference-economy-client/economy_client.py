#!/usr/bin/env python3
"""Third-party model-economy explorer: unix JSON-RPC only (no files, no wallet)."""

from __future__ import annotations

import json
import os
import socket
import sys
from typing import Any

EXPECTED_SCHEMA = {2, 3}
DEFAULT_LIMIT = 32


def _sock_path() -> str:
    path = os.environ.get("MODELD_SOCK", "").strip()
    if not path:
        raise RuntimeError("MODELD_SOCK is not set")
    return path


def rpc(method: str, params: list[Any] | None = None, *, timeout: float = 45.0) -> Any:
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
        raise RuntimeError(f"{method}: {err}")
    return reply.get("result")


def _results(page: Any) -> list[dict[str, Any]]:
    if not isinstance(page, dict):
        return []
    for key in ("results", "items", "models", "entries"):
        items = page.get(key)
        if isinstance(items, list):
            out = []
            for x in items:
                if not isinstance(x, dict):
                    continue
                if "entry" in x and isinstance(x["entry"], dict) and "name" in x["entry"]:
                    out.append(x["entry"])
                else:
                    out.append(x)
            return out
    return []


def _name(card: dict[str, Any]) -> str:
    if isinstance(card.get("name"), str) and card["name"].strip():
        return card["name"].strip()
    model = card.get("model")
    if isinstance(model, dict) and isinstance(model.get("name"), str):
        return model["name"]
    return str(card.get("model_id") or "(unnamed)")


def _desc(card: dict[str, Any]) -> str:
    for key in ("description", "short_description"):
        if isinstance(card.get(key), str):
            return card[key]
    model = card.get("model")
    if isinstance(model, dict) and isinstance(model.get("description"), str):
        return model["description"]
    return ""


def _release(card: dict[str, Any]) -> dict[str, Any]:
    rel = card.get("release")
    if isinstance(rel, dict):
        return rel
    entry = card.get("economy") or card.get("entry")
    if isinstance(entry, dict) and isinstance(entry.get("release"), dict):
        return entry["release"]
    return {}


def print_economy_line(card: dict[str, Any]) -> None:
    rel = _release(card)
    av = card.get("availability") if isinstance(card.get("availability"), dict) else {}
    providers = av.get("providers_observed", av.get("providers_total", "?"))
    klass = av.get("class", "?")
    target = rel.get("target_atoms", "")
    funded = rel.get("confirmed_funded_atoms", rel.get("funded_atoms", ""))
    remaining = rel.get("remaining_atoms", "")
    action = ""
    acts = card.get("actions")
    if isinstance(acts, list) and acts:
        action = ",".join(str(a) for a in acts)
    uri = card.get("uri") or ""
    if not uri and isinstance(card.get("model"), dict):
        uri = str(card["model"].get("uri") or "")
    print(
        "\t".join(
            [
                _name(card),
                str(card.get("lifecycle_state") or card.get("result_type") or ""),
                _desc(card)[:80],
                str(providers),
                str(klass),
                str(target),
                str(funded),
                str(remaining),
                action,
                uri,
            ]
        )
    )


def _header() -> None:
    print(
        "name\tlifecycle\tdescription\tproviders_observed\tavailability\t"
        "target_atoms\tfunded\tremaining\tactions\turi"
    )


def search(text: str, *, scope: str = "NETWORK") -> dict[str, Any]:
    page = rpc("searchmodels", [{"text": text, "scope": scope, "limit": DEFAULT_LIMIT}])
    _header()
    for card in _results(page):
        print_economy_line(card)
    return page if isinstance(page, dict) else {"raw": page}


def feed(mode: str = "NEWEST") -> dict[str, Any]:
    page = rpc("getmodelfeed", [{"scope": "NETWORK", "mode": mode, "limit": DEFAULT_LIMIT}])
    _header()
    for card in _results(page):
        print_economy_line(card)
    return page if isinstance(page, dict) else {"raw": page}


def economy(model_id: str) -> dict[str, Any]:
    result = rpc("getmodeleconomyentry", [model_id])
    _header()
    if isinstance(result, dict):
        print_economy_line(result)
    return result if isinstance(result, dict) else {"raw": result}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(
            "usage: economy_client.py <search|feed|newest|nearly|unlocked|economy> [arg]",
            file=sys.stderr,
        )
        return 2
    cmd, *rest = argv
    try:
        if cmd == "search":
            search(rest[0] if rest else "coding agent")
        elif cmd in ("feed", "newest"):
            feed(rest[0] if rest else "NEWEST")
        elif cmd in ("nearly", "nearly_funded"):
            feed("NEARLY_FUNDED")
        elif cmd in ("unlocked", "just_unlocked"):
            feed("JUST_UNLOCKED")
        elif cmd == "economy":
            if not rest:
                raise SystemExit("economy requires model_id")
            economy(rest[0])
        else:
            print(f"unknown command: {cmd}", file=sys.stderr)
            return 2
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
