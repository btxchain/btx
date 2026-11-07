#!/usr/bin/env python3
"""Host-side typed-tool adapter for the native BTX modelsecurity RPC.

Run OUTSIDE the model sandbox. Do not give models this process, the RPC cookie,
local policy files, or the private guard pipe. A model supplies only a tool name
and bounded JSON arguments; the owner pins grant, session/context and CLI image.
This adapter does not intercept tools executed independently by another harness.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any


class GuardError(RuntimeError):
    pass


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GuardError("duplicate JSON key")
        result[key] = value
    return result


def _digest(value: str) -> str:
    if len(value) != 96 or any(c not in "0123456789abcdef" for c in value):
        raise GuardError("expected lowercase SHA-384 identifier")
    return value


def translate_tool(name: str, arguments: str) -> dict[str, Any]:
    """No shell/network fallback. Unknown tools are rejected before any RPC."""
    if len(arguments.encode("utf-8")) > 140000:
        raise GuardError("tool arguments too large")
    try:
        args = json.loads(arguments, object_pairs_hook=_unique_pairs)
    except (ValueError, TypeError) as exc:
        raise GuardError("invalid tool JSON") from exc
    if not isinstance(args, dict):
        raise GuardError("tool arguments must be an object")
    layouts = {"read_file": ({"path"}, "read"),
               "hash_file": ({"path"}, "hash"),
               "write_new_file": ({"path", "payload_hex"}, "write-new"),
               "run_approved_static": ({"package", "payload_hex"}, "run-static")}
    if name not in layouts:
        raise GuardError("tool not authorized: no arbitrary shell or network")
    fields, operation = layouts[name]
    if set(args) != fields or not all(isinstance(v, str) for v in args.values()):
        raise GuardError("unexpected tool arguments")
    if "package" in args:
        _digest(args["package"])
    if "payload_hex" in args:
        raw = args["payload_hex"]
        if len(raw) > 131072 or len(raw) % 2 or any(c not in "0123456789abcdef" for c in raw):
            raise GuardError("bounded lowercase hex payload required")
    return {"tool": operation, **args}


class NativeGuardClient:
    def __init__(self, cli: Path, expected_cli_sha384: str, datadir: Path,
                 grant: str, context: dict[str, str], *, chain: str = "main"):
        self.cli = cli.resolve(strict=True)
        self.datadir = datadir.resolve(strict=True)
        self.grant = _digest(grant)
        if chain not in {"main", "test", "regtest", "signet"}:
            raise GuardError("unsupported chain")
        self.chain = chain
        if set(context) != {"realm", "composition", "runtime", "tool_schema", "session"}:
            raise GuardError("owner-pinned context required")
        for field in ("realm", "composition", "runtime", "tool_schema"):
            _digest(context[field])
        if len(context["session"]) != 64 or any(c not in "0123456789abcdef" for c in context["session"]):
            raise GuardError("session must be 32 bytes of lowercase hex")
        self.context = dict(context)
        self.expected_cli_sha384 = _digest(expected_cli_sha384)
        self._verify_cli()

    def _verify_cli(self) -> None:
        # Local CLI/deployment directory is owner-controlled TCB. Do not install
        # it in a model-writable directory; hashing alone is not an OS boundary.
        if not self.cli.is_file() or self.cli.stat().st_size > 256 * 1024 * 1024:
            raise GuardError("CLI image unavailable or oversized")
        with self.cli.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha384").hexdigest()
        if actual != self.expected_cli_sha384:
            raise GuardError("CLI image changed")

    def rpc(self, request: dict[str, Any]) -> dict[str, Any]:
        self._verify_cli()
        raw = json.dumps(request, separators=(",", ":"), ensure_ascii=True)
        if len(raw) > 1024 * 1024:
            raise GuardError("RPC request too large")
        command = [str(self.cli), f"-datadir={self.datadir}", f"-chain={self.chain}",
                   "-stdin", "modelsecurity"]
        environment = {"LANG": "C"}
        if os.name == "nt" and "SystemRoot" in os.environ:
            environment["SystemRoot"] = os.environ["SystemRoot"]
        result = subprocess.run(command, input=(raw + "\n").encode(), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=environment, shell=False,
                                close_fds=True, timeout=15, check=False)
        if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
            raise GuardError("native guard RPC failed")
        try:
            decoded = json.loads(result.stdout, object_pairs_hook=_unique_pairs)
        except (ValueError, TypeError) as exc:
            raise GuardError("invalid native response") from exc
        if not isinstance(decoded, dict) or decoded.get("ok") is False:
            raise GuardError(str(decoded.get("error", "guard refused")) if isinstance(decoded, dict) else "invalid response")
        return decoded

    def execute(self, tool_name: str, arguments: str, *, wait_seconds: float = 30) -> dict[str, Any]:
        if not 0 < wait_seconds <= 600:
            raise GuardError("invalid wait bound")
        request = translate_tool(tool_name, arguments)
        prepared = self.rpc({"op": "prepare", "grant": self.grant,
                             "context": self.context, "request": request})
        submitted = self.rpc({"op": "execute", "secret": prepared["secret"],
                              "context": self.context, "request": request})
        job = _digest(submitted["job"])
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            # take performs a current revocation check before releasing bytes.
            result = self.rpc({"op": "take", "job": job})
            if result.get("phase") == "finished":
                effect = result["result"]
                if effect.get("ok") is not True:
                    raise GuardError(str(effect.get("error", "effect refused")))
                return effect
            time.sleep(0.1)
        raise GuardError("job still running within its signed limits; no completion claimed")

    def pause_all(self) -> None:
        """Explicit owner operation, not a tool exposed to a model."""
        self.rpc({"op": "pause"})
