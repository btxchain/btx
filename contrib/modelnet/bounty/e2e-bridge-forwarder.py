#!/usr/bin/env python3
"""Read-only HTTP forwarder for bounty E2E-H (GET /api/v1/bounties only)."""
from __future__ import annotations

import json
import os
import socket
import socketserver
import sys
import threading
import urllib.parse
from http import HTTPStatus
from pathlib import Path


def unix_rpc(sock: Path, method: str, params=None, timeout=30.0):
    params = params if params is not None else []
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    payload = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}) + "\n"
    s.sendall(payload.encode())
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(1 << 20)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    s.close()
    reply = json.loads(data.decode())
    if reply.get("error"):
        raise RuntimeError(reply["error"])
    return reply.get("result")


class Handler(socketserver.BaseRequestHandler):
    sock: Path

    def _json(self, code: int, obj: dict):
        body = json.dumps(obj, separators=(",", ":")).encode()
        hdr = (
            f"HTTP/1.1 {code} {HTTPStatus(code).phrase}\r\n"
            "Content-Type: application/json\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "Content-Security-Policy: default-src 'none'\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        )
        self.request.sendall(hdr.encode() + body)

    def handle(self):
        try:
            raw = self.request.recv(8192).decode("utf-8", errors="replace")
        except OSError:
            return
        if not raw:
            return
        line = raw.split("\r\n", 1)[0]
        parts = line.split()
        if len(parts) < 2:
            self._json(400, {"error": "bad request"})
            return
        method, target = parts[0].upper(), parts[1]
        path = urllib.parse.urlparse(target).path
        if method != "GET":
            if any(x in path.lower() for x in ("wallet", "eval", "mandate", "sign", "dump")):
                self._json(403, {"error": "forbidden", "wallet": False})
            else:
                self._json(405, {"error": "method not allowed", "allow": "GET, HEAD"})
            return
        if path.startswith("/wallet") or "/mandate" in path or "/eval" in path:
            self._json(403, {"error": "wallet paths are not served"})
            return
        if path == "/api/v1/bounties":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(target).query).get("q", [""])[0]
            try:
                rpc = unix_rpc(
                    self.sock,
                    "searchbounties",
                    [{"text": q, "scope": "LOCAL", "limit": 50}],
                )
            except Exception as e:
                self._json(503, {"error": str(e), "results": []})
                return
            results = rpc.get("results") if isinstance(rpc, dict) else []
            self._json(
                200,
                {
                    "schema_version": 2,
                    "results": results or [],
                    "wallet": False,
                    "eval": False,
                    "mandate": False,
                },
            )
            return
        self._json(404, {"error": "not found"})


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} UNIX_SOCK PORT", file=sys.stderr)
        sys.exit(2)
    sock = Path(sys.argv[1])
    port = int(sys.argv[2])
    Handler.sock = sock
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", port), Handler)
    httpd.daemon_threads = True
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    print(port, flush=True)
    try:
        t.join()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
