#!/usr/bin/env python3
"""Optional D09 disclosed-weaker browser bridge (loopback HTTP).

This is a SEPARATE process from btx-modeld. Native model transport remains
strict PQ1. Operators who need PQ-only MUST omit this binary.

Browser-edge HTTP is conventional and is NOT end-to-end post-quantum.
Upstream to BTX is unix RPC (getmodel / listmodels) or PQ1 to the helper.
Never a native-client TLS fallback. Never wallet RPC, secrets, BanMan, or spend.

Default bind is 127.0.0.1. There is no 0.0.0.0 default.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

DISCLOSURE = {
    "pq_end_to_end": False,
    "native_fallback": False,
    "wallet": False,
}

NOTE = (
    "HTTP bridge is not the identity authority; verify native hash. "
    "Browser edge is not end-to-end PQ. Upstream to BTX remains PQ1 or unix RPC."
)
WEB_COMPAT = "WEB COMPATIBILITY - NOT NATIVE END-TO-END PQ"

FILE_PATH_RE = re.compile(r"^/([^/]+)/f/(\d+)(?:/.*)?$")


def split_token_file(raw_path: str) -> tuple[str, int] | None:
    parsed = urlparse(raw_path)
    m = FILE_PATH_RE.match(parsed.path)
    if not m:
        return None
    return m.group(1), int(m.group(2))


def verified_file_bytes(digest_hex: str, file_index: int) -> bytes | None:
    root = os.environ.get("BTX_BRIDGE_VERIFIED_DIR", "")
    if not root:
        return None
    path = Path(root) / digest_hex / str(file_index)
    if not path.is_file():
        return None
    data = path.read_bytes()
    if not data:
        return None
    return data


def parse_range(headers, size: int) -> tuple[int, int] | None:
    spec = headers.get("Range") or ""
    if not spec:
        return 0, size - 1
    spec = spec.strip()
    if not spec.lower().startswith("bytes="):
        return None
    spec = spec[6:]
    if "," in spec:
        return None
    a, _, b = spec.partition("-")
    try:
        first = int(a) if a else 0
        last = int(b) if b else size - 1
    except ValueError:
        return None
    if last < first or first >= size:
        return None
    return first, min(last, size - 1)


LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
MAX_BODY = 16 * 1024
RATE_LIMIT_PER_IP = 60
ALLOWED_RPC = {"getmodel", "listmodels", "getmodelnetworkinfo", "getmodelmanifest"}
WALLET_SEGMENTS = ("wallet", "sign", "dump")
SAFE_METHODS = {"GET", "HEAD"}

_REF = Path(__file__).resolve().parent.parent / "modelnet" / "reference"
if str(_REF) not in sys.path:
    sys.path.insert(0, str(_REF))

try:
    from reference_v11 import KINDS, decode_resource  # type: ignore
except Exception:  # pragma: no cover - tree layout
    KINDS = {}
    decode_resource = None


_rate_lock = threading.Lock()
_rate: dict[str, list[float]] = {}


def rate_ok(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        hits = [t for t in _rate.get(ip, []) if now - t < 60.0]
        if len(hits) >= RATE_LIMIT_PER_IP:
            _rate[ip] = hits
            return False
        hits.append(now)
        _rate[ip] = hits
        return True


def disclose(payload: dict) -> dict:
    out = dict(payload)
    out.update(DISCLOSURE)
    out.setdefault("web_compatibility", WEB_COMPAT)
    return out


def path_only(raw: str) -> str:
    parsed = urlparse(raw)
    path = parsed.path or "/"
    while len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


def normalized_route(raw: str) -> str:
    path = path_only(raw).lower()
    if not path.startswith("/"):
        path = "/" + path
    return path


def wallet_like_path(raw: str) -> bool:
    path = normalized_route(raw)
    for seg in path.split("/"):
        if not seg:
            continue
        low = seg.lower()
        if low.startswith(WALLET_SEGMENTS):
            return True
    return False


def wallet_like_body(body: str) -> bool:
    if not body:
        return False
    try:
        obj = json.loads(body)
        if isinstance(obj, dict) and isinstance(obj.get("method"), str):
            method = obj["method"].lower()
            if any(s in method for s in WALLET_SEGMENTS) or method.startswith("send"):
                return True
            if "importpriv" in method or "listunspent" in method:
                return True
    except json.JSONDecodeError:
        pass
    low = body.lower()
    for needle in (
        "dumpprivkey",
        "dumpwallet",
        "signrawtransaction",
        "walletpassphrase",
        "importprivkey",
        "sendtoaddress",
    ):
        if needle in low:
            return True
    return False


def unix_rpc(sock_path: str, method: str, params: list, timeout: float = 5.0):
    """Call helper unix JSON-RPC. Wallet methods are refused here, not forwarded."""
    name = method.lower()
    if name not in ALLOWED_RPC:
        raise RuntimeError(f"bridge may not call RPC {method!r}")
    if any(s in name for s in WALLET_SEGMENTS):
        raise RuntimeError("wallet RPC refused")
    payload = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}) + "\n"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        s.sendall(payload.encode())
        s.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break
    finally:
        s.close()
    reply = json.loads(data.decode())
    if reply.get("error"):
        raise RuntimeError(f"{method}: {reply['error']}")
    return reply.get("result")


def decode_uri(text: str):
    """HandleBridgeGet semantics via the v1.1 reference codec."""
    if decode_resource is None:
        raise ValueError("reference codec unavailable; use unix RPC getmodel/listmodels")
    try:
        return decode_resource(text)
    except Exception:
        if not text.lower().startswith("btx:"):
            return decode_resource("btx://" + text)
        raise


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "btx-modelbridge/0.34.7"
    rpc_socket = None

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send_html(self, status: int, html: str) -> None:
        body = html.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("X-BTX-Web-Compatibility", WEB_COMPAT)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _wants_html(self) -> bool:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if any(k.lower() == "format" and values and values[0].lower() == "html" for k, values in qs.items()):
            return True
        accept = (self.headers.get("Accept") or "").lower()
        return "text/html" in accept

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(disclose(payload)).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("X-BTX-Web-Compatibility", WEB_COMPAT)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length < 0 or length > MAX_BODY:
            return ""
        if length == 0:
            return ""
        return self.rfile.read(length).decode("utf-8", "replace")

    def _health(self) -> None:
        payload = {
            "ok": True,
            "service": "btx-model-browser-bridge",
            "profile": "D09",
            "bind_default": "127.0.0.1",
            "catalog_browser_bridge": False,
            "wildcard_dns_depth": 0,
            "public_download": os.environ.get("BTX_BRIDGE_PUBLIC_DOWNLOAD") == "1",
            "web_compatibility": WEB_COMPAT,
            "note": NOTE,
            "upstream": "unix RPC getmodel/listmodels on btx-modeld; never native-client TLS fallback",
        }
        self._send(200, payload)

    def _open(self) -> None:
        # Range query/header is ignored: JSON preview only, never model bytes.
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        uri = ""
        for key, values in qs.items():
            if key.lower() == "uri" and values:
                uri = unquote(values[0])
                break
        if not uri:
            self._send(400, {"error": "malformed URI", "note": NOTE})
            return
        try:
            resource = decode_uri(uri)
        except Exception:
            self._send(400, {"error": "malformed URI", "note": NOTE})
            return
        kind = KINDS.get(resource.kind, "UNKNOWN")
        payload = {
            "canonical": resource.uri,
            "kind": kind,
            "digest": resource.digest.hex(),
            "open_in_btx": resource.uri,
            "note": NOTE,
            "bind_default": "127.0.0.1",
            "upstream": "unix RPC getmodel/listmodels on btx-modeld; never native-client TLS fallback",
        }
        sock = getattr(self.server, "rpc_socket", None)
        if sock:
            try:
                listed = unix_rpc(sock, "listmodels", [])
                local = listed.get("local_count") if isinstance(listed, dict) else None
                payload["listmodels_local_count"] = local
                payload["retrieve"] = "call getmodel over unix RPC; this HTTP edge does not fetch"
            except Exception as exc:
                payload["listmodels_error"] = str(exc)
        if self._wants_html():
            html = (
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
                "<title>Open in BTX</title></head><body>"
                "<p>LINK_ONLY</p>"
                "<p><a href=\"%s\">Open in BTX</a></p>"
                "<p><code>%s</code></p>"
                "<p>%s</p></body></html>"
            ) % (resource.uri, resource.uri, WEB_COMPAT)
            self._send_html(200, html)
            return
        self._send(200, payload)

    def _legacy_token(self) -> None:
        token = path_only(self.path).lstrip("/")
        try:
            resource = decode_uri(token)
        except Exception:
            self._send(400, {"error": "malformed URI", "note": NOTE})
            return
        self._send(
            200,
            {
                "canonical": resource.uri,
                "kind": KINDS.get(resource.kind, "UNKNOWN"),
                "digest": resource.digest.hex(),
                "open_in_btx": resource.uri,
                "note": NOTE,
                "bind_default": "127.0.0.1",
                "upstream": "unix RPC getmodel/listmodels on btx-modeld; never native-client TLS fallback",
            },
        )

    def _public_file(self) -> None:
        split = split_token_file(self.path)
        if not split:
            self._send(400, {"error": "expected /<token>/f/<index>"})
            return
        token, file_index = split
        if os.environ.get("BTX_BRIDGE_PUBLIC_DOWNLOAD") != "1":
            self._send(403, {"error": "public download disabled", "public_download": False})
            return
        try:
            resource = decode_uri(token)
        except Exception:
            self._send(400, {"error": "malformed URI", "note": NOTE})
            return
        data = verified_file_bytes(resource.digest.hex(), file_index)
        if not data:
            self._send(409, {"error": "verified chunks required before emission", "public_download": True})
            return
        rng = parse_range(self.headers, len(data))
        if rng is None:
            self._send(416, {"error": "invalid range"})
            return
        first, last = rng
        body = data[first : last + 1]
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", "attachment")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("X-BTX-Web-Compatibility", WEB_COMPAT)
        self.send_header("X-BTX-Cache-Key", "%s/f/%d" % (resource.uri, file_index))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _dispatch(self) -> None:
        ip = self.client_address[0] if self.client_address else "unknown"
        if not rate_ok(ip):
            self._send(429, {"error": "rate limit", "web_compatibility": WEB_COMPAT})
            return
        body = self._read_body() if self.command not in SAFE_METHODS else ""
        mutating = self.command not in SAFE_METHODS
        wallet_path = wallet_like_path(self.path)
        wallet_body = mutating and wallet_like_body(body)
        if mutating and (wallet_path or wallet_body):
            self._send(405, {"error": "method not allowed", "allow": "GET, HEAD"})
            return
        if wallet_path:
            self._send(403, {"error": "wallet paths are not served"})
            return
        if mutating:
            self._send(405, {"error": "method not allowed", "allow": "GET, HEAD"})
            return
        route = normalized_route(self.path)
        if route == "/health":
            self._health()
            return
        if route == "/open":
            self._open()
            return
        if split_token_file(self.path):
            self._public_file()
            return
        self._legacy_token()

    def do_GET(self) -> None:
        self._dispatch()

    def do_HEAD(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def do_PUT(self) -> None:
        self._dispatch()

    def do_DELETE(self) -> None:
        self._dispatch()

    def do_PATCH(self) -> None:
        self._dispatch()

    def do_OPTIONS(self) -> None:
        self._dispatch()


class LoopbackServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, addr, handler, rpc_socket=None):
        super().__init__(addr, handler)
        self.rpc_socket = rpc_socket


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="modelbridge.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Optional D09 disclosed-weaker browser bridge for BTX 0.34.7.\n"
            "Native-only remains valid. Operators who need PQ-only MUST omit this binary."
        ),
        epilog=(
            "PQ-only operators: do not run this process. btx-modeld stays strict PQ1\n"
            "(ML-KEM-768, ML-DSA-44, TLS_AES_256_GCM_SHA384). This edge is conventional\n"
            "HTTP on 127.0.0.1 and discloses pq_end_to_end=false on every JSON body.\n"
            "Production retrieve/list is unix RPC getmodel/listmodels, never wallet RPC.\n"
            "Native feature bits (PRESERVATION_CIRCLE=64 and friends) are helper caps,\n"
            "not this bridge. catalog browser_bridge stays false until you start this."
        ),
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="loopback bind address (default: 127.0.0.1; 0.0.0.0 is refused)",
    )
    parser.add_argument("--port", type=int, default=18747, help="loopback port (default: 18747)")
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="opt-in LAN bind; still refuses 0.0.0.0 unless BTX_BRIDGE_PUBLIC_EDGE=1",
    )
    parser.add_argument(
        "--rpc-socket",
        default="",
        help="optional btx-modeld unix socket for listmodels (getmodel is documented, not auto-fetched)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    host = args.host.strip()
    public_edge = os.environ.get("BTX_BRIDGE_PUBLIC_EDGE") == "1"
    allow_noloop = args.allow_non_loopback or os.environ.get("BTX_BRIDGE_NON_LOOPBACK") == "1"
    if host in {"0.0.0.0", "::"} and not public_edge:
        sys.stderr.write("refusing wildcard bind %r (set BTX_BRIDGE_PUBLIC_EDGE=1 for a public edge)\n" % (host,))
        return 2
    if host not in LOOPBACK_HOSTS and not allow_noloop:
        sys.stderr.write(
            "loopback-only: refusing non-loopback bind %r (pass --allow-non-loopback or BTX_BRIDGE_NON_LOOPBACK=1)\n"
            % (host,)
        )
        return 2
    if args.port <= 0 or args.port > 65535:
        sys.stderr.write("invalid port\n")
        return 2
    rpc_socket = args.rpc_socket or None
    server = LoopbackServer((host, args.port), BridgeHandler, rpc_socket=rpc_socket)
    sys.stderr.write(
        "btx-modelbridge D09 disclosed-weaker edge on http://%s:%d "
        "(pq_end_to_end=false native_fallback=false wallet=false); "
        "PQ-only operators omit this process\n" % (host, args.port)
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
