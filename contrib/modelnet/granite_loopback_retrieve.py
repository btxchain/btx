#!/usr/bin/env python3
"""FREE_ONLY retrieve granite from a local host helper. Does not start a second host."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

URI = "btx://pqc0whmrlv2emtc8eknxja6l6ffdj5mta0nj9msfsdkrz6qg0de448gm0a3kcctd92p9ekje2c97wd5glyrdl"
ROOT = Path("/opt/btx-0347-rc")
BIN = ROOT / "bin"
PEER = ROOT / "peerdir"
SOCK = PEER / "modeld.sock"
HOST = "127.0.0.1:29447"


def rpc(method, params, timeout):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(SOCK))
    s.sendall(json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode() + b"\n")
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    s.close()
    reply = json.loads(data.decode())
    if reply.get("error"):
        raise RuntimeError(f"{method}: {reply['error']}")
    return reply["result"]


def main():
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = str(ROOT / "lib") + ((":" + env["LD_LIBRARY_PATH"]) if env.get("LD_LIBRARY_PATH") else "")
    env["PATH"] = str(BIN) + ":" + env.get("PATH", "")
    env["BTX_OPENSSL"] = str(BIN / "openssl35")
    PEER.mkdir(parents=True, exist_ok=True)
    log = open(ROOT / "logs" / "modeld-peer.log", "ab")
    proc = subprocess.Popen(
        [
            str(BIN / "run-modeld.sh"),
            f"-modeldir={PEER}",
            "-modelcache=85899345920",
            f"-modelrpcsocket={SOCK}",
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
        env=env,
    )
    try:
        t0 = time.time()
        while time.time() - t0 < 20:
            if proc.poll() is not None:
                extra = Path(log.name).read_text(errors="replace")[-4000:] if Path(log.name).exists() else ""
                raise SystemExit(f"peer helper exited rc={proc.returncode}\n{extra}")
            if SOCK.exists():
                try:
                    info = rpc("getmodelnetworkinfo", [], 5)
                    print("peer_pq1", info.get("pq1_ready"), info.get("openssl"), flush=True)
                    break
                except Exception:
                    time.sleep(0.2)
            time.sleep(0.1)
        else:
            extra = Path(log.name).read_text(errors="replace")[-4000:] if Path(log.name).exists() else ""
            raise SystemExit(f"peer helper did not start\n{extra}")
        rpc("addmodelnode", [HOST], 10)
        t0 = time.time()
        print("retrieve start", URI, flush=True)
        got = rpc("getmodel", [URI, "FREE_ONLY"], 14400)
        elapsed = int(time.time() - t0)
        print("getmodel", json.dumps(got, indent=2), "elapsed_s", elapsed, flush=True)
        listed = rpc("listmodels", [], 30)
        print("peer_local_count", listed.get("local_count"), flush=True)
        out = {"got": got, "listed": listed, "elapsed_s": elapsed}
        (ROOT / "logs" / "retrieve-granite-loopback.json").write_text(json.dumps(out, indent=2))
        if got.get("status") not in ("retrieved", "local") or listed.get("local_count") != 1:
            raise SystemExit("GRANITE_LOOPBACK_RETRIEVE FAIL")
        print("GRANITE_LOOPBACK_RETRIEVE PASS")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except Exception:
            proc.kill()
        log.close()


if __name__ == "__main__":
    sys.exit(main())
