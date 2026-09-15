#!/usr/bin/env python3
"""Two-helper free retrieve smoke. Not a claim of granite usefulness."""
from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from failfast import poll_job, wait_unix

BIN = Path(sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[2] / "build-gcc13" / "bin"))
MODELD = BIN / "btx-modeld"


def rpc(sock: Path, method: str, params):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(str(sock))
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


def pick_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    if port < 1024:
        raise SystemExit("refusing privileged port")
    return port


def wait_sock(path: Path, proc=None, timeout=20):
    wait_unix(
        lambda: rpc(path, "getmodelnetworkinfo", []),
        timeout=timeout,
        proc=proc,
        log=path.parent / "modeld.log",
    )


def write_safetensors(path: Path):
    header = b"{}"
    blob = struct.pack("<Q", len(header)) + header
    path.write_bytes(blob)


def main():
    pa = pb = None
    root = Path(tempfile.mkdtemp(prefix="btx-modelnet-smoke-"))
    try:
        src = root / "src"
        src.mkdir()
        write_safetensors(src / "model.safetensors")
        a = root / "a"
        b = root / "b"
        a.mkdir()
        b.mkdir()
        bind = f"127.0.0.1:{pick_port()}"
        pa = subprocess.Popen(
            [
                str(MODELD),
                f"-modeldir={a}",
                "-modelcache=10485760",
                f"-modelbind={bind}",
                "-modelhost",
                f"-modelrpcsocket={a / 'modeld.sock'}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        pb = subprocess.Popen(
            [
                str(MODELD),
                f"-modeldir={b}",
                "-modelcache=10485760",
                f"-modelrpcsocket={b / 'modeld.sock'}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        wait_sock(a / "modeld.sock", proc=pa)
        wait_sock(b / "modeld.sock", proc=pb)
        info_a = rpc(a / "modeld.sock", "getmodelnetworkinfo", [])
        prop = info_a.get("propagation") or {}
        if not prop.get("demand_propagation"):
            raise SystemExit(f"default demand_propagation false: {prop}")
        if prop.get("seed_upon_download_opt_in"):
            raise SystemExit(f"seed_upon_download still opt-in: {prop}")
        imported = rpc(a / "modeld.sock", "importmodel", [str(src), {"pin": True}])
        uri = imported["uri"]
        print("imported", uri, "seeded", imported.get("seeded"), "propagation", imported.get("propagation"))
        if imported.get("seeded") is not True:
            raise SystemExit(f"import must demand-seed without seedmodel: {imported}")
        if imported.get("propagation") != "demand":
            raise SystemExit(f"import propagation: {imported}")
        listed = rpc(a / "modeld.sock", "listmodels", [])
        assert listed["local_count"] == 1, listed
        rpc(b / "modeld.sock", "addmodelnode", [bind])
        got = rpc(b / "modeld.sock", "getmodel", [uri, "FREE_ONLY"])
        print("getmodel", json.dumps(got, indent=2))
        status = got.get("status")
        job_id = got.get("job_id")
        if status == "running" or got.get("async"):
            if not job_id:
                raise SystemExit(f"async getmodel missing job_id: {got}")
            job = poll_job(lambda: rpc(b / "modeld.sock", "getmodeljob", [job_id]), timeout=90)
            print("job", json.dumps(job, indent=2))
            result = job.get("result") or {}
            if result.get("status") not in ("retrieved", "local"):
                raise SystemExit(f"retrieve did not complete: {job}")
        elif status not in ("retrieved", "local"):
            raise SystemExit(f"retrieve did not complete: {got}")
        listed_b = rpc(b / "modeld.sock", "listmodels", [])
        print("peer local_count", listed_b["local_count"])
        assert listed_b["local_count"] == 1, listed_b
        models_b = listed_b.get("models") or []
        if not models_b or models_b[0].get("seeded") is not True:
            raise SystemExit(f"downloader must demand-seed the replica: {listed_b}")
        print("TWO_HELPER_FREE_RETRIEVE PASS")
    finally:
        for proc in (pa, pb):
            if proc:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
