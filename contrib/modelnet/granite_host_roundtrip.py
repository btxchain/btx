#!/usr/bin/env python3
"""Import/seed granite-4.0-h-tiny on a host helper and FREE_ONLY retrieve on a peer.

Not a claim of usefulness, safety, or alignment. execution_profile stays 0.
Does not touch production btxd or the GPU.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from failfast import wait_unix


def rpc(sock: Path, method: str, params, timeout: float):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
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


def wait_sock(path: Path, proc=None, timeout=20):
    wait_unix(
        lambda: rpc(path, "getmodelnetworkinfo", [], timeout=5) or True,
        timeout=timeout,
        proc=proc,
        log=path.parent / "modeld.log",
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bin", required=True, help="directory containing btx-modeld")
    p.add_argument("--fixture", required=True, help="granite-4.0-h-tiny directory")
    p.add_argument("--host-dir", required=True)
    p.add_argument("--peer-dir", required=True)
    p.add_argument("--bind", default="127.0.0.1:29447")
    p.add_argument("--cache", type=int, default=85899345920)
    p.add_argument("--import-timeout", type=float, default=7200)
    p.add_argument("--retrieve-timeout", type=float, default=14400)
    p.add_argument("--skip-import", action="store_true")
    args = p.parse_args()

    bindir = Path(args.bin)
    modeld = bindir / "run-modeld.sh"
    if not modeld.exists():
        modeld = bindir / "btx-modeld"
    env = os.environ.copy()
    lib = bindir.parent / "lib"
    if (lib / "libssl.so.3").exists():
        env["LD_LIBRARY_PATH"] = str(lib) + ((":" + env["LD_LIBRARY_PATH"]) if env.get("LD_LIBRARY_PATH") else "")
        env["PATH"] = str(bindir) + ":" + env.get("PATH", "")
        if (bindir / "openssl35").exists():
            env["BTX_OPENSSL"] = str(bindir / "openssl35")

    host_dir = Path(args.host_dir)
    peer_dir = Path(args.peer_dir)
    host_dir.mkdir(parents=True, exist_ok=True)
    peer_dir.mkdir(parents=True, exist_ok=True)
    hs = host_dir / "modeld.sock"
    ps = peer_dir / "modeld.sock"

    logh = open(host_dir / "modeld.log", "ab")
    logp = open(peer_dir / "modeld.log", "ab")
    ph = subprocess.Popen(
        [
            str(modeld),
            f"-modeldir={host_dir}",
            f"-modelcache={args.cache}",
            f"-modelbind={args.bind}",
            "-modelhost",
            f"-modelrpcsocket={hs}",
        ],
        stdout=logh,
        stderr=subprocess.STDOUT,
        env=env,
    )
    pp = subprocess.Popen(
        [
            str(modeld),
            f"-modeldir={peer_dir}",
            f"-modelcache={args.cache}",
            f"-modelrpcsocket={ps}",
        ],
        stdout=logp,
        stderr=subprocess.STDOUT,
        env=env,
    )
    try:
        wait_sock(hs, proc=ph)
        wait_sock(ps, proc=pp)
        info = rpc(hs, "getmodelnetworkinfo", [], timeout=10)
        print("host_info", json.dumps({k: info[k] for k in ("openssl", "pq1_ready", "quota_bytes", "used_bytes") if k in info}, indent=2))
        listed = rpc(hs, "listmodels", [], timeout=30)
        uri = None
        if listed.get("local_count") and listed.get("models"):
            uri = listed["models"][0].get("uri") or listed["models"][0].get("model_id")
            print("already_imported", uri)
        if not args.skip_import and not listed.get("local_count"):
            t0 = time.time()
            print("importing", args.fixture, flush=True)
            imported = rpc(hs, "importmodel", [args.fixture, {"pin": True}], timeout=args.import_timeout)
            print("imported", json.dumps(imported, indent=2), "elapsed_s", int(time.time() - t0), flush=True)
            uri = imported["uri"]
        if not uri:
            raise SystemExit("no model uri")
        listed_h = rpc(hs, "listmodels", [], timeout=30)
        models_h = listed_h.get("models") or []
        if not models_h or models_h[0].get("seeded") is not True:
            raise SystemExit(f"import/getmodel must demand-seed without seedmodel: {listed_h}")
        shard = Path(args.fixture) / "model-00001-of-00003.safetensors"
        if shard.exists():
            q = rpc(hs, "qualifymodel", [str(shard)], timeout=60)
            print("qualify_shard1", json.dumps(q, indent=2), flush=True)
            if q.get("result") == "REJECTED_UNSAFE_FORMAT":
                raise SystemExit("granite shard rejected")
        man = rpc(hs, "getmodelmanifest", [uri], timeout=30)
        print("files", [(f["path"], f["size"]) for f in man.get("files", [])], flush=True)
        rpc(ps, "addmodelnode", [args.bind], timeout=10)
        t0 = time.time()
        print("retrieve FREE_ONLY", uri, flush=True)
        got = rpc(ps, "getmodel", [uri, "FREE_ONLY"], timeout=args.retrieve_timeout)
        print("getmodel", json.dumps(got, indent=2), "elapsed_s", int(time.time() - t0), flush=True)
        if got.get("status") not in ("retrieved", "local"):
            raise SystemExit(f"retrieve did not complete: {got}")
        listed_b = rpc(ps, "listmodels", [], timeout=30)
        print("peer local_count", listed_b.get("local_count"), flush=True)
        if listed_b.get("local_count") != 1:
            raise SystemExit(listed_b)
        print("GRANITE_TWO_HELPER_FREE_RETRIEVE PASS")
    finally:
        for proc in (ph, pp):
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except Exception:
                proc.kill()
        logh.close()
        logp.close()


if __name__ == "__main__":
    main()
