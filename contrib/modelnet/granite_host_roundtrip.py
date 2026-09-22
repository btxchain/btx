#!/usr/bin/env python3
"""Import/seed granite-4.0-h-tiny on a host helper and FREE_ONLY retrieve on a peer.

ibm-granite/granite-4.0-h-tiny is SafeTensors hybrid MoE/Mamba.
execution_profile stays 0 (unqualified). Do not claim dense-decoder-v1.
llama.cpp cannot open this checkout without GGUF conversion.
Optional BTX_MODEL_INFER_CMD is an operator generate hook, not a fake PASS.

loadmodel with BTX_MODEL_CUDA_LOADER=contrib/modelnet/cuda_safetensors_load
keeps tensors resident (--hold --smoke): device_loaded, runtime_started,
weights_resident, smoke_passed from a CUDA kernel on loaded bytes. It does
not start a network inference server (inference=false, remote_inference=false).
unloadmodel SIGTERMs the loader child only (never production btxd).

Not a claim of usefulness, safety, or alignment.
Does not touch production btxd or the GPU.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from failfast import poll_job, wait_unix


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
            # Hybrid MoE/Mamba SafeTensors: execution_profile stays 0 (unqualified).
        man = rpc(hs, "getmodelmanifest", [uri], timeout=30)
        print("files", [(f["path"], f["size"]) for f in man.get("files", [])], flush=True)
        rpc(ps, "addmodelnode", [args.bind], timeout=10)
        t0 = time.time()
        print("retrieve FREE_ONLY", uri, flush=True)
        got = rpc(ps, "getmodel", [uri, "FREE_ONLY"], timeout=60)
        print("getmodel", json.dumps(got, indent=2), "elapsed_s", int(time.time() - t0), flush=True)
        status = got.get("status")
        job_id = got.get("job_id")
        if status == "running" or got.get("async"):
            if not job_id:
                raise SystemExit(f"async getmodel missing job_id: {got}")

            def progress(job):
                print(
                    "job",
                    job.get("job_id") or job_id,
                    job.get("status"),
                    "elapsed",
                    int(time.time() - t0),
                    "bytes_committed",
                    job.get("bytes_committed"),
                    "pieces",
                    job.get("pieces_committed"),
                    "file",
                    job.get("file_index"),
                    "piece",
                    job.get("piece_index"),
                    "inflight",
                    job.get("inflight"),
                    "last_err",
                    job.get("last_err") or job.get("error"),
                    flush=True,
                )

            job = poll_job(
                lambda: rpc(ps, "getmodeljob", [job_id], timeout=120),
                timeout=args.retrieve_timeout,
                interval=2.0,
                progress=progress,
                stall_s=300.0,
                job_id=job_id,
            )
            print("job_done", json.dumps(job, indent=2), "elapsed_s", int(time.time() - t0), flush=True)
            result = job.get("result") or {}
            if result.get("status") not in ("retrieved", "local"):
                raise SystemExit(f"retrieve did not complete: {job}")
        elif status not in ("retrieved", "local"):
            raise SystemExit(f"retrieve did not complete: {got}")
        listed_b = rpc(ps, "listmodels", [], timeout=30)
        print("peer local_count", listed_b.get("local_count"), flush=True)
        if listed_b.get("local_count") != 1:
            raise SystemExit(listed_b)
        models_b = listed_b.get("models") or []
        if not models_b or models_b[0].get("seeded") is not True:
            raise SystemExit(f"downloader must demand-seed the replica: {listed_b}")
        if models_b[0].get("incomplete") is True or models_b[0].get("complete") is False:
            raise SystemExit(f"peer replica is incomplete: {models_b[0]}")
        info_b = rpc(ps, "getmodelnetworkinfo", [], timeout=10)
        used = int(info_b.get("used_bytes") or 0)
        if used < 13888336427:
            raise SystemExit(f"peer used_bytes {used} < 13888336427 (partial store is not a retrieve)")
        pieces = list((peer_dir / "store" / "artifacts").rglob("*.piece"))
        nbytes = sum(p.stat().st_size for p in pieces)
        if len(pieces) != 3322 or nbytes != 13888336427:
            raise SystemExit(f"peer store {len(pieces)} pieces / {nbytes} bytes; want 3322 / 13888336427")
        # Hardlinks from source_path when SHA-384 still matches; checkout need
        # not double disk. Not a Hugging Face tree of piece files.
        exported = rpc(ps, "exportmodelpath", [uri], timeout=30)
        fixture = Path(args.fixture)
        files = exported.get("files") or []
        if len(files) != 13:
            raise SystemExit(f"expected 13 granite files, got {files}")
        total = 0
        for f in files:
            src = fixture / f["path"]
            if not src.is_file():
                raise SystemExit(f"fixture missing {f['path']}")
            size = src.stat().st_size
            total += size
            if size != int(f["size"]):
                raise SystemExit(f"size mismatch {f['path']}: fixture={size} export={f['size']}")
            digest = hashlib.sha384()
            with src.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != str(f.get("sha384") or "").lower():
                raise SystemExit(f"sha384 mismatch {f['path']}: fixture={digest.hexdigest()} export={f.get('sha384')}")
        if total != 13888336427:
            raise SystemExit(f"granite payload {total} != 13888336427")
        print("peer_files", [(f["path"], f["size"]) for f in files], "sha384_ok", True, flush=True)
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
