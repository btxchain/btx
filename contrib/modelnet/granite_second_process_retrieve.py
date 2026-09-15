#!/usr/bin/env python3
"""Second-process FREE_ONLY retrieve. Never touches production btxd.

Demand-seed is the default: this helper is started without -modelseed=auto
and without seedmodel. After retrieve, listmodels must show seeded=true.
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
from failfast import BytesStallTracker, pick_job

DEFAULT_URI = "btx://pqc0whmrlv2emtc8eknxja6l6ffdj5mta0nj9msfsdkrz6qg0de448gm0a3kcctd92p9ekje2c97wd5glyrdl"
ROOT = Path(os.environ.get("BTX_MODELD_ROOT", str(Path.home() / ".local/opt/btx-0.34.7-rc-modeld")))
BIN = ROOT / "bin"
DIR = ROOT / os.environ.get("BTX_MODELD_DIRNAME", "e2e-fetch")
SOCK = DIR / "modeld.sock"


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


def wait_helper(proc, timeout=30):
    t0 = time.time()
    last = None
    log = ROOT / "logs" / "modeld-e2e.log"
    while time.time() - t0 < timeout:
        if proc.poll() is not None:
            extra = log.read_text(errors="replace")[-4000:] if log.exists() else ""
            raise SystemExit(f"helper exited rc={proc.returncode}: {last}\n{extra}")
        if SOCK.exists():
            try:
                return rpc("getmodelnetworkinfo", [], 5)
            except Exception as e:
                last = e
        time.sleep(0.2)
    extra = log.read_text(errors="replace")[-4000:] if log.exists() else ""
    raise SystemExit(f"second-process helper did not start: {last}\n{extra}")


def helper_alive():
    try:
        rpc("getmodelnetworkinfo", [], 5)
        return True
    except Exception:
        return False


def poll_retrieve(got, timeout):
    status = got.get("status")
    if status in ("retrieved", "local"):
        return got
    job_id = got.get("job_id")
    if not (status == "running" or got.get("async")):
        raise SystemExit(f"retrieve did not complete: {got}")
    if not job_id:
        raise SystemExit(f"async getmodel missing job_id: {got}")
    t0 = time.time()
    job = {}
    stall = BytesStallTracker(float(os.environ.get("POLL_JOB_STALL_S", "120")))
    while time.time() - t0 < timeout:
        jobs = rpc("getmodeljob", [job_id], 120)
        job = pick_job(jobs, job_id=job_id)
        if job:
            st = job.get("status")
            used = jobs.get("used_bytes")
            if used is None:
                used = sum(p.stat().st_size for p in DIR.rglob("*") if p.is_file())
            print(
                "job",
                job.get("job_id") or job_id,
                st,
                "elapsed",
                int(time.time() - t0),
                "used_bytes",
                used,
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
                "retries",
                job.get("peer_retries"),
                "last_err",
                job.get("last_err") or job.get("error"),
                flush=True,
            )
            if st == "failed":
                raise SystemExit(f"retrieve failed: {job}")
            if st == "cancelled":
                raise SystemExit(f"retrieve cancelled: {job}")
            if st == "done":
                break
            stall.observe(job)
        time.sleep(0.5)
    else:
        raise SystemExit(f"getmodeljob timeout: {job}")
    if job.get("status") != "done":
        raise SystemExit(f"retrieve failed: {job}")
    return job.get("result") or {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=os.environ.get("SEEDER") or "", help="host:port of a non-production seeder")
    ap.add_argument("--uri", default=os.environ.get("URI") or DEFAULT_URI)
    ap.add_argument("--timeout", type=float, default=float(os.environ.get("WAN_TIMEOUT_S", "14400")))
    ap.add_argument("--keep", action="store_true", help="leave the second-process helper running")
    ap.add_argument("--attach", action="store_true", help="reuse a live helper on this datadir (resume)")
    ap.add_argument("--job-id", default=os.environ.get("JOB_ID") or "", help="poll this job_id instead of jobs[0]")
    args = ap.parse_args()
    if not args.host:
        raise SystemExit("set --host or SEEDER=host:port (non-production helper)")

    DIR.mkdir(parents=True, exist_ok=True)
    (ROOT / "logs").mkdir(exist_ok=True)
    log = open(ROOT / "logs" / "modeld-e2e.log", "ab")
    env = os.environ.copy()
    lib = ROOT / "lib"
    if (lib / "libssl.so.3").exists():
        env["LD_LIBRARY_PATH"] = str(lib) + ((":" + env["LD_LIBRARY_PATH"]) if env.get("LD_LIBRARY_PATH") else "")
    argv = [
        str(BIN / "btx-modeld"),
        f"-modeldir={DIR}",
        "-modelstorage=80GiB",
        f"-modelrpcsocket={SOCK}",
    ]
    proc = None
    if helper_alive():
        if not args.attach:
            raise SystemExit(f"helper already running at {SOCK}; pass --attach to resume or stop it first")
        print("attach existing helper", SOCK, flush=True)
    else:
        proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env)
    try:
        if proc is not None:
            info = wait_helper(proc)
        else:
            info = rpc("getmodelnetworkinfo", [], 10)
        prop = info.get("propagation") or {}
        print(
            "pq1",
            info.get("pq1_ready"),
            info.get("openssl"),
            "inflight",
            info.get("inflight_pieces"),
            "inbound_per_netgroup",
            info.get("inbound_per_netgroup"),
            "transfer_ms",
            info.get("transfer_timeout_ms"),
            "demand",
            prop.get("demand_propagation"),
            flush=True,
        )
        if not prop.get("demand_propagation"):
            raise SystemExit(f"default demand_propagation false: {prop}")
        if prop.get("seed_upon_download_opt_in"):
            raise SystemExit(f"seed_upon_download still opt-in: {prop}")
        rpc("addmodelnode", [args.host], 10)
        t0 = time.time()
        if args.job_id:
            print("poll job_id", args.job_id, "via", args.host, flush=True)
            got = {"status": "running", "async": True, "job_id": args.job_id}
        else:
            print("retrieve start", args.uri, "via", args.host, flush=True)
            got = rpc("getmodel", [args.uri, "FREE_ONLY"], 60)
        result = poll_retrieve(got, args.timeout)
        elapsed = int(time.time() - t0)
        listed = rpc("listmodels", [], 30)
        out = {"got": got, "result": result, "listed": listed, "elapsed_s": elapsed, "peer": args.host, "propagation": prop}
        (ROOT / "logs" / "retrieve-e2e.json").write_text(json.dumps(out, indent=2))
        print("result", json.dumps(result, indent=2), "elapsed_s", elapsed, flush=True)
        models = listed.get("models") or []
        if listed.get("local_count") != 1 or not models:
            raise SystemExit(f"SECOND_PROCESS_RETRIEVE FAIL list: {listed}")
        if models[0].get("seeded") is not True:
            raise SystemExit(f"downloader must demand-seed without seedmodel: {listed}")
        if result.get("status") not in ("retrieved", "local") and result.get("seeded") is not True:
            if models[0].get("bytes", 0) < 1:
                raise SystemExit(f"SECOND_PROCESS_RETRIEVE FAIL: {result}")
        print("SECOND_PROCESS_RETRIEVE PASS bytes", models[0].get("bytes"), "seeded", models[0].get("seeded"))
        return 0
    finally:
        if proc is not None and not args.keep:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except Exception:
                proc.kill()
        log.close()


if __name__ == "__main__":
    sys.exit(main())
