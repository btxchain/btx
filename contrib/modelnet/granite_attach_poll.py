#!/usr/bin/env python3
"""Poll an already-running second-process helper. Never starts or kills it.

Use this when a retrieve is in flight and the original poller must not be
allowed to SIGTERM the helper on timeout.

Picks the newest *running* job (highest created_ms, then job_id). A stale
failed jobs[0] is never treated as the live retrieve.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any, Optional

EXPECT_BYTES = 13888336427


def rpc(sock: Path, method, params, timeout):
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
        raise RuntimeError("%s: %s" % (method, reply["error"]))
    return reply["result"]


def _jobs_list(raw: Any) -> list:
    if isinstance(raw, dict):
        arr = raw.get("jobs") or []
        if not arr and raw.get("status"):
            return [raw]
        return [j for j in arr if isinstance(j, dict)]
    if isinstance(raw, list):
        return [j for j in raw if isinstance(j, dict)]
    return []


def _newness(job: dict):
    try:
        created = int(job.get("created_ms") or 0)
    except (TypeError, ValueError):
        created = 0
    return (created, str(job.get("job_id") or ""))


def pick_newest_running(raw: Any, job_id: Optional[str] = None) -> dict:
    """Prefer status==running; if several, highest created_ms then job_id.

    Never returns a stale failed jobs[0] when a newer/running job exists.
    """
    arr = _jobs_list(raw)
    if not arr:
        return {}
    if job_id:
        want = str(job_id)
        for j in arr:
            if str(j.get("job_id")) == want:
                return j
        return {}
    running = [j for j in arr if j.get("status") == "running"]
    if running:
        return max(running, key=_newness)
    done = [j for j in arr if j.get("status") == "done"]
    if done:
        return max(done, key=_newness)
    alive = [j for j in arr if j.get("status") not in ("failed",)]
    if alive:
        return max(alive, key=_newness)
    return max(arr, key=_newness)


class DigestAwareStallTracker:
    """STALL only when bytes are frozen *and* inflight>0.

    inflight==0 with empty last_err is digest verify — keep waiting.
    inflight==0 with last_err set is transient resume — keep waiting.
    """

    def __init__(self, stall_secs: float = 180.0):
        self.stall_secs = float(stall_secs)
        self._seen = False
        self._last: Any = None
        self._t = time.time()
        self._digest_note = False

    def observe(self, job: dict) -> None:
        if self.stall_secs <= 0 or not isinstance(job, dict):
            return
        if job.get("status") != "running":
            return
        if "bytes_committed" not in job:
            return
        bc = job.get("bytes_committed")
        now = time.time()
        if not self._seen or bc != self._last:
            self._seen = True
            self._last = bc
            self._t = now
            self._digest_note = False
            return
        if now - self._t < self.stall_secs:
            return
        try:
            inflight = int(job.get("inflight") or 0)
        except (TypeError, ValueError):
            inflight = 0
        last_err = job.get("last_err") or job.get("error") or ""
        if inflight <= 0 and not last_err:
            if not self._digest_note:
                print(
                    "bytes_committed flat inflight=0 last_err empty; waiting (digest verify)",
                    flush=True,
                )
                self._digest_note = True
            return
        if inflight > 0:
            raise SystemExit(
                "STALL: bytes_committed=%s unchanged for %ss while status=running inflight=%s: %s"
                % (bc, self.stall_secs, inflight, job)
            )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sock", required=True)
    ap.add_argument("--timeout", type=float, default=28800)
    ap.add_argument("--expect-bytes", type=int, default=EXPECT_BYTES)
    ap.add_argument("--job-id", default=os.environ.get("JOB_ID") or "", help="poll this job_id; else newest running")
    ap.add_argument(
        "--stall-secs",
        "--stall-s",
        type=float,
        default=float(os.environ.get("POLL_JOB_STALL_S", "180")),
        dest="stall_secs",
        help="STALL if bytes_committed frozen with inflight>0 (default 180; 0 disables). "
        "inflight=0 and empty last_err is digest verify (keep waiting)",
    )
    args = ap.parse_args()
    sock = Path(args.sock)
    if not sock.exists():
        raise SystemExit("missing helper socket %s" % sock)
    job_id = args.job_id or None
    stall = DigestAwareStallTracker(args.stall_secs)
    t0 = time.time()
    job = {}
    while time.time() - t0 < args.timeout:
        params = [job_id] if job_id else []
        jobs = rpc(sock, "getmodeljob", params, 120)
        job = pick_newest_running(jobs, job_id=job_id)
        if job:
            st = job.get("status")
            print(
                "job",
                job.get("job_id") or "",
                st,
                "elapsed",
                int(time.time() - t0),
                "used_bytes",
                jobs.get("used_bytes") if isinstance(jobs, dict) else None,
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
                "created_ms",
                job.get("created_ms"),
                flush=True,
            )
            if st == "failed":
                raise SystemExit("retrieve failed: %s" % job)
            if st == "cancelled":
                raise SystemExit("retrieve cancelled: %s" % job)
            if st == "done":
                break
            stall.observe(job)
        time.sleep(2)
    else:
        raise SystemExit("getmodeljob timeout: %s" % job)
    listed = rpc(sock, "listmodels", [], 30)
    models = listed.get("models") or []
    if not models:
        raise SystemExit("listmodels empty: %s" % listed)
    m = models[0]
    if int(m.get("bytes") or 0) != args.expect_bytes:
        raise SystemExit("bytes %s != %s" % (m.get("bytes"), args.expect_bytes))
    if m.get("seeded") is not True:
        raise SystemExit("not demand-seeded: %s" % listed)
    if m.get("content_admission") not in ("BYTES_VERIFIED",) and m.get("bytes_verified") is not True:
        raise SystemExit("admission: %s" % listed)
    print("GRANITE_ATTACH PASS", json.dumps({
        "bytes": m.get("bytes"),
        "seeded": m.get("seeded"),
        "content_admission": m.get("content_admission"),
        "elapsed_poll_s": int(time.time() - t0),
        "job_id": job.get("job_id"),
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
