#!/usr/bin/env python3
"""Fail-fast helpers for modeld e2e. Stop polling once a failure is already known."""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Callable, Optional

LOG_FATAL = (
    "unknown argument",
    "model subsystem fail-closed",
    "invalid -model",
    "terminate called",
    "Aborted (",
)


def pid_alive(pid: Optional[int]) -> bool:
    if not pid:
        return True
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


def log_tail(log: Optional[Path], n: int = 4000) -> str:
    if not log:
        return ""
    p = Path(log)
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")[-n:]


def helper_fatal(proc=None, pid: Optional[int] = None, log: Optional[Path] = None) -> Optional[str]:
    if proc is not None and proc.poll() is not None:
        return f"helper exited rc={proc.returncode}\n{log_tail(log)}"
    if pid and not pid_alive(pid):
        return f"helper pid {pid} is gone\n{log_tail(log)}"
    txt = log_tail(log, 8000)
    for needle in LOG_FATAL:
        if needle in txt:
            return f"helper log contains {needle!r}\n{txt[-2000:]}"
    return None


def wait_unix(
    connect: Callable[[], Any],
    *,
    timeout: float = 20.0,
    interval: float = 0.1,
    proc=None,
    pid: Optional[int] = None,
    log: Optional[Path] = None,
):
    """Retry connect() until it returns non-None. Abort at once if the helper is already dead."""
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        fatal = helper_fatal(proc=proc, pid=pid, log=log)
        if fatal:
            raise SystemExit(fatal)
        try:
            info = connect()
            if info is not None:
                return info
        except Exception as e:
            last = e
        time.sleep(interval)
    raise SystemExit(f"helper not ready in {timeout}s last={last}\n{log_tail(log)}")


def pick_job(raw: Any, job_id: Optional[str] = None) -> dict:
    """Select one getmodeljob entry.

    Honor job_id when set. Otherwise prefer a running job so a stale
    failed jobs[0] (helper stores jobs in std::map / lex order) cannot
    mask the live retrieve. Newest running = last running in the array.
    """
    arr: list = []
    if isinstance(raw, dict):
        arr = raw.get("jobs") or []
        if not arr and raw.get("status"):
            if job_id and raw.get("job_id") and str(raw.get("job_id")) != str(job_id):
                return {}
            return raw
    elif isinstance(raw, list):
        arr = raw
    if not arr:
        return {}
    if job_id:
        want = str(job_id)
        for j in arr:
            if isinstance(j, dict) and str(j.get("job_id")) == want:
                return j
        return {}
    running = [j for j in arr if isinstance(j, dict) and j.get("status") == "running"]
    if running:
        running.sort(
            key=lambda j: (int(j.get("created_ms") or 0), str(j.get("job_id") or "")),
            reverse=True,
        )
        return running[0]
    done = [j for j in arr if isinstance(j, dict) and j.get("status") == "done"]
    if done:
        done.sort(
            key=lambda j: (int(j.get("created_ms") or 0), str(j.get("job_id") or "")),
            reverse=True,
        )
        return done[0]
    last = arr[-1]
    return last if isinstance(last, dict) else {}


class BytesStallTracker:
    """Fail-fast when bytes_committed is present and frozen while status=running."""

    def __init__(self, stall_s: float = 120.0):
        self.stall_s = float(stall_s)
        self._seen = False
        self._last: Any = None
        self._t = time.time()

    def observe(self, job: dict) -> None:
        if self.stall_s <= 0 or not isinstance(job, dict):
            return
        if job.get("status") != "running":
            return
        inflight = job.get("inflight")
        try:
            inflight_n = int(inflight) if inflight is not None else -1
        except (TypeError, ValueError):
            inflight_n = -1
        # inflight==0 is typically VerifyFileDigest at a shard boundary, not a stall.
        if inflight_n == 0:
            self._seen = True
            self._last = job.get("bytes_committed")
            self._t = time.time()
            return
        if "bytes_committed" not in job:
            return
        bc = job.get("bytes_committed")
        now = time.time()
        if not self._seen or bc != self._last:
            self._seen = True
            self._last = bc
            self._t = now
            return
        if now - self._t >= self.stall_s:
            raise SystemExit(
                f"getmodeljob stalled: bytes_committed={bc} unchanged for {self.stall_s}s "
                f"while status=running: {job}"
            )


def poll_job(
    fetch: Callable[[], Any],
    *,
    timeout: float,
    interval: float = 0.2,
    progress: Optional[Callable[[Any], None]] = None,
    stall_s: float = 120.0,
    job_id: Optional[str] = None,
) -> dict:
    """Poll getmodeljob. status=failed/cancelled exits immediately (no remaining timeout).

    If bytes_committed is present and unchanged for stall_s (default 120)
    while status=running, fail-fast. last_err while running is resume, not FAIL.
    """
    t0 = time.time()
    job: dict = {}
    stall = BytesStallTracker(stall_s)
    while time.time() - t0 < timeout:
        raw = fetch()
        job = pick_job(raw, job_id=job_id)
        if job:
            st = job.get("status")
            if progress:
                progress(job)
            if st == "failed":
                raise SystemExit(f"retrieve failed: {job}")
            if st == "cancelled":
                raise SystemExit(f"retrieve cancelled: {job}")
            if st == "done":
                return job
            stall.observe(job)
        time.sleep(interval)
    raise SystemExit(f"getmodeljob timeout: {job}")
