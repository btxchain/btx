#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Deterministic REGTEST ONLY job runner.

This process never executes a command, prompt, model card, or downloaded file.
Production job classes are refused.
"""

from __future__ import annotations

import hashlib
import json
import sys

FORBIDDEN = {
    "command", "shell", "exec", "argv", "url", "download", "script", "eval", "prompt",
}


def commit(input_commitment: str) -> str:
    return hashlib.sha256(b"BTX/PWC/regtest-job/v1" + input_commitment.encode()).hexdigest()


def run(job: dict) -> dict:
    if not isinstance(job, dict):
        raise SystemExit("COMPUTE_RESULT_INVALID")
    extra = FORBIDDEN.intersection(job)
    if extra:
        raise SystemExit("COMPUTE_RESULT_INVALID: " + ",".join(sorted(extra)))
    if job.get("job_class") != "REGTEST_DETERMINISTIC":
        raise SystemExit("COMPUTE_RECORD_INVALID: only REGTEST_DETERMINISTIC is built in")
    raw = job.get("input_commitment")
    if not isinstance(raw, str) or not raw or len(raw) > 4096:
        raise SystemExit("COMPUTE_RECORD_INVALID: input_commitment")
    return {
        "job_class": "REGTEST_DETERMINISTIC",
        "test_only": True,
        "output_commitment": commit(raw),
        "note": "REGTEST TEST ONLY. This is not production inference.",
    }


def main() -> None:
    raw = sys.stdin.read() if len(sys.argv) == 1 else open(sys.argv[1], encoding="utf-8").read()
    print(json.dumps(run(json.loads(raw)), sort_keys=True))


if __name__ == "__main__":
    main()
