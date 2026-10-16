#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Drive git-lfs-btx as a subprocess over newline-delimited JSON."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
import traceback
from pathlib import Path

HELPER = Path(__file__).resolve().parent / "git-lfs-btx"
ROOT = Path(__file__).resolve().parents[3] / "test-data" / "git-lfs"
STATE = ROOT / "state"


def assert_true(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)


def run_helper(script: str, state: Path = STATE) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, str(HELPER), str(state)],
        input=script.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(ROOT),
        check=False,
    )
    return proc.returncode, proc.stdout.decode("utf-8"), proc.stderr.decode("utf-8")


def events(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        if line == "":
            continue
        out.append(json.loads(line))
    return out


def test_helper_does_not_shell() -> None:
    source = HELPER.read_text(encoding="utf-8")
    for banned in ("os.system", "shell=True"):
        assert_true(banned not in source, f"helper contains {banned}")
    assert_true(HELPER.stat().st_mode & 0o111, "helper is not executable")


def test_upload_download_and_rejects() -> None:
    payload = b"btx-lfs-payload-v1"
    oid = hashlib.sha256(payload).hexdigest()
    digest384 = hashlib.sha384(payload).hexdigest()
    encoded = base64.b64encode(payload).decode("ascii")
    bad_oid = ("0" if oid[0] != "0" else "1") + oid[1:]

    script = "\n".join(
        [
            json.dumps({"event": "init", "operation": "upload"}),
            json.dumps(
                {
                    "event": "upload",
                    "oid": bad_oid,
                    "size": len(payload),
                    "sha384": digest384,
                    "bytes": encoded,
                }
            ),
            json.dumps(
                {
                    "event": "upload",
                    "oid": oid,
                    "size": len(payload) + 1,
                    "sha384": digest384,
                    "bytes": encoded,
                }
            ),
            json.dumps(
                {
                    "event": "upload",
                    "oid": oid,
                    "size": len(payload),
                    "sha384": digest384,
                    "bytes": encoded,
                    "path": "objects/payload.bin",
                }
            ),
            json.dumps({"event": "download", "oid": oid, "size": len(payload), "path": "objects/payload.bin"}),
            json.dumps({"event": "upload", "oid": oid, "size": len(payload), "sha384": digest384, "bytes": encoded, "path": "/etc/passwd"}),
            json.dumps({"event": "download", "oid": oid, "size": len(payload), "path": "../escape"}),
            json.dumps({"event": "terminate"}),
        ]
    ) + "\n"
    code, out, err = run_helper(script)
    assert_true(code == 0, f"exit {code} stderr={err!r} stdout={out!r}")
    assert_true(err == "", err)
    parsed = events(out)
    assert_true(parsed[0] == {"event": "init"}, parsed)
    assert_true(parsed[1]["event"] == "error", parsed[1])
    assert_true(parsed[1]["error"]["code"] == "BTX035_DIGEST", parsed[1])
    assert_true(parsed[2]["event"] == "error", parsed[2])
    assert_true(parsed[2]["error"]["code"] == "BTX035_SIZE", parsed[2])
    assert_true(parsed[3]["event"] == "complete" and parsed[3]["oid"] == oid, parsed[3])
    downloaded = base64.b64decode(parsed[4]["bytes"], validate=True)
    assert_true(downloaded == payload, parsed[4])
    assert_true(parsed[4]["sha384"] == digest384, parsed[4])
    assert_true(parsed[5]["event"] == "error" and parsed[5]["error"]["code"] == "BTX035_PATH", parsed[5])
    assert_true(parsed[6]["event"] == "error" and parsed[6]["error"]["code"] == "BTX035_PATH", parsed[6])
    assert_true(parsed[7] == {"event": "terminate"}, parsed)
    stored = STATE / oid
    assert_true(stored.is_file(), "oid file missing")
    assert_true(stored.read_bytes() == payload, "stored bytes diverged")
    assert_true(not (STATE / bad_oid).exists(), "bad oid was stored")
    assert_true(not (ROOT / "escape").exists(), "escape path was written")
    assert_true(not (STATE / "objects").exists(), "request path was used as storage")
    names = sorted(path.name for path in STATE.iterdir())
    assert_true(names == [oid], names)


def main() -> int:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir(parents=True)
    STATE.mkdir()
    code = 0
    try:
        test_helper_does_not_shell()
        test_upload_download_and_rejects()
        print("PASS")
    except Exception as exc:
        traceback.print_exc()
        print(f"FAIL {exc}", file=sys.stderr)
        code = 1
    finally:
        shutil.rmtree(ROOT, ignore_errors=True)
        if ROOT.exists():
            print(f"FAIL leftover {ROOT}", file=sys.stderr)
            code = 1
    return code


if __name__ == "__main__":
    raise SystemExit(main())
