#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Two local regtest nodes. A publishes a snapshot. B pulls it and checks the bytes.

The Git origin directory is removed before B verifies. Neither node spends a wallet.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(os.environ.get("BTX035_JOURNEY_DIR", Path.cwd() / "lab035-independent"))
BIN = Path(os.environ["BTX035_BIN"])
BTXD = BIN / "btxd"
CLI = BIN / "btx-cli"
RPC_USER = "lab"
RPC_PASSWORD = "lab-pass-0001"


def rpc(datadir: Path, port: int, *args: str) -> dict:
    proc = subprocess.run(
        [str(CLI), "-regtest", f"-datadir={datadir}", f"-rpcport={port}",
         f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASSWORD}", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
    return json.loads(proc.stdout) if proc.stdout.strip() else {}


def start(name: str, index: int) -> tuple[Path, int, subprocess.Popen]:
    datadir = ROOT / name
    datadir.mkdir(parents=True)
    rpcport = 29300 + index
    log = open(datadir / "stdout.log", "w")
    proc = subprocess.Popen(
        [
            str(BTXD), "-regtest", f"-datadir={datadir}", f"-port={29400 + index}",
            f"-rpcport={rpcport}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
            f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASSWORD}",
            "-bind=127.0.0.1", "-listen=1", "-server=1", "-dnsseed=0", "-fixedseeds=0", "-daemon=0",
        ],
        stdout=log, stderr=subprocess.STDOUT,
    )
    deadline = time.time() + 40
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{name} exited")
        try:
            rpc(datadir, rpcport, "getblockchaininfo")
            return datadir, rpcport, proc
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"{name} did not answer")


def main() -> int:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir()
    nodes = []
    origin = ROOT / "origin"
    try:
        origin.mkdir()
        (origin / "README").write_text("independent source\n", encoding="utf-8")
        nodes.append(("a", *start("a", 0)))
        nodes.append(("b", *start("b", 1)))
        _a_name, a_dir, a_port, _a_proc = nodes[0]
        _b_name, b_dir, b_port, _b_proc = nodes[1]
        created = rpc(a_dir, a_port, "lab035", "lab.repository_create", json.dumps({
            "label": "independent", "nonce": "n1", "object_format": "git",
            "project_genesis_id": None, "default_ref": "refs/heads/main",
            "idempotency_key": "independent-repo-1", "expected_state": None,
        }))
        repo = created["result"]["repository_id"]
        rpc(a_dir, a_port, "lab035", "lab.git_snapshot", json.dumps({
            "repository_id": repo, "commit": {"bytes": "independent source\n"}, "dependency_lock_id": "lock",
            "history_required": False, "idempotency_key": "independent-snap-1", "expected_state": None,
        }))
        shutil.rmtree(origin)
        if origin.exists():
            raise RuntimeError("origin was not removed")
        pulled = rpc(b_dir, b_port, "lab035", "lab.snapshot_pull", json.dumps({
            "host": "127.0.0.1", "port": a_port, "rpc_user": RPC_USER, "rpc_password": RPC_PASSWORD,
            "repository_id": repo, "idempotency_key": "independent-pull-1", "expected_state": None,
        }))
        manifest = pulled["result"]["manifest"]
        if "independent source" not in manifest:
            raise RuntimeError("pull did not retain the source")
        retained = rpc(b_dir, b_port, "lab035", "lab.snapshot_export", json.dumps({
            "repository_id": repo, "idempotency_key": "independent-export-b", "expected_state": None,
        }))
        if retained["result"]["manifest"] != manifest:
            raise RuntimeError("node B did not keep the pulled manifest")
        bad = json.loads(manifest)
        bad["objects"][0]["content"] = "replaced"
        refused = subprocess.run(
            [str(CLI), "-regtest", f"-datadir={b_dir}", f"-rpcport={b_port}",
             f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASSWORD}",
             "lab035", "lab.snapshot_import",
             json.dumps({"manifest": json.dumps(bad), "idempotency_key": "independent-import-2", "expected_state": None})],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        if "BTX035_ID_MISMATCH" not in refused.stderr + refused.stdout:
            raise RuntimeError(refused.stderr or refused.stdout)
        print("PASS")
        return 0
    finally:
        for _name, datadir, port, proc in nodes:
            try:
                rpc(datadir, port, "stop")
            except Exception:
                proc.terminate()
            proc.wait(timeout=30)


if __name__ == "__main__":
    raise SystemExit(main())
