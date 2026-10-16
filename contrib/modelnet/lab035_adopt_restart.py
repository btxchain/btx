#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""One regtest node adopts a release, restarts, and still reports the prior.

The lab directory is a subdirectory of the journey directory. The second
process uses that same directory and the same datadir. No wallet RPC.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(os.environ["BTX035_JOURNEY_DIR"])
BIN = Path(os.environ["BTX035_BIN"])
BTXD = BIN / "btxd"
CLI = BIN / "btx-cli"
RPC_USER = "lab"
RPC_PASSWORD = "lab-pass-0001"
RPC_PORT = 29720
P2P_PORT = 29820


def hex96(*avoid: str) -> str:
    while True:
        value = secrets.token_hex(48)
        if value not in avoid:
            return value


def rpc(datadir: Path, *args: str) -> dict:
    proc = subprocess.run(
        [str(CLI), "-regtest", f"-datadir={datadir}", f"-rpcport={RPC_PORT}",
         f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASSWORD}", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
    return json.loads(proc.stdout) if proc.stdout.strip() else {}


def lab(datadir: Path, method: str, body: dict) -> dict:
    return rpc(datadir, "lab035", method, json.dumps(body))


def start(datadir: Path) -> subprocess.Popen:
    datadir.mkdir(parents=True, exist_ok=True)
    log = open(datadir / "stdout.log", "a")
    proc = subprocess.Popen(
        [
            str(BTXD), "-regtest", f"-datadir={datadir}", f"-port={P2P_PORT}",
            f"-rpcport={RPC_PORT}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
            f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASSWORD}",
            "-bind=127.0.0.1", "-listen=1", "-server=1", "-dnsseed=0", "-fixedseeds=0",
            "-listenonion=0", "-daemon=0", "-nomodelnet",
        ],
        stdout=log, stderr=subprocess.STDOUT,
    )
    deadline = time.time() + 40
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("btxd exited")
        try:
            rpc(datadir, "getblockchaininfo")
            return proc
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("btxd did not answer")


def halt(datadir: Path, proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        rpc(datadir, "stop")
    except Exception:
        proc.terminate()
    proc.wait(timeout=30)


def lineage_ids(datadir: Path, release_id: str) -> list:
    found = lab(datadir, "lab.agent_lineage", {
        "release_id": release_id,
        "max_depth": 8,
        "cursor": None,
        "limit": 8,
    })
    ids = found["result"].get("record_ids") or []
    if not isinstance(ids, list):
        raise RuntimeError("reloaded node has no lineage")
    return ids


def main() -> int:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir()
    lab_dir = ROOT / "lab"
    lab_dir.mkdir()
    os.environ["BTX035_LAB_DIR"] = str(lab_dir)
    datadir = ROOT / "node"
    proc = None
    try:
        proc = start(datadir)
        created = lab(datadir, "lab.identity_create", {
            "label": "adopt-restart",
            "recovery_key_ids": [],
            "recovery_threshold": 1,
            "recovery_delay_ms": "0",
            "idempotency_key": "identity-create-0001",
            "expected_state": None,
        })
        identity_id = created["result"]["record_id"]
        if created["result"]["state"] != "ACTIVE" or len(identity_id) != 96:
            raise RuntimeError("identity was not created")

        intent_id = hex96(identity_id)
        prepared = lab(datadir, "lab.action_prepare", {
            "intent_id": intent_id,
            "idempotency_key": "action-prepare-0001",
            "expected_state": None,
        })
        bearer = prepared["result"].get("one_use_permit") or ""
        if not bearer or prepared["result"]["state"] != "PREPARED":
            raise RuntimeError("action_prepare did not grant")

        evaluation_id = hex96(identity_id, intent_id)
        topic_id = hex96(identity_id, intent_id, evaluation_id)
        published = lab(datadir, "lab.research_publish", {
            "record_id": evaluation_id,
            "topic_ids": [topic_id],
            "visibility": "REPRODUCED",
            "idempotency_key": "research-publish-0001",
            "expected_state": None,
        })
        if published["result"]["state"] != "PUBLISHED" or published["result"]["record_id"] != evaluation_id:
            raise RuntimeError("research record was not stored")

        release_id = hex96(identity_id, intent_id, evaluation_id, topic_id)
        prior_release_id = hex96(identity_id, intent_id, evaluation_id, topic_id, release_id)
        adopted = lab(datadir, "lab.agent_adopt", {
            "release_id": release_id,
            "prior_release_id": prior_release_id,
            "grant_id": intent_id,
            "evaluation_ids": [evaluation_id],
            "idempotency_key": "agent-adopt-0001",
            "expected_state": None,
        })
        if adopted["result"]["state"] != "COMPLETE":
            raise RuntimeError("agent_adopt did not complete")

        repeated = lab(datadir, "lab.agent_adopt", {
            "release_id": release_id,
            "prior_release_id": prior_release_id,
            "grant_id": intent_id,
            "evaluation_ids": [evaluation_id],
            "idempotency_key": "agent-adopt-0002",
            "expected_state": None,
        })
        if repeated["result"]["state"] == "COMPLETE":
            if prior_release_id not in lineage_ids(datadir, release_id):
                raise RuntimeError("lineage did not return the prior release")
            denied = lab(datadir, "lab.agent_adopt", {
                "release_id": release_id,
                "prior_release_id": prior_release_id,
                "grant_id": identity_id,
                "evaluation_ids": [evaluation_id],
                "idempotency_key": "agent-adopt-secret1",
                "expected_state": None,
            })
            if denied["result"]["state"] != "FAILED":
                raise RuntimeError("identity secret grant was not refused")

        halt(datadir, proc)
        proc = None
        proc = start(datadir)
        if prior_release_id not in lineage_ids(datadir, release_id):
            raise RuntimeError("reloaded node has no lineage")
        print("PASS")
        return 0
    finally:
        if proc is not None:
            halt(datadir, proc)


if __name__ == "__main__":
    raise SystemExit(main())
