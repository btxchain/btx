#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Train the frozen CPU launch decoder, then a later process admits it.

Two identities each run the 1,024-step profile. A mirror pulls the snapshot
after the author exits. One replay root is refused. A copied lab directory
with a changed data cursor does not audit. A fresh grant adopts N+1, keeps N,
and a continuation produces N+2. The regtest nodes pass -nomodelnet so this
journey does not start a second GPU helper. No wallet RPC.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(os.environ.get("BTX035_JOURNEY_DIR", Path.cwd() / "lab035-launch"))
BIN = Path(os.environ["BTX035_BIN"])
BTXD = BIN / "btxd"
CLI = BIN / "btx-cli"
RPC_USER = "lab"
RPC_PASSWORD = "lab-pass-0001"
PROFILE = "BTX035-LAUNCH-DECODER-2x64"


def fail(body) -> None:
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            body = {"error": body}
    print(json.dumps(body))
    raise SystemExit(1)


def invoke(datadir: Path, port: int, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(CLI), "-regtest", f"-datadir={datadir}", f"-rpcport={port}",
         f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASSWORD}", *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True,
    )


def rpc(datadir: Path, port: int, *args: str) -> dict:
    proc = invoke(datadir, port, *args)
    text = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        fail(text.strip() or "RPC failed")
    if not proc.stdout.strip():
        fail({"error": "empty RPC response"})
    body = json.loads(proc.stdout)
    if not isinstance(body, dict):
        fail({"error": "RPC response was not an object"})
    return body


def lab(datadir: Path, port: int, method: str, request: dict) -> dict:
    try:
        return rpc(datadir, port, "lab035", method, json.dumps(request))
    except SystemExit:
        print("failed " + method, flush=True)
        raise


def start(name: str, rpcport: int, p2pport: int, labdir: Path) -> tuple[Path, int, subprocess.Popen]:
    datadir = ROOT / name
    if datadir.exists():
        shutil.rmtree(datadir)
    datadir.mkdir(parents=True)
    labdir.mkdir(parents=True, exist_ok=True)
    log = open(datadir / "stdout.log", "w")
    env = os.environ.copy()
    env["BTX035_LAB_DIR"] = str(labdir.resolve())
    env.pop("BTX035_BUNDLE_DIR", None)
    env.pop("BTX035_LAB_PEER", None)
    env.pop("BTX035_LAB_PEERS", None)
    proc = subprocess.Popen(
        [
            str(BTXD), "-regtest", f"-datadir={datadir}", f"-port={p2pport}",
            f"-rpcport={rpcport}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
            f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASSWORD}",
            "-bind=127.0.0.1", "-listen=1", "-server=1", "-dnsseed=0", "-fixedseeds=0",
            "-listenonion=0", "-daemon=0", "-nomodelnet",
        ],
        stdout=log, stderr=subprocess.STDOUT, env=env,
    )
    try:
        deadline = time.time() + 40
        while time.time() < deadline:
            if proc.poll() is not None:
                fail({"error": name + " exited", "log": (datadir / "stdout.log").read_text()[-2000:]})
            probe = invoke(datadir, rpcport, "getblockchaininfo")
            if probe.returncode != 0 or not probe.stdout.strip():
                time.sleep(0.2)
                continue
            info = json.loads(probe.stdout)
            if info.get("chain") != "regtest":
                fail(info)
            return datadir, rpcport, proc
        fail({"error": name + " did not answer"})
    except SystemExit:
        stop_node(datadir, rpcport, proc)
        raise


def stop_node(datadir: Path, port: int, proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        try:
            invoke(datadir, port, "stop")
        except Exception:
            proc.terminate()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=30)


def result_of(body: dict) -> dict:
    result = body.get("result")
    if not isinstance(result, dict):
        fail(body)
    return result


def require_state(body: dict, state: str) -> dict:
    result = result_of(body)
    if result.get("state") != state:
        fail(body)
    return result


def execute(datadir: Path, port: int, intent: str, idem: str, capsule: str) -> dict:
    prepared = lab(datadir, port, "lab.action_prepare", {
        "intent_id": intent,
        "idempotency_key": "prepare-" + idem,
        "expected_state": None,
    })
    require_state(prepared, "PREPARED")
    ran = lab(datadir, port, "lab.research_execute", {
        "input_capsule_id": capsule,
        "recipe_id": PROFILE,
        "runtime_binding_id": "3" * 96,
        "research_grant_id": "4" * 96,
        "local_capability_grant_id": intent,
        "idempotency_key": "execute-" + idem,
        "expected_state": None,
    })
    row = require_state(ran, "COMPLETE")
    if row.get("profile") != PROFILE or row.get("artifact_digest") in (None, "") or row.get("state_hash") in (None, ""):
        fail(ran)
    if row.get("tokenizer_digest") in (None, "") or row.get("dataset_digest") in (None, ""):
        fail(ran)
    if row.get("next_byte_hits") is None or row.get("miss_mass") is None:
        fail(ran)
    return row


def admit(datadir: Path, port: int, digest: str, evidence: list, idem: str) -> dict:
    return lab(datadir, port, "lab.admission_evaluate", {
        "model_ref": {"digest": digest},
        "policy_id": "e" * 96,
        "evidence_ids": evidence,
        "idempotency_key": idem,
        "expected_state": None,
    })


def main() -> int:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir()
    nodes = []
    try:
        author_dir, author_port, author_proc = start("author", 29360, 29460, ROOT / "author-lab")
        mirror_dir, mirror_port, mirror_proc = start("mirror", 29361, 29461, ROOT / "mirror-lab")
        nodes.extend((
            (author_dir, author_port, author_proc),
            (mirror_dir, mirror_port, mirror_proc),
        ))
        created = lab(author_dir, author_port, "lab.identity_create", {
            "label": "launch-a",
            "recovery_key_ids": [],
            "recovery_threshold": 1,
            "recovery_delay_ms": "1",
            "idempotency_key": "launch-identity-a-001",
            "expected_state": None,
        })
        require_state(created, "ACTIVE")
        first = execute(author_dir, author_port, "1" * 96, "launch-a-0001", "2" * 96)
        created = lab(author_dir, author_port, "lab.identity_create", {
            "label": "launch-b",
            "recovery_key_ids": [],
            "recovery_threshold": 1,
            "recovery_delay_ms": "1",
            "idempotency_key": "launch-identity-b-001",
            "expected_state": None,
        })
        require_state(created, "ACTIVE")
        second = execute(author_dir, author_port, "5" * 96, "launch-b-0001", "2" * 96)
        if first["artifact_digest"] != second["artifact_digest"] or first["state_hash"] != second["state_hash"]:
            fail({"error": "the two runs did not share one trajectory", "first": first, "second": second})
        if first["tokenizer_digest"] == first["dataset_digest"]:
            fail(first)
        digest = first["artifact_digest"]
        trajectory_a = first["operation_id"]
        trajectory_b = second["operation_id"]
        require_state(admit(author_dir, author_port, digest, [trajectory_a], "launch-admit-one"), "FAILED")
        require_state(admit(author_dir, author_port, digest, [trajectory_a, trajectory_b], "launch-admit-two"), "COMPLETE")

        created_repo = lab(author_dir, author_port, "lab.repository_create", {
            "label": "launch",
            "nonce": "launch-repo-nonce",
            "object_format": "git",
            "project_genesis_id": None,
            "default_ref": "refs/heads/main",
            "idempotency_key": "launch-repo-create-001",
            "expected_state": None,
        })
        repository_id = result_of(created_repo).get("repository_id")
        if not isinstance(repository_id, str) or len(repository_id) != 96:
            fail(created_repo)
        require_state(lab(author_dir, author_port, "lab.git_snapshot", {
            "repository_id": repository_id,
            "commit": {"bytes": "launch decoder source\n"},
            "dependency_lock_id": "d" * 96,
            "history_required": False,
            "idempotency_key": "launch-git-snapshot-01",
            "expected_state": None,
        }), "COMPLETE")
        pulled = lab(mirror_dir, mirror_port, "lab.snapshot_pull", {
            "host": "127.0.0.1",
            "port": author_port,
            "rpc_user": RPC_USER,
            "rpc_password": RPC_PASSWORD,
            "repository_id": repository_id,
            "idempotency_key": "mirror-snapshot-pull01",
            "expected_state": None,
        })
        if result_of(pulled).get("repository_id") != repository_id:
            fail(pulled)
        stop_node(author_dir, author_port, author_proc)
        nodes = [(mirror_dir, mirror_port, mirror_proc)]

        corrupt_lab = ROOT / "corrupt-lab"
        shutil.copytree(ROOT / "author-lab", corrupt_lab)
        disk = json.loads((corrupt_lab / "lab.json").read_text())
        row = disk.get("launch_trains", {}).get(trajectory_a)
        if not isinstance(row, dict):
            fail({"error": "launch checkpoint was not on disk", "keys": list(disk.keys())})
        row["cursor"] = str(int(row["cursor"]) + 1)
        (corrupt_lab / "lab.json").write_text(json.dumps(disk))
        corrupt_dir, corrupt_port, corrupt_proc = start("corrupt", 29362, 29462, corrupt_lab)
        nodes.append((corrupt_dir, corrupt_port, corrupt_proc))
        audited = lab(corrupt_dir, corrupt_port, "lab.audit_coverage", {
            "trajectory_id": trajectory_a,
            "policy_id": "e" * 96,
        })
        audit = result_of(audited)
        if audit.get("complete_path") is not False or "BTX035_RNG" not in (audit.get("gaps") or []):
            fail(audited)
        stop_node(corrupt_dir, corrupt_port, corrupt_proc)
        nodes = [(mirror_dir, mirror_port, mirror_proc)]

        acquired = lab(mirror_dir, mirror_port, "lab.artifact_acquire", {
            "resource": {"digest": digest, "repository_id": repository_id},
            "origin_policy_id": "e" * 96,
            "max_bytes": "10000000",
            "destination_class": "LOCAL",
            "idempotency_key": "mirror-acquire-launch1",
            "expected_state": None,
        })
        acquired_row = require_state(acquired, "COMPLETE")
        if acquired_row.get("artifact_digest") != digest:
            fail(acquired)
        for kind, blob in (("tokenizer", first["tokenizer_digest"]), ("dataset", first["dataset_digest"])):
            resolved = lab(mirror_dir, mirror_port, "lab.capsule_resolve", {
                "capsule_id": blob,
                "purpose": "REPLAY",
                "max_bytes": "10000000",
            })
            missing = result_of(resolved).get("missing_refs")
            if missing != []:
                fail({"error": kind + " was not retained", "body": resolved})
        require_state(admit(mirror_dir, mirror_port, digest, [trajectory_a], "mirror-admit-one"), "FAILED")
        require_state(admit(mirror_dir, mirror_port, digest, [trajectory_a, trajectory_b], "mirror-admit-two"), "COMPLETE")

        created = lab(mirror_dir, mirror_port, "lab.identity_create", {
            "label": "launch-reader",
            "recovery_key_ids": [],
            "recovery_threshold": 1,
            "recovery_delay_ms": "1",
            "idempotency_key": "launch-identity-reader",
            "expected_state": None,
        })
        require_state(created, "ACTIVE")
        prepared = lab(mirror_dir, mirror_port, "lab.action_prepare", {
            "intent_id": "a" * 96,
            "idempotency_key": "prepare-adopt-grant1",
            "expected_state": None,
        })
        require_state(prepared, "PREPARED")
        evaluation = "6" * 96
        topic = "7" * 96
        published = lab(mirror_dir, mirror_port, "lab.research_publish", {
            "record_id": evaluation,
            "topic_ids": [topic],
            "visibility": "REPRODUCED",
            "idempotency_key": "launch-publish-eval-01",
            "expected_state": None,
        })
        if result_of(published).get("state") != "PUBLISHED":
            fail(published)
        release = "8" * 96
        adopted = lab(mirror_dir, mirror_port, "lab.agent_adopt", {
            "release_id": release,
            "prior_release_id": trajectory_a,
            "grant_id": "a" * 96,
            "evaluation_ids": [evaluation],
            "idempotency_key": "launch-adopt-0001",
            "expected_state": None,
        })
        require_state(adopted, "COMPLETE")
        lineage = lab(mirror_dir, mirror_port, "lab.agent_lineage", {
            "release_id": release,
            "max_depth": 4,
            "cursor": None,
            "limit": 8,
        })
        ids = result_of(lineage).get("record_ids") or []
        if trajectory_a not in ids:
            fail(lineage)
        continued = execute(mirror_dir, mirror_port, "9" * 96, "launch-n2-0001", trajectory_a)
        if continued["previous_state"] != first["state_hash"] or continued["state_hash"] == first["state_hash"]:
            fail(continued)
        if continued["artifact_digest"] == digest:
            fail({"error": "the continuation replaced the parent artifact", "body": continued})
        still = lab(mirror_dir, mirror_port, "lab.capsule_resolve", {
            "capsule_id": digest,
            "purpose": "REPLAY",
            "max_bytes": "10000000",
        })
        if result_of(still).get("missing_refs") != []:
            fail({"error": "parent model was dropped", "body": still})
        print("PASS")
        return 0
    finally:
        for datadir, port, proc in nodes:
            try:
                stop_node(datadir, port, proc)
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
