#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Two regtest btxd processes: author and peer.

The author signs a negative result, a hypothesis informed by that result, and
an activity announcement, then publishes each record. The peer pulls the
author snapshot, runs the integer profile under a local grant, and publishes
a reproduction. No wallet RPC.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

ROLES = (
    ("author", 29910, 29920),
    ("peer", 29911, 29921),
)

ROOT = Path(os.environ.get("BTX035_JOURNEY_DIR", Path.cwd() / "lab035-peer-research"))
BIN = Path(os.environ["BTX035_BIN"])
BTXD = BIN / "btxd"
CLI = BIN / "btx-cli"
RPC_USER = "lab"
RPC_PASSWORD = "lab-pass-0001"
OBJECTIVE = "a" * 96
PARENT = "b" * 96
TOPIC = "c" * 96
RECIPE = "INTEGER_LINEAR"


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
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )


def rpc(datadir: Path, port: int, *args: str) -> dict:
    proc = invoke(datadir, port, *args)
    text = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        fail(text.strip() or "RPC failed")
    if not proc.stdout.strip():
        fail({"error": "empty RPC response", "method": args[0] if args else ""})
    try:
        body = json.loads(proc.stdout)
    except json.JSONDecodeError:
        fail(proc.stdout.strip())
    if not isinstance(body, dict):
        fail({"error": "RPC response was not an object", "body": body})
    return body


def lab(datadir: Path, port: int, method: str, request: dict) -> dict:
    return rpc(datadir, port, "lab035", method, json.dumps(request))


def start(name: str, rpcport: int, p2pport: int) -> tuple[str, Path, int, subprocess.Popen]:
    datadir = ROOT / name
    datadir.mkdir(parents=True)
    labdir = datadir / "lab"
    labdir.mkdir()
    log = open(datadir / "stdout.log", "w")
    env = os.environ.copy()
    env["BTX035_LAB_DIR"] = str(labdir.resolve())
    env.pop("BTX035_BUNDLE_DIR", None)
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
                fail({"error": name + " exited"})
            probe = invoke(datadir, rpcport, "getblockchaininfo")
            if probe.returncode != 0 or not probe.stdout.strip():
                time.sleep(0.2)
                continue
            try:
                info = json.loads(probe.stdout)
            except json.JSONDecodeError:
                time.sleep(0.2)
                continue
            if info.get("chain") != "regtest":
                fail(info)
            return name, datadir, rpcport, proc
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


def sign_and_import(datadir: Path, port: int, realm_id: str, record_type: str, payload: dict, idem: str) -> str:
    signed = lab(datadir, port, "lab.identity_sign", {
        "record_type": record_type,
        "payload": payload,
        "realm_id": realm_id,
        "delegation_id": None,
        "expires_ms": "10",
        "idempotency_key": idem,
        "expected_state": None,
    })
    envelope = result_of(signed).get("envelope")
    if not isinstance(envelope, dict):
        fail(signed)
    record_id = envelope.get("record_id")
    if not isinstance(record_id, str) or len(record_id) != 96:
        fail(signed)
    stored = lab(datadir, port, "lab.record_import", {
        "envelope": envelope,
        "publish": False,
        "idempotency_key": "import-" + idem,
        "expected_state": None,
    })
    imported = require_state(stored, "STORED")
    if imported.get("record_id") != record_id:
        fail(stored)
    return record_id


def contribution(kind: str, informed_by: list, summary: str, physical_parent_ids: list) -> dict:
    return {
        "objective_id": OBJECTIVE,
        "kind": kind,
        "source_snapshot_id": None,
        "physical_parent_ids": physical_parent_ids,
        "informed_by": informed_by,
        "capsule_id": None,
        "claim_refs": [],
        "evidence_refs": [],
        "summary": summary,
    }


def publish(datadir: Path, port: int, record_id: str, idem: str) -> None:
    published = lab(datadir, port, "lab.research_publish", {
        "record_id": record_id,
        "topic_ids": [TOPIC],
        "visibility": "PUBLIC",
        "idempotency_key": idem,
        "expected_state": None,
    })
    row = require_state(published, "PUBLISHED")
    if row.get("record_id") != record_id:
        fail(published)


def edge_count(result: dict, coverage: dict):
    if "informed_edges" in result:
        raw = result["informed_edges"]
    elif "informed_edges" in coverage:
        raw = coverage["informed_edges"]
    else:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float) and raw == int(raw):
        return int(raw)
    if isinstance(raw, str) and raw.isdigit():
        return int(raw)
    if isinstance(raw, list):
        return len(raw)
    return None


def require_context(body: dict, present: list, absent: list) -> None:
    result = result_of(body)
    ids = result.get("record_ids")
    if not isinstance(ids, list) or any(not isinstance(item, str) for item in ids):
        fail(body)
    for item in present:
        if item not in ids:
            fail(body)
    for item in absent:
        if item in ids:
            fail(body)
    coverage = result.get("coverage")
    if not isinstance(coverage, dict) or "selection_is_proof" not in coverage:
        fail(body)
    if coverage["selection_is_proof"] is not False:
        fail(body)
    count = edge_count(result, coverage)
    if count is None or count < 1:
        fail(body)


def context(datadir: Path, port: int, root_id: str) -> dict:
    return lab(datadir, port, "lab.research_context", {
        "root_ids": [root_id],
        "relations": ["INFORMED_BY"],
        "max_depth": 4,
        "max_records": 32,
    })


def main() -> int:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir()
    nodes = []
    try:
        for name, rpcport, p2pport in ROLES:
            nodes.append(start(name, rpcport, p2pport))
        _aname, author_dir, author_port, _aproc = nodes[0]
        _pname, peer_dir, peer_port, _pproc = nodes[1]

        created = lab(author_dir, author_port, "lab.identity_create", {
            "label": "author",
            "recovery_key_ids": [],
            "recovery_threshold": 1,
            "recovery_delay_ms": "1",
            "idempotency_key": "author-identity-0001",
            "expected_state": None,
        })
        require_state(created, "ACTIVE")

        realm = lab(author_dir, author_port, "lab.realm_create", {
            "name": "author",
            "nonce": "author-realm-nonce-1",
            "policy_template": "local",
            "idempotency_key": "author-realm-create-01",
            "expected_state": None,
        })
        realm_id = result_of(realm).get("realm_id", "")
        if not isinstance(realm_id, str) or len(realm_id) != 96:
            fail(realm)

        negative_id = sign_and_import(
            author_dir, author_port, realm_id, "ResearchContribution",
            contribution("NEGATIVE_RESULT", [], "This direction failed.", []),
            "sign-negative-00001",
        )
        if PARENT == negative_id:
            fail({"error": "physical parent collided with the negative result", "record_id": negative_id})
        publish(author_dir, author_port, negative_id, "publish-negative-0001")

        hypothesis_id = sign_and_import(
            author_dir, author_port, realm_id, "ResearchContribution",
            contribution(
                "HYPOTHESIS",
                [negative_id],
                "This branch uses the failed direction as evidence and does not merge it.",
                [PARENT],
            ),
            "sign-hypothesis-0001",
        )
        if hypothesis_id in (negative_id, PARENT):
            fail({"error": "hypothesis id collided", "record_id": hypothesis_id})
        publish(author_dir, author_port, hypothesis_id, "publish-hypothesis-001")

        announcement_id = sign_and_import(
            author_dir, author_port, realm_id, "ActivityAnnouncement",
            {
                "objective_id": OBJECTIVE,
                "base_contribution_ids": [hypothesis_id],
                "intent": "A peer can reproduce this branch.",
                "expires_ms": "10",
                "collaboration": "OPEN",
                "contact_binding_id": None,
            },
            "sign-announce-000001",
        )
        if announcement_id in (negative_id, hypothesis_id):
            fail({"error": "announcement id collided", "record_id": announcement_id})
        publish(author_dir, author_port, announcement_id, "publish-announce-00001")

        author_context = context(author_dir, author_port, hypothesis_id)
        require_context(author_context, [hypothesis_id, negative_id], [announcement_id])

        created_repo = lab(author_dir, author_port, "lab.repository_create", {
            "label": "peer-research",
            "nonce": "peer-research-nonce",
            "object_format": "git",
            "project_genesis_id": None,
            "default_ref": "refs/heads/main",
            "idempotency_key": "author-repo-create-001",
            "expected_state": None,
        })
        repository_id = result_of(created_repo).get("repository_id")
        if not isinstance(repository_id, str) or len(repository_id) != 96:
            fail(created_repo)
        snapped = lab(author_dir, author_port, "lab.git_snapshot", {
            "repository_id": repository_id,
            "commit": {"bytes": "peer research source\n"},
            "dependency_lock_id": "lock",
            "history_required": False,
            "idempotency_key": "author-git-snapshot-01",
            "expected_state": None,
        })
        require_state(snapped, "COMPLETE")

        pulled = lab(peer_dir, peer_port, "lab.snapshot_pull", {
            "host": "127.0.0.1",
            "port": author_port,
            "rpc_user": RPC_USER,
            "rpc_password": RPC_PASSWORD,
            "repository_id": repository_id,
            "idempotency_key": "peer-snapshot-pull-001",
            "expected_state": None,
        })
        pulled_result = result_of(pulled)
        manifest = pulled_result.get("manifest")
        if pulled_result.get("repository_id") != repository_id or not isinstance(manifest, str):
            fail(pulled)
        if negative_id not in manifest or hypothesis_id not in manifest:
            fail(pulled)

        peer_context = context(peer_dir, peer_port, hypothesis_id)
        require_context(peer_context, [hypothesis_id, negative_id], [announcement_id])

        intent = "1" * 96
        prepared = lab(peer_dir, peer_port, "lab.action_prepare", {
            "intent_id": intent,
            "idempotency_key": "peer-grant-prepare-01",
            "expected_state": None,
        })
        require_state(prepared, "PREPARED")
        executed = lab(peer_dir, peer_port, "lab.research_execute", {
            "input_capsule_id": "2" * 96,
            "recipe_id": RECIPE,
            "runtime_binding_id": "3" * 96,
            "research_grant_id": "4" * 96,
            "local_capability_grant_id": intent,
            "idempotency_key": "peer-research-exec-01",
            "expected_state": None,
        })
        require_state(executed, "COMPLETE")

        identified = lab(peer_dir, peer_port, "lab.identity_create", {
            "label": "peer",
            "recovery_key_ids": [],
            "recovery_threshold": 1,
            "recovery_delay_ms": "1",
            "idempotency_key": "peer-identity-create1",
            "expected_state": None,
        })
        require_state(identified, "ACTIVE")
        reproduction_id = sign_and_import(
            peer_dir, peer_port, realm_id, "ResearchContribution",
            contribution(
                "REPRODUCTION",
                [hypothesis_id],
                "This reproduction follows the hypothesis and keeps the failed direction as evidence.",
                [],
            ),
            "sign-reproduce-00001",
        )
        if reproduction_id in (negative_id, hypothesis_id, announcement_id):
            fail({"error": "reproduction id collided", "record_id": reproduction_id})
        publish(peer_dir, peer_port, reproduction_id, "publish-reproduce-001")

        reproduced = context(peer_dir, peer_port, reproduction_id)
        require_context(reproduced, [reproduction_id, hypothesis_id, negative_id], [])
        print("PASS")
        return 0
    finally:
        for _name, datadir, port, proc in nodes:
            stop_node(datadir, port, proc)


if __name__ == "__main__":
    raise SystemExit(main())
