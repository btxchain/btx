#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Chapter 26 sovereign laboratory journey on shipped binaries.

Three or more regtest data directories, two agent identities, and two Git
origins. The launch profile is the small rebuildable model. GUI and ZeroMQ
must already be compiled into the binaries. No wallet RPC.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(os.environ.get("BTX035_JOURNEY_DIR", "/tmp/lab035-chapter26"))
BIN = Path(os.environ["BTX035_BIN"])
BTXD = BIN / "btxd"
CLI = BIN / "btx-cli"
QT = BIN / "btx-qt"
RPC_USER = "lab"
RPC_PASSWORD = "lab-pass-0001"
PROFILE = "BTX035-LAUNCH-DECODER-2x64"
RPC_BASE = 30110
P2P_BASE = 30210


def fail(body) -> None:
    if not isinstance(body, str):
        body = json.dumps(body)
    print(body, flush=True)
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
    return rpc(datadir, port, "lab035", method, json.dumps(request))


def expect_error(datadir: Path, port: int, method: str, request: dict, code: str) -> None:
    proc = invoke(datadir, port, "lab035", method, json.dumps(request))
    text = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if proc.returncode == 0 or code not in text:
        fail({"error": method + " did not return " + code, "body": text})


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


def require_binaries() -> None:
    if not QT.is_file():
        fail({"error": "btx-qt is missing", "bin": str(BIN)})
    help_proc = subprocess.run([str(BTXD), "-help"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if "-zmqpubhashblock" not in (help_proc.stdout or ""):
        fail({"error": "btxd was built without ZeroMQ"})
    env = os.environ.copy()
    env["QT_QPA_PLATFORM"] = "offscreen"
    qt_proc = subprocess.run([str(QT), "-version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    if qt_proc.returncode != 0 or "BTX" not in (qt_proc.stdout or ""):
        fail({"error": "btx-qt -version failed", "body": (qt_proc.stdout or "")[-500:]})
    ldd = subprocess.run(["ldd", str(BTXD)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if "libzmq" not in (ldd.stdout or ""):
        fail({"error": "btxd is not linked to libzmq"})


def start(name: str, index: int, peers: str = "") -> tuple[Path, int, subprocess.Popen]:
    datadir = ROOT / name
    if datadir.exists():
        shutil.rmtree(datadir)
    datadir.mkdir(parents=True)
    labdir = ROOT / (name + "-lab")
    labdir.mkdir(parents=True, exist_ok=True)
    return launch(name, datadir, labdir, RPC_BASE + index, P2P_BASE + index, peers)


def launch(name: str, datadir: Path, labdir: Path, rpcport: int, p2pport: int, peers: str) -> tuple[Path, int, subprocess.Popen]:
    log = open(datadir / "stdout.log", "w")
    env = os.environ.copy()
    env["BTX035_LAB_DIR"] = str(labdir.resolve())
    env.pop("BTX035_BUNDLE_DIR", None)
    env.pop("BTX035_LAB_PEER", None)
    if peers:
        env["BTX035_LAB_PEERS"] = peers
        env["BTX035_LAB_PEER_USER"] = RPC_USER
        env["BTX035_LAB_PEER_PASSWORD"] = RPC_PASSWORD
    else:
        env.pop("BTX035_LAB_PEERS", None)
        env.pop("BTX035_LAB_PEER_USER", None)
        env.pop("BTX035_LAB_PEER_PASSWORD", None)
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
    deadline = time.time() + 40
    while time.time() < deadline:
        if proc.poll() is not None:
            fail({"error": name + " exited", "log": (datadir / "stdout.log").read_text()[-2000:]})
        probe = invoke(datadir, rpcport, "getblockchaininfo")
        if probe.returncode != 0 or not probe.stdout.strip():
            time.sleep(0.2)
            continue
        info = json.loads(probe.stdout)
        if info.get("chain") != "regtest" or info.get("blocks") != 0:
            fail(info)
        zmq = invoke(datadir, rpcport, "getzmqnotifications")
        if zmq.returncode != 0:
            fail({"error": name + " ZeroMQ RPC failed", "body": (zmq.stderr or zmq.stdout or "")[-500:]})
        return datadir, rpcport, proc
    fail({"error": name + " did not answer"})


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
    if require_state(stored, "STORED").get("record_id") != record_id:
        fail(stored)
    return record_id


def contribution(kind: str, informed_by: list, parents: list, summary: str) -> dict:
    return {
        "objective_id": "a" * 96,
        "kind": kind,
        "source_snapshot_id": None,
        "physical_parent_ids": parents,
        "informed_by": informed_by,
        "capsule_id": None,
        "claim_refs": [],
        "evidence_refs": [],
        "summary": summary,
    }


def publish(datadir: Path, port: int, record_id: str, idem: str, visibility: str) -> None:
    published = lab(datadir, port, "lab.research_publish", {
        "record_id": record_id,
        "topic_ids": ["c" * 96],
        "visibility": visibility,
        "idempotency_key": idem,
        "expected_state": None,
    })
    if require_state(published, "PUBLISHED").get("record_id") != record_id:
        fail(published)


def identity(datadir: Path, port: int, label: str, idem: str) -> None:
    require_state(lab(datadir, port, "lab.identity_create", {
        "label": label,
        "recovery_key_ids": [],
        "recovery_threshold": 1,
        "recovery_delay_ms": "1",
        "idempotency_key": idem,
        "expected_state": None,
    }), "ACTIVE")


def execute(datadir: Path, port: int, intent: str, idem: str, capsule: str) -> dict:
    require_state(lab(datadir, port, "lab.action_prepare", {
        "intent_id": intent,
        "idempotency_key": "prepare-" + idem,
        "expected_state": None,
    }), "PREPARED")
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
    if row.get("profile") != PROFILE or row.get("next_byte_hits") is None or row.get("miss_mass") is None:
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


def tamper(trajectory: str, field: str, value: str, code: str, index: int) -> None:
    labdir = ROOT / ("tamper-" + field + "-lab")
    if labdir.exists():
        shutil.rmtree(labdir)
    shutil.copytree(ROOT / "publisher-lab", labdir)
    disk = json.loads((labdir / "lab.json").read_text())
    row = disk.get("launch_trains", {}).get(trajectory)
    if not isinstance(row, dict) or field not in row:
        fail({"error": "checkpoint field missing", "field": field, "keys": list((row or {}).keys())})
    row[field] = value
    (labdir / "lab.json").write_text(json.dumps(disk))
    datadir = ROOT / ("tamper-" + field)
    datadir.mkdir(parents=True)
    node = launch("tamper-" + field, datadir, labdir, RPC_BASE + index, P2P_BASE + index, "")
    try:
        audited = lab(node[0], node[1], "lab.audit_coverage", {
            "trajectory_id": trajectory,
            "policy_id": "e" * 96,
        })
        audit = result_of(audited)
        if audit.get("complete_path") is not False or code not in (audit.get("gaps") or []):
            fail(audited)
    finally:
        stop_node(*node)


def main() -> int:
    require_binaries()
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir()
    nodes = []
    try:
        origin = start("origin", 0)
        second = start("second", 1)
        publisher = start("publisher", 2, "127.0.0.1:30113,127.0.0.1:30110")
        bootstrap = start("bootstrap", 3, "127.0.0.1:30110")
        replica = start("replica", 4)
        nodes.extend((origin, second, publisher, bootstrap, replica))
        origin_dir, origin_port, origin_proc = origin
        second_dir, second_port, _second_proc = second
        publisher_dir, publisher_port, publisher_proc = publisher
        _bootstrap_dir, _bootstrap_port, bootstrap_proc = bootstrap
        replica_dir, replica_port, replica_proc = replica

        identity(origin_dir, origin_port, "agent-origin", "ch26-origin-identity1")
        origin_realm = result_of(lab(origin_dir, origin_port, "lab.realm_create", {
            "name": "origin",
            "nonce": "ch26-origin-realm-01",
            "policy_template": "local",
            "idempotency_key": "ch26-origin-realm-0001",
            "expected_state": None,
        }))
        origin_realm_id = origin_realm.get("realm_id", "")
        if len(origin_realm_id) != 96 or result_of(lab(origin_dir, origin_port, "lab.realm_status", {
            "realm_id": origin_realm_id,
        })).get("public_connectivity") != "DISABLED":
            fail(origin_realm)
        objective = sign_and_import(origin_dir, origin_port, origin_realm_id, "ResearchObjective", {
            "title": "Reproduce the frozen launch decoder",
            "description_ref": {"kind": "RESEARCH", "digest48": "d" * 96},
            "evaluation_spec_id": "e" * 96,
            "resource_constraints": [],
            "project_policy_id": None,
            "parent_objective_id": None,
            "economic_refs": [],
        }, "ch26-sign-objective01")
        publish(origin_dir, origin_port, objective, "ch26-publish-objectiv1", "PUBLIC")
        origin_repo = result_of(lab(origin_dir, origin_port, "lab.repository_create", {
            "label": "origin-a",
            "nonce": "ch26-origin-repo-001",
            "object_format": "git",
            "project_genesis_id": None,
            "default_ref": "refs/heads/main",
            "idempotency_key": "ch26-origin-repo-00001",
            "expected_state": None,
        })).get("repository_id", "")
        if len(origin_repo) != 96:
            fail({"error": "origin repository missing"})
        snapped = require_state(lab(origin_dir, origin_port, "lab.git_snapshot", {
            "repository_id": origin_repo,
            "commit": {"bytes": "origin A source\n"},
            "dependency_lock_id": "d" * 96,
            "history_required": False,
            "idempotency_key": "ch26-origin-snapshot01",
            "expected_state": None,
        }), "COMPLETE")
        snapshot_id = snapped.get("operation_id", "")
        if len(snapshot_id) != 96:
            fail(snapped)

        identity(publisher_dir, publisher_port, "agent-n", "ch26-publisher-ident1")
        discovered = result_of(lab(publisher_dir, publisher_port, "lab.research_query", {
            "scope": "PEERS",
            "topics": [],
            "kinds": [],
            "after_cursor": None,
            "limit": 20,
        }))
        if objective not in (discovered.get("record_ids") or []):
            fail(discovered)
        pulled = lab(publisher_dir, publisher_port, "lab.snapshot_pull", {
            "host": "127.0.0.1",
            "port": origin_port,
            "rpc_user": RPC_USER,
            "rpc_password": RPC_PASSWORD,
            "repository_id": origin_repo,
            "idempotency_key": "ch26-publisher-pull001",
            "expected_state": None,
        })
        if result_of(pulled).get("repository_id") != origin_repo:
            fail(pulled)
        opened = result_of(lab(publisher_dir, publisher_port, "lab.workspace_create", {
            "snapshot_id": snapshot_id,
            "backend": "OPERATION_JOURNAL",
            "adapter_id": None,
            "storage_limit": "1000000",
            "idempotency_key": "ch26-workspace-create1",
            "expected_state": None,
        }))
        workspace_id = opened.get("workspace_id", "")
        generation = opened.get("generation", "")
        if len(workspace_id) != 96 or generation == "":
            fail(opened)
        expect_error(publisher_dir, publisher_port, "lab.workspace_operation", {
            "workspace_id": workspace_id,
            "event": {"hook": "pre-receive"},
            "idempotency_key": "ch26-workspace-hook001",
            "expected_state": None,
        }, "BTX035_SCOPE_DENIED")
        lab(publisher_dir, publisher_port, "lab.workspace_operation", {
            "workspace_id": workspace_id,
            "event": {"note": "selected experiment"},
            "idempotency_key": "ch26-workspace-note001",
            "expected_state": None,
        })
        advanced = str(int(generation) + 1)
        checkpoint = require_state(lab(publisher_dir, publisher_port, "lab.workspace_snapshot", {
            "workspace_id": workspace_id,
            "generation": advanced,
            "publishable": False,
            "idempotency_key": "ch26-workspace-snap001",
            "expected_state": None,
        }), "SNAPSHOT").get("record_id", "")
        require_state(lab(publisher_dir, publisher_port, "lab.workspace_restore", {
            "workspace_id": workspace_id,
            "checkpoint_id": checkpoint,
            "new_generation": str(int(advanced) + 1),
            "idempotency_key": "ch26-workspace-undo001",
            "expected_state": None,
        }), "COMPLETE")
        publisher_realm = result_of(lab(publisher_dir, publisher_port, "lab.realm_create", {
            "name": "publisher",
            "nonce": "ch26-publisher-realm1",
            "policy_template": "local",
            "idempotency_key": "ch26-publisher-realm01",
            "expected_state": None,
        })).get("realm_id", "")
        experiment = sign_and_import(
            publisher_dir, publisher_port, publisher_realm, "ResearchContribution",
            contribution("EXPERIMENT", [], [], "Selected the launch profile."),
            "ch26-sign-experiment01",
        )
        publish(publisher_dir, publisher_port, experiment, "ch26-publish-experimnt", "PUBLIC")
        negative = sign_and_import(
            publisher_dir, publisher_port, publisher_realm, "ResearchContribution",
            contribution("NEGATIVE_RESULT", [experiment], [], "This direction failed."),
            "ch26-sign-negative-001",
        )
        publish(publisher_dir, publisher_port, negative, "ch26-publish-negative1", "PUBLIC")
        branch_a = "1" * 96
        branch_b = "2" * 96
        ref_a = sign_and_import(publisher_dir, publisher_port, publisher_realm, "GitRefUpdate", {
            "repository_id": origin_repo,
            "ref_name": "refs/heads/personal-n",
            "old_target": None,
            "new_target": branch_a,
            "snapshot_id": snapshot_id,
            "sequence": "1",
            "previous_update_id": None,
            "policy_id": None,
            "force": False,
        }, "ch26-sign-personal-n01")
        require_state(lab(publisher_dir, publisher_port, "lab.git_publish_ref", {
            "update_id": ref_a,
            "approval_set_id": None,
            "idempotency_key": "ch26-publish-personaln",
            "expected_state": None,
        }), "PUBLISHED")
        ref_b = sign_and_import(publisher_dir, publisher_port, publisher_realm, "GitRefUpdate", {
            "repository_id": origin_repo,
            "ref_name": "refs/heads/personal-other",
            "old_target": branch_b,
            "new_target": "3" * 96,
            "snapshot_id": snapshot_id,
            "sequence": "1",
            "previous_update_id": None,
            "policy_id": None,
            "force": False,
        }, "ch26-sign-personal-o01")
        expect_error(publisher_dir, publisher_port, "lab.git_publish_ref", {
            "update_id": ref_b,
            "approval_set_id": None,
            "idempotency_key": "ch26-publish-conflict1",
            "expected_state": None,
        }, "BTX035_STALE")
        refs = result_of(lab(publisher_dir, publisher_port, "lab.git_refs", {
            "repository_id": origin_repo,
            "namespace": "refs/heads",
            "after_cursor": None,
        }))
        if branch_a not in (refs.get("record_ids") or []) or ("3" * 96) in (refs.get("record_ids") or []):
            fail(refs)

        identity(second_dir, second_port, "agent-second", "ch26-second-identity1")
        second_realm = result_of(lab(second_dir, second_port, "lab.realm_create", {
            "name": "second",
            "nonce": "ch26-second-realm-001",
            "policy_template": "local",
            "idempotency_key": "ch26-second-realm-0001",
            "expected_state": None,
        })).get("realm_id", "")
        second_repo = result_of(lab(second_dir, second_port, "lab.repository_create", {
            "label": "origin-b",
            "nonce": "ch26-second-repo-0001",
            "object_format": "git",
            "project_genesis_id": None,
            "default_ref": "refs/heads/main",
            "idempotency_key": "ch26-second-repo-00001",
            "expected_state": None,
        })).get("repository_id", "")
        if len(second_repo) != 96 or second_repo == origin_repo:
            fail({"error": "second git origin was not separate"})
        require_state(lab(second_dir, second_port, "lab.git_snapshot", {
            "repository_id": second_repo,
            "commit": {"bytes": "origin B source\n"},
            "dependency_lock_id": "d" * 96,
            "history_required": False,
            "idempotency_key": "ch26-second-snapshot01",
            "expected_state": None,
        }), "COMPLETE")
        pulled = lab(second_dir, second_port, "lab.snapshot_pull", {
            "host": "127.0.0.1",
            "port": publisher_port,
            "rpc_user": RPC_USER,
            "rpc_password": RPC_PASSWORD,
            "repository_id": origin_repo,
            "idempotency_key": "ch26-second-pull-0001",
            "expected_state": None,
        })
        if result_of(pulled).get("repository_id") != origin_repo:
            fail(pulled)
        citation = sign_and_import(
            second_dir, second_port, second_realm, "ResearchContribution",
            contribution("REPRODUCTION", [negative], [], "Cited across a separate repository."),
            "ch26-sign-citation001",
        )
        publish(second_dir, second_port, citation, "ch26-publish-citation1", "PUBLIC")
        cited = result_of(lab(second_dir, second_port, "lab.research_context", {
            "root_ids": [citation],
            "relations": ["INFORMED_BY"],
            "max_depth": 4,
            "max_records": 16,
        }))
        if negative not in (cited.get("record_ids") or []):
            fail(cited)
        if (cited.get("coverage") or {}).get("selection_is_proof") is not False:
            fail(cited)

        print("training", flush=True)
        identity(publisher_dir, publisher_port, "agent-n-train", "ch26-train-identity-a")
        first = execute(publisher_dir, publisher_port, "1" * 96, "ch26-train-a-000001", "2" * 96)
        identity(publisher_dir, publisher_port, "agent-n-other", "ch26-train-identity-b")
        second_run = execute(publisher_dir, publisher_port, "5" * 96, "ch26-train-b-000001", "2" * 96)
        if first["artifact_digest"] != second_run["artifact_digest"] or first["state_hash"] != second_run["state_hash"]:
            fail({"error": "the two runs diverged", "first": first, "second": second_run})
        if first["tokenizer_digest"] == first["dataset_digest"]:
            fail(first)
        digest = first["artifact_digest"]
        trajectory_a = first["operation_id"]
        trajectory_b = second_run["operation_id"]
        one = result_of(admit(publisher_dir, publisher_port, digest, [trajectory_a], "ch26-admit-one-root1"))
        two = result_of(admit(publisher_dir, publisher_port, digest, [trajectory_a, trajectory_b], "ch26-admit-two-root1"))
        if one.get("state") != "FAILED" or two.get("state") != "COMPLETE":
            fail({"one": one, "two": two})
        if "next_byte_hits" in two or "miss_mass" in two:
            fail({"error": "admission treated a quality field as protocol state", "body": two})
        state_hash = first["state_hash"]
        tamper(trajectory_a, "cursor", str(int(json.loads((ROOT / "publisher-lab" / "lab.json").read_text())["launch_trains"][trajectory_a]["cursor"]) + 1), "BTX035_RNG", 6)
        tamper(trajectory_a, "optimizer", "WITH_MOMENTUM", "BTX035_ID_MISMATCH", 6)
        flipped = ("0" if state_hash[-1] != "0" else "1")
        tamper(trajectory_a, "state_hash", state_hash[:-1] + flipped, "BTX035_ID_MISMATCH", 6)

        pulled = lab(replica_dir, replica_port, "lab.snapshot_pull", {
            "host": "127.0.0.1",
            "port": publisher_port,
            "rpc_user": RPC_USER,
            "rpc_password": RPC_PASSWORD,
            "repository_id": origin_repo,
            "idempotency_key": "ch26-replica-pull-001",
            "expected_state": None,
        })
        if result_of(pulled).get("repository_id") != origin_repo:
            fail(pulled)
        identity(replica_dir, replica_port, "agent-replica", "ch26-replica-ident001")
        require_state(lab(replica_dir, replica_port, "lab.action_prepare", {
            "intent_id": "a" * 96,
            "idempotency_key": "ch26-prepare-adopt001",
            "expected_state": None,
        }), "PREPARED")
        evaluation = "6" * 96
        publish_body = lab(replica_dir, replica_port, "lab.research_publish", {
            "record_id": evaluation,
            "topic_ids": ["7" * 96],
            "visibility": "REPRODUCED",
            "idempotency_key": "ch26-publish-eval-0001",
            "expected_state": None,
        })
        if result_of(publish_body).get("state") != "PUBLISHED":
            fail(publish_body)
        release = "8" * 96
        require_state(lab(replica_dir, replica_port, "lab.agent_adopt", {
            "release_id": release,
            "prior_release_id": trajectory_a,
            "grant_id": "a" * 96,
            "evaluation_ids": [evaluation],
            "idempotency_key": "ch26-adopt-n1-000001",
            "expected_state": None,
        }), "COMPLETE")
        lineage = result_of(lab(replica_dir, replica_port, "lab.agent_lineage", {
            "release_id": release,
            "max_depth": 4,
            "cursor": None,
            "limit": 8,
        }))
        if trajectory_a not in (lineage.get("record_ids") or []):
            fail(lineage)
        continued = execute(replica_dir, replica_port, "9" * 96, "ch26-train-n2-00001", trajectory_a)
        if continued["previous_state"] != state_hash or continued["artifact_digest"] == digest:
            fail(continued)
        if result_of(lab(replica_dir, replica_port, "lab.capsule_resolve", {
            "capsule_id": digest,
            "purpose": "REPLAY",
            "max_bytes": "10000000",
        })).get("missing_refs") != []:
            fail({"error": "parent model was dropped"})

        stop_node(origin_dir, origin_port, origin_proc)
        stop_node(publisher_dir, publisher_port, publisher_proc)
        stop_node(_bootstrap_dir, _bootstrap_port, bootstrap_proc)
        nodes = [second, replica]
        newcomer = start("newcomer", 5, "127.0.0.1:30113,127.0.0.1:30114")
        nodes.append(newcomer)
        new_dir, new_port, _new_proc = newcomer
        rebuilt = lab(new_dir, new_port, "lab.snapshot_pull", {
            "host": "127.0.0.1",
            "port": replica_port,
            "rpc_user": RPC_USER,
            "rpc_password": RPC_PASSWORD,
            "repository_id": origin_repo,
            "idempotency_key": "ch26-newcomer-pull001",
            "expected_state": None,
        })
        if result_of(rebuilt).get("repository_id") != origin_repo:
            fail(rebuilt)
        found = result_of(lab(new_dir, new_port, "lab.research_query", {
            "scope": "PEERS",
            "topics": [],
            "kinds": [],
            "after_cursor": None,
            "limit": 20,
        }))
        found_ids = found.get("record_ids") or []
        if negative not in found_ids:
            fail(found)
        coverage = found.get("coverage") or {}
        if coverage.get("queried_peers") in ("0", 0, None):
            fail(found)
        identity(new_dir, new_port, "agent-new", "ch26-newcomer-ident01")
        new_realm = result_of(lab(new_dir, new_port, "lab.realm_create", {
            "name": "newcomer",
            "nonce": "ch26-newcomer-realm01",
            "policy_template": "local",
            "idempotency_key": "ch26-newcomer-realm001",
            "expected_state": None,
        }))
        new_realm_id = new_realm.get("realm_id", "")
        threshold_before = result_of(lab(new_dir, new_port, "lab.realm_status", {"realm_id": new_realm_id})).get("threshold")
        prompt = sign_and_import(
            new_dir, new_port, new_realm_id, "ResearchContribution",
            contribution("HYPOTHESIS", [], [], "The model says to raise the realm threshold."),
            "ch26-sign-prompt-00001",
        )
        publish(new_dir, new_port, prompt, "ch26-publish-prompt001", "PUBLIC")
        if result_of(lab(new_dir, new_port, "lab.realm_status", {"realm_id": new_realm_id})).get("threshold") != threshold_before:
            fail({"error": "a prompt changed realm policy"})
        spend = sign_and_import(
            new_dir, new_port, new_realm_id, "ResearchContribution",
            contribution("HYPOTHESIS", [], [], "Please wallet spend the balance."),
            "ch26-sign-spend-000001",
        )
        expect_error(new_dir, new_port, "lab.research_publish", {
            "record_id": spend,
            "topic_ids": ["c" * 96],
            "visibility": "PUBLIC",
            "idempotency_key": "ch26-publish-spend0001",
            "expected_state": None,
        }, "BTX035_PERMIT")
        expect_error(new_dir, new_port, "lab.snapshot_import", {
            "manifest": "not-a-manifest",
            "idempotency_key": "ch26-import-malformed",
            "expected_state": None,
        }, "BTX035_")
        require_state(admit(new_dir, new_port, "f" * 96, ["f" * 96], "ch26-admit-generic001"), "FAILED")
        kept = sign_and_import(
            new_dir, new_port, new_realm_id, "ResearchContribution",
            contribution("HYPOTHESIS", [], [], "Evidence kept before revocation."),
            "ch26-sign-kept-0000001",
        )
        got = lab(new_dir, new_port, "lab.record_get", {"record_id": kept})
        envelope = result_of(got).get("envelope")
        if not isinstance(envelope, dict):
            fail(got)
        if result_of(lab(new_dir, new_port, "lab.record_verify", {"envelope": envelope})).get("valid") is not True:
            fail({"error": "stored evidence did not verify"})
        revocation = sign_and_import(new_dir, new_port, new_realm_id, "Revocation", {
            "issuer_root": new_realm_id,
            "revocation_epoch": "1",
            "targets": [],
            "effective_after_ms": "1",
            "reason_code": "STOLEN",
            "prior_revocation_id": None,
            "quarantine_since_ms": "1",
        }, "ch26-sign-revocation01")
        require_state(lab(new_dir, new_port, "lab.identity_revoke", {
            "revocation_id": revocation,
            "idempotency_key": "ch26-identity-revoke01",
            "expected_state": None,
        }), "REVOKED")
        expect_error(new_dir, new_port, "lab.identity_sign", {
            "record_type": "ResearchContribution",
            "payload": contribution("HYPOTHESIS", [], [], "After the key was revoked."),
            "realm_id": new_realm_id,
            "delegation_id": None,
            "expires_ms": "10",
            "idempotency_key": "ch26-sign-after-revoke",
            "expected_state": None,
        }, "BTX035_IDENTITY_REVOKED")
        if result_of(lab(new_dir, new_port, "lab.record_verify", {"envelope": envelope})).get("valid") is not True:
            fail({"error": "revocation erased earlier evidence"})
        economy = result_of(lab(new_dir, new_port, "lab.economy_refs", {"subject_id": kept}))
        if economy.get("spend_authorized") is not False:
            fail(economy)
        for datadir, port in ((new_dir, new_port), (replica_dir, replica_port)):
            height = invoke(datadir, port, "getblockcount")
            if height.returncode != 0 or height.stdout.strip() != "0":
                fail({"error": "monetary height changed", "body": height.stdout})
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
