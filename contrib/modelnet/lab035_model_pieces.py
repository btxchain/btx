#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Three regtest btxd processes: author, mirror, and a later reader.

The author runs INTEGER_MODEL twice, under two identities. The mirror pulls
that snapshot. The author process then exits. The reader queries the mirror,
fetches the model bytes, checks the digest, and admits the model only when
both replay roots are present. No wallet RPC.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

ROLES = (
    ("author", 29140, 29240),
    ("mirror", 29141, 29241),
    ("reader", 29142, 29242),
)

ROOT = Path(os.environ.get("BTX035_JOURNEY_DIR", Path.cwd() / "lab035-model-pieces"))
BIN = Path(os.environ["BTX035_BIN"])
BTXD = BIN / "btxd"
CLI = BIN / "btx-cli"
RPC_USER = "lab"
RPC_PASSWORD = "lab-pass-0001"
TOPIC = "c" * 96


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


def start(name: str, rpcport: int, p2pport: int, peer: str | None) -> tuple[str, Path, int, subprocess.Popen]:
    datadir = ROOT / name
    datadir.mkdir(parents=True)
    labdir = datadir / "lab"
    labdir.mkdir()
    log = open(datadir / "stdout.log", "w")
    env = os.environ.copy()
    env["BTX035_LAB_DIR"] = str(labdir.resolve())
    env.pop("BTX035_BUNDLE_DIR", None)
    env.pop("BTX035_LAB_PEER", None)
    env.pop("BTX035_LAB_PEER_USER", None)
    env.pop("BTX035_LAB_PEER_PASSWORD", None)
    if peer is not None:
        env["BTX035_LAB_PEER"] = peer
        env["BTX035_LAB_PEER_USER"] = RPC_USER
        env["BTX035_LAB_PEER_PASSWORD"] = RPC_PASSWORD
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


def execute_model(datadir: Path, port: int, intent: str, idem: str) -> tuple[str, str]:
    prepared = lab(datadir, port, "lab.action_prepare", {
        "intent_id": intent,
        "idempotency_key": "prepare-" + idem,
        "expected_state": None,
    })
    require_state(prepared, "PREPARED")
    ran = lab(datadir, port, "lab.research_execute", {
        "input_capsule_id": "2" * 96,
        "recipe_id": "INTEGER_MODEL",
        "runtime_binding_id": "3" * 96,
        "research_grant_id": "4" * 96,
        "local_capability_grant_id": intent,
        "idempotency_key": "execute-" + idem,
        "expected_state": None,
    })
    row = require_state(ran, "COMPLETE")
    trajectory = row.get("operation_id")
    digest = row.get("artifact_digest")
    if not isinstance(trajectory, str) or len(trajectory) != 96 or not isinstance(digest, str) or len(digest) != 96:
        fail(ran)
    return trajectory, digest


def admit(datadir: Path, port: int, digest: str, evidence: list, idem: str) -> dict:
    return lab(datadir, port, "lab.admission_evaluate", {
        "model_ref": {"digest": digest},
        "policy_id": "e" * 96,
        "evidence_ids": evidence,
        "idempotency_key": idem,
        "expected_state": None,
    })


def channel_payload(realm_id: str, policy_id: str, digest: str, sequence: str, previous) -> dict:
    return {
        "realm_id": realm_id,
        "channel": "model",
        "epoch": "0",
        "sequence": sequence,
        "previous_update_id": previous,
        "promotion_id": None,
        "trust_attestation_ids": [],
        "desired_closure_root": digest,
        "policy_id": policy_id,
        "valid_until_ms": "4102444800000",
        "rollback_of": None,
        "conflict_resolution_id": None,
    }


def receipt_payload(plan_id: str, update_id: str, digest: str, device: str, ring: str, state: str, authorization) -> dict:
    return {
        "rollout_id": plan_id,
        "channel_update_id": update_id,
        "device_id": device,
        "ring_id": ring,
        "state": state,
        "observed_closure_root": digest,
        "local_generation": "1",
        "health_evidence_id": None,
        "last_observed_ms": "1",
        "observation_epoch": "0",
        "receipt_sequence": "1",
        "previous_receipt_id": None,
        "controller_pause_epoch": "0",
        "activation_authorization_id": authorization,
        "observer_key_id": None,
    }


def main() -> int:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir()
    nodes = []
    try:
        author = start("author", 29140, 29240, None)
        mirror = start("mirror", 29141, 29241, None)
        nodes.extend((author, mirror))
        _aname, author_dir, author_port, author_proc = author
        _mname, mirror_dir, mirror_port, _mproc = mirror

        created = lab(author_dir, author_port, "lab.identity_create", {
            "label": "author-a",
            "recovery_key_ids": [],
            "recovery_threshold": 1,
            "recovery_delay_ms": "1",
            "idempotency_key": "author-identity-a-001",
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
        public_id = sign_and_import(author_dir, author_port, realm_id, "ResearchContribution", {
            "objective_id": "a" * 96,
            "kind": "HYPOTHESIS",
            "source_snapshot_id": None,
            "physical_parent_ids": [],
            "informed_by": [],
            "capsule_id": None,
            "claim_refs": [],
            "evidence_refs": [],
            "summary": "integer fixture shared with a peer",
        }, "sign-public-model-01")
        published = lab(author_dir, author_port, "lab.research_publish", {
            "record_id": public_id,
            "topic_ids": [TOPIC],
            "visibility": "PUBLIC",
            "idempotency_key": "publish-public-model1",
            "expected_state": None,
        })
        require_state(published, "PUBLISHED")

        created_repo = lab(author_dir, author_port, "lab.repository_create", {
            "label": "model-pieces",
            "nonce": "model-pieces-nonce",
            "object_format": "git",
            "project_genesis_id": None,
            "default_ref": "refs/heads/main",
            "idempotency_key": "author-repo-create-001",
            "expected_state": None,
        })
        repository_id = result_of(created_repo).get("repository_id")
        if not isinstance(repository_id, str) or len(repository_id) != 96:
            fail(created_repo)
        require_state(lab(author_dir, author_port, "lab.git_snapshot", {
            "repository_id": repository_id,
            "commit": {"bytes": "integer model source\n"},
            "dependency_lock_id": "d" * 96,
            "history_required": False,
            "idempotency_key": "author-git-snapshot-01",
            "expected_state": None,
        }), "COMPLETE")

        trajectory_a, digest = execute_model(author_dir, author_port, "1" * 96, "author-model-a-0001")
        created = lab(author_dir, author_port, "lab.identity_create", {
            "label": "author-b",
            "recovery_key_ids": [],
            "recovery_threshold": 1,
            "recovery_delay_ms": "1",
            "idempotency_key": "author-identity-b-001",
            "expected_state": None,
        })
        require_state(created, "ACTIVE")
        trajectory_b, digest_b = execute_model(author_dir, author_port, "5" * 96, "author-model-b-0001")
        if digest_b != digest or trajectory_a == trajectory_b:
            fail({"error": "the two runs did not share one artifact", "digest": digest, "other": digest_b})
        require_state(admit(author_dir, author_port, digest, [trajectory_a], "author-admit-one-0001"), "FAILED")
        require_state(admit(author_dir, author_port, digest, [trajectory_a, trajectory_b], "author-admit-two-0001"), "COMPLETE")

        pulled = lab(mirror_dir, mirror_port, "lab.snapshot_pull", {
            "host": "127.0.0.1",
            "port": author_port,
            "rpc_user": RPC_USER,
            "rpc_password": RPC_PASSWORD,
            "repository_id": repository_id,
            "idempotency_key": "mirror-snapshot-pull01",
            "expected_state": None,
        })
        manifest = result_of(pulled).get("manifest")
        if not isinstance(manifest, str) or digest not in manifest or public_id not in manifest:
            fail(pulled)
        stop_node(author_dir, author_port, author_proc)
        nodes = [mirror]

        reader = start("reader", 29142, 29242, f"127.0.0.1:{mirror_port}")
        nodes.append(reader)
        _rname, reader_dir, reader_port, _rproc = reader
        queried = lab(reader_dir, reader_port, "lab.research_query", {
            "scope": "PEERS",
            "topics": [TOPIC],
            "kinds": ["HYPOTHESIS"],
            "after_cursor": None,
            "limit": 8,
        })
        query_result = result_of(queried)
        ids = query_result.get("record_ids")
        coverage = query_result.get("coverage")
        if not isinstance(ids, list) or public_id not in ids or not isinstance(coverage, dict):
            fail(queried)
        if coverage.get("queried_peers") != "1" or coverage.get("complete") is not False:
            fail(queried)

        acquired = lab(reader_dir, reader_port, "lab.artifact_acquire", {
            "resource": {"digest": digest, "repository_id": repository_id},
            "origin_policy_id": "e" * 96,
            "max_bytes": "1000000",
            "destination_class": "LOCAL",
            "idempotency_key": "reader-acquire-model01",
            "expected_state": None,
        })
        acquired_row = require_state(acquired, "COMPLETE")
        if acquired_row.get("artifact_digest") != digest or acquired_row.get("byte_size") in (None, "0"):
            fail(acquired)

        pulled = lab(reader_dir, reader_port, "lab.snapshot_pull", {
            "host": "127.0.0.1",
            "port": mirror_port,
            "rpc_user": RPC_USER,
            "rpc_password": RPC_PASSWORD,
            "repository_id": repository_id,
            "idempotency_key": "reader-snapshot-pull01",
            "expected_state": None,
        })
        if result_of(pulled).get("repository_id") != repository_id:
            fail(pulled)
        require_state(admit(reader_dir, reader_port, digest, [trajectory_a], "reader-admit-one-0001"), "FAILED")
        admitted = require_state(admit(reader_dir, reader_port, digest, [trajectory_a, trajectory_b], "reader-admit-two-0001"), "COMPLETE")
        hosted = lab(reader_dir, reader_port, "lab.model_host", {
            "model_ref": {"digest": digest},
            "admission_id": admitted.get("operation_id"),
            "storage_limit_bytes": "1000000",
            "idempotency_key": "reader-model-host-0001",
            "expected_state": None,
        })
        if result_of(hosted).get("hosted") is not True:
            fail(hosted)

        created = lab(reader_dir, reader_port, "lab.identity_create", {
            "label": "reader",
            "recovery_key_ids": [],
            "recovery_threshold": 1,
            "recovery_delay_ms": "1",
            "idempotency_key": "reader-identity-00001",
            "expected_state": None,
        })
        require_state(created, "ACTIVE")
        source = lab(reader_dir, reader_port, "lab.realm_create", {
            "name": "source",
            "nonce": "reader-source-nonce1",
            "policy_template": "local",
            "idempotency_key": "reader-realm-source-01",
            "expected_state": None,
        })
        destination = lab(reader_dir, reader_port, "lab.realm_create", {
            "name": "destination",
            "nonce": "reader-dest-nonce-01",
            "policy_template": "local",
            "idempotency_key": "reader-realm-dest-0001",
            "expected_state": None,
        })
        source_id = result_of(source).get("realm_id", "")
        destination_id = result_of(destination).get("realm_id", "")
        policy_id = result_of(destination).get("policy_id", "")
        if len(source_id) != 96 or len(destination_id) != 96 or len(policy_id) != 96:
            fail({"source": source, "destination": destination})
        prepared = lab(reader_dir, reader_port, "lab.promotion_prepare", {
            "source_realm_id": source_id,
            "destination_realm_id": destination_id,
            "resource_refs": [digest],
            "policy_id": policy_id,
            "review_ref": {"ticket": "reader"},
            "idempotency_key": "reader-promo-prepare01",
            "expected_state": None,
        })
        promotion_id = require_state(prepared, "PREPARED").get("record_id", "")
        pins = []
        for idem, checks in (
            ("reader-promo-attest-01", {"closure": "checked", "realm_id": destination_id}),
            ("reader-promo-attest-02", {"policy": "checked", "realm_id": destination_id}),
        ):
            attested = lab(reader_dir, reader_port, "lab.promotion_attest", {
                "promotion_id": promotion_id,
                "checks_ref": checks,
                "valid_until_ms": "10",
                "idempotency_key": idem,
                "expected_state": None,
            })
            pins.append(require_state(attested, "ATTESTED").get("record_id"))
        if len(pins) != 2 or pins[0] == pins[1] or any(not isinstance(pin, str) or len(pin) != 96 for pin in pins):
            fail({"error": "the two attestations were not distinct", "pins": pins})
        wrong = invoke(reader_dir, reader_port, "lab035", "lab.promotion_attest", json.dumps({
            "promotion_id": promotion_id,
            "checks_ref": {"closure": "checked", "realm_id": source_id},
            "valid_until_ms": "10",
            "idempotency_key": "reader-promo-wrong-realm",
            "expected_state": None,
        }))
        if "BTX035_REALM" not in ((wrong.stdout or "") + (wrong.stderr or "")):
            fail({"error": "wrong-realm attestation was accepted", "body": (wrong.stdout or "") + (wrong.stderr or "")})
        verified = lab(reader_dir, reader_port, "lab.promotion_verify", {
            "promotion_id": promotion_id,
            "attestation_ids": pins,
            "policy_id": policy_id,
        })
        if result_of(verified).get("threshold") != "2":
            fail(verified)
        revoked = lab(reader_dir, reader_port, "lab.promotion_attest", {
            "promotion_id": promotion_id,
            "checks_ref": {"revoke_attestor": pins[0], "realm_id": destination_id},
            "valid_until_ms": "10",
            "idempotency_key": "reader-promo-revoke-01",
            "expected_state": None,
        })
        revoked_row = require_state(revoked, "REVOKED")
        if revoked_row.get("threshold") != "2":
            fail(revoked)
        realm_status = lab(reader_dir, reader_port, "lab.realm_status", {"realm_id": destination_id})
        if result_of(realm_status).get("threshold") != "2":
            fail(realm_status)

        update_0 = sign_and_import(
            reader_dir, reader_port, destination_id, "ChannelUpdate",
            channel_payload(destination_id, policy_id, digest, "0", None),
            "reader-channel-seq-000",
        )
        require_state(lab(reader_dir, reader_port, "lab.channel_publish", {
            "update_id": update_0,
            "approval_set_id": None,
            "idempotency_key": "reader-publish-seq-000",
            "expected_state": None,
        }), "PUBLISHED")
        plan_id = sign_and_import(reader_dir, reader_port, destination_id, "RolloutPlan", {
            "channel_update_id": update_0,
            "fleet_policy_id": policy_id,
            "rings": ["canary", "rest"],
            "activation": "ATOMIC",
            "deadline_ms": "10",
            "rollback_update_id": None,
            "bandwidth_limit_bytes_s": "1",
        }, "reader-rollout-plan-01")
        require_state(lab(reader_dir, reader_port, "lab.rollout_start", {
            "plan_id": plan_id,
            "approval_set_id": None,
            "idempotency_key": "reader-rollout-start01",
            "expected_state": None,
        }), "COMPLETE")
        staged = lab(reader_dir, reader_port, "lab.rollout_status", {"plan_id": plan_id})
        if result_of(staged).get("state") != "STAGED":
            fail(staged)

        def observe(device: str, ring: str, state: str, idem: str, authorization) -> None:
            receipt_id = sign_and_import(
                reader_dir, reader_port, destination_id, "DeploymentReceipt",
                receipt_payload(plan_id, update_0, digest, device, ring, state, authorization),
                idem,
            )
            observed = lab(reader_dir, reader_port, "lab.deployment_observe", {
                "receipt_id": receipt_id,
                "idempotency_key": "observe-" + idem,
                "expected_state": None,
            })
            require_state(observed, "OBSERVED")

        authorization = sign_and_import(reader_dir, reader_port, destination_id, "GovernanceApproval", {
            "proposal_id": plan_id,
            "policy_id": policy_id,
            "decision": "APPROVE",
            "decision_context": plan_id,
        }, "reader-owner-approval01")
        observe("device-a", "canary", "ACTIVE", "reader-receipt-a-0001", None)
        canary = lab(reader_dir, reader_port, "lab.rollout_status", {"plan_id": plan_id})
        if result_of(canary).get("state") != "CANARY":
            fail(canary)
        observe("device-b", "rest", "ACTIVE", "reader-receipt-hold001", None)
        held = lab(reader_dir, reader_port, "lab.rollout_status", {"plan_id": plan_id})
        if result_of(held).get("state") != "CANARY" or result_of(held).get("active_generation"):
            fail(held)
        observe("device-b", "rest", "ACTIVE", "reader-receipt-b-0001", authorization)
        active = lab(reader_dir, reader_port, "lab.rollout_status", {"plan_id": plan_id})
        if result_of(active).get("state") != "ACTIVE" or result_of(active).get("active_generation") != plan_id:
            fail(active)
        observe("device-c", "rest", "UNKNOWN", "reader-receipt-c-0001", None)
        unknown = result_of(lab(reader_dir, reader_port, "lab.rollout_status", {"plan_id": plan_id}))
        counts = unknown.get("counts")
        if unknown.get("state") != "ACTIVE" or not isinstance(counts, dict) or str(counts.get("unknown")) in ("0", "None", None):
            fail(unknown)
        bare = lab(reader_dir, reader_port, "lab.deployment_observe", {
            "receipt_id": "f" * 96,
            "idempotency_key": "reader-bare-receipt-01",
            "expected_state": None,
        })
        require_state(bare, "OBSERVED")
        update_1 = sign_and_import(
            reader_dir, reader_port, destination_id, "ChannelUpdate",
            channel_payload(destination_id, policy_id, digest, "1", update_0),
            "reader-channel-seq-001",
        )
        require_state(lab(reader_dir, reader_port, "lab.rollout_rollback", {
            "plan_id": plan_id,
            "new_channel_update_id": update_1,
            "idempotency_key": "reader-rollback-seq-001",
            "expected_state": None,
        }), "COMPLETE")
        rolled = lab(reader_dir, reader_port, "lab.rollout_status", {"plan_id": plan_id})
        if result_of(rolled).get("state") != "ROLLED_BACK":
            fail(rolled)
        print("PASS")
        return 0
    finally:
        for _name, datadir, port, proc in nodes:
            stop_node(datadir, port, proc)
        if ROOT.exists():
            shutil.rmtree(ROOT, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
