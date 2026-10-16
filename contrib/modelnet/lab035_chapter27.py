#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Chapter 27 WAN journey on shipped binaries.

One public ingress, one model attestor, one private controller, two site
mirrors, and three endpoints in two rings. A later single-attestor personal
node uses the same binaries. GUI and ZeroMQ must already be compiled in.
No wallet RPC.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(os.environ.get("BTX035_JOURNEY_DIR", "/tmp/lab035-chapter27"))
BIN = Path(os.environ["BTX035_BIN"])
BTXD = BIN / "btxd"
CLI = BIN / "btx-cli"
QT = BIN / "btx-qt"
RPC_USER = "lab"
RPC_PASSWORD = "lab-pass-0001"
PROFILE = "BTX035-LAUNCH-DECODER-2x64"
CHANNEL = "wan"
SECRET = "secret-realm-name-alpha"
RPC_BASE = 30320
P2P_BASE = 30420
ROLES = ("ingress", "attestor", "controller", "mirror_a", "mirror_b", "ep0", "ep1", "ep2")


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
    body = json.loads(proc.stdout) if proc.stdout.strip() else {}
    if not isinstance(body, dict):
        fail({"error": "RPC response was not an object", "body": proc.stdout})
    return body


def lab(datadir: Path, port: int, method: str, request: dict) -> dict:
    try:
        return rpc(datadir, port, "lab035", method, json.dumps(request))
    except SystemExit:
        print("failed " + method, flush=True)
        raise


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


def start(name: str, index: int, peers: str = "") -> tuple[str, Path, int, subprocess.Popen]:
    datadir = ROOT / name
    if datadir.exists():
        shutil.rmtree(datadir)
    datadir.mkdir(parents=True)
    labdir = ROOT / (name + "-lab")
    labdir.mkdir(parents=True)
    rpcport = RPC_BASE + index
    log = open(datadir / "stdout.log", "w")
    env = os.environ.copy()
    env["BTX035_LAB_DIR"] = str(labdir.resolve())
    env["BTX035_BUNDLE_DIR"] = str((ROOT / "bundles").resolve())
    env.pop("BTX035_LAB_PEER", None)
    if peers:
        env["BTX035_LAB_PEERS"] = peers
        env["BTX035_LAB_PEER_USER"] = RPC_USER
        env["BTX035_LAB_PEER_PASSWORD"] = RPC_PASSWORD
    else:
        env.pop("BTX035_LAB_PEERS", None)
    proc = subprocess.Popen(
        [
            str(BTXD), "-regtest", f"-datadir={datadir}", f"-port={P2P_BASE + index}",
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
        if invoke(datadir, rpcport, "getzmqnotifications").returncode != 0:
            fail({"error": name + " ZeroMQ RPC failed"})
        return name, datadir, rpcport, proc
    fail({"error": name + " did not answer"})


def relaunch(name: str, index: int) -> tuple[str, Path, int, subprocess.Popen]:
    datadir = ROOT / name
    labdir = ROOT / (name + "-lab")
    rpcport = RPC_BASE + index
    log = open(datadir / "stdout-restart.log", "w")
    env = os.environ.copy()
    env["BTX035_LAB_DIR"] = str(labdir.resolve())
    env["BTX035_BUNDLE_DIR"] = str((ROOT / "bundles").resolve())
    env.pop("BTX035_LAB_PEER", None)
    env.pop("BTX035_LAB_PEERS", None)
    proc = subprocess.Popen(
        [
            str(BTXD), "-regtest", f"-datadir={datadir}", f"-port={P2P_BASE + index}",
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
            fail({"error": name + " restart exited", "log": (datadir / "stdout-restart.log").read_text()[-2000:]})
        probe = invoke(datadir, rpcport, "getblockchaininfo")
        if probe.returncode != 0 or not probe.stdout.strip():
            time.sleep(0.2)
            continue
        return name, datadir, rpcport, proc
    fail({"error": name + " restart did not answer"})


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


def identity(datadir: Path, port: int, label: str) -> None:
    require_state(lab(datadir, port, "lab.identity_create", {
        "label": label,
        "recovery_key_ids": [],
        "recovery_threshold": 1,
        "recovery_delay_ms": "1",
        "idempotency_key": label + "-identity-0001",
        "expected_state": None,
    }), "ACTIVE")


def sign_envelope(datadir: Path, port: int, realm_id: str, record_type: str, payload: dict, idem: str) -> tuple[str, dict]:
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
    if not isinstance(envelope, dict) or not isinstance(envelope.get("record_id"), str):
        fail(signed)
    return envelope["record_id"], envelope


def import_envelope(datadir: Path, port: int, envelope: dict, idem: str) -> str:
    stored = lab(datadir, port, "lab.record_import", {
        "envelope": envelope,
        "publish": False,
        "idempotency_key": idem,
        "expected_state": None,
    })
    record_id = require_state(stored, "STORED").get("record_id")
    if record_id != envelope.get("record_id"):
        fail(stored)
    return record_id


def contribution(summary: str) -> dict:
    return {
        "objective_id": "a" * 96,
        "kind": "HYPOTHESIS",
        "source_snapshot_id": None,
        "physical_parent_ids": [],
        "informed_by": [],
        "capsule_id": None,
        "claim_refs": [],
        "evidence_refs": [],
        "summary": summary,
    }


def execute(datadir: Path, port: int, intent: str, idem: str) -> dict:
    require_state(lab(datadir, port, "lab.action_prepare", {
        "intent_id": intent,
        "idempotency_key": "prepare-" + idem,
        "expected_state": None,
    }), "PREPARED")
    return require_state(lab(datadir, port, "lab.research_execute", {
        "input_capsule_id": "2" * 96,
        "recipe_id": PROFILE,
        "runtime_binding_id": "3" * 96,
        "research_grant_id": "4" * 96,
        "local_capability_grant_id": intent,
        "idempotency_key": "execute-" + idem,
        "expected_state": None,
    }), "COMPLETE")


def trust_payload(promotion_id: str, destination_id: str, policy_id: str, closure: str) -> dict:
    return {
        "promotion_id": promotion_id,
        "destination_realm_id": destination_id,
        "policy_id": policy_id,
        "closure_root": closure,
        "resource_decisions": [{"resource": {"kind": "MODEL", "digest48": closure}, "admission_id": "e" * 96}],
        "checks_ref": {"kind": "MODEL", "digest48": closure},
        "attestor_set_epoch": "0",
        "valid_until_ms": "4102444800000",
        "scope": "MODEL_PROMOTION",
    }


def channel_payload(realm_id: str, policy_id: str, digest: str, sequence: str, previous) -> dict:
    return {
        "realm_id": realm_id,
        "channel": CHANNEL,
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


def receipt_payload(plan_id: str, update_id: str, digest: str, device: str, ring: str, authorization) -> dict:
    return {
        "rollout_id": plan_id,
        "channel_update_id": update_id,
        "device_id": device,
        "ring_id": ring,
        "state": "ACTIVE",
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


def pull(datadir: Path, port: int, source_port: int, repository_id: str, idem: str) -> None:
    pulled = lab(datadir, port, "lab.snapshot_pull", {
        "host": "127.0.0.1",
        "port": source_port,
        "rpc_user": RPC_USER,
        "rpc_password": RPC_PASSWORD,
        "repository_id": repository_id,
        "idempotency_key": idem,
        "expected_state": None,
    })
    if result_of(pulled).get("repository_id") != repository_id:
        fail(pulled)


def main() -> int:
    require_binaries()
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir()
    (ROOT / "bundles").mkdir()
    nodes = []
    try:
        for index, name in enumerate(ROLES):
            peers = "127.0.0.1:30322" if name == "ingress" else ""
            nodes.append(start(name, index, peers))
        by_name = {item[0]: item for item in nodes}
        ingress = by_name["ingress"]
        attestor = by_name["attestor"]
        controller = by_name["controller"]
        _mirror_a = by_name["mirror_a"]
        mirror_b = by_name["mirror_b"]
        endpoints = [by_name["ep0"], by_name["ep1"], by_name["ep2"]]

        print("training", flush=True)
        identity(ingress[1], ingress[2], "ingress-a")
        first = execute(ingress[1], ingress[2], "1" * 96, "ch27-train-a-000001")
        identity(ingress[1], ingress[2], "ingress-b")
        second = execute(ingress[1], ingress[2], "5" * 96, "ch27-train-b-000001")
        if first.get("artifact_digest") != second.get("artifact_digest"):
            fail({"first": first, "second": second})
        digest = first["artifact_digest"]
        one = lab(ingress[1], ingress[2], "lab.admission_evaluate", {
            "model_ref": {"digest": digest},
            "policy_id": "e" * 96,
            "evidence_ids": [first["operation_id"]],
            "idempotency_key": "ch27-admit-one-root01",
            "expected_state": None,
        })
        two = lab(ingress[1], ingress[2], "lab.admission_evaluate", {
            "model_ref": {"digest": digest},
            "policy_id": "e" * 96,
            "evidence_ids": [first["operation_id"], second["operation_id"]],
            "idempotency_key": "ch27-admit-two-root01",
            "expected_state": None,
        })
        if result_of(one).get("state") != "FAILED" or result_of(two).get("state") != "COMPLETE":
            fail({"one": one, "two": two})
        for kind in ("tokenizer_digest", "dataset_digest"):
            resolved = lab(ingress[1], ingress[2], "lab.capsule_resolve", {
                "capsule_id": first[kind],
                "purpose": "REPLAY",
                "max_bytes": "10000000",
            })
            if result_of(resolved).get("missing_refs") != []:
                fail(resolved)
        repository_id = result_of(lab(ingress[1], ingress[2], "lab.repository_create", {
            "label": "ingress",
            "nonce": "ch27-ingress-repo-01",
            "object_format": "git",
            "project_genesis_id": None,
            "default_ref": "refs/heads/main",
            "idempotency_key": "ch27-ingress-repo-0001",
            "expected_state": None,
        })).get("repository_id", "")
        if len(repository_id) != 96:
            fail({"error": "ingress repository missing"})
        require_state(lab(ingress[1], ingress[2], "lab.git_snapshot", {
            "repository_id": repository_id,
            "commit": {"bytes": "admitted launch model\n"},
            "dependency_lock_id": "d" * 96,
            "history_required": False,
            "idempotency_key": "ch27-ingress-snap-0001",
            "expected_state": None,
        }), "COMPLETE")

        identity(controller[1], controller[2], "controller")
        source = result_of(lab(controller[1], controller[2], "lab.realm_create", {
            "name": "public-source",
            "nonce": "ch27-source-nonce-01",
            "policy_template": "local",
            "idempotency_key": "ch27-realm-source-0001",
            "expected_state": None,
        }))
        destination = result_of(lab(controller[1], controller[2], "lab.realm_create", {
            "name": "private-dest",
            "nonce": "ch27-dest-nonce-0001",
            "policy_template": "local",
            "idempotency_key": "ch27-realm-dest-000001",
            "expected_state": None,
        }))
        source_id = source.get("realm_id", "")
        destination_id = destination.get("realm_id", "")
        policy_id = destination.get("policy_id", "")
        if len(source_id) != 96 or len(destination_id) != 96 or source_id == destination_id:
            fail({"source": source, "destination": destination})
        require_state(lab(controller[1], controller[2], "lab.realm_policy_apply", {
            "policy_id": policy_id,
            "approval_set_id": None,
            "idempotency_key": "ch27-policy-apply-0001",
            "expected_state": None,
        }), "APPLIED")
        if result_of(lab(controller[1], controller[2], "lab.realm_status", {
            "realm_id": destination_id,
        })).get("public_connectivity") != "DISABLED":
            fail({"error": "private realm is publicly connected"})
        private_id, private_env = sign_envelope(
            controller[1], controller[2], destination_id, "ResearchContribution",
            contribution(SECRET), "ch27-sign-private-0001",
        )
        import_envelope(controller[1], controller[2], private_env, "ch27-import-private01")
        require_state(lab(controller[1], controller[2], "lab.research_publish", {
            "record_id": private_id,
            "topic_ids": ["c" * 96],
            "visibility": "PRIVATE",
            "idempotency_key": "ch27-publish-private01",
            "expected_state": None,
        }), "PUBLISHED")
        leaked = json.dumps(lab(ingress[1], ingress[2], "lab.research_query", {
            "scope": "PEERS",
            "topics": [],
            "kinds": [],
            "after_cursor": None,
            "limit": 20,
        }))
        if private_id in leaked or SECRET in leaked:
            fail({"error": "a private name leaked to the public ingress", "body": leaked})

        pull(controller[1], controller[2], ingress[2], repository_id, "ch27-controller-pull01")
        prepared = require_state(lab(controller[1], controller[2], "lab.promotion_prepare", {
            "source_realm_id": source_id,
            "destination_realm_id": destination_id,
            "resource_refs": [digest],
            "policy_id": policy_id,
            "review_ref": {"ticket": "ch27"},
            "idempotency_key": "ch27-promo-prepare-001",
            "expected_state": None,
        }), "PREPARED")
        promotion_id = prepared.get("record_id", "")
        if len(promotion_id) != 96:
            fail(prepared)
        identity(attestor[1], attestor[2], "attestor")
        pin_a, env_a = sign_envelope(
            attestor[1], attestor[2], destination_id, "ModelTrustAttestation",
            trust_payload(promotion_id, destination_id, policy_id, digest),
            "ch27-attestor-sign-0001",
        )
        import_envelope(controller[1], controller[2], env_a, "ch27-import-attestor01")
        _wrong_id, wrong_env = sign_envelope(
            attestor[1], attestor[2], source_id, "ModelTrustAttestation",
            trust_payload(promotion_id, source_id, policy_id, digest),
            "ch27-attestor-wrong-0001",
        )
        wrong_pin = import_envelope(controller[1], controller[2], wrong_env, "ch27-import-wrong-0001")
        local = require_state(lab(controller[1], controller[2], "lab.promotion_attest", {
            "promotion_id": promotion_id,
            "checks_ref": {"closure": "checked", "realm_id": destination_id},
            "valid_until_ms": "10",
            "idempotency_key": "ch27-controller-pin001",
            "expected_state": None,
        }), "ATTESTED")
        pin_b = local.get("record_id", "")
        if len(pin_b) != 96 or pin_b == pin_a:
            fail(local)
        refused = lab(controller[1], controller[2], "lab.promotion_verify", {
            "promotion_id": promotion_id,
            "attestation_ids": [pin_b, wrong_pin],
            "policy_id": policy_id,
        })
        require_state(refused, "FAILED")
        verified = lab(controller[1], controller[2], "lab.promotion_verify", {
            "promotion_id": promotion_id,
            "attestation_ids": [pin_a, pin_b],
            "policy_id": policy_id,
        })
        if require_state(verified, "COMPLETE").get("threshold") != "2":
            fail(verified)
        revoked = lab(controller[1], controller[2], "lab.promotion_attest", {
            "promotion_id": promotion_id,
            "checks_ref": {"realm_id": destination_id, "revoke_attestor": pin_a},
            "valid_until_ms": "10",
            "idempotency_key": "ch27-revoke-attestor01",
            "expected_state": None,
        })
        if require_state(revoked, "REVOKED").get("threshold") != "2":
            fail(revoked)
        if result_of(lab(controller[1], controller[2], "lab.realm_status", {
            "realm_id": destination_id,
        })).get("threshold") != "2":
            fail({"error": "revoking one attestor shrank the threshold"})

        update_0, env_update = sign_envelope(
            controller[1], controller[2], destination_id, "ChannelUpdate",
            channel_payload(destination_id, policy_id, digest, "0", None),
            "ch27-sign-channel-seq0",
        )
        import_envelope(controller[1], controller[2], env_update, "ch27-import-channel-0")
        require_state(lab(controller[1], controller[2], "lab.channel_publish", {
            "update_id": update_0,
            "approval_set_id": None,
            "idempotency_key": "ch27-publish-channel-0",
            "expected_state": None,
        }), "PUBLISHED")
        stale_id, stale_env = sign_envelope(
            controller[1], controller[2], destination_id, "ChannelUpdate",
            channel_payload(destination_id, policy_id, digest, "0", None),
            "ch27-sign-channel-old0",
        )
        import_envelope(controller[1], controller[2], stale_env, "ch27-import-channel-old")
        expect_error(controller[1], controller[2], "lab.channel_publish", {
            "update_id": stale_id,
            "approval_set_id": None,
            "idempotency_key": "ch27-publish-channel-old",
            "expected_state": None,
        }, "BTX035_STALE")
        plan_id, plan_env = sign_envelope(controller[1], controller[2], destination_id, "RolloutPlan", {
            "channel_update_id": update_0,
            "fleet_policy_id": policy_id,
            "rings": ["canary", "rest"],
            "activation": "ATOMIC",
            "deadline_ms": "10",
            "rollback_update_id": None,
            "bandwidth_limit_bytes_s": "1",
        }, "ch27-sign-rollout-plan1")
        import_envelope(controller[1], controller[2], plan_env, "ch27-import-plan-00001")
        require_state(lab(controller[1], controller[2], "lab.rollout_start", {
            "plan_id": plan_id,
            "approval_set_id": None,
            "idempotency_key": "ch27-rollout-start0001",
            "expected_state": None,
        }), "COMPLETE")
        if result_of(lab(controller[1], controller[2], "lab.rollout_status", {"plan_id": plan_id})).get("state") != "STAGED":
            fail({"error": "rollout did not stage"})

        rings = ("canary", "rest", "rest")
        for endpoint, ring in zip(endpoints, rings):
            identity(endpoint[1], endpoint[2], endpoint[0])
            realm_id = result_of(lab(endpoint[1], endpoint[2], "lab.realm_create", {
                "name": endpoint[0],
                "nonce": endpoint[0] + "-realm-nonce",
                "policy_template": "local",
                "idempotency_key": endpoint[0] + "-realm-create01",
                "expected_state": None,
            })).get("realm_id", "")
            status = result_of(lab(endpoint[1], endpoint[2], "lab.realm_status", {"realm_id": realm_id}))
            if status.get("public_connectivity") != "DISABLED":
                fail(status)
            pull(endpoint[1], endpoint[2], ingress[2], repository_id, endpoint[0] + "-pull-0000001")
            acquired = require_state(lab(endpoint[1], endpoint[2], "lab.artifact_acquire", {
                "resource": {"digest": digest, "repository_id": repository_id},
                "origin_policy_id": "e" * 96,
                "max_bytes": "10000000",
                "destination_class": "LOCAL",
                "idempotency_key": endpoint[0] + "-acquire-00001",
                "expected_state": None,
            }), "COMPLETE")
            if acquired.get("artifact_digest") != digest:
                fail(acquired)
            missing = lab(endpoint[1], endpoint[2], "lab.capsule_resolve", {
                "capsule_id": "ab" * 48,
                "purpose": "REPLAY",
                "max_bytes": "1000",
            })
            if result_of(missing).get("missing_refs") == []:
                fail(missing)

        def observe(endpoint, ring: str, idem: str, authorization) -> None:
            receipt_id, receipt_env = sign_envelope(
                endpoint[1], endpoint[2], destination_id, "DeploymentReceipt",
                receipt_payload(plan_id, update_0, digest, endpoint[0], ring, authorization),
                idem,
            )
            import_envelope(controller[1], controller[2], receipt_env, "import-" + idem)
            require_state(lab(controller[1], controller[2], "lab.deployment_observe", {
                "receipt_id": receipt_id,
                "idempotency_key": "observe-" + idem,
                "expected_state": None,
            }), "OBSERVED")

        observe(endpoints[0], "canary", "ch27-receipt-ep0-0001", None)
        if result_of(lab(controller[1], controller[2], "lab.rollout_status", {"plan_id": plan_id})).get("state") != "CANARY":
            fail({"error": "one ring did not stay a canary"})
        observe(endpoints[1], "rest", "ch27-receipt-ep1-hold1", None)
        held = result_of(lab(controller[1], controller[2], "lab.rollout_status", {"plan_id": plan_id}))
        if held.get("state") != "CANARY" or held.get("active_generation"):
            fail(held)
        approval_id, approval_env = sign_envelope(controller[1], controller[2], destination_id, "GovernanceApproval", {
            "proposal_id": plan_id,
            "policy_id": policy_id,
            "decision": "APPROVE",
            "decision_context": plan_id,
        }, "ch27-owner-approval001")
        import_envelope(controller[1], controller[2], approval_env, "ch27-import-approval01")
        observe(endpoints[1], "rest", "ch27-receipt-ep1-00001", approval_id)
        active = result_of(lab(controller[1], controller[2], "lab.rollout_status", {"plan_id": plan_id}))
        if active.get("state") != "ACTIVE" or active.get("active_generation") != plan_id:
            fail(active)
        observe(endpoints[2], "rest", "ch27-receipt-ep2-00001", None)

        for mirror in (_mirror_a, mirror_b):
            pull(mirror[1], mirror[2], ingress[2], repository_id, mirror[0] + "-pull-0000001")
        stop_node(mirror_b[1], mirror_b[2], mirror_b[3])
        piece_files = [path for path in (ROOT / "mirror_b-lab" / "pieces").rglob("*.piece") if path.is_file()]
        if not piece_files:
            fail({"error": "mirror kept no piece files"})
        raw = bytearray(piece_files[0].read_bytes())
        raw[-1] ^= 0x01
        piece_files[0].write_bytes(raw)
        mirror_b = relaunch("mirror_b", 4)
        nodes = [mirror_b if item[0] == "mirror_b" else item for item in nodes]
        tampered = invoke(mirror_b[1], mirror_b[2], "lab035", "lab.artifact_acquire", json.dumps({
            "resource": {"digest": digest, "repository_id": repository_id},
            "origin_policy_id": "e" * 96,
            "max_bytes": "10000000",
            "destination_class": "LOCAL",
            "idempotency_key": "ch27-tampered-piece001",
            "expected_state": None,
        }))
        tampered_text = (tampered.stdout or "") + (tampered.stderr or "")
        if tampered.returncode == 0:
            served = json.loads(tampered.stdout).get("result", {}).get("state")
            if served == "COMPLETE":
                fail({"error": "a tampered piece was served", "body": tampered_text})
        elif "BTX035_ID_MISMATCH" not in tampered_text:
            fail({"error": "tampered piece was not refused", "body": tampered_text})
        false_id, false_env = sign_envelope(controller[1], controller[2], destination_id, "DeploymentReceipt", {
            "rollout_id": plan_id,
            "channel_update_id": update_0,
            "device_id": "offline",
            "ring_id": "canary",
            "state": "ACTIVE",
            "observed_closure_root": "f" * 96,
            "local_generation": "0",
            "health_evidence_id": None,
            "last_observed_ms": "1",
            "observation_epoch": "0",
            "receipt_sequence": "0",
            "previous_receipt_id": None,
            "controller_pause_epoch": "0",
            "activation_authorization_id": None,
            "observer_key_id": "e" * 96,
        }, "ch27-sign-false-healthy")
        import_envelope(controller[1], controller[2], false_env, "ch27-import-false-ok01")
        expect_error(controller[1], controller[2], "lab.deployment_observe", {
            "receipt_id": false_id,
            "idempotency_key": "ch27-observe-false-ok1",
            "expected_state": None,
        }, "BTX035_")
        paused = result_of(lab(controller[1], controller[2], "lab.rollout_pause", {
            "plan_id": plan_id,
            "reason": "canary miss",
            "idempotency_key": "ch27-rollout-pause0001",
            "expected_state": None,
        }))
        if paused.get("paused") is not True or paused.get("pause_epoch") != "1":
            fail(paused)
        update_1, update_env = sign_envelope(
            controller[1], controller[2], destination_id, "ChannelUpdate",
            channel_payload(destination_id, policy_id, digest, "1", update_0),
            "ch27-sign-channel-seq1",
        )
        import_envelope(controller[1], controller[2], update_env, "ch27-import-channel-1")
        require_state(lab(controller[1], controller[2], "lab.rollout_rollback", {
            "plan_id": plan_id,
            "new_channel_update_id": update_1,
            "idempotency_key": "ch27-rollback-seq-0001",
            "expected_state": None,
        }), "COMPLETE")
        if result_of(lab(controller[1], controller[2], "lab.rollout_status", {"plan_id": plan_id})).get("state") != "ROLLED_BACK":
            fail({"error": "rollback did not keep the receipt"})
        if result_of(lab(controller[1], controller[2], "lab.channel_get", {
            "realm_id": destination_id,
            "channel": CHANNEL,
        })).get("update_id") != update_1:
            fail({"error": "the higher channel update was not retained"})

        require_state(lab(controller[1], controller[2], "lab.bundle_export", {
            "bundle_id": destination_id,
            "local_destination": "wan-closure.bundle",
            "idempotency_key": "ch27-bundle-export-001",
            "expected_state": None,
        }), "COMPLETE")
        stop_node(ingress[1], ingress[2], ingress[3])
        stop_node(_mirror_a[1], _mirror_a[2], _mirror_a[3])
        nodes = [item for item in nodes if item[0] not in ("ingress", "mirror_a")]
        expect_error(mirror_b[1], mirror_b[2], "lab.bundle_import", {
            "local_source": "wan-closure.bundle",
            "destination_realm_id": destination_id,
            "minimum_policy_epoch": "1",
            "idempotency_key": "ch27-bundle-import-old1",
            "expected_state": None,
        }, "BTX035_POLICY")
        require_state(lab(mirror_b[1], mirror_b[2], "lab.bundle_import", {
            "local_source": "wan-closure.bundle",
            "destination_realm_id": destination_id,
            "minimum_policy_epoch": "0",
            "idempotency_key": "ch27-bundle-import-0001",
            "expected_state": None,
        }), "COMPLETE")
        plan = result_of(lab(mirror_b[1], mirror_b[2], "lab.migration_plan", {
            "target_version": "0.35",
            "include_private": False,
        }))
        expect_error(mirror_b[1], mirror_b[2], "lab.migration_apply", {
            "plan_ref": plan.get("plan_ref"),
            "backup_ref": {"digest48": "b" * 96, "sequence": "0", "realm_id": destination_id, "channel": CHANNEL},
            "idempotency_key": "ch27-migration-oldback",
            "expected_state": None,
        }, "BTX035_ROLLBACK")
        if result_of(lab(mirror_b[1], mirror_b[2], "lab.migration_verify", {
            "migration_id": "0" * 96,
        })).get("money_unchanged") is not True:
            fail({"error": "migration changed the money flag"})
        incident = "7" * 96
        require_state(lab(controller[1], controller[2], "lab.incident_publish", {
            "incident_id": incident,
            "audience": "LOCAL",
            "idempotency_key": "ch27-incident-publish1",
            "expected_state": None,
        }), "PUBLISHED")
        recovery = result_of(lab(controller[1], controller[2], "lab.trust_reconcile", {
            "anchor_record_ids": [],
            "identity_state_ids": [],
            "owner_approval_id": approval_id,
            "idempotency_key": "ch27-trust-missing-001",
            "expected_state": None,
        }))
        if recovery.get("state") != "RECOVERY_REQUIRED":
            fail(recovery)
        reconciled = result_of(lab(controller[1], controller[2], "lab.trust_reconcile", {
            "anchor_record_ids": [incident],
            "identity_state_ids": [],
            "owner_approval_id": approval_id,
            "idempotency_key": "ch27-trust-anchor-001",
            "expected_state": None,
        }))
        if reconciled.get("state") != "RECONCILED":
            fail(reconciled)
        revocation_id, revocation_env = sign_envelope(controller[1], controller[2], destination_id, "Revocation", {
            "issuer_root": destination_id,
            "revocation_epoch": "1",
            "targets": [],
            "effective_after_ms": "1",
            "reason_code": "STOLEN",
            "prior_revocation_id": None,
            "quarantine_since_ms": "1",
        }, "ch27-sign-revocation01")
        import_envelope(controller[1], controller[2], revocation_env, "ch27-import-revoke-001")
        require_state(lab(controller[1], controller[2], "lab.identity_revoke", {
            "revocation_id": revocation_id,
            "idempotency_key": "ch27-identity-revoke01",
            "expected_state": None,
        }), "REVOKED")
        expect_error(controller[1], controller[2], "lab.identity_sign", {
            "record_type": "ResearchContribution",
            "payload": contribution("After revocation."),
            "realm_id": destination_id,
            "delegation_id": None,
            "expires_ms": "10",
            "idempotency_key": "ch27-sign-after-revoke",
            "expected_state": None,
        }, "BTX035_IDENTITY_REVOKED")
        if result_of(lab(controller[1], controller[2], "lab.economy_refs", {
            "subject_id": private_id,
        })).get("spend_authorized") is not False:
            fail({"error": "spend was authorized"})
        for item in nodes:
            height = invoke(item[1], item[2], "getblockcount")
            if height.returncode != 0 or height.stdout.strip() != "0":
                fail({"error": "monetary height changed", "role": item[0]})

        for item in nodes:
            stop_node(item[1], item[2], item[3])
        nodes = []
        personal = start("personal", 8)
        nodes.append(personal)
        identity(personal[1], personal[2], "personal")
        personal_source = result_of(lab(personal[1], personal[2], "lab.realm_create", {
            "name": "personal-source",
            "nonce": "ch27-personal-source1",
            "policy_template": "local",
            "idempotency_key": "ch27-personal-source01",
            "expected_state": None,
        }))
        personal_dest = result_of(lab(personal[1], personal[2], "lab.realm_create", {
            "name": "personal-dest",
            "nonce": "ch27-personal-dest001",
            "policy_template": "local",
            "idempotency_key": "ch27-personal-dest-001",
            "expected_state": None,
        }))
        personal_promotion = require_state(lab(personal[1], personal[2], "lab.promotion_prepare", {
            "source_realm_id": personal_source["realm_id"],
            "destination_realm_id": personal_dest["realm_id"],
            "resource_refs": ["1" * 96],
            "policy_id": personal_dest["policy_id"],
            "review_ref": {"ticket": "personal"},
            "idempotency_key": "ch27-personal-prepare1",
            "expected_state": None,
        }), "PREPARED").get("record_id", "")
        personal_pin, personal_env = sign_envelope(
            personal[1], personal[2], personal_dest["realm_id"], "ModelTrustAttestation",
            trust_payload(personal_promotion, personal_dest["realm_id"], personal_dest["policy_id"], "1" * 96),
            "ch27-personal-sign-0001",
        )
        import_envelope(personal[1], personal[2], personal_env, "ch27-personal-import01")
        personal_verified = lab(personal[1], personal[2], "lab.promotion_verify", {
            "promotion_id": personal_promotion,
            "attestation_ids": [personal_pin],
            "policy_id": personal_dest["policy_id"],
        })
        if require_state(personal_verified, "COMPLETE").get("threshold") != "1":
            fail(personal_verified)
        if result_of(lab(personal[1], personal[2], "lab.realm_status", {
            "realm_id": personal_dest["realm_id"],
        })).get("public_connectivity") != "DISABLED":
            fail({"error": "personal realm is publicly connected"})
        print("PASS")
        return 0
    finally:
        for _name, datadir, port, proc in nodes:
            try:
                stop_node(datadir, port, proc)
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
