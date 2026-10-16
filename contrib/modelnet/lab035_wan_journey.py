#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""One-host WAN journey. Four regtest btxd processes: ingress, mirror_a, mirror_b, endpoint.

ingress creates the identity, realms, promotion, and channel, then exports a bundle.
mirror_a imports that bundle after ingress has stopped. mirror_b and endpoint stay up
for the same run. No wallet RPC.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

# ingress, mirror_a, mirror_b, endpoint
ROLES = ("ingress", "mirror_a", "mirror_b", "endpoint")

ROOT = Path(os.environ.get("BTX035_JOURNEY_DIR", Path.cwd() / "lab035-wan-journey"))
BIN = Path(os.environ["BTX035_BIN"])
BTXD = BIN / "btxd"
CLI = BIN / "btx-cli"
RPC_USER = "lab"
RPC_PASSWORD = "lab-pass-0001"
BUNDLE_NAME = "wan-closure.bundle"
CHANNEL = "wan"
RPC_BASE = 29510
P2P_BASE = 29610


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


def lab(datadir: Path, port: int, method: str, request: dict) -> dict:
    return rpc(datadir, port, "lab035", method, json.dumps(request))


def rpc_fail(datadir: Path, port: int, *args: str) -> str:
    proc = subprocess.run(
        [str(CLI), "-regtest", f"-datadir={datadir}", f"-rpcport={port}",
         f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASSWORD}", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    text = (proc.stderr or "") + (proc.stdout or "")
    if proc.returncode == 0:
        raise RuntimeError(text.strip() or "RPC succeeded")
    return text


def start(name: str, index: int) -> tuple[str, Path, int, subprocess.Popen]:
    datadir = ROOT / name
    datadir.mkdir(parents=True)
    rpcport = RPC_BASE + index
    log = open(datadir / "stdout.log", "w")
    proc = subprocess.Popen(
        [
            str(BTXD), "-regtest", f"-datadir={datadir}", f"-port={P2P_BASE + index}",
            f"-rpcport={rpcport}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
            f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASSWORD}",
            "-bind=127.0.0.1", "-listen=1", "-server=1", "-dnsseed=0", "-fixedseeds=0",
            "-listenonion=0", "-daemon=0", "-nomodelnet",
        ],
        stdout=log, stderr=subprocess.STDOUT,
    )
    deadline = time.time() + 40
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{name} exited")
        try:
            info = rpc(datadir, rpcport, "getblockchaininfo")
        except Exception:
            time.sleep(0.2)
            continue
        if info.get("chain") != "regtest":
            raise RuntimeError(f"{name} is not regtest")
        return name, datadir, rpcport, proc
    raise RuntimeError(f"{name} did not answer")


def stop_node(datadir: Path, port: int, proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        try:
            rpc(datadir, port, "stop")
        except Exception:
            proc.terminate()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=30)


def hex96(fill: str) -> str:
    if len(fill) != 1 or fill not in "0123456789abcdef":
        raise RuntimeError("hex fill")
    return fill * 96


def require_state(body: dict, state: str, what: str) -> dict:
    result = body.get("result")
    if not isinstance(result, dict) or result.get("state") != state:
        raise RuntimeError(f"{what}: {json.dumps(body)}")
    return result


def channel_payload(realm_id: str, policy_id: str, sequence: str, previous: str | None) -> dict:
    return {
        "realm_id": realm_id,
        "channel": CHANNEL,
        "epoch": "0",
        "sequence": sequence,
        "previous_update_id": previous,
        "promotion_id": None,
        "trust_attestation_ids": [],
        "desired_closure_root": hex96("c"),
        "policy_id": policy_id,
        "valid_until_ms": "4102444800000",
        "rollback_of": None,
        "conflict_resolution_id": None,
    }


def sign_and_store(datadir: Path, port: int, realm_id: str, policy_id: str, sequence: str, previous: str | None, idem: str) -> str:
    signed = lab(datadir, port, "lab.identity_sign", {
        "record_type": "ChannelUpdate",
        "payload": channel_payload(realm_id, policy_id, sequence, previous),
        "realm_id": realm_id,
        "delegation_id": None,
        "expires_ms": "10",
        "idempotency_key": idem,
        "expected_state": None,
    })
    envelope = signed.get("result", {}).get("envelope")
    if not isinstance(envelope, dict) or not envelope.get("record_id"):
        raise RuntimeError(json.dumps(signed))
    stored = lab(datadir, port, "lab.record_import", {
        "envelope": envelope,
        "publish": True,
        "idempotency_key": "import-" + idem,
        "expected_state": None,
    })
    require_state(stored, "PUBLISHED", "lab.record_import")
    return envelope["record_id"]


def main() -> int:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir()
    bundle_dir = ROOT / "bundles"
    bundle_dir.mkdir()
    os.environ["BTX035_BUNDLE_DIR"] = str(bundle_dir)
    nodes = []
    try:
        for index, name in enumerate(ROLES):
            nodes.append(start(name, index))
        ingress = nodes[0]
        mirror_a = nodes[1]
        _name, datadir, port, _proc = ingress

        created = lab(datadir, port, "lab.identity_create", {
            "label": "ingress",
            "recovery_key_ids": [],
            "recovery_threshold": 1,
            "recovery_delay_ms": "1",
            "idempotency_key": "wan-identity-create-1",
            "expected_state": None,
        })
        if created.get("result", {}).get("state") != "ACTIVE":
            raise RuntimeError(json.dumps(created))

        source = lab(datadir, port, "lab.realm_create", {
            "name": "source",
            "nonce": "source-nonce-1",
            "policy_template": "local",
            "idempotency_key": "wan-realm-source-0001",
            "expected_state": None,
        })
        destination = lab(datadir, port, "lab.realm_create", {
            "name": "destination",
            "nonce": "destination-nonce-1",
            "policy_template": "local",
            "idempotency_key": "wan-realm-destination1",
            "expected_state": None,
        })
        source_id = source.get("result", {}).get("realm_id", "")
        destination_id = destination.get("result", {}).get("realm_id", "")
        policy_id = destination.get("result", {}).get("policy_id", "")
        if len(source_id) != 96 or len(destination_id) != 96 or source_id == destination_id or len(policy_id) != 96:
            raise RuntimeError(json.dumps({"source": source, "destination": destination}))

        prepared = lab(datadir, port, "lab.promotion_prepare", {
            "source_realm_id": source_id,
            "destination_realm_id": destination_id,
            "resource_refs": [hex96("1"), hex96("2")],
            "policy_id": policy_id,
            "review_ref": {"ticket": "wan-review"},
            "idempotency_key": "wan-promo-prepare-001",
            "expected_state": None,
        })
        promotion_id = require_state(prepared, "PREPARED", "lab.promotion_prepare").get("record_id", "")
        if len(promotion_id) != 96:
            raise RuntimeError(json.dumps(prepared))

        attestations = []
        for idem, checks in (
            ("wan-promo-attest-0001", {"closure": "checked", "realm_id": destination_id}),
            ("wan-promo-attest-0002", {"policy": "checked", "realm_id": destination_id}),
        ):
            attested = lab(datadir, port, "lab.promotion_attest", {
                "promotion_id": promotion_id,
                "checks_ref": checks,
                "valid_until_ms": "10",
                "idempotency_key": idem,
                "expected_state": None,
            })
            attestation_id = require_state(attested, "ATTESTED", "lab.promotion_attest").get("record_id", "")
            if len(attestation_id) != 96:
                raise RuntimeError(json.dumps(attested))
            attestations.append(attestation_id)
        if len(attestations) != 2 or attestations[0] == attestations[1]:
            raise RuntimeError("the two attestations were not distinct")
        wrong = rpc_fail(
            datadir, port, "lab035", "lab.promotion_attest",
            json.dumps({
                "promotion_id": promotion_id,
                "checks_ref": {"closure": "checked", "realm_id": source_id},
                "valid_until_ms": "10",
                "idempotency_key": "wan-promo-wrong-realm1",
                "expected_state": None,
            }),
        )
        if "BTX035_REALM" not in wrong:
            raise RuntimeError(wrong.strip())

        verified = lab(datadir, port, "lab.promotion_verify", {
            "promotion_id": promotion_id,
            "attestation_ids": attestations,
            "policy_id": policy_id,
        })
        require_state(verified, "COMPLETE", "lab.promotion_verify")

        missing = hex96("e")
        if missing in attestations:
            raise RuntimeError("missing attestation id collided")
        refused = lab(datadir, port, "lab.promotion_verify", {
            "promotion_id": promotion_id,
            "attestation_ids": [attestations[0], missing],
            "policy_id": policy_id,
        })
        require_state(refused, "FAILED", "lab.promotion_verify missing attestation")

        first = sign_and_store(datadir, port, destination_id, policy_id, "0", None, "wan-sign-channel-seq0")
        published = lab(datadir, port, "lab.channel_publish", {
            "update_id": first,
            "approval_set_id": None,
            "idempotency_key": "wan-publish-channel-s0",
            "expected_state": None,
        })
        require_state(published, "PUBLISHED", "lab.channel_publish 0")

        second = sign_and_store(datadir, port, destination_id, policy_id, "1", first, "wan-sign-channel-seq1")
        published = lab(datadir, port, "lab.channel_publish", {
            "update_id": second,
            "approval_set_id": None,
            "idempotency_key": "wan-publish-channel-s1",
            "expected_state": None,
        })
        require_state(published, "PUBLISHED", "lab.channel_publish 1")

        stale = rpc_fail(
            datadir, port, "lab035", "lab.channel_publish",
            json.dumps({
                "update_id": first,
                "approval_set_id": None,
                "idempotency_key": "wan-publish-channel-s0b",
                "expected_state": None,
            }),
        )
        if "BTX035_ROLLBACK" not in stale and "BTX035_STALE" not in stale:
            raise RuntimeError(stale.strip())

        current = lab(datadir, port, "lab.channel_get", {
            "realm_id": destination_id,
            "channel": CHANNEL,
        })
        got = current.get("result", {})
        if got.get("sequence") != "1" or got.get("state") != "CURRENT" or got.get("update_id") != second:
            raise RuntimeError(json.dumps(current))

        exported = lab(datadir, port, "lab.bundle_export", {
            "bundle_id": destination_id,
            "local_destination": BUNDLE_NAME,
            "idempotency_key": "wan-bundle-export-0001",
            "expected_state": None,
        })
        require_state(exported, "COMPLETE", "lab.bundle_export")
        if not (bundle_dir / BUNDLE_NAME).is_file():
            raise RuntimeError("lab.bundle_export did not write " + BUNDLE_NAME)

        stop_node(ingress[1], ingress[2], ingress[3])

        _mname, mdir, mport, _mproc = mirror_a
        expired = rpc_fail(
            mdir, mport, "lab035", "lab.bundle_import",
            json.dumps({
                "local_source": BUNDLE_NAME,
                "destination_realm_id": destination_id,
                "minimum_policy_epoch": "1",
                "idempotency_key": "wan-bundle-import-old1",
                "expected_state": None,
            }),
        )
        if "BTX035_POLICY" not in expired:
            raise RuntimeError(expired.strip())
        imported = lab(mdir, mport, "lab.bundle_import", {
            "local_source": BUNDLE_NAME,
            "destination_realm_id": destination_id,
            "minimum_policy_epoch": "0",
            "idempotency_key": "wan-bundle-import-0001",
            "expected_state": None,
        })
        require_state(imported, "COMPLETE", "lab.bundle_import")
        mirrored = lab(mdir, mport, "lab.channel_get", {
            "realm_id": destination_id,
            "channel": CHANNEL,
        })
        mirror_state = mirrored.get("result", {})
        if mirror_state.get("state") == "UNKNOWN":
            print(json.dumps(imported))
            raise RuntimeError("lab.bundle_import succeeded but lab.channel_get is UNKNOWN; the offline bundle did not carry the channel closure")
        if mirror_state.get("state") != "CURRENT" or mirror_state.get("sequence") != "1" or mirror_state.get("update_id") != second:
            raise RuntimeError(json.dumps({"import": imported, "channel_get": mirrored}))
        print("PASS")
        return 0
    finally:
        for _name, datadir, port, proc in nodes:
            stop_node(datadir, port, proc)


if __name__ == "__main__":
    raise SystemExit(main())
