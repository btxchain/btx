#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Shipped-binary coverage for the lab journeys that are not the integer fixture.

Two regtest nodes, both started with -nomodelnet. The author publishes a
source snapshot, a hypothesis, and a negative result. A second repository
cites that result with informed_by and does not take it as a parent. A hook,
a wallet-spend summary, a stale ref, a malformed manifest, and a generic
artifact are refused. An older channel backup is refused. A paused rollout
rolls forward only through a higher channel sequence, and that sequence cannot
be reused. A revoked identity cannot sign. No wallet RPC.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(os.environ.get("BTX035_JOURNEY_DIR", Path.cwd() / "lab035-e2e-gaps"))
BIN = Path(os.environ["BTX035_BIN"])
BTXD = BIN / "btxd"
CLI = BIN / "btx-cli"
RPC_USER = "lab"
RPC_PASSWORD = "lab-pass-0001"
CHANNEL = "updates"


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


def error_text(datadir: Path, port: int, method: str, request: dict) -> str:
    proc = invoke(datadir, port, "lab035", method, json.dumps(request))
    return ((proc.stdout or "") + (proc.stderr or "")).strip()


def expect_error(datadir: Path, port: int, method: str, request: dict, code: str) -> None:
    text = error_text(datadir, port, method, request)
    if code not in text:
        fail({"error": method + " did not return " + code, "body": text})


def start(name: str, rpcport: int, p2pport: int) -> tuple[Path, int, subprocess.Popen]:
    datadir = ROOT / name
    if datadir.exists():
        shutil.rmtree(datadir)
    datadir.mkdir(parents=True)
    labdir = ROOT / (name + "-lab")
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
        proc.terminate()
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
    if require_state(stored, "STORED").get("record_id") != record_id:
        fail(stored)
    return record_id


def contribution(kind: str, snapshot: str, informed_by: list, parents: list, summary: str) -> dict:
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


def channel_payload(realm_id: str, policy_id: str, sequence: str, previous, until: str) -> dict:
    return {
        "realm_id": realm_id,
        "channel": CHANNEL,
        "epoch": "0",
        "sequence": sequence,
        "previous_update_id": previous,
        "promotion_id": None,
        "trust_attestation_ids": [],
        "desired_closure_root": "c" * 96,
        "policy_id": policy_id,
        "valid_until_ms": until,
        "rollback_of": None,
        "conflict_resolution_id": None,
    }


def main() -> int:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir()
    nodes = []
    try:
        author_dir, author_port, author_proc = start("author", 29020, 29120)
        peer_dir, peer_port, peer_proc = start("peer", 29021, 29121)
        nodes.extend(((author_dir, author_port, author_proc), (peer_dir, peer_port, peer_proc)))

        require_state(lab(author_dir, author_port, "lab.identity_create", {
            "label": "author",
            "recovery_key_ids": [],
            "recovery_threshold": 1,
            "recovery_delay_ms": "1",
            "idempotency_key": "gap-author-identity01",
            "expected_state": None,
        }), "ACTIVE")
        realm = result_of(lab(author_dir, author_port, "lab.realm_create", {
            "name": "author",
            "nonce": "gap-author-realm-01",
            "policy_template": "local",
            "idempotency_key": "gap-author-realm-0001",
            "expected_state": None,
        }))
        realm_id = realm.get("realm_id", "")
        policy_id = realm.get("policy_id", "")
        if len(realm_id) != 96 or len(policy_id) != 96:
            fail(realm)
        status = result_of(lab(author_dir, author_port, "lab.realm_status", {"realm_id": realm_id}))
        if status.get("public_connectivity") != "DISABLED":
            fail(status)

        created_repo = lab(author_dir, author_port, "lab.repository_create", {
            "label": "author-source",
            "nonce": "gap-author-repo-01",
            "object_format": "git",
            "project_genesis_id": None,
            "default_ref": "refs/heads/main",
            "idempotency_key": "gap-author-repo-00001",
            "expected_state": None,
        })
        author_repo = result_of(created_repo).get("repository_id", "")
        if len(author_repo) != 96:
            fail(created_repo)
        snapped = require_state(lab(author_dir, author_port, "lab.git_snapshot", {
            "repository_id": author_repo,
            "commit": {"bytes": "research source\n"},
            "dependency_lock_id": "d" * 96,
            "history_required": False,
            "idempotency_key": "gap-author-snap-0001",
            "expected_state": None,
        }), "COMPLETE")
        snapshot_id = snapped.get("operation_id", "")
        if len(snapshot_id) != 96:
            fail(snapped)
        opened = result_of(lab(author_dir, author_port, "lab.workspace_create", {
            "snapshot_id": snapshot_id,
            "backend": "OPERATION_JOURNAL",
            "adapter_id": None,
            "storage_limit": "1000000",
            "idempotency_key": "gap-workspace-create1",
            "expected_state": None,
        }))
        workspace_id = opened.get("workspace_id", "")
        if len(workspace_id) != 96:
            fail(opened)
        expect_error(author_dir, author_port, "lab.workspace_operation", {
            "workspace_id": workspace_id,
            "event": {"hook": "pre-receive"},
            "idempotency_key": "gap-workspace-hook001",
            "expected_state": None,
        }, "BTX035_SCOPE_DENIED")
        lab(author_dir, author_port, "lab.workspace_operation", {
            "workspace_id": workspace_id,
            "event": {"note": "reversible edit"},
            "idempotency_key": "gap-workspace-note001",
            "expected_state": None,
        })
        conflicted = require_state(lab(author_dir, author_port, "lab.workspace_reconcile", {
            "workspace_id": workspace_id,
            "parent_checkpoint_ids": ["b" * 96],
            "resolution_snapshot_id": snapshot_id,
            "idempotency_key": "gap-workspace-conflict",
            "expected_state": None,
        }), "CONFLICT")
        if conflicted.get("state") != "CONFLICT":
            fail(conflicted)

        hypothesis = sign_and_import(
            author_dir, author_port, realm_id, "ResearchContribution",
            contribution("HYPOTHESIS", snapshot_id, [], [], "A personal branch."),
            "gap-sign-hypothesis01",
        )
        publish(author_dir, author_port, hypothesis, "gap-publish-hypothes1", "PUBLIC")
        negative = sign_and_import(
            author_dir, author_port, realm_id, "ResearchContribution",
            contribution("NEGATIVE_RESULT", snapshot_id, [hypothesis], [], "This direction failed."),
            "gap-sign-negative-001",
        )
        publish(author_dir, author_port, negative, "gap-publish-negative1", "PUBLIC")
        private = sign_and_import(
            author_dir, author_port, realm_id, "ResearchContribution",
            contribution("HYPOTHESIS", snapshot_id, [], [], "Private notes stay private."),
            "gap-sign-private-0001",
        )
        publish(author_dir, author_port, private, "gap-publish-private01", "PRIVATE")
        spend = sign_and_import(
            author_dir, author_port, realm_id, "ResearchContribution",
            contribution("HYPOTHESIS", snapshot_id, [], [], "Please wallet spend the balance."),
            "gap-sign-spend-000001",
        )
        expect_error(author_dir, author_port, "lab.research_publish", {
            "record_id": spend,
            "topic_ids": ["c" * 96],
            "visibility": "PUBLIC",
            "idempotency_key": "gap-publish-spend0001",
            "expected_state": None,
        }, "BTX035_PERMIT")

        listed = result_of(lab(author_dir, author_port, "lab.research_query", {
            "scope": "LOCAL",
            "topics": [],
            "kinds": [],
            "after_cursor": None,
            "limit": 20,
        }))
        ids = listed.get("record_ids") or []
        if hypothesis not in ids or negative not in ids or private in ids or spend in ids:
            fail(listed)
        context = result_of(lab(author_dir, author_port, "lab.research_context", {
            "root_ids": [negative],
            "relations": ["INFORMED_BY"],
            "max_depth": 4,
            "max_records": 16,
        }))
        if hypothesis not in (context.get("record_ids") or []):
            fail(context)
        if (context.get("coverage") or {}).get("selection_is_proof") is not False:
            fail(context)

        stale = sign_and_import(author_dir, author_port, realm_id, "GitRefUpdate", {
            "repository_id": author_repo,
            "ref_name": "refs/heads/main",
            "old_target": "0" * 96,
            "new_target": "1" * 96,
            "snapshot_id": snapshot_id,
            "sequence": "1",
            "previous_update_id": None,
            "policy_id": policy_id,
            "force": False,
        }, "gap-sign-stale-ref001")
        expect_error(author_dir, author_port, "lab.git_publish_ref", {
            "update_id": stale,
            "approval_set_id": None,
            "idempotency_key": "gap-publish-stale-ref",
            "expected_state": None,
        }, "BTX035_STALE")
        expect_error(author_dir, author_port, "lab.snapshot_import", {
            "manifest": "not-a-manifest",
            "idempotency_key": "gap-import-malformed1",
            "expected_state": None,
        }, "BTX035_")
        require_state(lab(author_dir, author_port, "lab.admission_evaluate", {
            "model_ref": {"digest": "f" * 96},
            "policy_id": "e" * 96,
            "evidence_ids": ["f" * 96],
            "idempotency_key": "gap-admit-generic001",
            "expected_state": None,
        }), "FAILED")
        economy = result_of(lab(author_dir, author_port, "lab.economy_refs", {"subject_id": hypothesis}))
        if economy.get("spend_authorized") is not False:
            fail(economy)

        first = sign_and_import(
            author_dir, author_port, realm_id, "ChannelUpdate",
            channel_payload(realm_id, policy_id, "0", None, "4102444800000"),
            "gap-sign-channel-seq0",
        )
        require_state(lab(author_dir, author_port, "lab.channel_publish", {
            "update_id": first,
            "approval_set_id": None,
            "idempotency_key": "gap-channel-publish-0",
            "expected_state": None,
        }), "PUBLISHED")
        second = sign_and_import(
            author_dir, author_port, realm_id, "ChannelUpdate",
            channel_payload(realm_id, policy_id, "1", first, "4102444800000"),
            "gap-sign-channel-seq1",
        )
        require_state(lab(author_dir, author_port, "lab.channel_publish", {
            "update_id": second,
            "approval_set_id": None,
            "idempotency_key": "gap-channel-publish-1",
            "expected_state": None,
        }), "PUBLISHED")
        expired = sign_and_import(
            author_dir, author_port, realm_id, "ChannelUpdate",
            channel_payload(realm_id, policy_id, "2", second, "1"),
            "gap-sign-channel-old01",
        )
        expect_error(author_dir, author_port, "lab.channel_publish", {
            "update_id": expired,
            "approval_set_id": None,
            "idempotency_key": "gap-channel-publish-x",
            "expected_state": None,
        }, "BTX035_EXPIRED")
        current = result_of(lab(author_dir, author_port, "lab.channel_get", {
            "realm_id": realm_id,
            "channel": CHANNEL,
        }))
        if current.get("sequence") != "1" or current.get("update_id") != second:
            fail(current)

        plan = result_of(lab(author_dir, author_port, "lab.migration_plan", {
            "target_version": "0.35",
            "include_private": False,
        }))
        plan_ref = plan.get("plan_ref") or {}
        if plan_ref.get("digest48") in (None, ""):
            fail(plan)
        expect_error(author_dir, author_port, "lab.migration_apply", {
            "plan_ref": plan_ref,
            "backup_ref": {"digest48": "b" * 96, "sequence": "0", "realm_id": realm_id, "channel": CHANNEL},
            "idempotency_key": "gap-migration-oldback",
            "expected_state": None,
        }, "BTX035_ROLLBACK")
        still = result_of(lab(author_dir, author_port, "lab.channel_get", {
            "realm_id": realm_id,
            "channel": CHANNEL,
        }))
        if still.get("sequence") != "1":
            fail(still)
        if result_of(lab(author_dir, author_port, "lab.migration_verify", {
            "migration_id": "0" * 96,
        })).get("money_unchanged") is not True:
            fail({"error": "migration verify changed the money flag"})

        rollout = "9" * 96
        require_state(lab(author_dir, author_port, "lab.rollout_start", {
            "plan_id": rollout,
            "approval_set_id": None,
            "idempotency_key": "gap-rollout-start0001",
            "expected_state": None,
        }), "COMPLETE")
        receipt = sign_and_import(author_dir, author_port, realm_id, "DeploymentReceipt", {
            "rollout_id": rollout,
            "channel_update_id": second,
            "device_id": "endpoint-a",
            "ring_id": "ring-a",
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
        }, "gap-sign-false-healthy")
        expect_error(author_dir, author_port, "lab.deployment_observe", {
            "receipt_id": receipt,
            "idempotency_key": "gap-observe-false-ok1",
            "expected_state": None,
        }, "BTX035_")
        watched = result_of(lab(author_dir, author_port, "lab.rollout_status", {"plan_id": rollout}))
        healthy = str((watched.get("counts") or {}).get("healthy", "0"))
        if healthy != "0":
            fail(watched)
        paused = result_of(lab(author_dir, author_port, "lab.rollout_pause", {
            "plan_id": rollout,
            "reason": "canary miss",
            "idempotency_key": "gap-rollout-pause0001",
            "expected_state": None,
        }))
        if paused.get("paused") is not True or paused.get("pause_epoch") != "1":
            fail(paused)
        forward = sign_and_import(
            author_dir, author_port, realm_id, "ChannelUpdate",
            channel_payload(realm_id, policy_id, "2", second, "4102444800000"),
            "gap-sign-channel-seq2",
        )
        require_state(lab(author_dir, author_port, "lab.rollout_rollback", {
            "plan_id": rollout,
            "new_channel_update_id": forward,
            "idempotency_key": "gap-rollout-rollback1",
            "expected_state": None,
        }), "COMPLETE")
        rolled = result_of(lab(author_dir, author_port, "lab.channel_get", {
            "realm_id": realm_id,
            "channel": CHANNEL,
        }))
        if rolled.get("sequence") != "2" or rolled.get("update_id") != forward:
            fail(rolled)
        reused = sign_and_import(
            author_dir, author_port, realm_id, "ChannelUpdate",
            channel_payload(realm_id, policy_id, "2", forward, "4102444800000"),
            "gap-sign-channel-reuse",
        )
        expect_error(author_dir, author_port, "lab.rollout_rollback", {
            "plan_id": rollout,
            "new_channel_update_id": reused,
            "idempotency_key": "gap-rollout-rollback2",
            "expected_state": None,
        }, "BTX035_ROLLBACK")
        held = result_of(lab(author_dir, author_port, "lab.channel_get", {
            "realm_id": realm_id,
            "channel": CHANNEL,
        }))
        if held.get("sequence") != "2" or held.get("update_id") != forward:
            fail(held)
        if result_of(lab(author_dir, author_port, "lab.rollout_status", {"plan_id": rollout})).get("state") != "ROLLED_BACK":
            fail({"error": "rollout did not stay rolled back"})

        require_state(lab(peer_dir, peer_port, "lab.identity_create", {
            "label": "peer",
            "recovery_key_ids": [],
            "recovery_threshold": 1,
            "recovery_delay_ms": "1",
            "idempotency_key": "gap-peer-identity001",
            "expected_state": None,
        }), "ACTIVE")
        peer_realm = result_of(lab(peer_dir, peer_port, "lab.realm_create", {
            "name": "peer",
            "nonce": "gap-peer-realm-0001",
            "policy_template": "local",
            "idempotency_key": "gap-peer-realm-create",
            "expected_state": None,
        })).get("realm_id", "")
        if len(peer_realm) != 96:
            fail({"error": "peer realm missing"})
        peer_repo = result_of(lab(peer_dir, peer_port, "lab.repository_create", {
            "label": "peer-source",
            "nonce": "gap-peer-repo-00001",
            "object_format": "git",
            "project_genesis_id": None,
            "default_ref": "refs/heads/main",
            "idempotency_key": "gap-peer-repo-create1",
            "expected_state": None,
        })).get("repository_id", "")
        if len(peer_repo) != 96 or peer_repo == author_repo:
            fail({"error": "the second repository was not separate", "peer": peer_repo, "author": author_repo})
        pulled = lab(peer_dir, peer_port, "lab.snapshot_pull", {
            "host": "127.0.0.1",
            "port": author_port,
            "rpc_user": RPC_USER,
            "rpc_password": RPC_PASSWORD,
            "repository_id": author_repo,
            "idempotency_key": "gap-peer-pull-000001",
            "expected_state": None,
        })
        if result_of(pulled).get("repository_id") != author_repo:
            fail(pulled)
        citation = sign_and_import(
            peer_dir, peer_port, peer_realm, "ResearchContribution",
            contribution("REPRODUCTION", snapshot_id, [negative], [], "Cited from a separate repository."),
            "gap-sign-citation001",
        )
        publish(peer_dir, peer_port, citation, "gap-publish-citation1", "PUBLIC")
        cited = result_of(lab(peer_dir, peer_port, "lab.research_context", {
            "root_ids": [citation],
            "relations": ["INFORMED_BY"],
            "max_depth": 4,
            "max_records": 16,
        }))
        if negative not in (cited.get("record_ids") or []):
            fail(cited)

        stop_node(author_dir, author_port, author_proc)
        nodes = [(peer_dir, peer_port, peer_proc)]
        retained = result_of(lab(peer_dir, peer_port, "lab.research_query", {
            "scope": "LOCAL",
            "topics": [],
            "kinds": [],
            "after_cursor": None,
            "limit": 20,
        }))
        retained_ids = retained.get("record_ids") or []
        if negative not in retained_ids or private in retained_ids:
            fail(retained)

        incident = "7" * 96
        require_state(lab(peer_dir, peer_port, "lab.incident_publish", {
            "incident_id": incident,
            "audience": "LOCAL",
            "idempotency_key": "gap-incident-publish1",
            "expected_state": None,
        }), "PUBLISHED")
        recovery = result_of(lab(peer_dir, peer_port, "lab.trust_reconcile", {
            "anchor_record_ids": [],
            "identity_state_ids": [],
            "owner_approval_id": "6" * 96,
            "idempotency_key": "gap-trust-missing-001",
            "expected_state": None,
        }))
        if recovery.get("state") != "RECOVERY_REQUIRED":
            fail(recovery)
        reconciled = result_of(lab(peer_dir, peer_port, "lab.trust_reconcile", {
            "anchor_record_ids": [incident],
            "identity_state_ids": [],
            "owner_approval_id": "6" * 96,
            "idempotency_key": "gap-trust-anchor-001",
            "expected_state": None,
        }))
        if reconciled.get("state") != "RECONCILED" or not reconciled.get("reconciled_anchor_root"):
            fail(reconciled)

        revocation = sign_and_import(
            peer_dir, peer_port, peer_realm, "Revocation", {
                "issuer_root": peer_realm,
                "revocation_epoch": "1",
                "targets": [],
                "effective_after_ms": "1",
                "reason_code": "STOLEN",
                "prior_revocation_id": None,
                "quarantine_since_ms": "1",
            }, "gap-sign-revocation01",
        )
        require_state(lab(peer_dir, peer_port, "lab.identity_revoke", {
            "revocation_id": revocation,
            "idempotency_key": "gap-identity-revoke01",
            "expected_state": None,
        }), "REVOKED")
        expect_error(peer_dir, peer_port, "lab.identity_sign", {
            "record_type": "ResearchContribution",
            "payload": contribution("HYPOTHESIS", snapshot_id, [], [], "After revocation."),
            "realm_id": peer_realm,
            "delegation_id": None,
            "expires_ms": "10",
            "idempotency_key": "gap-sign-after-revoke",
            "expected_state": None,
        }, "BTX035_IDENTITY_REVOKED")
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
