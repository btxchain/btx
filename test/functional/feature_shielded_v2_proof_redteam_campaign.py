#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Live malformed-proof shielded_v2 red-team campaign with evidence capture."""

from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import subprocess
import time

from test_framework.authproxy import JSONRPCException
from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ShieldedV2ProofRedteamCampaignTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)
        parser.add_argument(
            "--artifact",
            dest="artifact",
            default=None,
            help="Write a JSON campaign artifact to this path",
        )
        parser.add_argument(
            "--corpus",
            dest="corpus",
            default=None,
            help="Write the malformed-proof corpus JSON to this path",
        )

    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        self.rpc_timeout = 600
        self.extra_args = [
            ["-autoshieldcoinbase=0", "-dandelion=0"],
            ["-autoshieldcoinbase=0", "-dandelion=0", "-walletbroadcast=0"],
            ["-autoshieldcoinbase=0", "-dandelion=0"],
            ["-autoshieldcoinbase=0", "-dandelion=0"],
        ]
        self._debug_offsets = {}

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    @staticmethod
    def utc_now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def write_artifact(self, payload):
        if not self.options.artifact:
            return
        artifact_path = Path(self.options.artifact)
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def connect_connected_mesh(self):
        for a, b in ((0, 1), (0, 2), (1, 2)):
            try:
                self.connect_nodes(a, b)
            except Exception:
                pass
        self.wait_until(lambda: all(len(node.getpeerinfo()) >= 2 for node in self.nodes[:3]), timeout=60)
        self.sync_blocks(self.nodes[:3])
        self.sync_mempools(self.nodes[:3])

    def isolate_late_joiner(self):
        for peer in range(3):
            try:
                self.disconnect_nodes(3, peer)
            except Exception:
                pass
        self.wait_until(lambda: len(self.nodes[3].getpeerinfo()) == 0, timeout=60)

    def connect_late_joiner(self):
        for peer in range(3):
            try:
                self.connect_nodes(3, peer)
            except Exception:
                pass
        self.wait_until(lambda: len(self.nodes[3].getpeerinfo()) >= 2, timeout=60)
        self.sync_blocks(self.nodes)
        self.sync_mempools(self.nodes)

    def reset_debug_offsets(self, node_indexes):
        for index in node_indexes:
            path = self.nodes[index].debug_log_path
            self._debug_offsets[index] = path.stat().st_size if path.exists() else 0

    def consume_debug_trace(self, node_index):
        path = self.nodes[node_index].debug_log_path
        if not path.exists():
            return []
        offset = self._debug_offsets.get(node_index, 0)
        size = path.stat().st_size
        if size < offset:
            offset = 0
        with path.open("rb") as fh:
            fh.seek(offset)
            data = fh.read()
        self._debug_offsets[node_index] = size
        text = data.decode("utf-8", errors="replace")
        lines = []
        for line in text.splitlines():
            lowered = line.lower()
            if "shielded" in lowered or "verifyv2sendproof" in line or "bad-shielded-proof" in lowered:
                lines.append(line)
        return lines[-20:]

    def capture_node_state(self, index):
        node = self.nodes[index]
        info = node.getblockchaininfo()
        return {
            "node": index,
            "blocks": info["blocks"],
            "headers": info["headers"],
            "bestblockhash": info["bestblockhash"],
            "initialblockdownload": info["initialblockdownload"],
            "shielded_retention": info["shielded_retention"],
            "snapshot_sync": info["snapshot_sync"],
            "mempool_size": len(node.getrawmempool()),
        }

    def wait_for_mempool(self, txids, nodes=None):
        if nodes is None:
            nodes = self.nodes
        wanted = set(txids)
        self.wait_until(
            lambda: all(wanted.issubset(set(node.getrawmempool())) for node in nodes),
            timeout=120,
        )
        if len(nodes) > 1:
            self.sync_mempools(nodes)

    def build_base_v2_send(self, user_wallet, miner_wallet, node1, user_mine_addr):
        user_zaddr = user_wallet.z_getnewaddress()
        recipient_zaddr = miner_wallet.z_getnewaddress()

        user_wallet.z_shieldfunds(Decimal("2.0"), user_zaddr)
        self.generatetoaddress(node1, 1, user_mine_addr, sync_fun=self.no_op)
        self.sync_blocks(self.nodes[:3])
        self.sync_mempools(self.nodes[:3])

        ensure_ring_diversity(
            self,
            node1,
            user_wallet,
            user_mine_addr,
            user_zaddr,
            min_notes=16,
            topup_amount=Decimal("0.5"),
            sync_fun=lambda: (self.sync_blocks(self.nodes[:3]), self.sync_mempools(self.nodes[:3])),
        )
        seeded_balance = user_wallet.z_getbalance()
        assert int(seeded_balance["note_count"]) >= 16, seeded_balance

        result = user_wallet.z_sendmany([{"address": recipient_zaddr, "amount": Decimal("0.25")}])
        txid = result["txid"]
        assert_equal(user_wallet.z_viewtransaction(txid)["family"], "v2_send")
        assert txid not in node1.getrawmempool(), txid
        tx_hex = user_wallet.gettransaction(txid)["hex"]
        return {
            "txid": txid,
            "tx_hex": tx_hex,
            "sender_zaddr": user_zaddr,
            "recipient_zaddr": recipient_zaddr,
            "seeded_note_count": int(seeded_balance["note_count"]),
        }

    def generate_corpus(self, base_tx_hex):
        binary = (
            Path(self.config["environment"]["BUILDDIR"])
            / "bin"
            / f"gen_shielded_v2_adversarial_proof_corpus{self.config['environment']['EXEEXT']}"
        )
        if self.options.corpus:
            corpus_path = Path(self.options.corpus)
        else:
            corpus_path = Path(self.options.tmpdir) / "shielded_v2_adversarial_proof_corpus.json"
        base_tx_path = Path(self.options.tmpdir) / "shielded_v2_adversarial_proof_base_tx.hex"
        corpus_path.parent.mkdir(parents=True, exist_ok=True)
        base_tx_path.write_text(base_tx_hex + "\n", encoding="utf-8")
        subprocess.check_call(
            [
                str(binary),
                f"--base-tx-file={base_tx_path}",
                f"--output={corpus_path}",
            ]
        )
        return corpus_path, json.loads(corpus_path.read_text(encoding="utf-8"))

    def assert_variant_rejected(self, node_index, variant):
        node = self.nodes[node_index]
        accept = node.testmempoolaccept([variant["tx_hex"]], 0)[0]
        assert_equal(accept["allowed"], False)
        assert_equal(accept["reject-reason"], variant["expected_reject_reason"])

        error = None
        try:
            node.sendrawtransaction(variant["tx_hex"], 0)
            raise AssertionError(f"{variant['id']} unexpectedly entered node {node_index} mempool")
        except JSONRPCException as e:
            error = e.error
        assert error is not None
        assert variant["expected_reject_reason"] in error["message"], error
        assert_equal(node.getrawmempool(), [])

        return {
            "node": node_index,
            "testmempoolaccept": accept,
            "sendrawtransaction_error": error,
            "debug_trace": self.consume_debug_trace(node_index),
        }

    def run_test(self):
        started_at = self.utc_now()
        started_monotonic = time.monotonic()

        self.isolate_late_joiner()
        self.connect_connected_mesh()

        node0, node1, node2, node3 = self.nodes
        node0.createwallet(wallet_name="miner", descriptors=True)
        node1.createwallet(wallet_name="user", descriptors=True)
        miner_wallet = encrypt_and_unlock_wallet(node0, "miner")
        user_wallet = encrypt_and_unlock_wallet(node1, "user")
        miner_mine_addr = miner_wallet.getnewaddress(address_type="p2mr")
        user_mine_addr = user_wallet.getnewaddress(address_type="p2mr")

        self.log.info("Fund trusted transparent balance and seed enough shielded notes for a real v2_send witness")
        fund_trusted_transparent_balance(
            self,
            node1,
            user_wallet,
            user_mine_addr,
            Decimal("6.0"),
            sync_fun=lambda: (self.sync_blocks(self.nodes[:3]), self.sync_mempools(self.nodes[:3])),
        )

        self.log.info("Build a wallet-originated v2_send without broadcasting it, then derive a malformed-proof corpus from that exact tx")
        base_tx = self.build_base_v2_send(user_wallet, miner_wallet, node1, user_mine_addr)
        corpus_path, corpus = self.generate_corpus(base_tx["tx_hex"])
        assert_equal(corpus["family"], "v2_send")
        assert_equal(corpus["base_txid"], base_tx["txid"])
        assert len(corpus["variants"]) >= 5

        self.log.info("Replay each malformed-proof variant against the active three-node mesh and record consistent reject reasons")
        self.reset_debug_offsets([0, 1, 2])
        campaign_results = []
        for variant in corpus["variants"]:
            node_results = []
            for node_index in (0, 1, 2):
                node_results.append(self.assert_variant_rejected(node_index, variant))
            for node in self.nodes[:3]:
                assert_equal(node.getrawmempool(), [])
            assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
            assert_equal(node0.getbestblockhash(), node2.getbestblockhash())
            campaign_results.append(
                {
                    "id": variant["id"],
                    "txid": variant["txid"],
                    "wtxid": variant["wtxid"],
                    "expected_reject_reason": variant["expected_reject_reason"],
                    "expected_failure_stage": variant["expected_failure_stage"],
                    "nodes": node_results,
                }
            )

        self.log.info("Bring in the late joiner, restart it, and confirm the same malformed corpus still rejects cleanly after sync")
        self.connect_late_joiner()
        self.restart_node(3)
        self.connect_late_joiner()
        self.reset_debug_offsets([3])
        late_joiner_results = []
        for variant in corpus["variants"]:
            late_joiner_results.append(
                {
                    "id": variant["id"],
                    "node": self.assert_variant_rejected(3, variant),
                }
            )
        for node in self.nodes:
            assert_equal(node.getrawmempool(), [])
        self.sync_blocks(self.nodes)

        self.log.info("Broadcast the original valid v2_send after the malformed campaign to prove the network and late joiner still converge normally")
        assert_equal(node1.sendrawtransaction(base_tx["tx_hex"], 0), base_tx["txid"])
        self.wait_for_mempool([base_tx["txid"]], nodes=self.nodes)
        mined_block = self.generatetoaddress(node1, 1, user_mine_addr, sync_fun=self.no_op)[0]
        self.sync_blocks(self.nodes)
        for node in self.nodes:
            assert_equal(node.getrawmempool(), [])
            assert_equal(node.getbestblockhash(), node0.getbestblockhash())
        mined_tx = node3.getrawtransaction(base_tx["txid"], True, mined_block)
        assert_equal(mined_tx["shielded"]["bundle_type"], "v2")
        assert_equal(mined_tx["shielded"]["family"], "v2_send")

        finished_at = self.utc_now()
        artifact = {
            "generated_at": finished_at,
            "overall_status": "pass",
            "started_at": started_at,
            "finished_at": finished_at,
            "runtime_seconds": round(time.monotonic() - started_monotonic, 3),
            "campaign": "shielded_v2_malformed_proof_redteam",
            "base_tx": base_tx,
            "corpus_path": str(corpus_path),
            "corpus_summary": {
                "base_txid": corpus["base_txid"],
                "base_wtxid": corpus["base_wtxid"],
                "variant_count": len(corpus["variants"]),
                "variant_ids": [variant["id"] for variant in corpus["variants"]],
            },
            "active_mesh_rejects": campaign_results,
            "late_joiner_rejects": late_joiner_results,
            "post_campaign_valid_flow": {
                "txid": base_tx["txid"],
                "mined_block": mined_block,
                "final_height": node0.getblockcount(),
                "bestblockhash": node0.getbestblockhash(),
            },
            "consensus_outcome": {
                "malformed_variants_admitted": False,
                "mempool_residue": False,
                "late_joiner_restart_confirmed": True,
                "valid_follow_up_mined": True,
            },
            "final_nodes": [self.capture_node_state(index) for index in range(len(self.nodes))],
            "resources": {
                "cloud_resources": [],
                "cost_usd": 0,
            },
        }
        self.write_artifact(artifact)


if __name__ == "__main__":
    ShieldedV2ProofRedteamCampaignTest(__file__).main()
