#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Disposable shieldedv2dev reset-network launch rehearsal with evidence capture."""

from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import time

from feature_shielded_v2_multinode_validation import ShieldedV2MultinodeValidationTest
from test_framework.shielded_utils import unlock_wallet
from test_framework.util import assert_equal


class ShieldedV2DevLaunchRehearsalTest(ShieldedV2MultinodeValidationTest):
    EXPECTED_GENESIS_HASH = "4ed72f2a7db044ff555197cddde63b1f50b74d750674316f75c3571ade9c80a3"

    def add_options(self, parser):
        super().add_options(parser)
        parser.add_argument(
            "--artifact",
            dest="artifact",
            default=None,
            help="Write a JSON launch-rehearsal artifact to this path",
        )

    def set_test_params(self):
        super().set_test_params()
        self.chain = "shieldedv2dev"

    @staticmethod
    def utc_now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def capture_node_state(self, index):
        node = self.nodes[index]
        info = node.getblockchaininfo()
        mining = node.getmininginfo()
        return {
            "node": index,
            "chain": info["chain"],
            "blocks": info["blocks"],
            "headers": info["headers"],
            "bestblockhash": info["bestblockhash"],
            "initialblockdownload": info["initialblockdownload"],
            "shielded_retention": info["shielded_retention"],
            "snapshot_sync": info["snapshot_sync"],
            "algorithm": mining["algorithm"],
        }

    def write_artifact(self, payload):
        if not self.options.artifact:
            return
        artifact_path = Path(self.options.artifact)
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def run_test(self):
        started_at = self.utc_now()
        started_monotonic = time.monotonic()

        bootstrap = {
            "per_node": [],
            "genesis_hashes": {},
        }
        for index, node in enumerate(self.nodes):
            info = node.getblockchaininfo()
            assert_equal(info["chain"], "shieldedv2dev")
            genesis_hash = node.getblockhash(0)
            assert_equal(genesis_hash, self.EXPECTED_GENESIS_HASH)
            bootstrap["per_node"].append({
                "node": index,
                "chain": info["chain"],
                "blocks": info["blocks"],
                "headers": info["headers"],
                "bestblockhash": info["bestblockhash"],
            })
            bootstrap["genesis_hashes"][f"node{index}"] = genesis_hash

        self.log.info("Run the full mixed-family shielded_v2 workload on the disposable shieldedv2dev reset network")
        scenario = self.run_validation_scenario()

        self.log.info("Restart the active wallet node and continue shielded flows on the reset network")
        self.restart_node(1)
        node1 = self.nodes[1]
        for peer in (0, 2, 3):
            try:
                self.connect_nodes(1, peer)
            except Exception:
                pass
        self.wait_until(lambda: len(node1.getpeerinfo()) >= 2, timeout=60)
        self.sync_blocks(self.nodes)
        self.assert_default_retention_surface(node1, scenario["expected_height"])

        if scenario["wallets"]["user"] not in node1.listwallets():
            node1.loadwallet(scenario["wallets"]["user"])
        if scenario["wallets"]["operator"] not in self.nodes[2].listwallets():
            self.nodes[2].loadwallet(scenario["wallets"]["operator"])

        user_wallet = unlock_wallet(node1, scenario["wallets"]["user"])
        operator_wallet = unlock_wallet(self.nodes[2], scenario["wallets"]["operator"])

        post_restart_recipient = operator_wallet.z_getnewaddress()
        post_restart_result = user_wallet.z_sendmany([{"address": post_restart_recipient, "amount": Decimal("0.02")}])
        post_restart_txid = post_restart_result["txid"]
        assert_equal(user_wallet.z_viewtransaction(post_restart_txid)["family"], "v2_send")

        self.wait_for_mempool([post_restart_txid], nodes=self.nodes[:3])
        post_restart_block = self.generatetoaddress(
            node1, 1, scenario["wallets"]["user_mine_addr"], sync_fun=self.no_op
        )[0]
        self.sync_blocks(self.nodes)

        self.assert_block_family(self.nodes[3], post_restart_txid, post_restart_block, "v2_send")

        hrp_addresses = {
            "miner": self.nodes[0].get_wallet_rpc(scenario["wallets"]["miner"]).getnewaddress(address_type="p2mr"),
            "user": user_wallet.getnewaddress(address_type="p2mr"),
            "operator": operator_wallet.getnewaddress(address_type="p2mr"),
        }
        for address in hrp_addresses.values():
            assert address.startswith("btxv2"), address

        final_height = self.nodes[0].getblockcount()
        for node in self.nodes:
            self.assert_default_retention_surface(node, final_height)
            assert_equal(node.getblockhash(0), self.EXPECTED_GENESIS_HASH)
            assert_equal(node.getbestblockhash(), self.nodes[0].getbestblockhash())
            assert_equal(node.getrawmempool(), [])

        finished_at = self.utc_now()
        artifact = {
            "generated_at": finished_at,
            "overall_status": "pass",
            "chain": "shieldedv2dev",
            "expected_genesis_hash": self.EXPECTED_GENESIS_HASH,
            "bootstrap": bootstrap,
            "started_at": started_at,
            "finished_at": finished_at,
            "runtime_seconds": round(time.monotonic() - started_monotonic, 3),
            "mixed_family_workload": scenario,
            "wallet_node_restart": {
                "restarted_node": 1,
                "wallet": scenario["wallets"]["user"],
                "post_restart_txid": post_restart_txid,
                "post_restart_block": post_restart_block,
                "post_restart_recipient": post_restart_recipient,
            },
            "hrp_addresses": hrp_addresses,
            "final_height": final_height,
            "bestblockhash": self.nodes[0].getbestblockhash(),
            "final_nodes": [self.capture_node_state(index) for index in range(len(self.nodes))],
            "resources": {
                "cloud_resources": [],
                "cost_usd": 0,
            },
        }
        self.write_artifact(artifact)


if __name__ == "__main__":
    ShieldedV2DevLaunchRehearsalTest(__file__).main()
