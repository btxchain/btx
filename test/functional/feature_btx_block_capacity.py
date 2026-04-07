#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""BTX block-capacity defaults and mining policy checks."""

from decimal import Decimal

from test_framework.bridge_utils import (
    build_signed_shielded_relay_fixture_tx,
    build_unsigned_shielded_relay_fixture_tx,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

MAX_BLOCK_SHIELDED_VERIFY_UNITS = 240_000
MAX_BLOCK_SHIELDED_SCAN_UNITS = 24_576
MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS = 24_576
HIGH_SHIELDED_FEE_DELTA = 100_000_000
DEFAULT_EGRESS_OUTPUT_COUNT = 2
DEFAULT_EGRESS_OUTPUT_CHUNK_COUNT = 1
REBALANCE_USAGE = {
    "verify": 100,
    "scan": 0,
    "tree": 1,
}
SETTLEMENT_USAGE = {
    "verify": 100,
    "scan": 0,
    "tree": 0,
}
EGRESS_USAGE = {
    "verify": 100,
    "scan": DEFAULT_EGRESS_OUTPUT_COUNT + DEFAULT_EGRESS_OUTPUT_CHUNK_COUNT,
    "tree": DEFAULT_EGRESS_OUTPUT_COUNT,
}


class BTXBlockCapacityTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_template_usage(self, node, expected_txid, usage):
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        txids = [entry["txid"] for entry in tmpl["transactions"]]
        assert_equal(txids, [expected_txid])
        assert_equal(tmpl["block_capacity"]["template_shielded_verify_units"], usage["verify"])
        assert_equal(tmpl["block_capacity"]["template_shielded_scan_units"], usage["scan"])
        assert_equal(tmpl["block_capacity"]["template_shielded_tree_update_units"], usage["tree"])
        assert_equal(
            tmpl["block_capacity"]["remaining_shielded_verify_units"],
            MAX_BLOCK_SHIELDED_VERIFY_UNITS - usage["verify"],
        )
        assert_equal(
            tmpl["block_capacity"]["remaining_shielded_scan_units"],
            MAX_BLOCK_SHIELDED_SCAN_UNITS - usage["scan"],
        )
        assert_equal(
            tmpl["block_capacity"]["remaining_shielded_tree_update_units"],
            MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS - usage["tree"],
        )

    def assert_mined_usage(self, node, block_hash, expected_txid, usage):
        block = node.getblock(block_hash, 2)
        mined_txids = [tx["txid"] for tx in block["tx"]]
        assert expected_txid in mined_txids, mined_txids
        mining_info = node.getmininginfo()
        assert_equal(mining_info["currentblockshieldedverifyunits"], usage["verify"])
        assert_equal(mining_info["currentblockshieldedscanunits"], usage["scan"])
        assert_equal(mining_info["currentblockshieldedtreeupdateunits"], usage["tree"])

    def run_test(self):
        node = self.nodes[0]

        # Ensure we are out of IBD so getblocktemplate is available.
        self.generate(node, 1)

        # TEST: rpc_getblocktemplate_block_capacity
        # TEST: mining_template_respects_policy_weight
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(tmpl["weightlimit"], 24_000_000)
        assert_equal(tmpl["sizelimit"], 24_000_000)
        assert_equal(tmpl["sigoplimit"], 480_000)
        assert_equal(tmpl["block_capacity"]["max_block_weight"], 24_000_000)
        assert_equal(tmpl["block_capacity"]["max_block_serialized_size"], 24_000_000)
        assert_equal(tmpl["block_capacity"]["max_block_sigops_cost"], 480_000)
        assert_equal(tmpl["block_capacity"]["default_block_max_weight"], 24_000_000)
        assert_equal(tmpl["block_capacity"]["witness_scale_factor"], 1)
        assert_equal(tmpl["block_capacity"]["policy_block_max_weight"], 24_000_000)
        assert_equal(tmpl["block_capacity"]["max_block_shielded_verify_units"], MAX_BLOCK_SHIELDED_VERIFY_UNITS)
        assert_equal(tmpl["block_capacity"]["max_block_shielded_scan_units"], MAX_BLOCK_SHIELDED_SCAN_UNITS)
        assert_equal(tmpl["block_capacity"]["max_block_shielded_tree_update_units"], MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS)
        assert_equal(tmpl["block_capacity"]["template_shielded_verify_units"], 0)
        assert_equal(tmpl["block_capacity"]["template_shielded_scan_units"], 0)
        assert_equal(tmpl["block_capacity"]["template_shielded_tree_update_units"], 0)
        assert_equal(tmpl["block_capacity"]["remaining_shielded_verify_units"], MAX_BLOCK_SHIELDED_VERIFY_UNITS)
        assert_equal(tmpl["block_capacity"]["remaining_shielded_scan_units"], MAX_BLOCK_SHIELDED_SCAN_UNITS)
        assert_equal(tmpl["block_capacity"]["remaining_shielded_tree_update_units"], MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS)
        assert_equal(tmpl["matmul"]["n"], tmpl["matmul_n"])
        assert_equal(tmpl["matmul"]["b"], tmpl["matmul_b"])
        assert_equal(tmpl["matmul"]["r"], tmpl["matmul_r"])
        assert_equal(tmpl["matmul"]["seed_a"], tmpl["seed_a"])
        assert_equal(tmpl["matmul"]["seed_b"], tmpl["seed_b"])

        # The consensus limit is stable even if the local template policy is overridden.
        # TEST: mining_template_can_use_consensus_max
        self.restart_node(0, extra_args=["-blockmaxweight=24000000"])
        node = self.nodes[0]
        self.generate(node, 1)

        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(tmpl["weightlimit"], 24_000_000)
        assert_equal(tmpl["sizelimit"], 24_000_000)
        assert_equal(tmpl["sigoplimit"], 480_000)
        assert_equal(tmpl["block_capacity"]["max_block_weight"], 24_000_000)
        assert_equal(tmpl["block_capacity"]["policy_block_max_weight"], 24_000_000)
        assert_equal(tmpl["block_capacity"]["remaining_shielded_verify_units"], MAX_BLOCK_SHIELDED_VERIFY_UNITS)
        assert_equal(tmpl["block_capacity"]["remaining_shielded_scan_units"], MAX_BLOCK_SHIELDED_SCAN_UNITS)
        assert_equal(tmpl["block_capacity"]["remaining_shielded_tree_update_units"], MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS)

        # TEST: rpc_getmininginfo_algorithm
        # TEST: rpc_getmininginfo_reports_capacity
        mining_info = node.getmininginfo()
        assert_equal(mining_info["algorithm"], "matmul")
        assert_equal(mining_info["powalgorithm"], "matmul")
        assert_equal(mining_info["max_block_weight"], 24_000_000)
        assert_equal(mining_info["policy_block_max_weight"], 24_000_000)
        assert_equal(mining_info["max_block_shielded_verify_units"], MAX_BLOCK_SHIELDED_VERIFY_UNITS)
        assert_equal(mining_info["max_block_shielded_scan_units"], MAX_BLOCK_SHIELDED_SCAN_UNITS)
        assert_equal(mining_info["max_block_shielded_tree_update_units"], MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS)
        assert_equal(mining_info["currentblockshieldedverifyunits"], 0)
        assert_equal(mining_info["currentblockshieldedscanunits"], 0)
        assert_equal(mining_info["currentblockshieldedtreeupdateunits"], 0)

        self.log.info("Build and mine live shielded fixture families through getblocktemplate")
        node.createwallet(wallet_name="shielded", descriptors=True)
        wallet = node.get_wallet_rpc("shielded")
        mine_addr = wallet.getnewaddress(address_type="p2mr")
        self.generatetoaddress(node, 110, mine_addr)

        relay_utxos = [
            utxo
            for utxo in wallet.listunspent(101)
            if utxo.get("spendable", False) and Decimal(str(utxo["amount"])) > Decimal("0.001")
        ]
        assert len(relay_utxos) >= 2, relay_utxos

        self.log.info("Rebalance should appear in getblocktemplate and mine with its shielded resource footprint")
        rebalance_fixture = build_signed_shielded_relay_fixture_tx(
            self, node, wallet, "rebalance", relay_utxos[0], require_mempool_accept=True
        )
        rebalance_decoded = node.decoderawtransaction(rebalance_fixture["signed_tx_hex"])
        assert_equal(rebalance_decoded["shielded"]["bundle_type"], "v2")
        assert_equal(rebalance_decoded["shielded"]["family"], "v2_rebalance")
        assert_equal(
            rebalance_decoded["shielded"]["payload"]["netting_manifest"]["manifest_id"],
            rebalance_fixture["netting_manifest_id"],
        )
        assert_equal(len(rebalance_decoded["shielded"]["payload"]["reserve_deltas"]), 2)
        assert_equal(node.sendrawtransaction(rebalance_fixture["signed_tx_hex"], 0), rebalance_fixture["txid"])
        self.assert_template_usage(node, rebalance_fixture["txid"], REBALANCE_USAGE)
        rebalance_block = self.generatetoaddress(node, 1, mine_addr)[0]
        self.assert_mined_usage(node, rebalance_block, rebalance_fixture["txid"], REBALANCE_USAGE)
        rebalance_verbose = node.getrawtransaction(rebalance_fixture["txid"], True, rebalance_block)
        assert_equal(
            rebalance_verbose["shielded"]["payload"]["netting_manifest"]["manifest_id"],
            rebalance_fixture["netting_manifest_id"],
        )
        assert_equal(node.getrawmempool(), [])

        self.log.info("Reserve-bound settlement anchors should appear in getblocktemplate once the manifest is anchored")
        settlement_fixture = build_signed_shielded_relay_fixture_tx(
            self, node, wallet, "settlement_anchor_receipt", relay_utxos[1], require_mempool_accept=True
        )
        settlement_decoded = node.decoderawtransaction(settlement_fixture["signed_tx_hex"])
        assert_equal(settlement_decoded["shielded"]["bundle_type"], "v2")
        assert_equal(settlement_decoded["shielded"]["family"], "v2_settlement_anchor")
        assert_equal(
            settlement_decoded["shielded"]["payload"]["anchored_netting_manifest_id"],
            settlement_fixture["netting_manifest_id"],
        )
        assert_equal(len(settlement_decoded["shielded"]["payload"]["reserve_deltas"]), 2)
        assert_equal(node.sendrawtransaction(settlement_fixture["signed_tx_hex"], 0), settlement_fixture["txid"])
        self.assert_template_usage(node, settlement_fixture["txid"], SETTLEMENT_USAGE)
        settlement_block = self.generatetoaddress(node, 1, mine_addr)[0]
        self.assert_mined_usage(node, settlement_block, settlement_fixture["txid"], SETTLEMENT_USAGE)
        settlement_verbose = node.getrawtransaction(settlement_fixture["txid"], True, settlement_block)
        assert_equal(
            settlement_verbose["shielded"]["payload"]["anchored_netting_manifest_id"],
            settlement_fixture["netting_manifest_id"],
        )
        assert_equal(node.getrawmempool(), [])

        self.log.info("Bare v2 egress should appear in getblocktemplate once prioritised against the active settlement anchor")
        egress_fixture = build_unsigned_shielded_relay_fixture_tx(
            self, node, "egress_receipt"
        )
        assert_equal(
            egress_fixture["settlement_anchor_digest"],
            settlement_fixture["settlement_anchor_digest"],
        )
        egress_decoded = node.decoderawtransaction(egress_fixture["tx_hex"])
        assert_equal(egress_decoded["shielded"]["bundle_type"], "v2")
        assert_equal(egress_decoded["shielded"]["family"], "v2_egress_batch")
        assert_equal(
            egress_decoded["shielded"]["payload"]["settlement_anchor"],
            egress_fixture["settlement_anchor_digest"],
        )
        assert_equal(len(egress_decoded["shielded"]["payload"]["outputs"]), DEFAULT_EGRESS_OUTPUT_COUNT)
        node.prioritisetransaction(txid=egress_fixture["txid"], fee_delta=HIGH_SHIELDED_FEE_DELTA)
        assert_equal(node.sendrawtransaction(egress_fixture["tx_hex"], 0), egress_fixture["txid"])
        self.assert_template_usage(node, egress_fixture["txid"], EGRESS_USAGE)
        egress_block = self.generatetoaddress(node, 1, mine_addr)[0]
        self.assert_mined_usage(node, egress_block, egress_fixture["txid"], EGRESS_USAGE)
        egress_verbose = node.getrawtransaction(egress_fixture["txid"], True, egress_block)
        assert_equal(
            egress_verbose["shielded"]["payload"]["settlement_anchor"],
            egress_fixture["settlement_anchor_digest"],
        )
        assert_equal(node.getrawmempool(), [])


if __name__ == "__main__":
    BTXBlockCapacityTest(__file__).main()
