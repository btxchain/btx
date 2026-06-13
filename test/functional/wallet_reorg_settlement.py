#!/usr/bin/env python3
# Copyright (c) 2026-present The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet settlement metadata across a shallow heavier-chain reorg."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_is_hash_string,
)


class WalletReorgSettlementTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [["-walletreorgsafetydepth=3", "-walletreorgholdblocks=8", "-walletreorgholdseconds=60"] for _ in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node0, node1 = self.nodes
        self.sync_all()

        self.log.info("Mine a wallet transaction to settlement-safe depth on the public branch")
        self.disconnect_nodes(0, 1)
        txid = node0.sendtoaddress(node0.getnewaddress(), Decimal("10"))
        tx_hex = node0.gettransaction(txid)["hex"]
        self.generate(node0, 4, sync_fun=self.no_op)
        node0.syncwithvalidationinterfacequeue()

        tx_before_reorg = node0.gettransaction(txid)
        stale_tip = node0.getbestblockhash()
        stale_tx_blockhash = tx_before_reorg["blockhash"]
        assert_equal(tx_before_reorg["confirmations"], 4)
        assert_equal(tx_before_reorg["settlement_confirmations_required"], 3)
        assert_equal(tx_before_reorg["settlement_reorg_hold_active"], False)
        assert_equal(tx_before_reorg["settlement_safe"], True)
        assert_equal(tx_before_reorg["settlement_status"], "safe")
        assert_equal(tx_before_reorg["wallet_tx_state"], "confirmed")
        walletinfo_before_reorg = node0.getwalletinfo()
        assert_equal(walletinfo_before_reorg["wallet_reorg_safety_depth"], 3)
        assert_equal(walletinfo_before_reorg["wallet_reorg_hold_blocks"], 8)
        assert_equal(walletinfo_before_reorg["wallet_reorg_hold_seconds"], 60)
        assert_equal(walletinfo_before_reorg["settlement_reorg_hold_active"], False)

        outputs_before_reorg = [utxo for utxo in node0.listunspent(0) if utxo["txid"] == txid]
        assert outputs_before_reorg
        assert all(utxo["settlement_safe"] for utxo in outputs_before_reorg)

        self.log.info("Build a heavier private branch that includes the same transaction later")
        self.generate(node1, 4, sync_fun=self.no_op)
        node1.sendrawtransaction(tx_hex)
        self.generate(node1, 10, sync_fun=self.no_op)

        self.log.info("Follow the heavier branch, but downgrade wallet settlement safety")
        self.connect_nodes(0, 1)
        self.sync_blocks()
        node0.syncwithvalidationinterfacequeue()

        tx_after_reorg = node0.gettransaction(txid)
        assert_equal(tx_after_reorg["confirmations"], 10)
        assert tx_after_reorg["blockhash"] != stale_tx_blockhash
        assert_equal(tx_after_reorg["settlement_confirmations_required"], 3)
        assert_equal(tx_after_reorg["settlement_reorg_hold_active"], True)
        assert tx_after_reorg["settlement_reorg_hold_remaining_seconds"] > 0
        assert_equal(tx_after_reorg["settlement_safe"], False)
        assert_equal(tx_after_reorg["settlement_status"], "reorg_hold")
        assert_equal(tx_after_reorg["wallet_tx_state"], "confirmed")

        walletinfo_after_reorg = node0.getwalletinfo()
        assert_equal(walletinfo_after_reorg["settlement_reorg_hold_active"], True)
        assert walletinfo_after_reorg["settlement_reorg_hold_remaining_seconds"] > 0
        assert_equal(walletinfo_after_reorg["settlement_safe_balance"], Decimal("0E-8"))
        assert_equal(walletinfo_after_reorg["last_reorg_disconnected_block"], stale_tip)

        self.log.info("Restart during the hold and keep settlement-safe reporting disabled")
        self.restart_node(0, self.extra_args[0])
        node0 = self.nodes[0]
        node0.syncwithvalidationinterfacequeue()
        tx_after_restart = node0.gettransaction(txid)
        assert_equal(tx_after_restart["settlement_reorg_hold_active"], True)
        assert tx_after_restart["settlement_reorg_hold_remaining_seconds"] > 0
        assert_equal(tx_after_restart["settlement_safe"], False)
        assert_equal(tx_after_restart["settlement_status"], "reorg_hold")
        assert_equal(node0.getwalletinfo()["settlement_safe_balance"], Decimal("0E-8"))

        outputs_after_reorg = [utxo for utxo in node0.listunspent(0) if utxo["txid"] == txid]
        assert outputs_after_reorg
        assert all(not utxo["settlement_safe"] for utxo in outputs_after_reorg)
        assert all(utxo["settlement_reorg_hold_active"] for utxo in outputs_after_reorg)

        stale_entries = node0.listsinceblock(stale_tip)["removed"]
        removed_tx = next(tx for tx in stale_entries if tx["txid"] == txid)
        assert_equal(removed_tx["removed_blockhash"], stale_tx_blockhash)
        assert_equal(removed_tx["removed_blockheight"], tx_before_reorg["blockheight"])
        assert_is_hash_string(removed_tx["removed_blockhash"])
        assert removed_tx["removed_blockindex"] >= 0
        assert_equal(removed_tx["settlement_safe"], False)
        assert_equal(removed_tx["settlement_status"], "reorg_hold")

        self.log.info("Release the automatic reorg settlement hold without operator intervention")
        hold_until_time = tx_after_restart["settlement_reorg_hold_until_time"]
        node0.setmocktime(hold_until_time + 1)
        node1.setmocktime(hold_until_time + 1)
        self.connect_nodes(0, 1)
        remaining_blocks = tx_after_restart["settlement_reorg_hold_remaining_blocks"]
        if remaining_blocks > 0:
            self.generate(node1, remaining_blocks, sync_fun=lambda: self.sync_all())
            node0.syncwithvalidationinterfacequeue()

        tx_after_hold = node0.gettransaction(txid)
        assert_equal(tx_after_hold["settlement_reorg_hold_active"], False)
        assert_equal(tx_after_hold["settlement_reorg_hold_remaining_blocks"], 0)
        assert_equal(tx_after_hold["settlement_reorg_hold_remaining_seconds"], 0)
        assert_equal(tx_after_hold["settlement_safe"], True)
        assert_equal(tx_after_hold["settlement_status"], "safe")
        assert node0.getwalletinfo()["settlement_safe_balance"] > Decimal("0")
        node0.setmocktime(0)
        node1.setmocktime(0)


if __name__ == '__main__':
    WalletReorgSettlementTest(__file__).main()
