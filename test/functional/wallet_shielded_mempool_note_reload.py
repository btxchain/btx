#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Unconfirmed shielded transactions stay known after the wallet is loaded again.

An encrypted wallet loads locked, so the mempool pass at load cannot see its
shielded side. After walletpassphrase:
- the note of a shielding transaction still in the mempool shows again, after
  unload/load and after a restart;
- a note spent by a transaction still in the mempool stays spent, so the next
  send does not pick it again.
"""
from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

PASSPHRASE = "mempool note reload"


class WalletShieldedMempoolNoteReloadTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + ["-autoshieldcoinbase=0", "-nomodelnet"]]
        self.rpc_timeout = 300

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def wallet(self):
        return self.nodes[0].get_wallet_rpc("shielded")

    def unconfirmed_view(self):
        self.nodes[0].syncwithvalidationinterfacequeue()
        notes = self.wallet().z_listunspent(0, 9999999, False, True)
        return Decimal(str(self.wallet().z_getbalance(0)["balance"])), sorted(n.get("confirmations") for n in notes)

    def balances(self):
        self.nodes[0].syncwithvalidationinterfacequeue()
        w = self.wallet()
        return Decimal(str(w.z_getbalance(0)["balance"])), Decimal(str(w.z_getbalance(1)["balance"]))

    def unlock(self):
        self.wallet().walletpassphrase(PASSPHRASE, 600)

    def reload(self):
        node = self.nodes[0]
        node.unloadwallet("shielded")
        node.loadwallet("shielded")
        self.unlock()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("miner")
        miner = node.get_wallet_rpc("miner")
        node.createwallet(wallet_name="shielded", passphrase=PASSPHRASE)
        self.unlock()
        zaddr = self.wallet().z_getnewaddress()
        other_zaddr = self.wallet().z_getnewaddress()
        self.generatetoaddress(node, 18, self.wallet().getnewaddress())
        self.generatetoaddress(node, 101, miner.getnewaddress())

        self.log.info("A note of a shielding transaction still in the mempool")
        txid = self.wallet().z_shieldcoinbase(zaddr, None, 1)["txid"]
        assert txid in node.getrawmempool()
        amount, confs = self.unconfirmed_view()
        assert amount > 0
        assert_equal(confs, [0])

        self.reload()
        assert txid in node.getrawmempool()
        assert_equal(self.unconfirmed_view(), (amount, [0]))

        self.restart_node(0)
        node.loadwallet("miner")
        node.loadwallet("shielded")
        self.unlock()
        assert txid in node.getrawmempool()
        assert_equal(self.unconfirmed_view(), (amount, [0]))

        self.generatetoaddress(node, 1, node.get_wallet_rpc("miner").getnewaddress())
        assert_equal(self.unconfirmed_view(), (amount, [1]))

        self.log.info("A note spent by a transaction still in the mempool")
        # Shielded sends need at least 16 shielded outputs on chain.
        for _ in range(16):
            self.wallet().z_shieldcoinbase(zaddr, None, 1)
        self.generatetoaddress(node, 2, node.get_wallet_rpc("miner").getnewaddress())
        self.wallet().z_sendmany([{"address": other_zaddr, "amount": Decimal("5")}])
        assert_equal(len(node.getrawmempool()), 1)
        before = self.balances()
        assert before[1] < before[0]  # the spent note no longer counts as confirmed balance

        self.reload()
        assert_equal(self.balances(), before)
        # The next send picks another note: both transactions stay in the mempool.
        self.wallet().z_sendmany([{"address": other_zaddr, "amount": Decimal("3")}])
        assert_equal(len(node.getrawmempool()), 2)


if __name__ == "__main__":
    WalletShieldedMempoolNoteReloadTest(__file__).main()
