#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


class WalletChainReprocess(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Test every block is reprocessed by a wallet after an unclean shutdown")
        self.nodes[0].createwallet("target")
        wallet = self.nodes[0].get_wallet_rpc("target")

        self.generatetoaddress(self.nodes[0], 1, wallet.getnewaddress(), sync_fun=self.no_op)
        self.generate(self.nodes[0], 101, sync_fun=self.no_op)
        self.restart_node(0)
        self.connect_nodes(0, 1)
        self.nodes[0].loadwallet("target")
        wallet = self.nodes[0].get_wallet_rpc("target")

        txids = []
        for _ in range(100):
            result = wallet.sendall([wallet.getnewaddress()])
            assert_equal(result["complete"], True)
            txids.append(result["txid"])
            self.generate(self.nodes[0], 1, sync_fun=self.no_op)

        self.sync_all()
        tip_height = self.nodes[0].getblockcount()
        wallet_height = wallet.getwalletinfo()["lastprocessedblock"]["height"]
        assert_equal(tip_height, wallet_height)

        wallet.unloadwallet()
        self.nodes[0].kill_process()
        self.start_node(0)
        restart_tip_height = self.nodes[0].getblockcount()
        assert_greater_than(tip_height, restart_tip_height)
        assert_greater_than(wallet_height, restart_tip_height)

        self.nodes[0].loadwallet("target")
        wallet = self.nodes[0].get_wallet_rpc("target")
        assert_greater_than(wallet_height, wallet.getwalletinfo()["lastprocessedblock"]["height"])

        self.connect_nodes(0, 1)
        self.sync_all()
        assert_equal(wallet.getwalletinfo()["lastprocessedblock"]["height"], self.nodes[0].getblockcount())

        for txid in txids:
            assert_greater_than(wallet.gettransaction(txid)["confirmations"], 0)
            assert_raises_rpc_error(
                -5,
                "Transaction not eligible for abandonment",
                wallet.abandontransaction,
                txid,
            )


if __name__ == "__main__":
    WalletChainReprocess(__file__).main()
