#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Two z_shieldfunds calls from one wallet at the same time shield different inputs.

z_shieldfunds collects the spendable transparent outputs, releases the wallet
lock while it builds each shielding chunk and commits it afterwards. A second
call running at the same time must not spend the same inputs, and the inputs
held for a call are released when it returns, also on failure.
"""
import threading
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, get_rpc_proxy

PASSPHRASE = "concurrent shieldfunds"
ROUNDS = 3


class WalletShieldedConcurrentShieldFundsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + ["-autoshieldcoinbase=0", "-nomodelnet"]]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def shield_at_once(self, zaddr):
        node = self.nodes[0]
        results = {}

        def shield(key):
            proxy = get_rpc_proxy(node.url + "/wallet/shielded", 0, timeout=600, coveragedir=node.coverage_dir)
            try:
                results[key] = proxy.z_shieldfunds(1, zaddr)["txid"]
            except JSONRPCException as e:
                results[key] = e.error

        threads = [threading.Thread(target=shield, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return [results[0], results[1]]

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("miner")
        miner = node.get_wallet_rpc("miner")
        node.createwallet(wallet_name="shielded", passphrase=PASSPHRASE)
        wallet = node.get_wallet_rpc("shielded")
        wallet.walletpassphrase(PASSPHRASE, 600)
        zaddr = wallet.z_getnewaddress()
        self.generatetoaddress(node, 2 * ROUNDS + 2, wallet.getnewaddress())
        self.generatetoaddress(node, 101, miner.getnewaddress())

        for round_number in range(ROUNDS):
            self.log.info(f"Round {round_number}: two z_shieldfunds calls at the same time")
            txids = self.shield_at_once(zaddr)
            for txid in txids:
                assert isinstance(txid, str), f"a concurrent z_shieldfunds failed: {txid}"
            assert txids[0] != txids[1]
            mempool = node.getrawmempool()
            for txid in txids:
                assert txid in mempool
            assert_equal(wallet.listlockunspent(), [])
            self.generatetoaddress(node, 1, miner.getnewaddress())

        self.log.info("A call that fails leaves no input locked")
        assert_raises_rpc_error(-4, "Fee too low", wallet.z_shieldfunds, 1, zaddr, Decimal("0.00000001"))
        assert_equal(wallet.listlockunspent(), [])


if __name__ == "__main__":
    WalletShieldedConcurrentShieldFundsTest(__file__).main()
