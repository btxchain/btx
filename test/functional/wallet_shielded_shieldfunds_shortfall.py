#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""z_shieldfunds does not send a chunk it then reports as failed.

The amount is a requested minimum. When the inputs left cannot cover it after
the fee, the call fails before it sends anything. When an earlier chunk is
already in the mempool, the call reports that chunk with "complete": false
instead of an error that hides it.
"""
from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

PASSPHRASE = "shieldfunds shortfall"


class WalletShieldedShieldFundsShortfallTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + ["-autoshieldcoinbase=0", "-nomodelnet"]]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("miner")
        miner = node.get_wallet_rpc("miner")
        node.createwallet(wallet_name="shielded", passphrase=PASSPHRASE)
        wallet = node.get_wallet_rpc("shielded")
        wallet.walletpassphrase(PASSPHRASE, 600)
        zaddr = wallet.z_getnewaddress()
        self.generatetoaddress(node, 6, wallet.getnewaddress())
        self.generatetoaddress(node, 101, miner.getnewaddress())
        utxos = wallet.listunspent()
        assert_equal(len(utxos), 6)
        coin_value = Decimal(str(utxos[0]["amount"]))

        self.log.info("Exactly the spendable amount: refused, nothing sent")
        held = [{"txid": u["txid"], "vout": u["vout"]} for u in utxos[1:]]
        wallet.lockunspent(False, held)
        assert_raises_rpc_error(-6, "Insufficient transparent funds", wallet.z_shieldfunds, coin_value, zaddr)
        assert_equal(node.getrawmempool(), [])
        assert_equal(len(wallet.listunspent()), 1)
        assert_equal(len(wallet.listlockunspent()), 5)

        self.log.info("Less than the spendable amount still works")
        res = wallet.z_shieldfunds(coin_value - Decimal("1"), zaddr)
        assert_equal(res["complete"], True)
        assert_equal(node.getrawmempool(), [res["txid"]])
        self.generatetoaddress(node, 1, miner.getnewaddress())

        self.log.info("A second chunk that cannot reach the amount is not sent; the first one is reported")
        wallet.lockunspent(True, held)
        # Five coins left and chunks of at most four inputs (and a value cap per
        # chunk): the coins left after the first chunk cannot cover the rest.
        res = wallet.z_shieldfunds(5 * coin_value - Decimal("0.00001"), zaddr, None, {"max_inputs_per_chunk": 4})
        assert_equal(res["complete"], False)
        assert "Insufficient transparent funds" in res["error"]
        assert_equal(len(res["txids"]), 1)
        assert_equal(node.getrawmempool(), res["txids"])
        assert_equal(len(wallet.listunspent()), 5 - res["transparent_inputs"])
        assert_equal(wallet.listlockunspent(), [])


if __name__ == "__main__":
    WalletShieldedShieldFundsShortfallTest(__file__).main()
