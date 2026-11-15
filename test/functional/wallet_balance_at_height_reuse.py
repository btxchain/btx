#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""getbalanceatheight reports a past height that later spends do not change.

On a wallet with avoid_reuse, a coin on an address that is spent from later
must still count at a height before that spend.
"""

from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBalanceAtHeightReuseTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-fallbackfee=0.0002", "-nomodelnet"] + list(REGTEST_GENERIC_P2P_MATMUL_ARGS)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        funder = node.get_wallet_rpc(self.default_wallet_name)
        self.generatetoaddress(node, 110, funder.getnewaddress(), sync_fun=self.no_op)

        node.createwallet(wallet_name="reuse", avoid_reuse=True)
        wallet = node.get_wallet_rpc("reuse")
        address = wallet.getnewaddress()
        funder.sendtoaddress(address, Decimal("2"))
        funder.sendtoaddress(address, Decimal("3"))
        self.generatetoaddress(node, 1, funder.getnewaddress(), sync_fun=self.no_op)
        height = node.getblockcount()
        before = wallet.getbalanceatheight(height)
        assert_equal(before["amount"], Decimal("5"))

        self.log.info("Spend one of the two coins on the address, which marks it as used")
        wallet.sendtoaddress(funder.getnewaddress(), Decimal("1"))
        self.generatetoaddress(node, 1, funder.getnewaddress(), sync_fun=self.no_op)
        assert_equal(wallet.getbalanceatheight(height)["amount"], before["amount"])

        self.log.info("At the tip, a new coin on the used address is left out, as getbalances does")
        funder.sendtoaddress(address, Decimal("4"))
        self.generatetoaddress(node, 1, funder.getnewaddress(), sync_fun=self.no_op)
        mine = wallet.getbalances()["mine"]
        assert_equal(mine["used"], Decimal("4"))
        assert_equal(wallet.getbalanceatheight(node.getblockcount())["amount"], mine["trusted"])


if __name__ == "__main__":
    WalletBalanceAtHeightReuseTest(__file__).main()
