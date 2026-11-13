#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""rescanblockchain with a stop_height keeps a wallet's shielded notes.

The shielded part of a rescan clears the notes and rebuilds them from the
start height. With a stop_height below the tip it rebuilt them only up to that
height, so notes received later disappeared from the balance.
"""

from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletShieldedRescanStopHeightTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-autoshieldcoinbase=0",
            "-regtestshieldedmatrictdisableheight=500",
            "-nomodelnet",
        ] + list(REGTEST_GENERIC_P2P_MATMUL_ARGS)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="w", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "w")
        mine_addr = wallet.getnewaddress()
        fund_trusted_transparent_balance(self, node, wallet, mine_addr, Decimal("3.0"), sync_fun=self.no_op)
        zaddr = wallet.z_getnewaddress()

        self.log.info("Receive shielded notes at two heights")
        wallet.z_shieldfunds(Decimal("1.0"), zaddr)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        first_height = node.getblockcount()
        wallet.z_shieldfunds(Decimal("0.5"), zaddr)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        balance = Decimal(wallet.z_getbalance()["balance"])
        assert_equal(balance, Decimal("1.5"))

        self.log.info("A rescan that would stop between them is refused and keeps the notes")
        assert_raises_rpc_error(-8, "stop_height below the tip", wallet.rescanblockchain, 0, first_height)
        assert_equal(Decimal(wallet.z_getbalance()["balance"]), balance)

        self.log.info("A rescan up to the tip still works")
        wallet.rescanblockchain(0)
        assert_equal(Decimal(wallet.z_getbalance()["balance"]), balance)


if __name__ == "__main__":
    WalletShieldedRescanStopHeightTest(__file__).main()
