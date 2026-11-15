#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A blank wallet whose only keys are shielded scans new blocks.

Such a wallet has no transparent key, so nothing else gives it a birth time.
Without one, the block-connected scan skips every new block, and a note sent to
its shielded address stays invisible until the next restart.
"""

from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletShieldedBlankBirthTimeTest(BitcoinTestFramework):
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
        node.createwallet(wallet_name="owner", descriptors=True)
        owner = encrypt_and_unlock_wallet(node, "owner")
        mine_addr = owner.getnewaddress()
        fund_trusted_transparent_balance(self, node, owner, mine_addr, Decimal("3.0"), sync_fun=self.no_op)

        self.log.info("A blank encrypted wallet gets only a shielded address")
        node.createwallet(wallet_name="zonly", blank=True, descriptors=True)
        zonly = encrypt_and_unlock_wallet(node, "zonly")
        zaddr = zonly.z_getnewaddress()

        self.log.info("Shield transparent funds of another wallet to that address")
        owner.z_shieldfunds(Decimal("1.0"), zaddr)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        assert_equal(Decimal(zonly.z_getbalance()["balance"]), Decimal("1.0"))
        assert_equal(zonly.z_verifywalletintegrity()["scan_height"], node.getblockcount())


if __name__ == "__main__":
    WalletShieldedBlankBirthTimeTest(__file__).main()
