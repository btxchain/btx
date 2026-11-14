#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A blank wallet whose only keys are shielded keeps scanning after a restart.

Shielded keys are not in the wallet's birth time, and the birth time is not
stored. After a restart such a wallet has none, and the block-connected scan
skips every new block, so a note sent to its address after the restart was not
seen until a rescan.
"""

from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    fund_trusted_transparent_balance,
    unlock_wallet,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletShieldedBirthTimeRestartTest(BitcoinTestFramework):
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

    def assert_scanned(self, wallet, balance):
        assert_equal(Decimal(wallet.z_getbalance()["balance"]), Decimal(balance))
        assert_equal(wallet.z_verifywalletintegrity()["scan_height"], self.nodes[0].getblockcount())

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="owner", descriptors=True)
        owner = encrypt_and_unlock_wallet(node, "owner")
        mine_addr = owner.getnewaddress()
        fund_trusted_transparent_balance(self, node, owner, mine_addr, Decimal("5.0"), sync_fun=self.no_op)

        self.log.info("Two blank encrypted wallets get only a shielded address; zonly also gets a note")
        node.createwallet(wallet_name="zonly", blank=True, descriptors=True)
        zonly = encrypt_and_unlock_wallet(node, "zonly")
        zaddr = zonly.z_getnewaddress()
        node.createwallet(wallet_name="zfresh", blank=True, descriptors=True)
        zfresh = encrypt_and_unlock_wallet(node, "zfresh")
        zfresh_addr = zfresh.z_getnewaddress()
        owner.z_shieldfunds(Decimal("1.0"), zaddr)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Restart; a note arrives while zonly is still locked")
        self.restart_node(0)
        for name in ("owner", "zonly", "zfresh"):
            if name not in node.listwallets():
                node.loadwallet(name)
        owner = unlock_wallet(node, "owner")
        owner.z_shieldfunds(Decimal("1.0"), zaddr)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        zonly = unlock_wallet(node, "zonly")
        zfresh = unlock_wallet(node, "zfresh")
        self.assert_scanned(zonly, "2.0")
        self.assert_scanned(zfresh, "0")

        self.log.info("Notes sent after the unlock are found in their block")
        owner.z_shieldfunds(Decimal("1.0"), zaddr)
        owner.z_shieldfunds(Decimal("1.0"), zfresh_addr)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        self.assert_scanned(zonly, "3.0")
        self.assert_scanned(zfresh, "1.0")
        self.generatetoaddress(node, 2, mine_addr, sync_fun=self.no_op)
        self.assert_scanned(zonly, "3.0")
        self.assert_scanned(zfresh, "1.0")


if __name__ == "__main__":
    WalletShieldedBirthTimeRestartTest(__file__).main()
