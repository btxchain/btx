#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""z_sendtoaddress reports the fee the transaction pays.

Once canonical fee buckets apply, a shielded send rounds an explicit fee up to
its bucket. z_sendmany rounds the fee before it builds the transaction;
z_sendtoaddress must report and subtract the same rounded fee.
"""

from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletShieldedSendFeeBucketTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Canonical fee buckets apply from the MatRiCT disable height on.
        self.extra_args = [[
            "-autoshieldcoinbase=0",
            "-regtestshieldedmatrictdisableheight=120",
            "-nomodelnet",
        ] + list(REGTEST_GENERIC_P2P_MATMUL_ARGS)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="w", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "w")
        mine_addr = wallet.getnewaddress()
        fund_trusted_transparent_balance(self, node, wallet, mine_addr, Decimal("6.0"), sync_fun=self.no_op)
        zaddr = wallet.z_getnewaddress()
        wallet.z_shieldfunds(Decimal("4.0"), zaddr)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        ensure_ring_diversity(self, node, wallet, mine_addr, zaddr, min_notes=16,
                              topup_amount=Decimal("0.25"), sync_fun=self.no_op)

        self.log.info("Send with an explicit fee that is not on a bucket")
        to = wallet.z_getnewaddress()
        res = wallet.z_sendtoaddress(to, Decimal("1.0"), "", "", True, Decimal("0.000135"), True)
        paid = node.getmempoolentry(res["txid"])["fees"]["base"]
        assert_equal(Decimal(res["fee"]), Decimal(paid))


if __name__ == "__main__":
    WalletShieldedSendFeeBucketTest(__file__).main()
