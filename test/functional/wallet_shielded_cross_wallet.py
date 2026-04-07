#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal

from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletShieldedCrossWalletTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-autoshieldcoinbase=0"], ["-autoshieldcoinbase=0"]]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]

        n0.createwallet(wallet_name="w0", descriptors=True)
        n1.createwallet(wallet_name="w1", descriptors=True)
        w0 = encrypt_and_unlock_wallet(n0, "w0")
        w1 = encrypt_and_unlock_wallet(n1, "w1")

        self.log.info("Mine spendable funds and shield on wallet 0")
        mine_addr0 = w0.getnewaddress()
        fund_trusted_transparent_balance(
            self, n0, w0, mine_addr0, Decimal("10.0"), sync_fun=self.no_op
        )
        self.sync_blocks()

        z0 = w0.z_getnewaddress()
        w0.z_shieldfunds(Decimal("5.0"), z0)
        self.generatetoaddress(n0, 1, mine_addr0, sync_fun=self.no_op)
        self.sync_blocks()
        ensure_ring_diversity(
            self,
            n0,
            w0,
            mine_addr0,
            z0,
            min_notes=16,
            topup_amount=Decimal("0.25"),
            sync_fun=self.sync_all,
        )

        self.log.info("Send shielded funds from wallet 0 to wallet 1 shielded address")
        z1 = w1.z_getnewaddress()
        send = w0.z_sendmany([{"address": z1, "amount": Decimal("2.0")}])
        assert send["txid"] in n0.getrawmempool()
        self.generatetoaddress(n0, 1, mine_addr0, sync_fun=self.no_op)
        self.sync_blocks()

        bal1 = Decimal(w1.z_getbalance()["balance"])
        assert bal1 >= Decimal("2.0")

        self.log.info("Spend received note on wallet 1 by unshielding to transparent output")
        t1 = w1.getnewaddress()
        unshield = w1.z_sendmany([{"address": t1, "amount": Decimal("1.0")}])
        assert unshield["txid"] in n1.getrawmempool()
        self.sync_mempools()
        self.generatetoaddress(n0, 1, mine_addr0, sync_fun=self.no_op)
        self.sync_blocks()
        self.wait_until(lambda: w1.getreceivedbyaddress(t1) == Decimal("1.0"))
        assert_equal(w1.getreceivedbyaddress(t1), Decimal("1.0"))


if __name__ == "__main__":
    WalletShieldedCrossWalletTest(__file__).main()
