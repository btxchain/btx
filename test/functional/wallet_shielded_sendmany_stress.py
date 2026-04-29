#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal

from test_framework.shielded_utils import (
    SHIELDED_WALLET_PASSPHRASE,
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class WalletShieldedSendmanyStressTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-regtestshieldedmatrictdisableheight=500"]]
        # Repeated direct SMILE proving can legitimately exceed the framework's
        # default per-call HTTP timeout on slower CI/dev machines.
        self.rpc_timeout = 180

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="shielded", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")

        self.log.info("Prepare transparent funds and shield into the pool")
        mine_addr = wallet.getnewaddress()
        fund_trusted_transparent_balance(
            self, node, wallet, mine_addr, Decimal("10.0"), sync_fun=self.no_op
        )

        z_source = wallet.z_getnewaddress()
        wallet.z_shieldfunds(Decimal("6.0"), z_source)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        ensure_ring_diversity(
            self, node, wallet, mine_addr, z_source, min_notes=16, topup_amount=Decimal("0.25")
        )

        unspent_notes = wallet.z_listunspent(1, 9999999, False)
        assert_greater_than(len(unspent_notes), 0)

        self.log.info("Run sustained mixed shielded sendmany flow")
        expected_transparent_total = Decimal("0")
        transparent_dests = []
        stress_rounds = 12
        for i in range(stress_rounds):
            if i % 2 == 0:
                z_dest = wallet.z_getnewaddress()
                send_result = wallet.z_sendmany([{"address": z_dest, "amount": Decimal("0.04")}])
                assert send_result["txid"] in node.getrawmempool()
            else:
                t_dest = wallet.getnewaddress()
                transparent_dests.append(t_dest)
                send_result = wallet.z_sendmany([{"address": t_dest, "amount": Decimal("0.03")}])
                assert send_result["txid"] in node.getrawmempool()
                expected_transparent_total += Decimal("0.03")

            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

            if i == (stress_rounds // 2) - 1:
                self.log.info("Restart node mid-run to exercise wallet state recovery")
                self.restart_node(0)
                node = self.nodes[0]
                if "shielded" not in node.listwallets():
                    node.loadwallet("shielded")
                wallet = node.get_wallet_rpc("shielded")
                wallet.walletpassphrase(SHIELDED_WALLET_PASSPHRASE, 999000)

        self.log.info("Verify unshielded receipts and residual shielded balance")
        actual_transparent_total = Decimal("0")
        for addr in transparent_dests:
            actual_transparent_total += wallet.getreceivedbyaddress(addr)
        assert_equal(actual_transparent_total, expected_transparent_total)

        shielded_balance = Decimal(wallet.z_getbalance()["balance"])
        assert shielded_balance >= Decimal("0")
        assert_greater_than(len(wallet.z_listunspent(0, 9999999, True)), 0)


if __name__ == "__main__":
    WalletShieldedSendmanyStressTest(__file__).main()
