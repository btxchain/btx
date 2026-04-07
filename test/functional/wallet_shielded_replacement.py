#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Shielded same-note replacement coverage for conflict_txid RPC support."""

from decimal import Decimal

from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletShieldedReplacementTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-autoshieldcoinbase=0"]]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="sender", descriptors=True)
        node.createwallet(wallet_name="receiver", descriptors=True)
        sender = encrypt_and_unlock_wallet(node, "sender")
        receiver = encrypt_and_unlock_wallet(node, "receiver")

        mine_addr = sender.getnewaddress()
        fund_trusted_transparent_balance(
            self, node, sender, mine_addr, Decimal("12.0"), sync_fun=self.no_op
        )

        shield_addr = sender.z_getnewaddress()
        shield_res = sender.z_shieldfunds(Decimal("5.0"), shield_addr)
        assert shield_res["txid"] in node.getrawmempool()
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        ensure_ring_diversity(self, node, sender, mine_addr, shield_addr, sync_fun=self.no_op)

        low_fee = Decimal("0.00160000")
        high_fee = Decimal("0.00320000")

        self.log.info("Replace a low-fee z_sendtoaddress by respending the same notes")
        receiver_a = receiver.z_getnewaddress()
        receiver_b = receiver.z_getnewaddress()
        original = sender.z_sendtoaddress(
            receiver_a,
            Decimal("0.35"),
            "",
            "",
            False,
            low_fee,
            True,
        )
        assert original["txid"] in node.getrawmempool()

        replacement = sender.z_sendtoaddress(
            receiver_b,
            Decimal("0.35"),
            "",
            "",
            False,
            high_fee,
            True,
            None,
            None,
            original["txid"],
        )
        assert replacement["txid"] in node.getrawmempool()
        assert original["txid"] not in node.getrawmempool()

        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(Decimal(receiver.z_getbalance()["balance"]), Decimal("0.35"))
        replacement_view = receiver.z_viewtransaction(replacement["txid"])
        assert_equal(replacement_view["family"], "v2_send")

        assert_raises_rpc_error(
            -8,
            "conflict_txid is not currently in the wallet mempool",
            sender.z_sendtoaddress,
            receiver.z_getnewaddress(),
            Decimal("0.10"),
            "",
            "",
            False,
            high_fee,
            True,
            None,
            None,
            original["txid"],
        )

        self.log.info("Replace a low-fee z_sendmany by respending the same notes")
        receiver_c = receiver.z_getnewaddress()
        receiver_d = receiver.z_getnewaddress()
        receiver_e = receiver.z_getnewaddress()
        receiver_f = receiver.z_getnewaddress()
        original_many = sender.z_sendmany(
            [
                {"address": receiver_c, "amount": Decimal("0.20")},
                {"address": receiver_d, "amount": Decimal("0.10")},
            ],
            low_fee,
        )
        assert original_many["txid"] in node.getrawmempool()

        replacement_many = sender.z_sendmany(
            [
                {"address": receiver_e, "amount": Decimal("0.15")},
                {"address": receiver_f, "amount": Decimal("0.15")},
            ],
            high_fee,
            [],
            None,
            None,
            original_many["txid"],
        )
        assert replacement_many["txid"] in node.getrawmempool()
        assert original_many["txid"] not in node.getrawmempool()

        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(Decimal(receiver.z_getbalance()["balance"]), Decimal("0.65"))


if __name__ == "__main__":
    WalletShieldedReplacementTest(__file__).main()
