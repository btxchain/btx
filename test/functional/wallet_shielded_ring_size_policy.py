#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.util import assert_equal


class WalletShieldedRingSizePolicyTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Keep the legacy verbose send result in scope so the configured ring
        # policy can be asserted directly; post-fork RPC redaction has separate
        # functional coverage.
        self.extra_args = [[
            "-autoshieldcoinbase=0",
            "-shieldedringsize=16",
            "-regtestshieldedmatrictdisableheight=500",
        ]]
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
        z_sender = sender.z_getnewaddress()
        z_receiver = receiver.z_getnewaddress()

        self.log.info("Fund and shield on a node configured for 16-member rings")
        fund_trusted_transparent_balance(
            # Initial 3 BTX shield plus 23 diversity top-ups at 0.25 BTX needs
            # more than 8 BTX before fees. Keep a deterministic margin so the
            # helper cannot stop early at the transparent balance boundary.
            self, node, sender, mine_addr, Decimal("12.0"), sync_fun=self.no_op
        )
        sender.z_shieldfunds(Decimal("3.0"), z_sender)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        ensure_ring_diversity(
            self, node, sender, mine_addr, z_sender, min_notes=24, topup_amount=Decimal("0.25")
        )

        send = sender.z_sendmany([{"address": z_receiver, "amount": Decimal("0.2")}])
        assert send["txid"] in node.getrawmempool()
        assert send["spends"] >= 1
        assert_equal(sender.z_viewtransaction(send["txid"])["family"], "v2_send")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(Decimal(receiver.z_getbalance()["balance"]), Decimal("0.2"))

        self.log.info("Reject unsupported ring sizes at init time")
        node.stop_node()
        node.assert_start_raises_init_error(
            extra_args=[
                "-autoshieldcoinbase=0",
                "-shieldedringsize=7",
                "-regtestshieldedmatrictdisableheight=500",
            ],
            expected_msg="Error: Unsupported -shieldedringsize=7 (supported: 8..32)",
        )


if __name__ == "__main__":
    WalletShieldedRingSizePolicyTest(__file__).main()
