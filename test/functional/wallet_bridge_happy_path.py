#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""End-to-end bridge-in settlement to the shielded pool."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    create_bridge_wallet,
    find_output,
    mine_block,
    planin,
    sign_finalize_and_send,
)
from test_framework.shielded_utils import encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBridgeHappyPathTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        node = self.nodes[0]
        wallet, mine_addr = create_bridge_wallet(self, node, wallet_name="bridge_happy")
        fee_margin = Decimal("0.00020000")
        node.createwallet(wallet_name="bridge_happy_recipient", descriptors=True)
        recipient_wallet = encrypt_and_unlock_wallet(node, "bridge_happy_recipient")

        recipient = recipient_wallet.z_getnewaddress()
        refund_lock_height = node.getblockcount() + 20
        plan, _, _ = planin(
            wallet,
            Decimal("3.5"),
            refund_lock_height,
            bridge_id=bridge_hex(50),
            operation_id=bridge_hex(51),
            recipient=recipient,
            memo="bridge-in-settlement",
        )

        self.log.info("Fund the bridge output, settle it through the normal path, and confirm the note lands in the wallet")
        funding_txid = wallet.sendtoaddress(plan["bridge_address"], Decimal("3.5") + fee_margin)
        mine_block(self, node, mine_addr)
        vout, value = find_output(node, funding_txid, plan["bridge_address"], wallet)

        built = wallet.bridge_buildshieldtx(plan["plan_hex"], funding_txid, vout, value)
        assert_equal(built["relay_fee_analysis_available"], True)
        assert_equal(built["relay_fee_sufficient"], True)
        assert built["relay_fee_analysis"]["estimated_fee"] >= built["relay_fee_analysis"]["required_total_fee"]
        settlement_txid, _ = sign_finalize_and_send(wallet, node, built["psbt"])
        mine_block(self, node, mine_addr)

        assert_equal(Decimal(recipient_wallet.z_getbalance()["balance"]), Decimal("3.5"))


if __name__ == "__main__":
    WalletBridgeHappyPathTest(__file__).main()
