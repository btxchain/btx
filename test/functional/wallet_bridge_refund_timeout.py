#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""End-to-end refund coverage for both bridge plan kinds."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    create_bridge_wallet,
    find_output,
    mine_block,
    planin,
    planout,
    sign_finalize_and_send,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBridgeRefundTimeoutTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_refund_case(self, wallet, mine_addr, plan, amount, refund_destination, fee):
        node = self.nodes[0]
        funding_txid = wallet.sendtoaddress(plan["bridge_address"], amount)
        mine_block(self, node, mine_addr)
        vout, value = find_output(node, funding_txid, plan["bridge_address"], wallet)

        assert_raises_rpc_error(
            -8,
            "Refund path not yet eligible",
            wallet.bridge_buildrefund,
            plan["plan_hex"],
            funding_txid,
            vout,
            value,
            refund_destination,
            fee,
            True,
        )

        blocks_needed = max(0, plan["refund_lock_height"] - node.getblockcount())
        if blocks_needed:
            mine_block(self, node, mine_addr, blocks_needed)

        refund = wallet.bridge_buildrefund(
            plan["plan_hex"],
            funding_txid,
            vout,
            value,
            refund_destination,
            fee,
            True,
        )
        txid, _ = sign_finalize_and_send(wallet, node, refund["psbt"])
        mine_block(self, node, mine_addr)
        assert_equal(wallet.gettransaction(txid)["confirmations"] >= 1, True)

    def run_test(self):
        node = self.nodes[0]
        wallet, mine_addr = create_bridge_wallet(self, node, wallet_name="bridge_refund_timeout")

        self.log.info("Exercise timeout-gated refunds for bridge-out")
        refund_lock_height = node.getblockcount() + 6
        payout_address = wallet.getnewaddress(address_type="p2mr")
        plan_out, _, _ = planout(
            wallet,
            payout_address,
            Decimal("2.2"),
            refund_lock_height,
            bridge_id=bridge_hex(70),
            operation_id=bridge_hex(71),
        )
        refund_destination_out = wallet.getnewaddress(address_type="p2mr")
        fee = Decimal("0.00010000")
        self.run_refund_case(wallet, mine_addr, plan_out, Decimal("2.2"), refund_destination_out, fee)
        assert_equal(Decimal(str(wallet.getreceivedbyaddress(refund_destination_out))), Decimal("2.2") - fee)

        self.log.info("Exercise timeout-gated refunds for bridge-in and confirm no shielded settlement occurs")
        refund_lock_height = node.getblockcount() + 6
        recipient = wallet.z_getnewaddress()
        plan_in, _, _ = planin(
            wallet,
            Decimal("1.4"),
            refund_lock_height,
            bridge_id=bridge_hex(72),
            operation_id=bridge_hex(73),
            recipient=recipient,
        )
        refund_destination_in = wallet.getnewaddress(address_type="p2mr")
        self.run_refund_case(wallet, mine_addr, plan_in, Decimal("1.4"), refund_destination_in, fee)
        assert_equal(Decimal(str(wallet.getreceivedbyaddress(refund_destination_in))), Decimal("1.4") - fee)
        notes = [entry for entry in wallet.z_listreceivedbyaddress() if entry["address"] == recipient and entry["note_count"] > 0]
        assert_equal(notes, [])


if __name__ == "__main__":
    WalletBridgeRefundTimeoutTest(__file__).main()
