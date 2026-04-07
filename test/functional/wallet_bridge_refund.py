#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for refund-path PSBT construction."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    create_bridge_wallet,
    find_output,
    mine_block,
    planout,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBridgeRefundTest(BitcoinTestFramework):
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
        wallet, mine_addr = create_bridge_wallet(self, node, wallet_name="bridge_refund")

        refund_lock_height = node.getblockcount() + 25
        payout_address = wallet.getnewaddress(address_type="p2mr")
        plan, _, _ = planout(
            wallet,
            payout_address,
            Decimal("3"),
            refund_lock_height,
            bridge_id=bridge_hex(20),
            operation_id=bridge_hex(21),
        )

        self.log.info("Fund the bridge output and build a refund PSBT without timeout enforcement")
        funding_txid = wallet.sendtoaddress(plan["bridge_address"], Decimal("3"))
        mine_block(self, node, mine_addr)
        vout, value = find_output(node, funding_txid, plan["bridge_address"], wallet)
        refund_destination = wallet.getnewaddress(address_type="p2mr")
        refund = wallet.bridge_buildrefund(
            plan["plan_hex"],
            funding_txid,
            vout,
            value,
            refund_destination,
            Decimal("0.00010000"),
            False,
        )

        assert_equal(refund["selected_path"], "refund")
        assert_equal(refund["relay_fee_analysis_available"], True)
        assert_equal(refund["relay_fee_sufficient"], True)
        assert_equal(refund["locktime"], refund_lock_height)
        assert_equal(refund["refund_lock_height"], refund_lock_height)
        decoded = node.decodepsbt(refund["psbt"])
        assert_equal(decoded["inputs"][0]["p2mr_merkle_root"], plan["bridge_root"])
        assert_equal(decoded["inputs"][0]["p2mr_leaf_script"], refund["p2mr_leaf_script"])
        assert_equal(decoded["inputs"][0]["p2mr_control_block"], refund["p2mr_control_block"])
        assert_equal(decoded["tx"]["vout"][0]["scriptPubKey"]["address"], refund_destination)

        signed = wallet.walletprocesspsbt(refund["psbt"], True, "ALL", True, False)
        decoded_signed = node.decodepsbt(signed["psbt"])
        assert_equal(len(decoded_signed["inputs"][0]["p2mr_partial_signatures"]), 1)
        assert_equal(decoded_signed["inputs"][0].get("p2mr_csfs_signatures", []), [])


if __name__ == "__main__":
    WalletBridgeRefundTest(__file__).main()
