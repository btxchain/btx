#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""End-to-end bridge-out settlement using the attested normal path."""

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


class WalletBridgeAttestedUnshieldTest(BitcoinTestFramework):
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
        wallet, mine_addr = create_bridge_wallet(self, node, wallet_name="bridge_unshield")
        fee_margin = Decimal("0.00100000")

        payout_address = wallet.getnewaddress(address_type="p2mr")
        refund_lock_height = node.getblockcount() + 20
        plan, _, _ = planout(
            wallet,
            payout_address,
            Decimal("2.75"),
            refund_lock_height,
            bridge_id=bridge_hex(60),
            operation_id=bridge_hex(61),
        )

        self.log.info("Fund the bridge output, settle through the attested normal path, and confirm the payout arrives")
        funding_txid = wallet.sendtoaddress(plan["bridge_address"], Decimal("2.75") + fee_margin)
        mine_block(self, node, mine_addr)
        vout, value = find_output(node, funding_txid, plan["bridge_address"], wallet)

        built = wallet.bridge_buildunshieldtx(plan["plan_hex"], funding_txid, vout, value)
        assert_equal(built["p2mr_csfs_messages"][0]["message"], plan["attestation"]["bytes"])
        submitted = wallet.bridge_submitunshieldtx(plan["plan_hex"], funding_txid, vout, value)
        settlement_txid = submitted["txid"]
        assert_equal(submitted["selected_path"], "normal")
        assert_equal(submitted["bridge_root"], plan["bridge_root"])
        assert_equal(submitted["ctv_hash"], plan["ctv_hash"])
        mine_block(self, node, mine_addr)

        assert_equal(Decimal(str(wallet.getreceivedbyaddress(payout_address))), Decimal("2.75"))
        assert_equal(wallet.gettransaction(settlement_txid)["confirmations"] >= 1, True)


if __name__ == "__main__":
    WalletBridgeAttestedUnshieldTest(__file__).main()
