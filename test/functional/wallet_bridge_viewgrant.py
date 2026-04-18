#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Bridge-in view-grant coverage."""

from decimal import Decimal

from test_framework.bridge_utils import bridge_hex, create_bridge_wallet, get_kem_public_key, planin
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBridgeViewGrantTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-regtestshieldedmatrictdisableheight=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        node = self.nodes[0]
        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_viewgrant")

        recipient = wallet.z_getnewaddress()
        _, operator_kem_pubkey = get_kem_public_key(wallet)
        refund_lock_height = node.getblockcount() + 20

        self.log.info("Bridge-in planning should embed operator view grants only when requested")
        with_grant, operator_key, refund_key = planin(
            wallet,
            Decimal("2.5"),
            refund_lock_height,
            bridge_id=bridge_hex(30),
            operation_id=bridge_hex(31),
            recipient=recipient,
            operator_view_pubkeys=[operator_kem_pubkey],
        )
        structured_grant, _, _ = planin(
            wallet,
            Decimal("2.5"),
            refund_lock_height,
            bridge_id=bridge_hex(34),
            operation_id=bridge_hex(35),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            operator_view_grants=[{
                "pubkey": operator_kem_pubkey,
                "format": "structured_disclosure",
                "disclosure_fields": ["amount", "recipient", "sender"],
            }],
        )
        without_grant, _, _ = planin(
            wallet,
            Decimal("2.5"),
            refund_lock_height,
            bridge_id=bridge_hex(32),
            operation_id=bridge_hex(33),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
        )

        assert_equal(with_grant["bundle"]["shielded_output_count"], 1)
        assert_equal(with_grant["bundle"]["view_grant_count"], 1)
        assert_equal(len(with_grant["bundle"]["view_grants"]), 1)
        assert_equal(with_grant["bundle"]["view_grants"][0]["format"], "structured_disclosure")
        assert_equal(
            with_grant["bundle"]["view_grants"][0]["disclosure_fields"],
            ["amount", "recipient", "sender"],
        )
        assert len(with_grant["bundle"]["view_grants"][0]["kem_ciphertext"]) > 0
        assert len(with_grant["bundle"]["view_grants"][0]["nonce"]) > 0
        assert len(with_grant["bundle"]["view_grants"][0]["encrypted_data"]) > 0
        assert_equal(with_grant["operator_view_grants"][0]["format"], "structured_disclosure")

        assert_equal(without_grant["bundle"]["view_grant_count"], 0)
        assert_equal(without_grant["bundle"]["view_grants"], [])

        assert_equal(structured_grant["bundle"]["view_grant_count"], 1)
        assert_equal(structured_grant["bundle"]["view_grants"][0]["format"], "structured_disclosure")
        assert_equal(
            structured_grant["bundle"]["view_grants"][0]["disclosure_fields"],
            ["amount", "recipient", "sender"],
        )
        assert_equal(
            structured_grant["operator_view_grants"][0]["disclosure_fields"],
            ["amount", "recipient", "sender"],
        )


if __name__ == "__main__":
    WalletBridgeViewGrantTest(__file__).main()
