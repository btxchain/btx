#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for deterministic bridge-in planning."""

from decimal import Decimal

from test_framework.bridge_utils import bridge_hex, create_bridge_wallet, get_kem_public_key, planin
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBridgePlanInTest(BitcoinTestFramework):
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
        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_planin")

        recipient = wallet.z_getnewaddress()
        _, disclosure_pubkey = get_kem_public_key(wallet)
        refund_lock_height = node.getblockcount() + 10

        self.log.info("Build the same bridge-in plan twice and confirm deterministic output")
        first, operator_key, refund_key = planin(
            wallet,
            Decimal("5"),
            refund_lock_height,
            bridge_id=bridge_hex(1),
            operation_id=bridge_hex(2),
            recipient=recipient,
            memo="handoff-planin",
        )
        second, _, _ = planin(
            wallet,
            Decimal("5"),
            refund_lock_height,
            bridge_id=bridge_hex(1),
            operation_id=bridge_hex(2),
            recipient=recipient,
            memo="handoff-planin",
            operator_key=operator_key,
            refund_key=refund_key,
        )

        assert_equal(first["kind"], "shield")
        assert_equal(first["recipient"], recipient)
        assert_equal(first["recipient_generated"], False)
        assert_equal(first["bridge_address"], second["bridge_address"])
        assert_equal(first["bridge_root"], second["bridge_root"])
        assert_equal(first["ctv_hash"], second["ctv_hash"])
        assert_equal(first["plan_hex"], second["plan_hex"])
        assert_equal(first["bundle"]["shielded_output_count"], 1)
        assert_equal(first["bundle"]["view_grant_count"], 0)
        assert_equal(first["refund_lock_height"], refund_lock_height)

        self.log.info("Disclosure policies should auto-add required grants once the threshold is met")
        policy_grant, _, _ = planin(
            wallet,
            Decimal("5"),
            refund_lock_height + 2,
            bridge_id=bridge_hex(5),
            operation_id=bridge_hex(6),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            disclosure_policy={
                "threshold_amount": Decimal("4"),
                "required_grants": [{
                    "pubkey": disclosure_pubkey,
                    "format": "structured_disclosure",
                    "disclosure_fields": ["amount", "recipient"],
                }],
            },
        )
        assert_equal(policy_grant["bundle"]["view_grant_count"], 1)
        assert_equal(policy_grant["bundle"]["view_grants"][0]["format"], "structured_disclosure")
        assert_equal(policy_grant["bundle"]["view_grants"][0]["disclosure_fields"], ["amount", "recipient"])
        assert_equal(policy_grant["disclosure_policy"]["threshold_amount"], Decimal("4"))

        below_threshold, _, _ = planin(
            wallet,
            Decimal("1"),
            refund_lock_height + 3,
            bridge_id=bridge_hex(7),
            operation_id=bridge_hex(8),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            disclosure_policy={
                "threshold_amount": Decimal("2"),
                "required_grants": [{
                    "pubkey": disclosure_pubkey,
                    "format": "structured_disclosure",
                    "disclosure_fields": ["amount"],
                }],
            },
        )
        assert_equal(below_threshold["bundle"]["view_grant_count"], 0)

        self.log.info("Omitting recipient should generate a local shielded address")
        generated, _, _ = planin(
            wallet,
            Decimal("1.5"),
            refund_lock_height + 1,
            bridge_id=bridge_hex(3),
            operation_id=bridge_hex(4),
            operator_key=operator_key,
            refund_key=refund_key,
        )
        assert_equal(generated["kind"], "shield")
        assert_equal(generated["recipient_generated"], True)
        assert generated["recipient"].startswith("btxs")


if __name__ == "__main__":
    WalletBridgePlanInTest(__file__).main()
