#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for deterministic bridge-out planning and attestation decoding."""

from decimal import Decimal

from test_framework.bridge_utils import bridge_hex, create_bridge_wallet, planout
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBridgePlanOutTest(BitcoinTestFramework):
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
        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_planout")

        payout_address = wallet.getnewaddress(address_type="p2mr")
        refund_lock_height = node.getblockcount() + 15

        self.log.info("Build the same bridge-out plan twice and confirm canonical attestation output")
        first, operator_key, refund_key = planout(
            wallet,
            payout_address,
            Decimal("4"),
            refund_lock_height,
            bridge_id=bridge_hex(10),
            operation_id=bridge_hex(11),
        )
        second, _, _ = planout(
            wallet,
            payout_address,
            Decimal("4"),
            refund_lock_height,
            bridge_id=bridge_hex(10),
            operation_id=bridge_hex(11),
            operator_key=operator_key,
            refund_key=refund_key,
        )

        assert_equal(first["kind"], "unshield")
        assert_equal(first["bridge_root"], second["bridge_root"])
        assert_equal(first["ctv_hash"], second["ctv_hash"])
        assert_equal(first["plan_hex"], second["plan_hex"])
        assert_equal(first["payout_address"], payout_address)
        assert_equal(first["attestation"]["bytes"], second["attestation"]["bytes"])
        assert_equal(first["attestation"]["hash"], second["attestation"]["hash"])

        self.log.info("Decode the canonical attestation and confirm network/domain binding")
        decoded = wallet.bridge_decodeattestation(first["attestation"]["bytes"])
        assert_equal(decoded["bytes"], first["attestation"]["bytes"])
        assert_equal(decoded["hash"], first["attestation"]["hash"])
        assert_equal(decoded["matches_active_genesis"], True)
        assert_equal(decoded["message"]["direction"], "bridge_out")
        assert_equal(decoded["message"]["ctv_hash"], first["ctv_hash"])
        assert_equal(decoded["message"]["refund_lock_height"], refund_lock_height)
        assert_equal(decoded["message"]["ids"]["bridge_id"], bridge_hex(10))
        assert_equal(decoded["message"]["ids"]["operation_id"], bridge_hex(11))


if __name__ == "__main__":
    WalletBridgePlanOutTest(__file__).main()
