#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for external DA/proof anchors on bridge batch commitments."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_batch_commitment,
    create_bridge_wallet,
    planbatchin,
    planbatchout,
    sign_batch_authorization,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBridgeBatchAnchorTest(BitcoinTestFramework):
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
        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_anchor")

        refund_lock_height = node.getblockcount() + 25
        recipient = wallet.z_getnewaddress()
        external_anchor = {
            "domain_id": bridge_hex(0x2100),
            "source_epoch": 7,
            "data_root": bridge_hex(0x2101),
            "verification_root": bridge_hex(0x2102),
        }
        expected_anchor = {
            "version": 1,
            **external_anchor,
        }

        bridge_out_id = bridge_hex(0x2200)
        bridge_out_operation = bridge_hex(0x2201)
        payout_amounts = [Decimal("1.10"), Decimal("1.40")]
        payout_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]
        out_authorizers = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]

        self.log.info("Build an anchored bridge-out batch commitment from signed user authorizations")
        out_entries = []
        payouts = []
        for index, amount in enumerate(payout_amounts):
            signed = sign_batch_authorization(
                wallet,
                out_authorizers[index],
                "bridge_out",
                {
                    "kind": "transparent_payout",
                    "wallet_id": bridge_hex(0x2300 + index),
                    "destination_id": bridge_hex(0x2400 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0x2500 + index),
                },
                bridge_id=bridge_out_id,
                operation_id=bridge_out_operation,
            )
            out_entries.append({"authorization_hex": signed["authorization_hex"]})
            payouts.append({"address": payout_addresses[index], "amount": amount})

        anchored_commitment = build_batch_commitment(
            wallet,
            "bridge_out",
            out_entries,
            bridge_id=bridge_out_id,
            operation_id=bridge_out_operation,
            external_anchor=external_anchor,
        )
        decoded_commitment = wallet.bridge_decodebatchcommitment(anchored_commitment["commitment_hex"])
        assert_equal(decoded_commitment["commitment"]["version"], 3)
        assert_equal(decoded_commitment["commitment"]["external_anchor"], expected_anchor)
        assert_equal(len(bytes.fromhex(anchored_commitment["commitment_hex"])), 344)

        batch_out_plan, _, _ = planbatchout(
            wallet,
            payouts,
            refund_lock_height,
            bridge_id=bridge_out_id,
            operation_id=bridge_out_operation,
            batch_commitment_hex=anchored_commitment["commitment_hex"],
        )
        assert_equal(batch_out_plan["attestation"]["message"]["version"], 3)
        assert_equal(batch_out_plan["attestation"]["message"]["external_anchor"], expected_anchor)
        assert_equal(len(bytes.fromhex(batch_out_plan["attestation"]["bytes"])), 279)

        self.log.info("Build an anchored bridge-in batch plan for off-chain shield credits")
        bridge_in_id = bridge_hex(0x2600)
        bridge_in_operation = bridge_hex(0x2601)
        credit_amounts = [Decimal("0.90"), Decimal("1.20")]
        in_authorizers = [wallet.getnewaddress(address_type="p2mr") for _ in credit_amounts]
        in_entries = []
        for index, amount in enumerate(credit_amounts):
            signed = sign_batch_authorization(
                wallet,
                in_authorizers[index],
                "bridge_in",
                {
                    "kind": "shield_credit",
                    "wallet_id": bridge_hex(0x2700 + index),
                    "destination_id": bridge_hex(0x2800 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0x2900 + index),
                },
                bridge_id=bridge_in_id,
                operation_id=bridge_in_operation,
            )
            in_entries.append({"authorization_hex": signed["authorization_hex"]})

        batch_in_plan, _, _ = planbatchin(
            wallet,
            in_entries,
            refund_lock_height,
            bridge_id=bridge_in_id,
            operation_id=bridge_in_operation,
            recipient=recipient,
            external_anchor=external_anchor,
        )
        assert_equal(batch_in_plan["batch_commitment"]["version"], 3)
        assert_equal(batch_in_plan["batch_commitment"]["external_anchor"], expected_anchor)
        assert_equal(len(bytes.fromhex(batch_in_plan["batch_commitment_hex"])), 344)

        self.log.info(
            "Anchored batch surfaces observed: commitment %d bytes, attestation %d bytes",
            len(bytes.fromhex(batch_in_plan["batch_commitment_hex"])),
            len(bytes.fromhex(batch_out_plan["attestation"]["bytes"])),
        )


if __name__ == "__main__":
    WalletBridgeBatchAnchorTest(__file__).main()
