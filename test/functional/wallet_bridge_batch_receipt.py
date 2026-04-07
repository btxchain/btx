#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for committee/prover receipts over bridge batch statements."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_batch_commitment,
    build_batch_statement,
    build_external_anchor,
    create_bridge_wallet,
    planbatchin,
    planbatchout,
    sign_batch_authorization,
    sign_batch_receipt,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBridgeBatchReceiptTest(BitcoinTestFramework):
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
        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_receipt")

        refund_lock_height = node.getblockcount() + 30
        recipient = wallet.z_getnewaddress()
        expected_source = {
            "domain_id": bridge_hex(0x3100),
            "source_epoch": 19,
            "data_root": bridge_hex(0x3101),
        }
        expected_anchor = {
            "version": 1,
            **expected_source,
        }

        bridge_id = bridge_hex(0x3200)
        operation_id = bridge_hex(0x3201)
        payout_amounts = [Decimal("1.05"), Decimal("1.25"), Decimal("1.45")]
        payout_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]
        user_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]
        attestor_addresses = [
            wallet.getnewaddress(address_type="p2mr"),
            wallet.getnewaddress(address_type="p2mr"),
        ]

        self.log.info("Build a canonical batch statement from signed bridge-out authorizations")
        out_entries = []
        payouts = []
        for index, amount in enumerate(payout_amounts):
            signed = sign_batch_authorization(
                wallet,
                user_addresses[index],
                "bridge_out",
                {
                    "kind": "transparent_payout",
                    "wallet_id": bridge_hex(0x3300 + index),
                    "destination_id": bridge_hex(0x3400 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0x3500 + index),
                },
                bridge_id=bridge_id,
                operation_id=operation_id,
            )
            out_entries.append({"authorization_hex": signed["authorization_hex"]})
            payouts.append({"address": payout_addresses[index], "amount": amount})

        statement = build_batch_statement(
            wallet,
            "bridge_out",
            out_entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            domain_id=expected_source["domain_id"],
            source_epoch=expected_source["source_epoch"],
            data_root=expected_source["data_root"],
        )
        assert_equal(statement["statement"]["entry_count"], len(out_entries))
        assert_equal(statement["statement"]["source_epoch"], expected_source["source_epoch"])

        self.log.info("Have multiple wallet-backed attestors sign the same batch statement")
        receipts = []
        for attestor in attestor_addresses:
            signed_receipt = sign_batch_receipt(wallet, attestor, statement["statement_hex"])
            decoded = wallet.bridge_decodebatchreceipt(signed_receipt["receipt_hex"])
            assert_equal(decoded["statement_hash"], statement["statement_hash"])
            assert_equal(decoded["verified"], True)
            receipts.append(signed_receipt["receipt_hex"])

        required_attestors = [wallet.bridge_decodebatchreceipt(receipt)["receipt"]["attestor"] for receipt in receipts]
        external_anchor = build_external_anchor(
            wallet,
            statement["statement_hex"],
            receipts,
            {
                "min_receipts": 2,
                "required_attestors": required_attestors,
            },
        )
        assert_equal(external_anchor["statement_hash"], statement["statement_hash"])
        assert_equal(external_anchor["external_anchor"]["domain_id"], expected_anchor["domain_id"])
        assert_equal(external_anchor["external_anchor"]["source_epoch"], expected_anchor["source_epoch"])
        assert_equal(external_anchor["external_anchor"]["data_root"], expected_anchor["data_root"])
        assert_equal(external_anchor["distinct_attestor_count"], 2)
        assert_equal(external_anchor["required_attestor_count"], 2)

        self.log.info("Reject duplicate attestors and underspecified committees")
        assert_raises_rpc_error(
            -8,
            "receipts contain duplicate attestors",
            wallet.bridge_buildexternalanchor,
            statement["statement_hex"],
            [receipts[0], receipts[0]],
            {},
        )
        assert_raises_rpc_error(
            -8,
            "required_attestors[1] is missing from the receipt set",
            wallet.bridge_buildexternalanchor,
            statement["statement_hex"],
            [receipts[0]],
            {
                "required_attestors": required_attestors,
            },
        )

        self.log.info("Feed the derived anchor into the existing bridge batch commitment and plan flows")
        anchored_commitment = build_batch_commitment(
            wallet,
            "bridge_out",
            out_entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            external_anchor=external_anchor["external_anchor"],
        )
        assert_equal(anchored_commitment["commitment"]["external_anchor"], external_anchor["external_anchor"])

        batch_out_plan, _, _ = planbatchout(
            wallet,
            payouts,
            refund_lock_height,
            bridge_id=bridge_id,
            operation_id=operation_id,
            batch_commitment_hex=anchored_commitment["commitment_hex"],
        )
        assert_equal(batch_out_plan["attestation"]["message"]["version"], 3)
        assert_equal(batch_out_plan["attestation"]["message"]["external_anchor"], external_anchor["external_anchor"])

        bridge_in_id = bridge_hex(0x3600)
        bridge_in_operation = bridge_hex(0x3601)
        in_entries = []
        for index, amount in enumerate([Decimal("0.90"), Decimal("1.10")]):
            signed = sign_batch_authorization(
                wallet,
                wallet.getnewaddress(address_type="p2mr"),
                "bridge_in",
                {
                    "kind": "shield_credit",
                    "wallet_id": bridge_hex(0x3700 + index),
                    "destination_id": bridge_hex(0x3800 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0x3900 + index),
                },
                bridge_id=bridge_in_id,
                operation_id=bridge_in_operation,
            )
            in_entries.append({"authorization_hex": signed["authorization_hex"]})

        in_statement = build_batch_statement(
            wallet,
            "bridge_in",
            in_entries,
            bridge_id=bridge_in_id,
            operation_id=bridge_in_operation,
            domain_id=expected_source["domain_id"],
            source_epoch=expected_source["source_epoch"] + 1,
            data_root=bridge_hex(0x3A00),
        )
        in_receipts = [
            sign_batch_receipt(wallet, attestor_addresses[0], in_statement["statement_hex"])["receipt_hex"],
            sign_batch_receipt(wallet, attestor_addresses[1], in_statement["statement_hex"], algorithm="slh-dsa-shake-128s")["receipt_hex"],
        ]
        in_anchor = build_external_anchor(wallet, in_statement["statement_hex"], in_receipts)
        batch_in_plan, _, _ = planbatchin(
            wallet,
            in_entries,
            refund_lock_height,
            bridge_id=bridge_in_id,
            operation_id=bridge_in_operation,
            recipient=recipient,
            external_anchor=in_anchor["external_anchor"],
        )
        assert_equal(batch_in_plan["batch_commitment"]["external_anchor"], in_anchor["external_anchor"])

        self.log.info(
            "Receipt-backed surfaces observed: statement %d bytes, receipt %d bytes, verification_root %s",
            len(bytes.fromhex(statement["statement_hex"])),
            len(bytes.fromhex(external_anchor["receipts"][0]["receipt_hex"])),
            external_anchor["external_anchor"]["verification_root"],
        )


if __name__ == "__main__":
    WalletBridgeBatchReceiptTest(__file__).main()
