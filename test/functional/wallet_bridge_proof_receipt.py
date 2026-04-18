#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for imported proof receipts over bridge batch statements."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_batch_commitment,
    build_batch_statement,
    build_proof_anchor,
    build_proof_policy,
    build_proof_receipt,
    create_bridge_wallet,
    planbatchout,
    sign_batch_authorization,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBridgeProofReceiptTest(BitcoinTestFramework):
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
        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_proof_receipt")

        refund_lock_height = node.getblockcount() + 30
        bridge_id = bridge_hex(0x5100)
        operation_id = bridge_hex(0x5101)
        expected_source = {
            "domain_id": bridge_hex(0x5102),
            "source_epoch": 31,
            "data_root": bridge_hex(0x5103),
        }

        payout_amounts = [Decimal("1.10"), Decimal("1.25"), Decimal("1.40")]
        payout_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]
        user_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]

        self.log.info("Build one bridge-out batch statement for an imported proof bundle")
        entries = []
        payouts = []
        for index, amount in enumerate(payout_amounts):
            signed = sign_batch_authorization(
                wallet,
                user_addresses[index],
                "bridge_out",
                {
                    "kind": "transparent_payout",
                    "wallet_id": bridge_hex(0x5200 + index),
                    "destination_id": bridge_hex(0x5300 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0x5400 + index),
                },
                bridge_id=bridge_id,
                operation_id=operation_id,
            )
            entries.append({"authorization_hex": signed["authorization_hex"]})
            payouts.append({"address": payout_addresses[index], "amount": amount})

        statement = build_batch_statement(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            domain_id=expected_source["domain_id"],
            source_epoch=expected_source["source_epoch"],
            data_root=expected_source["data_root"],
        )
        assert_equal(statement["statement"]["entry_count"], len(entries))

        self.log.info("Commit one canonical proof-policy set for imported proof descriptors")
        descriptors = [
            {
                "proof_system_id": bridge_hex(0x5500),
                "verifier_key_hash": bridge_hex(0x5501),
            },
            {
                "proof_system_id": bridge_hex(0x5600),
                "verifier_key_hash": bridge_hex(0x5601),
            },
        ]
        proof_policy = build_proof_policy(
            wallet,
            descriptors,
            required_receipts=2,
            targets=descriptors,
        )
        assert_equal(proof_policy["proof_policy"]["descriptor_count"], 2)
        assert_equal(proof_policy["proof_policy"]["required_receipts"], 2)
        proof_hexes = [entry["proof_hex"] for entry in proof_policy["proofs"]]

        statement = build_batch_statement(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            domain_id=expected_source["domain_id"],
            source_epoch=expected_source["source_epoch"],
            data_root=expected_source["data_root"],
            proof_policy=proof_policy["proof_policy"],
        )
        assert_equal(statement["statement"]["version"], 3)
        assert_equal(statement["statement"]["proof_policy"], proof_policy["proof_policy"])

        self.log.info("Build canonical proof receipts for two imported proof systems")
        sp1_receipt = build_proof_receipt(
            wallet,
            statement["statement_hex"],
            proof_system_id=descriptors[0]["proof_system_id"],
            verifier_key_hash=descriptors[0]["verifier_key_hash"],
            public_values_hash=bridge_hex(0x5502),
            proof_commitment=bridge_hex(0x5503),
        )
        decoded_sp1 = wallet.bridge_decodeproofreceipt(sp1_receipt["proof_receipt_hex"])
        assert_equal(decoded_sp1["proof_receipt_hash"], sp1_receipt["proof_receipt_hash"])
        assert_equal(decoded_sp1["statement_hash"], statement["statement_hash"])

        risc0_receipt = build_proof_receipt(
            wallet,
            statement["statement_hex"],
            proof_system_id=descriptors[1]["proof_system_id"],
            verifier_key_hash=descriptors[1]["verifier_key_hash"],
            public_values_hash=bridge_hex(0x5602),
            proof_commitment=bridge_hex(0x5603),
        )

        proof_receipt_hexes = [
            sp1_receipt["proof_receipt_hex"],
            risc0_receipt["proof_receipt_hex"],
        ]
        proof_system_ids = [
            sp1_receipt["proof_receipt"]["proof_system_id"],
            risc0_receipt["proof_receipt"]["proof_system_id"],
        ]
        verifier_key_hashes = [
            sp1_receipt["proof_receipt"]["verifier_key_hash"],
            risc0_receipt["proof_receipt"]["verifier_key_hash"],
        ]

        self.log.info("Derive one external anchor from imported proof receipts using compact descriptor proofs")
        proof_anchor = build_proof_anchor(
            wallet,
            statement["statement_hex"],
            proof_receipt_hexes,
            {
                "min_receipts": 2,
                "required_proof_system_ids": proof_system_ids,
                "required_verifier_key_hashes": verifier_key_hashes,
                "descriptor_proofs": proof_hexes,
            },
        )
        assert_equal(proof_anchor["receipt_count"], 2)
        assert_equal(proof_anchor["distinct_receipt_count"], 2)
        assert_equal(proof_anchor["external_anchor"]["domain_id"], expected_source["domain_id"])
        assert_equal(proof_anchor["external_anchor"]["source_epoch"], expected_source["source_epoch"])
        assert_equal(proof_anchor["external_anchor"]["data_root"], expected_source["data_root"])
        assert_equal(proof_anchor["proof_policy"], proof_policy["proof_policy"])

        fallback_anchor = build_proof_anchor(
            wallet,
            statement["statement_hex"],
            proof_receipt_hexes,
            {
                "revealed_descriptors": descriptors,
            },
        )
        assert_equal(fallback_anchor["external_anchor"], proof_anchor["external_anchor"])

        self.log.info("Reject duplicate proof receipts, missing systems, and mismatched statements")
        assert_raises_rpc_error(
            -8,
            "proof_receipts contain duplicates",
            wallet.bridge_buildproofanchor,
            statement["statement_hex"],
            [proof_receipt_hexes[0], proof_receipt_hexes[0]],
            {},
        )
        assert_raises_rpc_error(
            -8,
            "proof receipt set does not satisfy statement proof_policy",
            wallet.bridge_buildproofanchor,
            statement["statement_hex"],
            [proof_receipt_hexes[0]],
            {
                "required_proof_system_ids": proof_system_ids,
                "descriptor_proofs": [proof_hexes[0]],
            },
        )
        assert_raises_rpc_error(
            -8,
            "required_proof_system_ids[2] is missing from the proof receipt set",
            wallet.bridge_buildproofanchor,
            statement["statement_hex"],
            proof_receipt_hexes,
            {
                "required_proof_system_ids": proof_system_ids + [bridge_hex(0x59FF)],
                "descriptor_proofs": proof_hexes,
            },
        )
        assert_raises_rpc_error(
            -8,
            "statement requires options.descriptor_proofs or options.revealed_descriptors to validate proof_policy membership",
            wallet.bridge_buildproofanchor,
            statement["statement_hex"],
            proof_receipt_hexes,
            {},
        )
        assert_raises_rpc_error(
            -8,
            "options.descriptor_proofs must contain one proof per receipt",
            wallet.bridge_buildproofanchor,
            statement["statement_hex"],
            proof_receipt_hexes,
            {"descriptor_proofs": [proof_hexes[0]]},
        )

        other_statement = build_batch_statement(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            domain_id=expected_source["domain_id"],
            source_epoch=expected_source["source_epoch"] + 1,
            data_root=bridge_hex(0x5105),
            proof_policy=proof_policy["proof_policy"],
        )
        mismatched_receipt = build_proof_receipt(
            wallet,
            other_statement["statement_hex"],
            proof_system_id=bridge_hex(0x5700),
            verifier_key_hash=bridge_hex(0x5701),
            public_values_hash=bridge_hex(0x5702),
            proof_commitment=bridge_hex(0x5703),
        )
        assert_raises_rpc_error(
            -8,
            "proof_receipts[1] does not match statement_hex",
            wallet.bridge_buildproofanchor,
            statement["statement_hex"],
            [proof_receipt_hexes[0], mismatched_receipt["proof_receipt_hex"]],
            {"descriptor_proofs": proof_hexes},
        )

        outsider_receipt = build_proof_receipt(
            wallet,
            statement["statement_hex"],
            proof_system_id=bridge_hex(0x5800),
            verifier_key_hash=bridge_hex(0x5801),
            public_values_hash=bridge_hex(0x5802),
            proof_commitment=bridge_hex(0x5803),
        )
        assert_raises_rpc_error(
            -8,
            "options.descriptor_proofs[1] does not verify for proof_receipts[1] descriptor",
            wallet.bridge_buildproofanchor,
            statement["statement_hex"],
            [proof_receipt_hexes[0], outsider_receipt["proof_receipt_hex"]],
            {"descriptor_proofs": proof_hexes},
        )

        self.log.info("Feed the proof-backed anchor into the existing bridge-out settlement path")
        anchored_commitment = build_batch_commitment(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            external_anchor=proof_anchor["external_anchor"],
        )
        batch_out_plan, _, _ = planbatchout(
            wallet,
            payouts,
            refund_lock_height,
            bridge_id=bridge_id,
            operation_id=operation_id,
            batch_commitment_hex=anchored_commitment["commitment_hex"],
        )
        assert_equal(batch_out_plan["attestation"]["message"]["version"], 3)
        assert_equal(batch_out_plan["attestation"]["message"]["external_anchor"], proof_anchor["external_anchor"])

        self.log.info(
            "Proof-backed surfaces observed: statement %d bytes, proof receipt %d bytes, descriptor proof %d bytes, verification_root %s",
            len(bytes.fromhex(statement["statement_hex"])),
            len(bytes.fromhex(sp1_receipt["proof_receipt_hex"])),
            len(bytes.fromhex(proof_hexes[0])),
            proof_anchor["external_anchor"]["verification_root"],
        )


if __name__ == "__main__":
    WalletBridgeProofReceiptTest(__file__).main()
