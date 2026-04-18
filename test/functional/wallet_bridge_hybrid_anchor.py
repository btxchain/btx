#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for hybrid committee-plus-proof bridge anchors."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_batch_commitment,
    build_batch_statement,
    build_external_anchor,
    build_hybrid_anchor,
    build_proof_anchor,
    build_proof_policy,
    build_proof_receipt,
    build_verifier_set,
    create_bridge_wallet,
    export_bridge_key,
    planbatchout,
    sign_batch_authorization,
    sign_batch_receipt,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBridgeHybridAnchorTest(BitcoinTestFramework):
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
        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_hybrid_anchor")

        refund_lock_height = node.getblockcount() + 30
        bridge_id = bridge_hex(0x6100)
        operation_id = bridge_hex(0x6101)
        expected_source = {
            "domain_id": bridge_hex(0x6102),
            "source_epoch": 41,
            "data_root": bridge_hex(0x6103),
        }

        payout_amounts = [Decimal("1.30"), Decimal("1.45"), Decimal("1.60")]
        payout_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]
        user_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]
        attestor_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in range(3)]

        self.log.info("Build one batch statement that commits to both verifier-set and proof-policy constraints")
        entries = []
        payouts = []
        for index, amount in enumerate(payout_amounts):
            signed = sign_batch_authorization(
                wallet,
                user_addresses[index],
                "bridge_out",
                {
                    "kind": "transparent_payout",
                    "wallet_id": bridge_hex(0x6200 + index),
                    "destination_id": bridge_hex(0x6300 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0x6400 + index),
                },
                bridge_id=bridge_id,
                operation_id=operation_id,
            )
            entries.append({"authorization_hex": signed["authorization_hex"]})
            payouts.append({"address": payout_addresses[index], "amount": amount})

        attestors = [export_bridge_key(wallet, address, "ml-dsa-44") for address in attestor_addresses]
        verifier_set = build_verifier_set(
            wallet,
            attestors,
            required_signers=2,
            targets=attestors[:2],
        )
        attestor_proofs = [entry["proof_hex"] for entry in verifier_set["proofs"]]

        descriptors = [
            {"proof_system_id": bridge_hex(0x6500), "verifier_key_hash": bridge_hex(0x6501)},
            {"proof_system_id": bridge_hex(0x6600), "verifier_key_hash": bridge_hex(0x6601)},
        ]
        proof_policy = build_proof_policy(
            wallet,
            descriptors,
            required_receipts=2,
            targets=descriptors,
        )
        descriptor_proofs = [entry["proof_hex"] for entry in proof_policy["proofs"]]

        statement = build_batch_statement(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            domain_id=expected_source["domain_id"],
            source_epoch=expected_source["source_epoch"],
            data_root=expected_source["data_root"],
            verifier_set=verifier_set["verifier_set"],
            proof_policy=proof_policy["proof_policy"],
        )
        assert_equal(statement["statement"]["version"], 4)
        assert_equal(statement["statement"]["verifier_set"], verifier_set["verifier_set"])
        assert_equal(statement["statement"]["proof_policy"], proof_policy["proof_policy"])

        self.log.info("Build committee receipts and imported proof receipts against the same statement")
        receipt_hexes = [
            sign_batch_receipt(wallet, attestor_addresses[0], statement["statement_hex"])["receipt_hex"],
            sign_batch_receipt(wallet, attestor_addresses[1], statement["statement_hex"])["receipt_hex"],
        ]
        proof_receipt_hexes = [
            build_proof_receipt(
                wallet,
                statement["statement_hex"],
                proof_system_id=descriptors[0]["proof_system_id"],
                verifier_key_hash=descriptors[0]["verifier_key_hash"],
                public_values_hash=bridge_hex(0x6700),
                proof_commitment=bridge_hex(0x6701),
            )["proof_receipt_hex"],
            build_proof_receipt(
                wallet,
                statement["statement_hex"],
                proof_system_id=descriptors[1]["proof_system_id"],
                verifier_key_hash=descriptors[1]["verifier_key_hash"],
                public_values_hash=bridge_hex(0x6800),
                proof_commitment=bridge_hex(0x6801),
            )["proof_receipt_hex"],
        ]

        self.log.info("Reject attempts to downcast a hybrid statement into one-sided anchors")
        assert_raises_rpc_error(
            -8,
            "statement also commits to proof_policy; use bridge_buildhybridanchor",
            wallet.bridge_buildexternalanchor,
            statement["statement_hex"],
            receipt_hexes,
            {"attestor_proofs": attestor_proofs},
        )
        assert_raises_rpc_error(
            -8,
            "statement also commits to verifier_set; use bridge_buildhybridanchor",
            wallet.bridge_buildproofanchor,
            statement["statement_hex"],
            proof_receipt_hexes,
            {"descriptor_proofs": descriptor_proofs},
        )

        self.log.info("Derive one hybrid external anchor from both witness sets")
        hybrid_anchor = build_hybrid_anchor(
            wallet,
            statement["statement_hex"],
            receipt_hexes,
            proof_receipt_hexes,
            {
                "receipt_policy": {"attestor_proofs": attestor_proofs},
                "proof_receipt_policy": {"descriptor_proofs": descriptor_proofs},
            },
        )
        assert_equal(hybrid_anchor["verifier_set"], verifier_set["verifier_set"])
        assert_equal(hybrid_anchor["proof_policy"], proof_policy["proof_policy"])
        assert_equal(hybrid_anchor["distinct_attestor_count"], 2)
        assert_equal(hybrid_anchor["distinct_proof_receipt_count"], 2)
        assert_equal(hybrid_anchor["external_anchor"]["domain_id"], expected_source["domain_id"])
        assert_equal(hybrid_anchor["external_anchor"]["source_epoch"], expected_source["source_epoch"])
        assert_equal(hybrid_anchor["external_anchor"]["data_root"], expected_source["data_root"])

        fallback_anchor = build_hybrid_anchor(
            wallet,
            statement["statement_hex"],
            receipt_hexes,
            proof_receipt_hexes,
            {
                "receipt_policy": {"revealed_attestors": attestors},
                "proof_receipt_policy": {"revealed_descriptors": descriptors},
            },
        )
        assert_equal(fallback_anchor["external_anchor"], hybrid_anchor["external_anchor"])

        self.log.info("Feed the hybrid anchor into the existing batch commitment and settlement path")
        anchored_commitment = build_batch_commitment(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            external_anchor=hybrid_anchor["external_anchor"],
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
        assert_equal(batch_out_plan["attestation"]["message"]["external_anchor"], hybrid_anchor["external_anchor"])

        self.log.info(
            "Hybrid surfaces observed: statement %d bytes, receipt %d bytes, proof receipt %d bytes, attestor proof %d bytes, descriptor proof %d bytes, verification_root %s",
            len(bytes.fromhex(statement["statement_hex"])),
            len(bytes.fromhex(receipt_hexes[0])),
            len(bytes.fromhex(proof_receipt_hexes[0])),
            len(bytes.fromhex(attestor_proofs[0])),
            len(bytes.fromhex(descriptor_proofs[0])),
            hybrid_anchor["external_anchor"]["verification_root"],
        )


if __name__ == "__main__":
    WalletBridgeHybridAnchorTest(__file__).main()
