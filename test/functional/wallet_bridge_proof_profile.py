#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for canonical imported-proof profiles over bridge batch statements."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_batch_commitment,
    build_batch_statement,
    build_proof_anchor,
    build_proof_policy,
    build_proof_profile,
    build_proof_receipt,
    create_bridge_wallet,
    planbatchout,
    sign_batch_authorization,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBridgeProofProfileTest(BitcoinTestFramework):
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
        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_proof_profile")

        refund_lock_height = node.getblockcount() + 30
        bridge_id = bridge_hex(0x7100)
        operation_id = bridge_hex(0x7101)
        expected_source = {
            "domain_id": bridge_hex(0x7102),
            "source_epoch": 51,
            "data_root": bridge_hex(0x7103),
        }

        payout_amounts = [Decimal("1.55"), Decimal("1.70"), Decimal("1.85")]
        payout_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]
        user_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]

        self.log.info("Build one bridge-out batch statement for proof-profile-backed imported receipts")
        entries = []
        payouts = []
        for index, amount in enumerate(payout_amounts):
            signed = sign_batch_authorization(
                wallet,
                user_addresses[index],
                "bridge_out",
                {
                    "kind": "transparent_payout",
                    "wallet_id": bridge_hex(0x7200 + index),
                    "destination_id": bridge_hex(0x7300 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0x7400 + index),
                },
                bridge_id=bridge_id,
                operation_id=operation_id,
            )
            entries.append({"authorization_hex": signed["authorization_hex"]})
            payouts.append({"address": payout_addresses[index], "amount": amount})

        raw_statement = build_batch_statement(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            domain_id=expected_source["domain_id"],
            source_epoch=expected_source["source_epoch"],
            data_root=expected_source["data_root"],
        )
        assert_equal(raw_statement["statement"]["entry_count"], len(entries))

        self.log.info("Build canonical proof profiles for SP1, RISC Zero, and Blobstream-style receipts")
        sp1_profile = build_proof_profile(
            wallet,
            family="sp1",
            proof_type="groth16",
            claim_system="public-values-v1",
        )
        risc0_profile = build_proof_profile(
            wallet,
            family="risc0-zkvm",
            proof_type="succinct",
            claim_system="journal-digest-v1",
        )
        blobstream_profile = build_proof_profile(
            wallet,
            family="blobstream",
            proof_type="sp1",
            claim_system="data-root-tuple-v1",
        )
        for profile in [sp1_profile, risc0_profile, blobstream_profile]:
            decoded = wallet.bridge_decodeproofprofile(profile["profile_hex"])
            assert_equal(decoded["profile"], profile["profile"])
            assert_equal(decoded["proof_system_id"], profile["proof_system_id"])

        sp1_verifier = bridge_hex(0x7500)
        risc0_verifier = bridge_hex(0x7600)
        blobstream_verifier = bridge_hex(0x7700)
        descriptors = [
            {
                "proof_profile_hex": sp1_profile["profile_hex"],
                "verifier_key_hash": sp1_verifier,
            },
            {
                "proof_profile": {
                    "family": "risc0-zkvm",
                    "proof_type": "succinct",
                    "claim_system": "journal-digest-v1",
                },
                "verifier_key_hash": risc0_verifier,
            },
            {
                "proof_profile_hex": blobstream_profile["profile_hex"],
                "verifier_key_hash": blobstream_verifier,
            },
        ]

        self.log.info("Build one proof policy from profile-backed descriptors")
        proof_policy = build_proof_policy(
            wallet,
            descriptors,
            required_receipts=2,
            targets=[descriptors[0], descriptors[2]],
        )
        assert_equal(proof_policy["proof_policy"]["descriptor_count"], 3)
        assert_equal(proof_policy["proof_policy"]["required_receipts"], 2)
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
            proof_policy=proof_policy["proof_policy"],
        )
        assert_equal(statement["statement"]["version"], 3)
        assert_equal(statement["statement"]["proof_policy"], proof_policy["proof_policy"])

        self.log.info("Build canonical proof receipts from proof-profile ids instead of raw ad hoc proof_system_id hashes")
        sp1_receipt = build_proof_receipt(
            wallet,
            statement["statement_hex"],
            proof_profile_hex=sp1_profile["profile_hex"],
            verifier_key_hash=sp1_verifier,
            public_values_hash=bridge_hex(0x7501),
            proof_commitment=bridge_hex(0x7502),
        )
        assert_equal(sp1_receipt["proof_receipt"]["proof_system_id"], sp1_profile["proof_system_id"])

        blobstream_receipt = build_proof_receipt(
            wallet,
            statement["statement_hex"],
            proof_profile={
                "family": "blobstream",
                "proof_type": "sp1",
                "claim_system": "data-root-tuple-v1",
            },
            verifier_key_hash=blobstream_verifier,
            public_values_hash=bridge_hex(0x7701),
            proof_commitment=bridge_hex(0x7702),
        )
        assert_equal(blobstream_receipt["proof_receipt"]["proof_system_id"], blobstream_profile["proof_system_id"])

        self.log.info("Reject conflicting or missing proof-system selectors")
        assert_raises_rpc_error(
            -8,
            "proof_receipt must include exactly one of proof_system_id, proof_profile_hex, or proof_profile",
            wallet.bridge_buildproofreceipt,
            statement["statement_hex"],
            {
                "verifier_key_hash": risc0_verifier,
                "public_values_hash": bridge_hex(0x7601),
                "proof_commitment": bridge_hex(0x7602),
            },
        )
        assert_raises_rpc_error(
            -8,
            "proof_receipt must include exactly one of proof_system_id, proof_profile_hex, or proof_profile",
            wallet.bridge_buildproofreceipt,
            statement["statement_hex"],
            {
                "proof_system_id": sp1_profile["proof_system_id"],
                "proof_profile_hex": sp1_profile["profile_hex"],
                "verifier_key_hash": sp1_verifier,
                "public_values_hash": bridge_hex(0x75A1),
                "proof_commitment": bridge_hex(0x75A2),
            },
        )
        assert_raises_rpc_error(
            -8,
            "descriptors[0] must include exactly one of proof_system_id, proof_profile_hex, or proof_profile",
            wallet.bridge_buildproofpolicy,
            [
                {
                    "verifier_key_hash": sp1_verifier,
                }
            ],
            {
                "required_receipts": 1,
            },
        )

        self.log.info("Anchor the batch with profile-derived receipts and compact descriptor proofs")
        proof_anchor = build_proof_anchor(
            wallet,
            statement["statement_hex"],
            [
                sp1_receipt["proof_receipt_hex"],
                blobstream_receipt["proof_receipt_hex"],
            ],
            {
                "descriptor_proofs": descriptor_proofs,
            },
        )
        assert_equal(proof_anchor["proof_policy"], proof_policy["proof_policy"])
        assert_equal(proof_anchor["receipt_count"], 2)
        assert_equal(proof_anchor["distinct_receipt_count"], 2)
        assert_equal(proof_anchor["external_anchor"]["domain_id"], expected_source["domain_id"])
        assert_equal(proof_anchor["external_anchor"]["source_epoch"], expected_source["source_epoch"])
        assert_equal(proof_anchor["external_anchor"]["data_root"], expected_source["data_root"])

        fallback_anchor = build_proof_anchor(
            wallet,
            statement["statement_hex"],
            [
                sp1_receipt["proof_receipt_hex"],
                blobstream_receipt["proof_receipt_hex"],
            ],
            {
                "revealed_descriptors": proof_policy["descriptors"],
            },
        )
        assert_equal(fallback_anchor["external_anchor"], proof_anchor["external_anchor"])

        self.log.info("Feed the profile-backed anchor into the existing bridge-out settlement path")
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
            "Proof-profile surfaces observed: profile %d bytes, statement %d bytes, proof receipt %d bytes, descriptor proof %d bytes, proof_system_ids %s %s %s",
            len(bytes.fromhex(sp1_profile["profile_hex"])),
            len(bytes.fromhex(statement["statement_hex"])),
            len(bytes.fromhex(sp1_receipt["proof_receipt_hex"])),
            len(bytes.fromhex(descriptor_proofs[0])),
            sp1_profile["proof_system_id"],
            risc0_profile["proof_system_id"],
            blobstream_profile["proof_system_id"],
        )


if __name__ == "__main__":
    WalletBridgeProofProfileTest(__file__).main()
