#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for canonical BTX proof claims over bridge batch statements."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_batch_commitment,
    build_batch_statement,
    build_proof_anchor,
    build_proof_claim,
    build_proof_policy,
    build_proof_profile,
    build_proof_receipt,
    create_bridge_wallet,
    planbatchout,
    sign_batch_authorization,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBridgeProofClaimTest(BitcoinTestFramework):
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
        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_proof_claim")

        refund_lock_height = node.getblockcount() + 30
        bridge_id = bridge_hex(0x8100)
        operation_id = bridge_hex(0x8101)
        expected_source = {
            "domain_id": bridge_hex(0x8102),
            "source_epoch": 73,
            "data_root": bridge_hex(0x8103),
        }

        payout_amounts = [Decimal("1.45"), Decimal("1.55"), Decimal("1.65")]
        payout_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]
        user_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]

        entries = []
        payouts = []
        for index, amount in enumerate(payout_amounts):
            signed = sign_batch_authorization(
                wallet,
                user_addresses[index],
                "bridge_out",
                {
                    "kind": "transparent_payout",
                    "wallet_id": bridge_hex(0x8200 + index),
                    "destination_id": bridge_hex(0x8300 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0x8400 + index),
                },
                bridge_id=bridge_id,
                operation_id=operation_id,
            )
            entries.append({"authorization_hex": signed["authorization_hex"]})
            payouts.append({"address": payout_addresses[index], "amount": amount})

        self.log.info("Build imported-proof profiles and a statement-bound proof policy")
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

        sp1_verifier = bridge_hex(0x8500)
        risc0_verifier = bridge_hex(0x8600)
        blobstream_verifier = bridge_hex(0x8700)
        descriptors = [
            {
                "proof_profile_hex": sp1_profile["profile_hex"],
                "verifier_key_hash": sp1_verifier,
            },
            {
                "proof_profile_hex": risc0_profile["profile_hex"],
                "verifier_key_hash": risc0_verifier,
            },
            {
                "proof_profile_hex": blobstream_profile["profile_hex"],
                "verifier_key_hash": blobstream_verifier,
            },
        ]
        proof_policy = build_proof_policy(
            wallet,
            descriptors,
            required_receipts=2,
            targets=descriptors,
        )

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

        self.log.info("Build canonical proof claims from the statement for settlement, batch-only, and data-root-only adapters")
        settlement_claim = build_proof_claim(wallet, statement["statement_hex"], kind="settlement_metadata_v1")
        batch_claim = build_proof_claim(wallet, statement["statement_hex"], kind="batch_tuple_v1")
        data_root_claim = build_proof_claim(wallet, statement["statement_hex"], kind="data_root_tuple_v1")
        for claim in [settlement_claim, batch_claim, data_root_claim]:
            decoded = wallet.bridge_decodeproofclaim(claim["claim_hex"])
            assert_equal(decoded["claim"], claim["claim"])
            assert_equal(decoded["public_values_hash"], claim["public_values_hash"])

        assert_equal(settlement_claim["claim"]["statement_hash"], statement["statement_hash"])
        assert_equal(batch_claim["claim"]["batch_root"], statement["statement"]["batch_root"])
        assert_equal(data_root_claim["claim"]["domain_id"], expected_source["domain_id"])
        assert_equal(data_root_claim["claim"]["source_epoch"], expected_source["source_epoch"])
        assert_equal(data_root_claim["claim"]["data_root"], expected_source["data_root"])

        self.log.info("Build proof receipts from canonical proof claims instead of opaque public_values_hash inputs")
        sp1_receipt = build_proof_receipt(
            wallet,
            statement["statement_hex"],
            proof_profile_hex=sp1_profile["profile_hex"],
            verifier_key_hash=sp1_verifier,
            claim_hex=settlement_claim["claim_hex"],
            proof_commitment=bridge_hex(0x8501),
        )
        assert_equal(sp1_receipt["proof_receipt"]["public_values_hash"], settlement_claim["public_values_hash"])

        risc0_receipt = build_proof_receipt(
            wallet,
            statement["statement_hex"],
            proof_profile_hex=risc0_profile["profile_hex"],
            verifier_key_hash=risc0_verifier,
            claim=batch_claim["claim"],
            proof_commitment=bridge_hex(0x8601),
        )
        assert_equal(risc0_receipt["proof_receipt"]["public_values_hash"], batch_claim["public_values_hash"])

        blobstream_receipt = build_proof_receipt(
            wallet,
            statement["statement_hex"],
            proof_profile_hex=blobstream_profile["profile_hex"],
            verifier_key_hash=blobstream_verifier,
            claim_hex=data_root_claim["claim_hex"],
            proof_commitment=bridge_hex(0x8701),
        )
        assert_equal(blobstream_receipt["proof_receipt"]["public_values_hash"], data_root_claim["public_values_hash"])

        self.log.info("Reject missing, conflicting, or mismatched proof-claim selectors")
        assert_raises_rpc_error(
            -8,
            "proof_receipt must include exactly one of public_values_hash, claim_hex, or claim",
            wallet.bridge_buildproofreceipt,
            statement["statement_hex"],
            {
                "proof_profile_hex": sp1_profile["profile_hex"],
                "verifier_key_hash": sp1_verifier,
                "proof_commitment": bridge_hex(0x85A0),
            },
        )
        assert_raises_rpc_error(
            -8,
            "proof_receipt must include exactly one of public_values_hash, claim_hex, or claim",
            wallet.bridge_buildproofreceipt,
            statement["statement_hex"],
            {
                "proof_profile_hex": sp1_profile["profile_hex"],
                "verifier_key_hash": sp1_verifier,
                "public_values_hash": settlement_claim["public_values_hash"],
                "claim_hex": settlement_claim["claim_hex"],
                "proof_commitment": bridge_hex(0x85A1),
            },
        )

        other_statement = build_batch_statement(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            domain_id=expected_source["domain_id"],
            source_epoch=expected_source["source_epoch"] + 1,
            data_root=expected_source["data_root"],
            proof_policy=proof_policy["proof_policy"],
        )
        other_claim = build_proof_claim(wallet, other_statement["statement_hex"], kind="settlement_metadata_v1")
        assert_raises_rpc_error(
            -8,
            "proof_receipt claim does not match statement_hex",
            wallet.bridge_buildproofreceipt,
            statement["statement_hex"],
            {
                "proof_profile_hex": sp1_profile["profile_hex"],
                "verifier_key_hash": sp1_verifier,
                "claim_hex": other_claim["claim_hex"],
                "proof_commitment": bridge_hex(0x85A2),
            },
        )

        self.log.info("Anchor the batch from claim-backed imported receipts and bind it into the bridge-out commitment")
        descriptor_proofs = [entry["proof_hex"] for entry in proof_policy["proofs"]]
        proof_anchor = build_proof_anchor(
            wallet,
            statement["statement_hex"],
            [
                sp1_receipt["proof_receipt_hex"],
                risc0_receipt["proof_receipt_hex"],
                blobstream_receipt["proof_receipt_hex"],
            ],
            {
                "descriptor_proofs": descriptor_proofs,
            },
        )
        assert_equal(proof_anchor["proof_policy"], proof_policy["proof_policy"])
        assert_equal(proof_anchor["receipt_count"], 3)
        assert_equal(proof_anchor["distinct_receipt_count"], 3)
        assert_equal(proof_anchor["external_anchor"]["domain_id"], expected_source["domain_id"])
        assert_equal(proof_anchor["external_anchor"]["source_epoch"], expected_source["source_epoch"])
        assert_equal(proof_anchor["external_anchor"]["data_root"], expected_source["data_root"])

        batch_commitment = build_batch_commitment(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            external_anchor=proof_anchor["external_anchor"],
        )
        assert_equal(batch_commitment["commitment"]["external_anchor"], proof_anchor["external_anchor"])

        plan, _, _ = planbatchout(
            wallet,
            payouts,
            refund_lock_height,
            bridge_id=bridge_id,
            operation_id=operation_id,
            batch_commitment_hex=batch_commitment["commitment_hex"],
        )
        assert_equal(plan["attestation"]["message"]["external_anchor"], proof_anchor["external_anchor"])

        self.log.info(
            "claim bytes: settlement=%d batch=%d data_root=%d; proof receipt bytes=%d",
            len(settlement_claim["claim_hex"]) // 2,
            len(batch_claim["claim_hex"]) // 2,
            len(data_root_claim["claim_hex"]) // 2,
            len(sp1_receipt["proof_receipt_hex"]) // 2,
        )


if __name__ == "__main__":
    WalletBridgeProofClaimTest(__file__).main()
