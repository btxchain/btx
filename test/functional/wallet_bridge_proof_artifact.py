#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for canonical proof artifacts over bridge batch statements."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_batch_commitment,
    build_batch_statement,
    build_proof_adapter,
    build_proof_anchor,
    build_proof_artifact,
    build_proof_policy,
    build_proof_receipt,
    create_bridge_wallet,
    planbatchout,
    sign_batch_authorization,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBridgeProofArtifactTest(BitcoinTestFramework):
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
        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_proof_artifact")

        refund_lock_height = node.getblockcount() + 30
        bridge_id = bridge_hex(0xA100)
        operation_id = bridge_hex(0xA101)
        expected_source = {
            "domain_id": bridge_hex(0xA102),
            "source_epoch": 113,
            "data_root": bridge_hex(0xA103),
        }

        payout_amounts = [Decimal("1.10"), Decimal("1.30"), Decimal("1.50")]
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
                    "wallet_id": bridge_hex(0xA200 + index),
                    "destination_id": bridge_hex(0xA300 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0xA400 + index),
                },
                bridge_id=bridge_id,
                operation_id=operation_id,
            )
            entries.append({"authorization_hex": signed["authorization_hex"]})
            payouts.append({"address": payout_addresses[index], "amount": amount})

        sp1_adapter = build_proof_adapter(wallet, adapter_name="sp1-groth16-settlement-metadata-v1")
        risc0_adapter = build_proof_adapter(wallet, adapter_name="risc0-zkvm-succinct-batch-tuple-v1")
        blobstream_inline_adapter = {
            "proof_profile": {
                "family": "blobstream",
                "proof_type": "sp1",
                "claim_system": "data-root-tuple-v1",
            },
            "claim_kind": "data_root_tuple_v1",
        }

        descriptors = [
            {
                "proof_adapter_name": "sp1-groth16-settlement-metadata-v1",
                "verifier_key_hash": bridge_hex(0xA500),
            },
            {
                "proof_adapter_hex": risc0_adapter["proof_adapter_hex"],
                "verifier_key_hash": bridge_hex(0xA600),
            },
            {
                "proof_adapter": blobstream_inline_adapter,
                "verifier_key_hash": bridge_hex(0xA700),
            },
        ]
        proof_policy = build_proof_policy(wallet, descriptors, required_receipts=2, targets=descriptors)

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

        self.log.info("Build imported proof artifacts for SP1-, RISC Zero-, and Blobstream-shaped adapter paths")
        sp1_artifact = build_proof_artifact(
            wallet,
            statement["statement_hex"],
            proof_adapter_name="sp1-groth16-settlement-metadata-v1",
            verifier_key_hash=descriptors[0]["verifier_key_hash"],
            proof_commitment=bridge_hex(0xA501),
            artifact_hex="11" * 48,
            proof_size_bytes=393216,
            public_values_size_bytes=96,
            auxiliary_data_size_bytes=2048,
        )
        risc0_artifact = build_proof_artifact(
            wallet,
            statement["statement_hex"],
            proof_adapter_hex=risc0_adapter["proof_adapter_hex"],
            verifier_key_hash=descriptors[1]["verifier_key_hash"],
            proof_commitment=bridge_hex(0xA601),
            artifact_hex="22" * 40,
            proof_size_bytes=262144,
            public_values_size_bytes=64,
            auxiliary_data_size_bytes=4096,
        )
        blobstream_artifact = build_proof_artifact(
            wallet,
            statement["statement_hex"],
            proof_adapter=blobstream_inline_adapter,
            verifier_key_hash=descriptors[2]["verifier_key_hash"],
            proof_commitment=bridge_hex(0xA701),
            artifact_commitment=bridge_hex(0xA702),
            proof_size_bytes=131072,
            public_values_size_bytes=72,
            auxiliary_data_size_bytes=8192,
        )

        for artifact in [sp1_artifact, risc0_artifact, blobstream_artifact]:
            decoded = wallet.bridge_decodeproofartifact(artifact["proof_artifact_hex"])
            assert_equal(decoded["proof_artifact"], artifact["proof_artifact"])
            assert_equal(decoded["proof_artifact_id"], artifact["proof_artifact_id"])
            assert_equal(decoded["proof_receipt"], artifact["proof_receipt"])
            assert decoded["proof_descriptor"]["proof_system_id"] != "00" * 32

        self.log.info("Regenerate the same proof policy from artifact-backed descriptors after the statement exists")
        artifact_policy = build_proof_policy(
            wallet,
            [
                {"proof_artifact_hex": sp1_artifact["proof_artifact_hex"]},
                {"proof_artifact_hex": risc0_artifact["proof_artifact_hex"]},
                {"proof_artifact": blobstream_artifact["proof_artifact"]},
            ],
            required_receipts=2,
        )
        assert_equal(artifact_policy["proof_policy"], proof_policy["proof_policy"])

        self.log.info("Build canonical proof receipts back from proof artifacts")
        sp1_receipt = build_proof_receipt(
            wallet,
            statement["statement_hex"],
            proof_artifact_hex=sp1_artifact["proof_artifact_hex"],
        )
        assert_equal(sp1_receipt["proof_receipt"], sp1_artifact["proof_receipt"])

        risc0_receipt = build_proof_receipt(
            wallet,
            statement["statement_hex"],
            proof_artifact=risc0_artifact["proof_artifact"],
        )
        assert_equal(risc0_receipt["proof_receipt"], risc0_artifact["proof_receipt"])

        blobstream_receipt = build_proof_receipt(
            wallet,
            statement["statement_hex"],
            proof_artifact_hex=blobstream_artifact["proof_artifact_hex"],
        )
        assert_equal(blobstream_receipt["proof_receipt"], blobstream_artifact["proof_receipt"])

        self.log.info("Reject statement mismatches and selector mixing on the artifact path")
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
        assert_raises_rpc_error(
            -8,
            "proof_artifact does not match statement_hex",
            wallet.bridge_buildproofreceipt,
            other_statement["statement_hex"],
            {"proof_artifact_hex": sp1_artifact["proof_artifact_hex"]},
        )
        assert_raises_rpc_error(
            -8,
            "descriptors[0] cannot mix proof_artifact_* selectors with verifier_key_hash, proof_adapter_*, proof_system_id, proof_profile_hex, or proof_profile",
            wallet.bridge_buildproofpolicy,
            [
                {
                    "proof_artifact_hex": sp1_artifact["proof_artifact_hex"],
                    "proof_adapter_name": "sp1-groth16-settlement-metadata-v1",
                }
            ],
            {"required_receipts": 1},
        )
        assert_raises_rpc_error(
            -8,
            "proof_receipt cannot mix proof_artifact_* selectors with verifier_key_hash, proof_commitment, proof_adapter_*, proof_system_id, proof_profile_hex, proof_profile, public_values_hash, claim_hex, or claim",
            wallet.bridge_buildproofreceipt,
            statement["statement_hex"],
            {
                "proof_artifact_hex": sp1_artifact["proof_artifact_hex"],
                "verifier_key_hash": descriptors[0]["verifier_key_hash"],
            },
        )

        self.log.info("Anchor the batch from artifact-backed receipts and feed it into the existing bridge-out settlement path")
        descriptor_proofs = [entry["proof_hex"] for entry in proof_policy["proofs"]]
        proof_anchor = build_proof_anchor(
            wallet,
            statement["statement_hex"],
            [
                sp1_receipt["proof_receipt_hex"],
                risc0_receipt["proof_receipt_hex"],
                blobstream_receipt["proof_receipt_hex"],
            ],
            {"descriptor_proofs": descriptor_proofs},
        )
        assert_equal(proof_anchor["receipt_count"], 3)

        anchored_commitment = build_batch_commitment(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            external_anchor=proof_anchor["external_anchor"],
        )
        plan, _, _ = planbatchout(
            wallet,
            payouts,
            refund_lock_height,
            bridge_id=bridge_id,
            operation_id=operation_id,
            batch_commitment_hex=anchored_commitment["commitment_hex"],
        )
        assert_equal(plan["attestation"]["message"]["external_anchor"], proof_anchor["external_anchor"])

        self.log.info(
            "artifact bytes: sp1=%d risc0=%d blobstream=%d; storage bytes: sp1=%d risc0=%d blobstream=%d; proof receipt bytes=%d",
            len(sp1_artifact["proof_artifact_hex"]) // 2,
            len(risc0_artifact["proof_artifact_hex"]) // 2,
            len(blobstream_artifact["proof_artifact_hex"]) // 2,
            sp1_artifact["proof_artifact"]["storage_bytes"],
            risc0_artifact["proof_artifact"]["storage_bytes"],
            blobstream_artifact["proof_artifact"]["storage_bytes"],
            len(sp1_receipt["proof_receipt_hex"]) // 2,
        )


if __name__ == "__main__":
    WalletBridgeProofArtifactTest(__file__).main()
