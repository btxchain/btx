#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for canonical proof adapters over bridge batch statements."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_batch_commitment,
    build_batch_statement,
    build_proof_adapter,
    build_proof_anchor,
    build_proof_claim,
    build_proof_policy,
    build_proof_receipt,
    create_bridge_wallet,
    list_proof_adapters,
    planbatchout,
    sign_batch_authorization,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBridgeProofAdapterTest(BitcoinTestFramework):
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
        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_proof_adapter")

        refund_lock_height = node.getblockcount() + 30
        bridge_id = bridge_hex(0x9100)
        operation_id = bridge_hex(0x9101)
        expected_source = {
            "domain_id": bridge_hex(0x9102),
            "source_epoch": 89,
            "data_root": bridge_hex(0x9103),
        }

        payout_amounts = [Decimal("1.25"), Decimal("1.40"), Decimal("1.55")]
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
                    "wallet_id": bridge_hex(0x9200 + index),
                    "destination_id": bridge_hex(0x9300 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0x9400 + index),
                },
                bridge_id=bridge_id,
                operation_id=operation_id,
            )
            entries.append({"authorization_hex": signed["authorization_hex"]})
            payouts.append({"address": payout_addresses[index], "amount": amount})

        self.log.info("List built-in proof adapters and build three adapters across SP1, RISC Zero, and Blobstream-style flows")
        adapter_listing = list_proof_adapters(wallet)
        adapter_names = {entry["adapter_name"] for entry in adapter_listing["adapters"]}
        assert "sp1-groth16-settlement-metadata-v1" in adapter_names
        assert "risc0-zkvm-succinct-batch-tuple-v1" in adapter_names
        assert "blobstream-sp1-data-root-tuple-v1" in adapter_names

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
        blobstream_adapter = build_proof_adapter(
            wallet,
            proof_profile=blobstream_inline_adapter["proof_profile"],
            claim_kind=blobstream_inline_adapter["claim_kind"],
        )
        for adapter in [sp1_adapter, risc0_adapter, blobstream_adapter]:
            decoded = wallet.bridge_decodeproofadapter(adapter["proof_adapter_hex"])
            assert_equal(decoded["proof_adapter"], adapter["proof_adapter"])
            assert_equal(decoded["proof_adapter_id"], adapter["proof_adapter_id"])
            assert_equal(decoded["proof_system_id"], adapter["proof_system_id"])

        sp1_verifier = bridge_hex(0x9500)
        risc0_verifier = bridge_hex(0x9600)
        blobstream_verifier = bridge_hex(0x9700)
        descriptors = [
            {
                "proof_adapter_name": "sp1-groth16-settlement-metadata-v1",
                "verifier_key_hash": sp1_verifier,
            },
            {
                "proof_adapter_hex": risc0_adapter["proof_adapter_hex"],
                "verifier_key_hash": risc0_verifier,
            },
            {
                "proof_adapter": blobstream_inline_adapter,
                "verifier_key_hash": blobstream_verifier,
            },
        ]

        self.log.info("Build one proof policy from adapter-backed descriptors")
        proof_policy = build_proof_policy(
            wallet,
            descriptors,
            required_receipts=2,
            targets=descriptors,
        )
        assert_equal(proof_policy["proof_policy"]["descriptor_count"], 3)

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

        settlement_claim = build_proof_claim(wallet, statement["statement_hex"], kind="settlement_metadata_v1")
        batch_claim = build_proof_claim(wallet, statement["statement_hex"], kind="batch_tuple_v1")
        data_root_claim = build_proof_claim(wallet, statement["statement_hex"], kind="data_root_tuple_v1")

        self.log.info("Build imported proof receipts directly from named and explicit proof adapters")
        sp1_receipt = build_proof_receipt(
            wallet,
            statement["statement_hex"],
            proof_adapter_name="sp1-groth16-settlement-metadata-v1",
            verifier_key_hash=sp1_verifier,
            proof_commitment=bridge_hex(0x9501),
        )
        assert_equal(sp1_receipt["proof_receipt"]["proof_system_id"], sp1_adapter["proof_system_id"])
        assert_equal(sp1_receipt["proof_receipt"]["public_values_hash"], settlement_claim["public_values_hash"])

        risc0_receipt = build_proof_receipt(
            wallet,
            statement["statement_hex"],
            proof_adapter_hex=risc0_adapter["proof_adapter_hex"],
            verifier_key_hash=risc0_verifier,
            proof_commitment=bridge_hex(0x9601),
        )
        assert_equal(risc0_receipt["proof_receipt"]["proof_system_id"], risc0_adapter["proof_system_id"])
        assert_equal(risc0_receipt["proof_receipt"]["public_values_hash"], batch_claim["public_values_hash"])

        blobstream_receipt = build_proof_receipt(
            wallet,
            statement["statement_hex"],
            proof_adapter=blobstream_inline_adapter,
            verifier_key_hash=blobstream_verifier,
            proof_commitment=bridge_hex(0x9701),
        )
        assert_equal(blobstream_receipt["proof_receipt"]["proof_system_id"], blobstream_adapter["proof_system_id"])
        assert_equal(blobstream_receipt["proof_receipt"]["public_values_hash"], data_root_claim["public_values_hash"])

        self.log.info("Reject unknown adapters and selector mixing")
        assert_raises_rpc_error(
            -8,
            "adapter.adapter_name is not a supported built-in proof adapter",
            wallet.bridge_buildproofadapter,
            {
                "adapter_name": "does-not-exist",
            },
        )
        assert_raises_rpc_error(
            -8,
            "descriptors[0] cannot mix proof_adapter_* selectors with proof_system_id, proof_profile_hex, or proof_profile",
            wallet.bridge_buildproofpolicy,
            [
                {
                    "proof_adapter_name": "sp1-groth16-settlement-metadata-v1",
                    "proof_system_id": sp1_adapter["proof_system_id"],
                    "verifier_key_hash": sp1_verifier,
                }
            ],
            {"required_receipts": 1},
        )
        assert_raises_rpc_error(
            -8,
            "proof_receipt cannot mix proof_adapter_* selectors with public_values_hash, claim_hex, or claim",
            wallet.bridge_buildproofreceipt,
            statement["statement_hex"],
            {
                "proof_adapter_name": "sp1-groth16-settlement-metadata-v1",
                "verifier_key_hash": sp1_verifier,
                "public_values_hash": settlement_claim["public_values_hash"],
                "proof_commitment": bridge_hex(0x95A0),
            },
        )

        self.log.info("Anchor the batch from adapter-backed receipts and feed it into the existing bridge-out settlement path")
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
        assert_equal(proof_anchor["external_anchor"]["domain_id"], expected_source["domain_id"])
        assert_equal(proof_anchor["external_anchor"]["source_epoch"], expected_source["source_epoch"])
        assert_equal(proof_anchor["external_anchor"]["data_root"], expected_source["data_root"])

        anchored_commitment = build_batch_commitment(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            external_anchor=proof_anchor["external_anchor"],
        )
        assert_equal(anchored_commitment["commitment"]["external_anchor"], proof_anchor["external_anchor"])

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
            "adapter bytes: sp1=%d risc0=%d blobstream=%d; proof receipt bytes=%d",
            len(sp1_adapter["proof_adapter_hex"]) // 2,
            len(risc0_adapter["proof_adapter_hex"]) // 2,
            len(blobstream_adapter["proof_adapter_hex"]) // 2,
            len(sp1_receipt["proof_receipt_hex"]) // 2,
        )


if __name__ == "__main__":
    WalletBridgeProofAdapterTest(__file__).main()
