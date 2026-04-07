#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Measure finalized bridge settlement transactions and feed them into bridge_estimatecapacity."""

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
    estimate_capacity,
    find_output,
    mine_block,
    planbatchout,
    planout,
    sign_batch_authorization,
    sign_finalize_and_send,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBridgeCapacityEstimateTest(BitcoinTestFramework):
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
        wallet, mine_addr = create_bridge_wallet(self, node, wallet_name="bridge_capacity", amount=Decimal("15"))
        fee_margin = Decimal("0.00100000")

        refund_lock_height = node.getblockcount() + 40
        bridge_id = bridge_hex(0xC100)
        batch_operation_id = bridge_hex(0xC101)
        expected_source = {
            "domain_id": bridge_hex(0xC102),
            "source_epoch": 77,
            "data_root": bridge_hex(0xC103),
        }

        payout_amounts = [Decimal("1.10"), Decimal("1.30"), Decimal("1.50")]
        payout_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]
        user_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]

        def settle_unshield(plan, amount):
            funding_txid = wallet.sendtoaddress(plan["bridge_address"], amount + fee_margin)
            mine_block(self, node, mine_addr)
            vout, value = find_output(node, funding_txid, plan["bridge_address"], wallet)
            built = wallet.bridge_buildunshieldtx(plan["plan_hex"], funding_txid, vout, value)
            txid, tx_hex = sign_finalize_and_send(wallet, node, built["psbt"])
            decoded = node.decoderawtransaction(tx_hex)
            assert_equal(decoded["txid"], txid)
            mine_block(self, node, mine_addr)
            return {
                "size": decoded["size"],
                "weight": decoded["weight"],
                "attestation_bytes": len(bytes.fromhex(plan["attestation"]["bytes"])),
            }

        self.log.info("Create one authorization-backed batch commitment for three bridge payouts")
        entries = []
        payouts = []
        for index, amount in enumerate(payout_amounts):
            signed = sign_batch_authorization(
                wallet,
                user_addresses[index],
                "bridge_out",
                {
                    "kind": "transparent_payout",
                    "wallet_id": bridge_hex(0xC200 + index),
                    "destination_id": bridge_hex(0xC300 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0xC400 + index),
                },
                bridge_id=bridge_id,
                operation_id=batch_operation_id,
            )
            entries.append({"authorization_hex": signed["authorization_hex"]})
            payouts.append({"address": payout_addresses[index], "amount": amount})

        batch_commitment = build_batch_commitment(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=batch_operation_id,
        )

        self.log.info("Measure finalized single bridge-out settlements")
        operator_key = None
        refund_key = None
        single_metrics = []
        for index, amount in enumerate(payout_amounts):
            plan, operator_key, refund_key = planout(
                wallet,
                payout_addresses[index],
                amount,
                refund_lock_height,
                bridge_id=bridge_id,
                operation_id=bridge_hex(0xC500 + index),
                operator_key=operator_key,
                refund_key=refund_key,
            )
            single_metrics.append(settle_unshield(plan, amount))

        self.log.info("Measure one finalized batch bridge-out settlement")
        batch_plan, operator_key, refund_key = planbatchout(
            wallet,
            payouts,
            refund_lock_height,
            bridge_id=bridge_id,
            operation_id=batch_operation_id,
            operator_key=operator_key,
            refund_key=refund_key,
            batch_commitment_hex=batch_commitment["commitment_hex"],
        )
        total_amount = sum(payout_amounts, Decimal("0"))
        batch_metrics = settle_unshield(batch_plan, total_amount)

        self.log.info("Build a proof-anchored batch and measure its finalized settlement transaction")
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
                "verifier_key_hash": bridge_hex(0xC600),
            },
            {
                "proof_adapter_hex": risc0_adapter["proof_adapter_hex"],
                "verifier_key_hash": bridge_hex(0xC601),
            },
            {
                "proof_adapter": blobstream_inline_adapter,
                "verifier_key_hash": bridge_hex(0xC602),
            },
        ]
        proof_policy = build_proof_policy(wallet, descriptors, required_receipts=2, targets=descriptors)
        statement = build_batch_statement(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=batch_operation_id,
            domain_id=expected_source["domain_id"],
            source_epoch=expected_source["source_epoch"],
            data_root=expected_source["data_root"],
            proof_policy=proof_policy["proof_policy"],
        )
        artifacts = [
            build_proof_artifact(
                wallet,
                statement["statement_hex"],
                proof_adapter_name="sp1-groth16-settlement-metadata-v1",
                verifier_key_hash=descriptors[0]["verifier_key_hash"],
                proof_commitment=bridge_hex(0xC610),
                artifact_hex="11" * 48,
                proof_size_bytes=393216,
                public_values_size_bytes=96,
                auxiliary_data_size_bytes=2048,
            ),
            build_proof_artifact(
                wallet,
                statement["statement_hex"],
                proof_adapter_hex=risc0_adapter["proof_adapter_hex"],
                verifier_key_hash=descriptors[1]["verifier_key_hash"],
                proof_commitment=bridge_hex(0xC611),
                artifact_hex="22" * 40,
                proof_size_bytes=262144,
                public_values_size_bytes=64,
                auxiliary_data_size_bytes=4096,
            ),
            build_proof_artifact(
                wallet,
                statement["statement_hex"],
                proof_adapter=blobstream_inline_adapter,
                verifier_key_hash=descriptors[2]["verifier_key_hash"],
                proof_commitment=bridge_hex(0xC612),
                artifact_commitment=bridge_hex(0xC613),
                proof_size_bytes=131072,
                public_values_size_bytes=72,
                auxiliary_data_size_bytes=8192,
            ),
        ]
        proof_receipts = [
            build_proof_receipt(wallet, statement["statement_hex"], proof_artifact_hex=artifacts[0]["proof_artifact_hex"]),
            build_proof_receipt(wallet, statement["statement_hex"], proof_artifact=artifacts[1]["proof_artifact"]),
            build_proof_receipt(wallet, statement["statement_hex"], proof_artifact_hex=artifacts[2]["proof_artifact_hex"]),
        ]
        proof_anchor = build_proof_anchor(
            wallet,
            statement["statement_hex"],
            [receipt["proof_receipt_hex"] for receipt in proof_receipts],
            {"descriptor_proofs": [entry["proof_hex"] for entry in proof_policy["proofs"]]},
        )
        anchored_commitment = build_batch_commitment(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=batch_operation_id,
            external_anchor=proof_anchor["external_anchor"],
        )
        proof_plan, _, _ = planbatchout(
            wallet,
            payouts,
            refund_lock_height,
            bridge_id=bridge_id,
            operation_id=batch_operation_id,
            operator_key=operator_key,
            refund_key=refund_key,
            batch_commitment_hex=anchored_commitment["commitment_hex"],
        )
        proof_metrics = settle_unshield(proof_plan, total_amount)

        native_baseline = {
            "l1_serialized_bytes": 586196,
            "l1_weight": 2344784,
            "batched_user_count": 1,
        }
        single_footprint = {
            "l1_serialized_bytes": max(item["size"] for item in single_metrics),
            "l1_weight": max(item["weight"] for item in single_metrics),
            "control_plane_bytes": max(item["attestation_bytes"] for item in single_metrics),
            "offchain_storage_bytes": 0,
            "batched_user_count": 1,
        }
        batch_footprint = {
            "l1_serialized_bytes": batch_metrics["size"],
            "l1_weight": batch_metrics["weight"],
            "control_plane_bytes": batch_metrics["attestation_bytes"],
            "offchain_storage_bytes": 0,
            "batched_user_count": len(payouts),
        }
        proof_footprint = {
            "l1_serialized_bytes": proof_metrics["size"],
            "l1_weight": proof_metrics["weight"],
            "control_plane_bytes": proof_metrics["attestation_bytes"] + sum(len(bytes.fromhex(receipt["proof_receipt_hex"])) for receipt in proof_receipts),
            "offchain_storage_bytes": sum(artifact["proof_artifact"]["storage_bytes"] for artifact in artifacts),
            "batched_user_count": len(payouts),
        }

        self.log.info("Run the generic bridge capacity estimator against finalized settlements and the measured native shielded baseline")
        single_estimate = estimate_capacity(wallet, single_footprint, {"baseline": native_baseline})
        batch_estimate = estimate_capacity(wallet, batch_footprint, {"baseline": native_baseline})
        proof_estimate = estimate_capacity(wallet, proof_footprint, {"baseline": native_baseline})

        assert_equal(single_estimate["baseline_estimate"]["users_per_block"], 10)
        assert batch_estimate["users_per_block"] > single_estimate["users_per_block"]
        assert batch_estimate["per_user"]["l1_weight"] < single_estimate["per_user"]["l1_weight"]
        assert batch_estimate["comparison"]["users_per_block_gain"] > single_estimate["comparison"]["users_per_block_gain"]
        assert proof_estimate["users_per_block"] > single_estimate["users_per_block"]
        assert proof_estimate["comparison"]["l1_weight_ratio_per_user"] < 1.0
        assert proof_estimate["block_totals"]["offchain_storage_bytes"] > 0
        assert proof_estimate["comparison"]["offchain_storage_bytes_delta_per_settlement"] > 0

        self.log.info(
            "Finalized capacity observed: native=%d users/block, single=%d users/block (%d bytes, %d weight), batch=%d users/block (%d bytes, %d weight), proof=%d users/block (%d bytes, %d weight, %d off-chain bytes/settlement)",
            single_estimate["baseline_estimate"]["users_per_block"],
            single_estimate["users_per_block"],
            single_footprint["l1_serialized_bytes"],
            single_footprint["l1_weight"],
            batch_estimate["users_per_block"],
            batch_footprint["l1_serialized_bytes"],
            batch_footprint["l1_weight"],
            proof_estimate["users_per_block"],
            proof_footprint["l1_serialized_bytes"],
            proof_footprint["l1_weight"],
            proof_footprint["offchain_storage_bytes"],
        )


if __name__ == "__main__":
    WalletBridgeCapacityEstimateTest(__file__).main()
