#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Proof-compression target modeling for artifact-backed aggregate settlement."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_aggregate_artifact_bundle,
    build_aggregate_settlement,
    build_batch_statement,
    build_data_artifact,
    build_proof_artifact,
    build_proof_compression_target,
    create_bridge_wallet,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_approx, assert_equal


class WalletBridgeProofCompressionTargetTest(BitcoinTestFramework):
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
        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_proof_compression_target")

        bridge_id = bridge_hex(0xF100)
        operation_id = bridge_hex(0xF101)
        source = {
            "domain_id": bridge_hex(0xF102),
            "source_epoch": 211,
            "data_root": bridge_hex(0xF103),
        }

        entries = []
        for index in range(64):
            entries.append({
                "kind": "transparent_payout",
                "wallet_id": bridge_hex(0xF200 + index),
                "destination_id": bridge_hex(0xF300 + index),
                "amount": Decimal("0.10"),
                "authorization_hash": bridge_hex(0xF400 + index),
            })

        statement = build_batch_statement(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            domain_id=source["domain_id"],
            source_epoch=source["source_epoch"],
            data_root=source["data_root"],
        )

        self.log.info("Build the same artifact-backed aggregate bundle used by the hard-fork capacity path")
        proof_artifact = build_proof_artifact(
            wallet,
            statement["statement_hex"],
            proof_adapter_name="sp1-groth16-settlement-metadata-v1",
            verifier_key_hash=bridge_hex(0xF500),
            proof_commitment=bridge_hex(0xF501),
            artifact_hex="44" * 48,
            proof_size_bytes=393216,
            public_values_size_bytes=96,
            auxiliary_data_size_bytes=2048,
        )
        state_diff_artifact = build_data_artifact(
            wallet,
            statement["statement_hex"],
            kind="state_diff_v1",
            payload_hex="66" * 32,
            artifact_hex="77" * 48,
            payload_size_bytes=6080,
            auxiliary_data_size_bytes=512,
        )
        snapshot_artifact = build_data_artifact(
            wallet,
            statement["statement_hex"],
            kind="snapshot_appendix_v1",
            payload_hex="88" * 24,
            artifact_hex="99" * 40,
            payload_size_bytes=2048,
            auxiliary_data_size_bytes=256,
        )
        artifact_bundle = build_aggregate_artifact_bundle(
            wallet,
            statement["statement_hex"],
            proof_artifacts=[{"proof_artifact_hex": proof_artifact["proof_artifact_hex"]}],
            data_artifacts=[
                {"data_artifact_hex": state_diff_artifact["data_artifact_hex"]},
                {"data_artifact_hex": snapshot_artifact["data_artifact_hex"]},
            ],
        )
        assert_equal(artifact_bundle["artifact_bundle"]["proof_payload_bytes"], 393312)
        assert_equal(artifact_bundle["artifact_bundle"]["proof_auxiliary_bytes"], 2048)
        assert_equal(artifact_bundle["artifact_bundle"]["data_availability_payload_bytes"], 8128)

        self.log.info("The DA-lane path cannot recover 8k+ users/block because fixed DA bytes bind before proof size does")
        da_settlement = build_aggregate_settlement(wallet, statement["statement_hex"], {
            "batched_user_count": 64,
            "new_wallet_count": 24,
            "input_count": 64,
            "output_count": 64,
            "base_non_witness_bytes": 900,
            "base_witness_bytes": 2600,
            "state_commitment_bytes": 192,
            "artifact_bundle_hex": artifact_bundle["artifact_bundle_hex"],
            "proof_payload_location": "witness",
            "data_availability_location": "data_availability",
            "control_plane_bytes": 320,
        })
        da_target = build_proof_compression_target(wallet, da_settlement["aggregate_settlement_hex"], {
            "target_users_per_block": 8418,
            "block_data_availability_limit": 786432,
            "artifact_bundle_hex": artifact_bundle["artifact_bundle_hex"],
        })
        decoded_da_target = wallet.bridge_decodeproofcompressiontarget(da_target["proof_compression_target_hex"])
        assert_equal(decoded_da_target["proof_compression_target"], da_target["proof_compression_target"])
        da_estimate = da_target["proof_compression_estimate"]
        assert_equal(da_estimate["achievable"], False)
        assert_equal(da_estimate["current_capacity"]["users_per_block"], 1920)
        assert_equal(da_estimate["zero_proof_capacity"]["users_per_block"], 6144)
        assert_equal(da_estimate["zero_proof_capacity"]["binding_limit"], "data_availability")
        assert "required_max_proof_payload_bytes" not in da_estimate

        self.log.info("On the validium-style path, compute the exact final proof ceiling for 12,288 users/block")
        validium_settlement = build_aggregate_settlement(wallet, statement["statement_hex"], {
            "batched_user_count": 64,
            "new_wallet_count": 24,
            "input_count": 64,
            "output_count": 64,
            "base_non_witness_bytes": 900,
            "base_witness_bytes": 2600,
            "state_commitment_bytes": 192,
            "artifact_bundle_hex": artifact_bundle["artifact_bundle_hex"],
            "proof_payload_location": "witness",
            "data_availability_location": "offchain",
            "control_plane_bytes": 320,
        })
        validium_target_12288 = build_proof_compression_target(wallet, validium_settlement["aggregate_settlement_hex"], {
            "target_users_per_block": 12288,
            "artifact_bundle_hex": artifact_bundle["artifact_bundle_hex"],
        })
        estimate_12288 = validium_target_12288["proof_compression_estimate"]
        assert_equal(estimate_12288["achievable"], True)
        assert_equal(estimate_12288["target"]["current_proof_payload_bytes"], 393312)
        assert_equal(estimate_12288["target"]["current_proof_artifact_total_bytes"], 395360)
        assert_equal(estimate_12288["current_capacity"]["users_per_block"], 1920)
        assert_equal(estimate_12288["zero_proof_capacity"]["users_per_block"], 208000)
        assert_equal(estimate_12288["required_max_proof_payload_bytes"], 58808)
        assert_equal(estimate_12288["required_proof_payload_reduction_bytes"], 334504)
        assert_equal(estimate_12288["max_proof_payload_bytes_by_serialized_size"], 58808)
        assert_equal(estimate_12288["max_proof_payload_bytes_by_weight"], 118032)
        assert_equal(estimate_12288["target_binding_limit"], "serialized_size")
        assert_equal(estimate_12288["modeled_target_capacity"]["max_settlements_per_block"], 192)
        assert_equal(estimate_12288["modeled_target_capacity"]["users_per_block"], 12288)
        assert_approx(estimate_12288["required_proof_payload_remaining_ratio"], 58808 / 393312)
        assert_approx(estimate_12288["required_proof_payload_remaining_ratio_vs_artifact_total"], 58808 / 395360)

        self.log.info("Recovering the earlier witness-validium upper bound requires a proof envelope near 16 KiB again")
        validium_target_38208 = build_proof_compression_target(wallet, validium_settlement["aggregate_settlement_hex"], {
            "target_users_per_block": 38208,
            "artifact_bundle_hex": artifact_bundle["artifact_bundle_hex"],
        })
        estimate_38208 = validium_target_38208["proof_compression_estimate"]
        assert_equal(estimate_38208["achievable"], True)
        assert_equal(estimate_38208["target"]["target_settlements_per_block"], 597)
        assert_equal(estimate_38208["required_max_proof_payload_bytes"], 16408)
        assert_equal(estimate_38208["required_proof_payload_reduction_bytes"], 376904)
        assert_equal(estimate_38208["modeled_target_capacity"]["max_settlements_per_block"], 597)
        assert_equal(estimate_38208["modeled_target_capacity"]["users_per_block"], 38208)
        assert_approx(estimate_38208["required_proof_payload_remaining_ratio"], 16408 / 393312)


if __name__ == "__main__":
    WalletBridgeProofCompressionTargetTest(__file__).main()
