#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Model hard-fork aggregate settlement modes against current BTX bridge and native baselines."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_aggregate_settlement,
    build_batch_statement,
    build_proof_artifact,
    estimate_capacity,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class WalletBridgeAggregateSettlementTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="bridge_aggregate_settlement", descriptors=True)
        wallet = node.get_wallet_rpc("bridge_aggregate_settlement")

        bridge_id = bridge_hex(0xD100)
        operation_id = bridge_hex(0xD101)
        source = {
            "domain_id": bridge_hex(0xD102),
            "source_epoch": 144,
            "data_root": bridge_hex(0xD103),
        }

        entries = []
        for index in range(64):
            entries.append({
                "kind": "transparent_payout",
                "wallet_id": bridge_hex(0xD200 + index),
                "destination_id": bridge_hex(0xD300 + index),
                "amount": Decimal("0.10"),
                "authorization_hash": bridge_hex(0xD400 + index),
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

        proof_artifact = build_proof_artifact(
            wallet,
            statement["statement_hex"],
            proof_adapter_name="sp1-groth16-settlement-metadata-v1",
            verifier_key_hash=bridge_hex(0xD500),
            proof_commitment=bridge_hex(0xD501),
            artifact_hex="44" * 48,
            proof_size_bytes=16000,
            public_values_size_bytes=384,
            auxiliary_data_size_bytes=1024,
        )

        common = {
            "batched_user_count": 64,
            "new_wallet_count": 24,
            "input_count": 64,
            "output_count": 64,
            "base_non_witness_bytes": 900,
            "base_witness_bytes": 2600,
            "state_commitment_bytes": 192,
            "data_availability_payload_bytes": 4096,
            "control_plane_bytes": 320,
            "auxiliary_offchain_bytes": 512,
        }
        native_baseline = {
            "l1_serialized_bytes": 586196,
            "l1_weight": 2344784,
            "batched_user_count": 1,
        }
        bridge_baseline = {
            "l1_serialized_bytes": 4276,
            "l1_weight": 4816,
            "control_plane_bytes": 661,
            "offchain_storage_bytes": 801000,
            "batched_user_count": 3,
        }

        self.log.info("Build witness-discounted hard-fork validium settlement")
        witness_validium = build_aggregate_settlement(wallet, statement["statement_hex"], {
            **common,
            "proof_payload_bytes": 16384,
            "proof_payload_location": "witness",
            "data_availability_location": "offchain",
        })
        witness_estimate = estimate_capacity(wallet, witness_validium["footprint"], {"baseline": native_baseline})
        assert_equal(witness_validium["footprint"]["l1_serialized_bytes"], 20076)
        assert_equal(witness_validium["footprint"]["l1_weight"], 23352)
        assert_equal(witness_validium["footprint"]["offchain_storage_bytes"], 4608)
        assert_equal(witness_estimate["binding_limit"], "serialized_size")
        assert_equal(witness_estimate["max_settlements_per_block"], 597)
        assert_equal(witness_estimate["users_per_block"], 38208)
        assert_greater_than(witness_estimate["comparison"]["users_per_block_gain"], 3800)

        self.log.info("Build non-witness hard-fork validium settlement to expose weight penalty")
        nonwitness_validium = build_aggregate_settlement(wallet, statement["statement_hex"], {
            **common,
            "proof_payload_bytes": 16384,
            "proof_payload_location": "non_witness",
            "data_availability_location": "offchain",
        })
        nonwitness_estimate = estimate_capacity(wallet, nonwitness_validium["footprint"], {"baseline": bridge_baseline})
        assert_equal(nonwitness_validium["footprint"]["l1_serialized_bytes"], witness_validium["footprint"]["l1_serialized_bytes"])
        assert_greater_than(nonwitness_validium["footprint"]["l1_weight"], witness_validium["footprint"]["l1_weight"])
        assert_equal(nonwitness_estimate["binding_limit"], "weight")
        assert_equal(nonwitness_estimate["max_settlements_per_block"], 331)
        assert_equal(nonwitness_estimate["users_per_block"], 21184)
        assert_greater_than(nonwitness_estimate["comparison"]["users_per_block_gain"], 2.5)

        self.log.info("Build artifact-backed rollup settlement using a separate L1 data-availability lane")
        blob_rollup = build_aggregate_settlement(wallet, statement["statement_hex"], {
            **common,
            "proof_artifact_hex": proof_artifact["proof_artifact_hex"],
            "proof_payload_location": "witness",
            "data_availability_location": "data_availability",
        })
        decoded_rollup = wallet.bridge_decodeaggregatesettlement(blob_rollup["aggregate_settlement_hex"])
        assert_equal(decoded_rollup["aggregate_settlement"]["proof_payload_bytes"], 16384)
        assert_equal(decoded_rollup["aggregate_settlement"]["auxiliary_offchain_bytes"], 1536)
        assert_equal(decoded_rollup["footprint"]["l1_data_availability_bytes"], 4096)

        rollup_estimate = estimate_capacity(wallet, blob_rollup["footprint"], {
            "block_data_availability_limit": 786432,
            "baseline": bridge_baseline,
        })
        assert_equal(rollup_estimate["binding_limit"], "data_availability")
        assert_equal(rollup_estimate["fit_by_data_availability"], 192)
        assert_equal(rollup_estimate["max_settlements_per_block"], 192)
        assert_equal(rollup_estimate["users_per_block"], 12288)
        assert_equal(rollup_estimate["block_totals"]["l1_data_availability_bytes"], 786432)
        assert_greater_than(rollup_estimate["comparison"]["users_per_block_gain"], 1.45)
        assert_greater_than(witness_estimate["users_per_block"], rollup_estimate["users_per_block"])
        assert_greater_than(rollup_estimate["users_per_block"], rollup_estimate["baseline_estimate"]["users_per_block"])


if __name__ == "__main__":
    WalletBridgeAggregateSettlementTest(__file__).main()
