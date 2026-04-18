#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Model aggregate-settlement shielded state growth against BTX's current storage surfaces."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_aggregate_settlement,
    build_batch_statement,
    build_shielded_state_profile,
    estimate_state_growth,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class WalletBridgeStateGrowthTest(BitcoinTestFramework):
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
        node.createwallet(wallet_name="bridge_state_growth", descriptors=True)
        wallet = node.get_wallet_rpc("bridge_state_growth")

        bridge_id = bridge_hex(0xE100)
        operation_id = bridge_hex(0xE101)
        source = {
            "domain_id": bridge_hex(0xE102),
            "source_epoch": 211,
            "data_root": bridge_hex(0xE103),
        }

        entries = []
        for index in range(64):
            entries.append({
                "kind": "transparent_payout",
                "wallet_id": bridge_hex(0xE200 + index),
                "destination_id": bridge_hex(0xE300 + index),
                "amount": Decimal("0.10"),
                "authorization_hash": bridge_hex(0xE400 + index),
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

        common = {
            "batched_user_count": 64,
            "new_wallet_count": 24,
            "input_count": 64,
            "output_count": 64,
            "base_non_witness_bytes": 900,
            "base_witness_bytes": 2600,
            "state_commitment_bytes": 192,
            "proof_payload_bytes": 16384,
            "data_availability_payload_bytes": 4096,
            "control_plane_bytes": 320,
            "auxiliary_offchain_bytes": 1024,
            "proof_payload_location": "witness",
        }

        self.log.info("Build the DA-lane rollup aggregate settlement used for the state-growth baseline")
        rollup = build_aggregate_settlement(wallet, statement["statement_hex"], {
            **common,
            "data_availability_location": "data_availability",
        })
        default_profile = build_shielded_state_profile(wallet)
        default_estimate = estimate_state_growth(wallet, rollup["aggregate_settlement_hex"], {
            "block_data_availability_limit": 786432,
        })

        assert_equal(default_profile["state_profile"]["commitment_index_key_bytes"], 9)
        assert_equal(default_profile["state_profile"]["commitment_index_value_bytes"], 32)
        assert_equal(default_profile["state_profile"]["nullifier_index_key_bytes"], 33)
        assert_equal(default_profile["state_profile"]["nullifier_index_value_bytes"], 1)
        assert_equal(default_profile["state_profile"]["snapshot_commitment_bytes"], 32)
        assert_equal(default_profile["state_profile"]["snapshot_nullifier_bytes"], 32)
        assert_equal(default_profile["state_profile"]["nullifier_cache_bytes"], 96)
        assert_equal(default_profile["state_profile"]["bounded_anchor_history_bytes"], 800)

        assert_equal(default_estimate["capacity_estimate"]["binding_limit"], "data_availability")
        assert_equal(default_estimate["capacity_estimate"]["max_settlements_per_block"], 192)
        assert_equal(default_estimate["capacity_estimate"]["users_per_block"], 12288)
        assert_equal(default_estimate["state_estimate"]["per_settlement"]["note_commitments"], 64)
        assert_equal(default_estimate["state_estimate"]["per_settlement"]["nullifiers"], 64)
        assert_equal(default_estimate["state_estimate"]["per_settlement"]["new_wallets"], 24)
        assert_equal(default_estimate["state_estimate"]["per_settlement"]["commitment_index_bytes"], 2624)
        assert_equal(default_estimate["state_estimate"]["per_settlement"]["nullifier_index_bytes"], 2176)
        assert_equal(default_estimate["state_estimate"]["per_settlement"]["snapshot_appendix_bytes"], 4096)
        assert_equal(default_estimate["state_estimate"]["per_settlement"]["wallet_materialization_bytes"], 0)
        assert_equal(default_estimate["state_estimate"]["per_settlement"]["persistent_state_bytes"], 4800)
        assert_equal(default_estimate["state_estimate"]["per_settlement"]["hot_cache_bytes"], 6144)
        assert_equal(default_estimate["state_estimate"]["per_settlement"]["bounded_state_bytes"], 800)
        assert_equal(default_estimate["state_estimate"]["per_block"]["note_commitments"], 12288)
        assert_equal(default_estimate["state_estimate"]["per_block"]["nullifiers"], 12288)
        assert_equal(default_estimate["state_estimate"]["per_block"]["new_wallets"], 4608)
        assert_equal(default_estimate["state_estimate"]["per_block"]["persistent_state_bytes"], 921600)
        assert_equal(default_estimate["state_estimate"]["per_block"]["snapshot_appendix_bytes"], 786432)
        assert_equal(default_estimate["state_estimate"]["per_block"]["hot_cache_bytes"], 1179648)
        assert_equal(default_estimate["state_estimate"]["per_hour"]["note_commitments"], 491520)
        assert_equal(default_estimate["state_estimate"]["per_hour"]["nullifiers"], 491520)
        assert_equal(default_estimate["state_estimate"]["per_hour"]["new_wallets"], 184320)
        assert_equal(default_estimate["state_estimate"]["per_hour"]["persistent_state_bytes"], 36864000)
        assert_equal(default_estimate["state_estimate"]["per_hour"]["snapshot_appendix_bytes"], 31457280)
        assert_equal(default_estimate["state_estimate"]["per_hour"]["hot_cache_bytes"], 47185920)
        assert_equal(default_estimate["state_estimate"]["per_day"]["persistent_state_bytes"], 884736000)
        assert_equal(default_estimate["state_estimate"]["per_day"]["snapshot_appendix_bytes"], 754974720)
        assert_equal(default_estimate["state_estimate"]["per_day"]["hot_cache_bytes"], 1132462080)

        self.log.info("Increase first-touch materialization cost to expose wallet/account growth")
        materialized_profile = build_shielded_state_profile(wallet, {"wallet_materialization_bytes": 96})
        materialized_estimate = estimate_state_growth(wallet, rollup["aggregate_settlement_hex"], {
            "block_data_availability_limit": 786432,
            "state_profile_hex": materialized_profile["state_profile_hex"],
        })
        assert_equal(materialized_estimate["state_profile"]["wallet_materialization_bytes"], 96)
        assert_equal(materialized_estimate["state_estimate"]["per_settlement"]["wallet_materialization_bytes"], 2304)
        assert_equal(materialized_estimate["state_estimate"]["per_settlement"]["persistent_state_bytes"], 7104)
        assert_equal(materialized_estimate["state_estimate"]["per_block"]["persistent_state_bytes"], 1363968)
        assert_equal(materialized_estimate["state_estimate"]["per_hour"]["persistent_state_bytes"], 54558720)
        assert_equal(materialized_estimate["state_estimate"]["per_day"]["persistent_state_bytes"], 1309409280)

        self.log.info("Compare the DA-lane rollup with witness-validium to show that higher L1 throughput also accelerates state growth")
        witness_validium = build_aggregate_settlement(wallet, statement["statement_hex"], {
            **common,
            "data_availability_location": "offchain",
        })
        witness_estimate = estimate_state_growth(wallet, witness_validium["aggregate_settlement_hex"])
        assert_equal(witness_estimate["capacity_estimate"]["binding_limit"], "serialized_size")
        assert_equal(witness_estimate["capacity_estimate"]["max_settlements_per_block"], 597)
        assert_equal(witness_estimate["capacity_estimate"]["users_per_block"], 38208)
        assert_equal(witness_estimate["state_estimate"]["per_block"]["persistent_state_bytes"], 2865600)
        assert_greater_than(witness_estimate["state_estimate"]["per_hour"]["persistent_state_bytes"],
                            default_estimate["state_estimate"]["per_hour"]["persistent_state_bytes"])
        assert_greater_than(witness_estimate["state_estimate"]["per_hour"]["snapshot_appendix_bytes"],
                            default_estimate["state_estimate"]["per_hour"]["snapshot_appendix_bytes"])


if __name__ == "__main__":
    WalletBridgeStateGrowthTest(__file__).main()
