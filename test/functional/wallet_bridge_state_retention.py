#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Model aggregate-settlement shielded state retention and snapshot cadence."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_aggregate_settlement,
    build_batch_statement,
    build_shielded_state_profile,
    build_state_retention_policy,
    estimate_state_retention,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class WalletBridgeStateRetentionTest(BitcoinTestFramework):
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
        node.createwallet(wallet_name="bridge_state_retention", descriptors=True)
        wallet = node.get_wallet_rpc("bridge_state_retention")

        bridge_id = bridge_hex(0xE500)
        operation_id = bridge_hex(0xE501)
        source = {
            "domain_id": bridge_hex(0xE502),
            "source_epoch": 377,
            "data_root": bridge_hex(0xE503),
        }

        entries = []
        for index in range(64):
            entries.append({
                "kind": "transparent_payout",
                "wallet_id": bridge_hex(0xE600 + index),
                "destination_id": bridge_hex(0xE700 + index),
                "amount": Decimal("0.10"),
                "authorization_hash": bridge_hex(0xE800 + index),
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

        rollup = build_aggregate_settlement(wallet, statement["statement_hex"], {
            "batched_user_count": 64,
            "new_wallet_count": 24,
            "input_count": 64,
            "output_count": 64,
            "base_non_witness_bytes": 900,
            "base_witness_bytes": 2600,
            "state_commitment_bytes": 192,
            "proof_payload_bytes": 16384,
            "proof_payload_location": "witness",
            "data_availability_payload_bytes": 4096,
            "data_availability_location": "data_availability",
            "control_plane_bytes": 320,
            "auxiliary_offchain_bytes": 1024,
        })
        state_profile = build_shielded_state_profile(wallet, {"wallet_materialization_bytes": 96})

        self.log.info("Measure the default production externalized weekly-snapshot policy")
        default_policy = build_state_retention_policy(wallet)
        decoded_default_policy = wallet.bridge_decodestateretentionpolicy(default_policy["retention_policy_hex"])
        assert_equal(decoded_default_policy["retention_policy"]["retain_commitment_index"], False)
        assert_equal(decoded_default_policy["retention_policy"]["snapshot_include_commitments"], False)
        assert_equal(decoded_default_policy["retention_policy"]["wallet_l1_materialization_bps"], 2500)
        assert_equal(decoded_default_policy["retention_policy"]["snapshot_target_bytes"], 2642412320)

        default_retention = estimate_state_retention(wallet, rollup["aggregate_settlement_hex"], {
            "block_data_availability_limit": 786432,
            "state_profile_hex": state_profile["state_profile_hex"],
            "retention_policy_hex": default_policy["retention_policy_hex"],
        })
        assert_equal(default_retention["capacity_estimate"]["max_settlements_per_block"], 192)
        assert_equal(default_retention["state_estimate"]["per_settlement"]["persistent_state_bytes"], 7104)
        assert_equal(default_retention["retention_estimate"]["per_settlement"]["materialized_wallets"], 6)
        assert_equal(default_retention["retention_estimate"]["per_settlement"]["deferred_wallets"], 18)
        assert_equal(default_retention["retention_estimate"]["per_settlement"]["retained_persistent_state_bytes"], 2752)
        assert_equal(default_retention["retention_estimate"]["per_settlement"]["externalized_persistent_state_bytes"], 4352)
        assert_equal(default_retention["retention_estimate"]["per_settlement"]["deferred_wallet_materialization_bytes"], 1728)
        assert_equal(default_retention["retention_estimate"]["per_settlement"]["snapshot_export_bytes"], 2048)
        assert_equal(default_retention["retention_estimate"]["per_settlement"]["externalized_snapshot_bytes"], 2048)
        assert_equal(default_retention["retention_estimate"]["per_block"]["retained_persistent_state_bytes"], 528384)
        assert_equal(default_retention["retention_estimate"]["per_block"]["externalized_persistent_state_bytes"], 835584)
        assert_equal(default_retention["retention_estimate"]["per_block"]["deferred_wallet_materialization_bytes"], 331776)
        assert_equal(default_retention["retention_estimate"]["per_block"]["snapshot_export_bytes"], 393216)
        assert_equal(default_retention["retention_estimate"]["per_block"]["externalized_snapshot_bytes"], 393216)
        assert_equal(default_retention["retention_estimate"]["per_day"]["retained_persistent_state_bytes"], 507248640)
        assert_equal(default_retention["retention_estimate"]["per_day"]["externalized_persistent_state_bytes"], 802160640)
        assert_equal(default_retention["retention_estimate"]["per_day"]["snapshot_export_bytes"], 377487360)
        assert_equal(default_retention["retention_estimate"]["time_to_snapshot_target"]["blocks"], 6720)
        assert_equal(default_retention["retention_estimate"]["time_to_snapshot_target"]["hours"], 168)
        assert_equal(default_retention["retention_estimate"]["time_to_snapshot_target"]["days"], 7)
        assert_equal(default_retention["retention_estimate"]["time_to_snapshot_target"]["represented_users"], 82575360)

        self.log.info("Measure the explicit full-retention dev/audit policy")
        full_policy = build_state_retention_policy(wallet, {
            "retain_commitment_index": True,
            "retain_nullifier_index": True,
            "snapshot_include_commitments": True,
            "snapshot_include_nullifiers": True,
            "wallet_l1_materialization_bps": 10000,
            "snapshot_target_bytes": 4294967296,
        })
        full_retention = estimate_state_retention(wallet, rollup["aggregate_settlement_hex"], {
            "block_data_availability_limit": 786432,
            "state_profile_hex": state_profile["state_profile_hex"],
            "retention_policy_hex": full_policy["retention_policy_hex"],
        })
        assert_equal(full_retention["retention_policy"]["retain_commitment_index"], True)
        assert_equal(full_retention["retention_estimate"]["per_settlement"]["materialized_wallets"], 24)
        assert_equal(full_retention["retention_estimate"]["per_settlement"]["deferred_wallets"], 0)
        assert_equal(full_retention["retention_estimate"]["per_settlement"]["retained_persistent_state_bytes"], 7104)
        assert_equal(full_retention["retention_estimate"]["per_settlement"]["externalized_persistent_state_bytes"], 0)
        assert_equal(full_retention["retention_estimate"]["per_settlement"]["snapshot_export_bytes"], 4096)
        assert_equal(full_retention["retention_estimate"]["per_settlement"]["externalized_snapshot_bytes"], 0)
        assert_equal(full_retention["retention_estimate"]["per_block"]["retained_persistent_state_bytes"], 1363968)
        assert_equal(full_retention["retention_estimate"]["per_block"]["snapshot_export_bytes"], 786432)
        assert_equal(full_retention["retention_estimate"]["per_day"]["retained_persistent_state_bytes"], 1309409280)
        assert_equal(full_retention["retention_estimate"]["per_day"]["snapshot_export_bytes"], 754974720)
        assert_equal(full_retention["retention_estimate"]["time_to_snapshot_target"]["blocks"], 5461)
        assert_equal(full_retention["retention_estimate"]["time_to_snapshot_target"]["hours"], 136)
        assert_equal(full_retention["retention_estimate"]["time_to_snapshot_target"]["days"], 5)
        assert_equal(full_retention["retention_estimate"]["time_to_snapshot_target"]["represented_users"], 67104768)

        assert_greater_than(full_retention["retention_estimate"]["per_block"]["retained_persistent_state_bytes"],
                            default_retention["retention_estimate"]["per_block"]["retained_persistent_state_bytes"])
        assert_greater_than(default_retention["retention_estimate"]["per_block"]["externalized_persistent_state_bytes"], 0)
        assert_greater_than(default_retention["retention_estimate"]["time_to_snapshot_target"]["blocks"],
                            full_retention["retention_estimate"]["time_to_snapshot_target"]["blocks"])


if __name__ == "__main__":
    WalletBridgeStateRetentionTest(__file__).main()
