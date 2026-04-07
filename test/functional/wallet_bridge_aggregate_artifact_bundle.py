#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Artifact-backed aggregate settlement coverage for proof/data bundles."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_aggregate_artifact_bundle,
    build_aggregate_settlement,
    build_batch_statement,
    build_data_artifact,
    build_proof_artifact,
    build_shielded_state_profile,
    build_state_retention_policy,
    create_bridge_wallet,
    estimate_capacity,
    estimate_state_retention,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error


class WalletBridgeAggregateArtifactBundleTest(BitcoinTestFramework):
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
        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_aggregate_artifact_bundle")

        bridge_id = bridge_hex(0xE100)
        operation_id = bridge_hex(0xE101)
        source = {
            "domain_id": bridge_hex(0xE102),
            "source_epoch": 145,
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

        self.log.info("Build proof artifacts representing one settlement proof and one optional DA-query proof")
        sp1_artifact = build_proof_artifact(
            wallet,
            statement["statement_hex"],
            proof_adapter_name="sp1-groth16-settlement-metadata-v1",
            verifier_key_hash=bridge_hex(0xE500),
            proof_commitment=bridge_hex(0xE501),
            artifact_hex="44" * 48,
            proof_size_bytes=393216,
            public_values_size_bytes=96,
            auxiliary_data_size_bytes=2048,
        )
        blobstream_artifact = build_proof_artifact(
            wallet,
            statement["statement_hex"],
            proof_adapter_name="blobstream-sp1-data-root-tuple-v1",
            verifier_key_hash=bridge_hex(0xE600),
            proof_commitment=bridge_hex(0xE601),
            artifact_hex="55" * 40,
            proof_size_bytes=131072,
            public_values_size_bytes=72,
            auxiliary_data_size_bytes=8192,
        )

        self.log.info("Derive DA payload bytes from the externalized retention path instead of typing them manually")
        prototype = build_aggregate_settlement(wallet, statement["statement_hex"], {
            "batched_user_count": 64,
            "new_wallet_count": 24,
            "input_count": 64,
            "output_count": 64,
            "base_non_witness_bytes": 900,
            "base_witness_bytes": 2600,
            "state_commitment_bytes": 192,
            "proof_artifact_hex": sp1_artifact["proof_artifact_hex"],
            "proof_payload_location": "witness",
            "data_availability_payload_bytes": 0,
            "data_availability_location": "offchain",
            "control_plane_bytes": 320,
            "auxiliary_offchain_bytes": 0,
        })
        state_profile = build_shielded_state_profile(wallet, {"wallet_materialization_bytes": 96})
        retention_policy = build_state_retention_policy(wallet, {
            "retain_commitment_index": False,
            "retain_nullifier_index": True,
            "snapshot_include_commitments": False,
            "snapshot_include_nullifiers": True,
            "wallet_l1_materialization_bps": 2500,
        })
        retention = estimate_state_retention(wallet, prototype["aggregate_settlement_hex"], {
            "block_data_availability_limit": 786432,
            "state_profile_hex": state_profile["state_profile_hex"],
            "retention_policy_hex": retention_policy["retention_policy_hex"],
        })
        estimate = retention["retention_estimate"]["per_settlement"]
        state_diff_payload_bytes = (
            estimate["externalized_persistent_state_bytes"] +
            estimate["deferred_wallet_materialization_bytes"]
        )
        snapshot_payload_bytes = estimate["externalized_snapshot_bytes"]
        assert_equal(state_diff_payload_bytes, 6080)
        assert_equal(snapshot_payload_bytes, 2048)

        self.log.info("Canonicalize the externalized state and snapshot payloads as DA artifacts")
        state_diff_artifact = build_data_artifact(
            wallet,
            statement["statement_hex"],
            kind="state_diff_v1",
            payload_hex="66" * 32,
            artifact_hex="77" * 48,
            payload_size_bytes=state_diff_payload_bytes,
            auxiliary_data_size_bytes=512,
        )
        snapshot_artifact = build_data_artifact(
            wallet,
            statement["statement_hex"],
            kind="snapshot_appendix_v1",
            payload_hex="88" * 24,
            artifact_hex="99" * 40,
            payload_size_bytes=snapshot_payload_bytes,
            auxiliary_data_size_bytes=256,
        )

        self.log.info("Build an artifact-backed bundle over one proof artifact plus the externalized state payloads")
        single_bundle = build_aggregate_artifact_bundle(
            wallet,
            statement["statement_hex"],
            proof_artifacts=[{"proof_artifact_hex": sp1_artifact["proof_artifact_hex"]}],
            data_artifacts=[
                {"data_artifact_hex": state_diff_artifact["data_artifact_hex"]},
                {"data_artifact": snapshot_artifact["data_artifact"]},
            ],
        )
        decoded_single_bundle = wallet.bridge_decodeaggregateartifactbundle(single_bundle["artifact_bundle_hex"])
        assert_equal(decoded_single_bundle["artifact_bundle"], single_bundle["artifact_bundle"])
        assert_equal(single_bundle["artifact_bundle"]["proof_artifact_count"], 1)
        assert_equal(single_bundle["artifact_bundle"]["data_artifact_count"], 2)
        assert_equal(single_bundle["artifact_bundle"]["proof_payload_bytes"], 393312)
        assert_equal(single_bundle["artifact_bundle"]["proof_auxiliary_bytes"], 2048)
        assert_equal(single_bundle["artifact_bundle"]["data_availability_payload_bytes"], 8128)
        assert_equal(single_bundle["artifact_bundle"]["data_auxiliary_bytes"], 768)
        assert_equal(single_bundle["artifact_bundle"]["storage_bytes"], 404256)

        self.log.info("Use the bundle to derive the aggregate settlement footprint with no manual proof/DA byte inputs")
        single_settlement = build_aggregate_settlement(wallet, statement["statement_hex"], {
            "batched_user_count": 64,
            "new_wallet_count": 24,
            "input_count": 64,
            "output_count": 64,
            "base_non_witness_bytes": 900,
            "base_witness_bytes": 2600,
            "state_commitment_bytes": 192,
            "artifact_bundle_hex": single_bundle["artifact_bundle_hex"],
            "proof_payload_location": "witness",
            "data_availability_location": "data_availability",
            "control_plane_bytes": 320,
        })
        assert_equal(single_settlement["aggregate_settlement"]["proof_payload_bytes"], 393312)
        assert_equal(single_settlement["aggregate_settlement"]["data_availability_payload_bytes"], 8128)
        assert_equal(single_settlement["aggregate_settlement"]["auxiliary_offchain_bytes"], 2816)
        assert_equal(single_settlement["footprint"]["l1_serialized_bytes"], 397004)
        assert_equal(single_settlement["footprint"]["l1_weight"], 400280)
        assert_equal(single_settlement["footprint"]["l1_data_availability_bytes"], 8128)
        assert_equal(single_settlement["footprint"]["offchain_storage_bytes"], 2816)

        single_capacity = estimate_capacity(wallet, single_settlement["footprint"], {
            "block_data_availability_limit": 786432,
        })
        assert_equal(single_capacity["binding_limit"], "serialized_size")
        assert_equal(single_capacity["max_settlements_per_block"], 30)
        assert_equal(single_capacity["users_per_block"], 1920)
        assert_equal(single_capacity["fit_by_data_availability"], 96)

        self.log.info("Add a second proof artifact to model a DA-query / bridge-proof path and re-measure block fit")
        dual_bundle = build_aggregate_artifact_bundle(
            wallet,
            statement["statement_hex"],
            proof_artifacts=[
                {"proof_artifact_hex": sp1_artifact["proof_artifact_hex"]},
                {"proof_artifact_hex": blobstream_artifact["proof_artifact_hex"]},
            ],
            data_artifacts=[
                {"data_artifact_hex": state_diff_artifact["data_artifact_hex"]},
                {"data_artifact_hex": snapshot_artifact["data_artifact_hex"]},
            ],
        )
        assert_equal(dual_bundle["artifact_bundle"]["proof_artifact_count"], 2)
        assert_equal(dual_bundle["artifact_bundle"]["proof_payload_bytes"], 524456)
        assert_equal(dual_bundle["artifact_bundle"]["proof_auxiliary_bytes"], 10240)
        assert_equal(dual_bundle["artifact_bundle"]["data_availability_payload_bytes"], 8128)
        assert_equal(dual_bundle["artifact_bundle"]["storage_bytes"], 543592)

        dual_settlement = build_aggregate_settlement(wallet, statement["statement_hex"], {
            "batched_user_count": 64,
            "new_wallet_count": 24,
            "input_count": 64,
            "output_count": 64,
            "base_non_witness_bytes": 900,
            "base_witness_bytes": 2600,
            "state_commitment_bytes": 192,
            "artifact_bundle_hex": dual_bundle["artifact_bundle_hex"],
            "proof_payload_location": "witness",
            "data_availability_location": "data_availability",
            "control_plane_bytes": 320,
        })
        dual_capacity = estimate_capacity(wallet, dual_settlement["footprint"], {
            "block_data_availability_limit": 786432,
        })
        assert_equal(dual_capacity["binding_limit"], "serialized_size")
        assert_equal(dual_capacity["max_settlements_per_block"], 22)
        assert_equal(dual_capacity["users_per_block"], 1408)
        assert_greater_than(single_capacity["users_per_block"], dual_capacity["users_per_block"])

        self.log.info("Reject selector mixing once an artifact bundle is used")
        assert_raises_rpc_error(
            -8,
            "aggregate must not mix artifact_bundle_* with proof_artifact_*, proof_payload_bytes, data_availability_payload_bytes, or auxiliary_offchain_bytes",
            wallet.bridge_buildaggregatesettlement,
            statement["statement_hex"],
            {
                "batched_user_count": 64,
                "base_non_witness_bytes": 900,
                "state_commitment_bytes": 192,
                "artifact_bundle_hex": single_bundle["artifact_bundle_hex"],
                "proof_payload_bytes": 1,
            },
        )


if __name__ == "__main__":
    WalletBridgeAggregateArtifactBundleTest(__file__).main()
