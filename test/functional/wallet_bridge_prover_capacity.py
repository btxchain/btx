#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Model prover-side throughput for a finalized proof-anchored bridge settlement."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_batch_commitment,
    build_batch_statement,
    build_proof_anchor,
    build_proof_artifact,
    build_proof_policy,
    build_proof_receipt,
    create_bridge_wallet,
    estimate_capacity,
    find_output,
    mine_block,
    planbatchout,
    sign_batch_authorization,
    sign_finalize_and_send,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBridgeProverCapacityTest(BitcoinTestFramework):
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
        wallet, mine_addr = create_bridge_wallet(self, node, wallet_name="bridge_prover_capacity", amount=Decimal("10"))
        fee_margin = Decimal("0.00100000")

        refund_lock_height = node.getblockcount() + 40
        bridge_id = bridge_hex(0xD100)
        operation_id = bridge_hex(0xD101)
        source = {
            "domain_id": bridge_hex(0xD102),
            "source_epoch": 88,
            "data_root": bridge_hex(0xD103),
        }

        payout_amounts = [Decimal("1.10"), Decimal("1.30"), Decimal("1.50")]
        payout_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]
        authorizer_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]
        payouts = [{"address": address, "amount": amount} for address, amount in zip(payout_addresses, payout_amounts)]

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

        self.log.info("Build a proof-policy-backed batch statement and measure its finalized settlement")
        entries = []
        for index, amount in enumerate(payout_amounts):
            signed = sign_batch_authorization(
                wallet,
                authorizer_addresses[index],
                "bridge_out",
                {
                    "kind": "transparent_payout",
                    "wallet_id": bridge_hex(0xD200 + index),
                    "destination_id": bridge_hex(0xD300 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0xD400 + index),
                },
                bridge_id=bridge_id,
                operation_id=operation_id,
            )
            entries.append({"authorization_hex": signed["authorization_hex"]})

        descriptors = [
            {
                "proof_adapter_name": "sp1-groth16-settlement-metadata-v1",
                "verifier_key_hash": bridge_hex(0xD500),
            },
            {
                "proof_adapter_name": "risc0-zkvm-succinct-batch-tuple-v1",
                "verifier_key_hash": bridge_hex(0xD501),
            },
            {
                "proof_adapter": {
                    "proof_profile": {
                        "family": "blobstream",
                        "proof_type": "sp1",
                        "claim_system": "data-root-tuple-v1",
                    },
                    "claim_kind": "data_root_tuple_v1",
                },
                "verifier_key_hash": bridge_hex(0xD502),
            },
        ]
        proof_policy = build_proof_policy(wallet, descriptors, required_receipts=2, targets=descriptors)
        statement = build_batch_statement(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            domain_id=source["domain_id"],
            source_epoch=source["source_epoch"],
            data_root=source["data_root"],
            proof_policy=proof_policy["proof_policy"],
        )

        adapters = [
            {"proof_adapter_name": "sp1-groth16-settlement-metadata-v1"},
            {"proof_adapter_name": "risc0-zkvm-succinct-batch-tuple-v1"},
            {"proof_adapter": descriptors[2]["proof_adapter"]},
        ]
        artifacts = [
            build_proof_artifact(
                wallet,
                statement["statement_hex"],
                verifier_key_hash=descriptors[0]["verifier_key_hash"],
                proof_commitment=bridge_hex(0xD510),
                artifact_hex="33" * 48,
                proof_size_bytes=393216,
                public_values_size_bytes=96,
                auxiliary_data_size_bytes=2048,
                **adapters[0],
            ),
            build_proof_artifact(
                wallet,
                statement["statement_hex"],
                verifier_key_hash=descriptors[1]["verifier_key_hash"],
                proof_commitment=bridge_hex(0xD511),
                artifact_hex="44" * 40,
                proof_size_bytes=262144,
                public_values_size_bytes=64,
                auxiliary_data_size_bytes=4096,
                **adapters[1],
            ),
            build_proof_artifact(
                wallet,
                statement["statement_hex"],
                verifier_key_hash=descriptors[2]["verifier_key_hash"],
                proof_commitment=bridge_hex(0xD512),
                artifact_commitment=bridge_hex(0xD513),
                proof_size_bytes=131072,
                public_values_size_bytes=72,
                auxiliary_data_size_bytes=8192,
                **adapters[2],
            ),
        ]
        proof_receipts = [
            build_proof_receipt(wallet, statement["statement_hex"], proof_artifact_hex=artifacts[0]["proof_artifact_hex"]),
            build_proof_receipt(wallet, statement["statement_hex"], proof_artifact_hex=artifacts[1]["proof_artifact_hex"]),
            build_proof_receipt(wallet, statement["statement_hex"], proof_artifact_hex=artifacts[2]["proof_artifact_hex"]),
        ]
        proof_anchor = build_proof_anchor(
            wallet,
            statement["statement_hex"],
            [receipt["proof_receipt_hex"] for receipt in proof_receipts],
            {"descriptor_proofs": [entry["proof_hex"] for entry in proof_policy["proofs"]]},
        )
        commitment = build_batch_commitment(
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
            batch_commitment_hex=commitment["commitment_hex"],
        )
        metrics = settle_unshield(plan, sum(payout_amounts, Decimal("0")))

        footprint = {
            "l1_serialized_bytes": metrics["size"],
            "l1_weight": metrics["weight"],
            "control_plane_bytes": metrics["attestation_bytes"] + sum(len(bytes.fromhex(receipt["proof_receipt_hex"])) for receipt in proof_receipts),
            "offchain_storage_bytes": sum(artifact["proof_artifact"]["storage_bytes"] for artifact in artifacts),
            "batched_user_count": len(payouts),
        }

        self.log.info("Run the capacity estimator with modeled native, CPU, GPU, and proving-network lanes")
        estimate = estimate_capacity(
            wallet,
            footprint,
            {
                "baseline": {
                    "l1_serialized_bytes": 586196,
                    "l1_weight": 2344784,
                    "batched_user_count": 1,
                },
                "prover": {
                    "native": {"millis_per_settlement": 650, "workers": 32, "hourly_cost_cents": 35},
                    "cpu": {"millis_per_settlement": 180000, "workers": 32, "hourly_cost_cents": 250},
                    "gpu": {"millis_per_settlement": 12000, "workers": 8, "hourly_cost_cents": 1800},
                    "network": {
                        "millis_per_settlement": 4000,
                        "workers": 16,
                        "parallel_jobs_per_worker": 8,
                        "hourly_cost_cents": 1600,
                    },
                },
            },
        )

        prover = estimate["prover"]
        assert_equal(prover["l1_limits"]["block_interval_millis"], 90000)
        assert_equal(prover["l1_limits"]["max_settlements_per_block"], estimate["max_settlements_per_block"])
        assert_equal(prover["l1_limits"]["users_per_block"], estimate["users_per_block"])
        assert_equal(prover["l1_limits"]["settlements_per_hour"], estimate["max_settlements_per_block"] * 40)
        assert_equal(prover["l1_limits"]["users_per_hour"], estimate["users_per_block"] * 40)

        assert_equal(prover["native"]["binding_limit"], "l1")
        assert_equal(prover["native"]["sustainable_users_per_block"], estimate["users_per_block"])
        assert prover["native"]["coverage_of_l1_capacity"] == 1.0

        assert_equal(prover["cpu"]["binding_limit"], "prover")
        assert prover["cpu"]["sustainable_users_per_block"] < estimate["users_per_block"]
        assert prover["cpu"]["required_workers_to_fill_l1_capacity"] > prover["cpu"]["lane"]["workers"]
        assert prover["cpu"]["hourly_cost"]["required_cents"] > prover["cpu"]["hourly_cost"]["current_cents"]

        assert_equal(prover["gpu"]["binding_limit"], "prover")
        assert prover["gpu"]["sustainable_users_per_block"] > prover["cpu"]["sustainable_users_per_block"]
        assert prover["gpu"]["required_workers_to_fill_l1_capacity"] > prover["gpu"]["lane"]["workers"]

        assert_equal(prover["network"]["binding_limit"], "l1")
        assert_equal(prover["network"]["sustainable_users_per_block"], estimate["users_per_block"])
        assert_equal(prover["network"]["required_workers_to_fill_l1_capacity"], prover["network"]["lane"]["workers"])
        assert_equal(prover["network"]["hourly_cost"]["required_cents"], prover["network"]["hourly_cost"]["current_cents"])

        self.log.info(
            "Proof settlement (%d bytes, %d weight, %d off-chain bytes) sustains %d users/block on L1; modeled native=%d, cpu=%d, gpu=%d, network=%d users/block",
            footprint["l1_serialized_bytes"],
            footprint["l1_weight"],
            footprint["offchain_storage_bytes"],
            estimate["users_per_block"],
            prover["native"]["sustainable_users_per_block"],
            prover["cpu"]["sustainable_users_per_block"],
            prover["gpu"]["sustainable_users_per_block"],
            prover["network"]["sustainable_users_per_block"],
        )


if __name__ == "__main__":
    WalletBridgeProverCapacityTest(__file__).main()
