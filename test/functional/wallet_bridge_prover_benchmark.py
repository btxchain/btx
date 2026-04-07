#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Aggregate repeated prover profiles into a canonical benchmark and feed p50/p90 into capacity estimation."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_batch_commitment,
    build_batch_statement,
    build_proof_anchor,
    build_proof_artifact,
    build_proof_policy,
    build_proof_receipt,
    build_prover_benchmark,
    build_prover_profile,
    build_prover_sample,
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


class WalletBridgeProverBenchmarkTest(BitcoinTestFramework):
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
        wallet, mine_addr = create_bridge_wallet(self, node, wallet_name="bridge_prover_benchmark", amount=Decimal("10"))
        fee_margin = Decimal("0.00100000")

        refund_lock_height = node.getblockcount() + 40
        bridge_id = bridge_hex(0xA100)
        operation_id = bridge_hex(0xA101)
        source = {
            "domain_id": bridge_hex(0xA102),
            "source_epoch": 93,
            "data_root": bridge_hex(0xA103),
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

        entries = []
        for index, amount in enumerate(payout_amounts):
            signed = sign_batch_authorization(
                wallet,
                authorizer_addresses[index],
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

        descriptors = [
            {
                "proof_adapter_name": "sp1-groth16-settlement-metadata-v1",
                "verifier_key_hash": bridge_hex(0xA500),
            },
            {
                "proof_adapter_name": "risc0-zkvm-succinct-batch-tuple-v1",
                "verifier_key_hash": bridge_hex(0xA501),
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
                "verifier_key_hash": bridge_hex(0xA502),
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
                proof_commitment=bridge_hex(0xA510),
                artifact_hex="55" * 48,
                proof_size_bytes=393216,
                public_values_size_bytes=96,
                auxiliary_data_size_bytes=2048,
                **adapters[0],
            ),
            build_proof_artifact(
                wallet,
                statement["statement_hex"],
                verifier_key_hash=descriptors[1]["verifier_key_hash"],
                proof_commitment=bridge_hex(0xA511),
                artifact_hex="66" * 40,
                proof_size_bytes=262144,
                public_values_size_bytes=64,
                auxiliary_data_size_bytes=4096,
                **adapters[1],
            ),
            build_proof_artifact(
                wallet,
                statement["statement_hex"],
                verifier_key_hash=descriptors[2]["verifier_key_hash"],
                proof_commitment=bridge_hex(0xA512),
                artifact_commitment=bridge_hex(0xA513),
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

        run_specs = [
            [
                {"prover_template_name": "sp1-groth16-reference-v1", "native_millis": 210, "cpu_millis": 58000, "gpu_millis": 4300, "network_millis": 1450, "peak_memory_bytes": 900000000},
                {"prover_template_name": "risc0-succinct-reference-v1", "native_millis": 170, "cpu_millis": 70000, "gpu_millis": 4000, "network_millis": 1150, "peak_memory_bytes": 1100000000},
                {"prover_template_name": "blobstream-sp1-reference-v1", "native_millis": 240, "cpu_millis": 47000, "gpu_millis": 3200, "network_millis": 1200, "peak_memory_bytes": 700000000},
            ],
            [
                {"prover_template_name": "sp1-groth16-reference-v1", "native_millis": 215, "cpu_millis": 59000, "gpu_millis": 4400, "network_millis": 1500, "peak_memory_bytes": 920000000},
                {"prover_template_name": "risc0-succinct-reference-v1", "native_millis": 175, "cpu_millis": 71000, "gpu_millis": 4100, "network_millis": 1200, "peak_memory_bytes": 1110000000},
                {"prover_template_name": "blobstream-sp1-reference-v1", "native_millis": 250, "cpu_millis": 48000, "gpu_millis": 3300, "network_millis": 1200, "peak_memory_bytes": 710000000},
            ],
            [
                {"prover_template_name": "sp1-groth16-reference-v1", "peak_memory_bytes": 940000000},
                {"prover_template_name": "risc0-succinct-reference-v1", "peak_memory_bytes": 1120000000},
                {"prover_template_name": "blobstream-sp1-reference-v1", "peak_memory_bytes": 720000000},
            ],
            [
                {"prover_template_name": "sp1-groth16-reference-v1", "native_millis": 225, "cpu_millis": 60500, "gpu_millis": 4600, "network_millis": 1600, "peak_memory_bytes": 960000000},
                {"prover_template_name": "risc0-succinct-reference-v1", "native_millis": 180, "cpu_millis": 72500, "gpu_millis": 4300, "network_millis": 1250, "peak_memory_bytes": 1130000000},
                {"prover_template_name": "blobstream-sp1-reference-v1", "native_millis": 255, "cpu_millis": 49000, "gpu_millis": 3400, "network_millis": 1350, "peak_memory_bytes": 730000000},
            ],
            [
                {"prover_template_name": "sp1-groth16-reference-v1", "native_millis": 240, "cpu_millis": 63000, "gpu_millis": 4800, "network_millis": 1700, "peak_memory_bytes": 980000000},
                {"prover_template_name": "risc0-succinct-reference-v1", "native_millis": 190, "cpu_millis": 75000, "gpu_millis": 4500, "network_millis": 1350, "peak_memory_bytes": 1140000000},
                {"prover_template_name": "blobstream-sp1-reference-v1", "native_millis": 270, "cpu_millis": 52000, "gpu_millis": 3700, "network_millis": 1450, "peak_memory_bytes": 740000000},
            ],
        ]

        self.log.info("Build five repeated prover profiles over the same settlement and aggregate them into one benchmark")
        profiles = []
        for run_spec in run_specs:
            samples = [
                build_prover_sample(wallet, proof_artifact_hex=artifact["proof_artifact_hex"], **sample_spec)
                for artifact, sample_spec in zip(artifacts, run_spec)
            ]
            profiles.append(
                build_prover_profile(wallet, [{"prover_sample_hex": sample["prover_sample_hex"]} for sample in samples])
            )

        benchmark = build_prover_benchmark(wallet, [{"prover_profile_hex": profile["prover_profile_hex"]} for profile in profiles])
        decoded_benchmark = wallet.bridge_decodeproverbenchmark(benchmark["prover_benchmark_hex"])
        assert_equal(decoded_benchmark["prover_benchmark"]["profile_count"], 5)
        assert_equal(decoded_benchmark["prover_benchmark"]["sample_count_per_profile"], 3)
        assert_equal(decoded_benchmark["prover_benchmark"]["native_millis_per_settlement"]["p50"], 650)
        assert_equal(decoded_benchmark["prover_benchmark"]["native_millis_per_settlement"]["p90"], 700)
        assert_equal(decoded_benchmark["prover_benchmark"]["cpu_millis_per_settlement"]["p50"], 180000)
        assert_equal(decoded_benchmark["prover_benchmark"]["cpu_millis_per_settlement"]["p90"], 190000)
        assert_equal(decoded_benchmark["prover_benchmark"]["gpu_millis_per_settlement"]["p50"], 12000)
        assert_equal(decoded_benchmark["prover_benchmark"]["gpu_millis_per_settlement"]["p90"], 13000)
        assert_equal(decoded_benchmark["prover_benchmark"]["network_millis_per_settlement"]["p50"], 4000)
        assert_equal(decoded_benchmark["prover_benchmark"]["network_millis_per_settlement"]["p90"], 4500)

        p50_estimate = estimate_capacity(
            wallet,
            footprint,
            {
                "prover": {
                    "prover_benchmark_hex": benchmark["prover_benchmark_hex"],
                    "benchmark_statistic": "p50",
                    "native": {"workers": 32, "hourly_cost_cents": 35},
                    "cpu": {"workers": 32, "hourly_cost_cents": 250},
                    "gpu": {"workers": 8, "hourly_cost_cents": 1800},
                    "network": {"workers": 16, "parallel_jobs_per_worker": 8, "hourly_cost_cents": 1600},
                },
            },
        )
        p90_estimate = estimate_capacity(
            wallet,
            footprint,
            {
                "prover": {
                    "prover_benchmark_hex": benchmark["prover_benchmark_hex"],
                    "benchmark_statistic": "p90",
                    "native": {"workers": 32, "hourly_cost_cents": 35},
                    "cpu": {"workers": 32, "hourly_cost_cents": 250},
                    "gpu": {"workers": 8, "hourly_cost_cents": 1800},
                    "network": {"workers": 16, "parallel_jobs_per_worker": 8, "hourly_cost_cents": 1600},
                },
            },
        )
        assert_equal(p50_estimate["prover"]["benchmark_statistic"], "p50")
        assert_equal(p50_estimate["prover"]["artifact_storage_bytes_delta_vs_footprint"], 0)
        assert_equal(p50_estimate["prover"]["native"]["lane"]["millis_per_settlement"], 650)
        assert_equal(p50_estimate["prover"]["cpu"]["lane"]["millis_per_settlement"], 180000)
        assert_equal(p50_estimate["prover"]["gpu"]["lane"]["millis_per_settlement"], 12000)
        assert_equal(p50_estimate["prover"]["network"]["lane"]["millis_per_settlement"], 4000)
        assert_equal(p50_estimate["prover"]["native"]["sustainable_users_per_block"], 8418)
        assert_equal(p50_estimate["prover"]["cpu"]["sustainable_users_per_block"], 48)
        assert_equal(p50_estimate["prover"]["gpu"]["sustainable_users_per_block"], 180)
        assert_equal(p50_estimate["prover"]["network"]["sustainable_users_per_block"], 8418)

        assert_equal(p90_estimate["prover"]["benchmark_statistic"], "p90")
        assert_equal(p90_estimate["prover"]["native"]["lane"]["millis_per_settlement"], 700)
        assert_equal(p90_estimate["prover"]["cpu"]["lane"]["millis_per_settlement"], 190000)
        assert_equal(p90_estimate["prover"]["gpu"]["lane"]["millis_per_settlement"], 13000)
        assert_equal(p90_estimate["prover"]["network"]["lane"]["millis_per_settlement"], 4500)
        assert_equal(p90_estimate["prover"]["native"]["sustainable_users_per_block"], 8418)
        assert_equal(p90_estimate["prover"]["cpu"]["sustainable_users_per_block"], 45)
        assert_equal(p90_estimate["prover"]["gpu"]["sustainable_users_per_block"], 165)
        assert_equal(p90_estimate["prover"]["network"]["sustainable_users_per_block"], 7680)

        benchmark_bytes = len(bytes.fromhex(benchmark["prover_benchmark_hex"]))
        profile_bytes = len(bytes.fromhex(profiles[0]["prover_profile_hex"]))
        self.log.info(
            "Prover benchmark from %d repeated profiles: benchmark=%d bytes profile=%d bytes p50=%d/%d/%d/%d ms p90=%d/%d/%d/%d ms",
            len(profiles),
            benchmark_bytes,
            profile_bytes,
            p50_estimate["prover"]["native"]["lane"]["millis_per_settlement"],
            p50_estimate["prover"]["cpu"]["lane"]["millis_per_settlement"],
            p50_estimate["prover"]["gpu"]["lane"]["millis_per_settlement"],
            p50_estimate["prover"]["network"]["lane"]["millis_per_settlement"],
            p90_estimate["prover"]["native"]["lane"]["millis_per_settlement"],
            p90_estimate["prover"]["cpu"]["lane"]["millis_per_settlement"],
            p90_estimate["prover"]["gpu"]["lane"]["millis_per_settlement"],
            p90_estimate["prover"]["network"]["lane"]["millis_per_settlement"],
        )


if __name__ == "__main__":
    WalletBridgeProverBenchmarkTest(__file__).main()
