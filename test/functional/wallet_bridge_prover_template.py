#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""List built-in prover templates and derive prover capacity from template-backed samples."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_batch_commitment,
    build_batch_statement,
    build_proof_anchor,
    build_proof_artifact,
    build_proof_policy,
    build_proof_receipt,
    build_prover_profile,
    build_prover_sample,
    create_bridge_wallet,
    estimate_capacity,
    find_output,
    list_prover_templates,
    mine_block,
    planbatchout,
    sign_batch_authorization,
    sign_finalize_and_send,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBridgeProverTemplateTest(BitcoinTestFramework):
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
        wallet, mine_addr = create_bridge_wallet(self, node, wallet_name="bridge_prover_template", amount=Decimal("10"))
        fee_margin = Decimal("0.00100000")

        refund_lock_height = node.getblockcount() + 40
        bridge_id = bridge_hex(0xF100)
        operation_id = bridge_hex(0xF101)
        source = {
            "domain_id": bridge_hex(0xF102),
            "source_epoch": 92,
            "data_root": bridge_hex(0xF103),
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
                    "wallet_id": bridge_hex(0xF200 + index),
                    "destination_id": bridge_hex(0xF300 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0xF400 + index),
                },
                bridge_id=bridge_id,
                operation_id=operation_id,
            )
            entries.append({"authorization_hex": signed["authorization_hex"]})

        descriptors = [
            {
                "proof_adapter_name": "sp1-groth16-settlement-metadata-v1",
                "verifier_key_hash": bridge_hex(0xF500),
            },
            {
                "proof_adapter_name": "risc0-zkvm-succinct-batch-tuple-v1",
                "verifier_key_hash": bridge_hex(0xF501),
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
                "verifier_key_hash": bridge_hex(0xF502),
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
                proof_commitment=bridge_hex(0xF510),
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
                proof_commitment=bridge_hex(0xF511),
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
                proof_commitment=bridge_hex(0xF512),
                artifact_commitment=bridge_hex(0xF513),
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

        self.log.info("List the built-in modeled prover templates and verify the three families used in the artifact set")
        template_listing = list_prover_templates(wallet)
        templates = {entry["template_name"]: entry for entry in template_listing["templates"]}
        assert "sp1-groth16-reference-v1" in templates
        assert "risc0-succinct-reference-v1" in templates
        assert "blobstream-sp1-reference-v1" in templates
        assert_equal(templates["sp1-groth16-reference-v1"]["proof_adapter_name"], "sp1-groth16-settlement-metadata-v1")
        assert_equal(templates["sp1-groth16-reference-v1"]["claim_kind"], "settlement_metadata_v1")
        assert_equal(templates["sp1-groth16-reference-v1"]["labels"]["family"], "sp1")
        assert_equal(templates["risc0-succinct-reference-v1"]["labels"]["proof_type"], "succinct")
        assert_equal(templates["blobstream-sp1-reference-v1"]["labels"]["claim_system"], "data-root-tuple-v1")

        self.log.info("Build template-backed samples directly from the imported proof artifacts")
        samples = [
            build_prover_sample(wallet, proof_artifact_hex=artifacts[0]["proof_artifact_hex"], prover_template_name="sp1-groth16-reference-v1"),
            build_prover_sample(wallet, proof_artifact_hex=artifacts[1]["proof_artifact_hex"], prover_template_name="risc0-succinct-reference-v1"),
            build_prover_sample(wallet, proof_artifact_hex=artifacts[2]["proof_artifact_hex"], prover_template_name="blobstream-sp1-reference-v1"),
        ]
        assert_equal(samples[0]["prover_template"]["template_name"], "sp1-groth16-reference-v1")
        assert_equal(samples[0]["prover_sample"]["cpu_millis"], templates["sp1-groth16-reference-v1"]["cpu_millis"])
        assert_equal(samples[1]["prover_sample"]["network_millis"], templates["risc0-succinct-reference-v1"]["network_millis"])
        assert_equal(samples[2]["prover_sample"]["peak_memory_bytes"], templates["blobstream-sp1-reference-v1"]["peak_memory_bytes"])

        override_sample = build_prover_sample(
            wallet,
            proof_artifact_hex=artifacts[0]["proof_artifact_hex"],
            prover_template_name="sp1-groth16-reference-v1",
            gpu_millis=5000,
        )
        assert_equal(override_sample["prover_sample"]["gpu_millis"], 5000)

        assert_raises_rpc_error(
            -8,
            "sample.prover_template_name expects proof_adapter_name sp1-groth16-settlement-metadata-v1",
            wallet.bridge_buildproversample,
            {
                "proof_artifact_hex": artifacts[1]["proof_artifact_hex"],
                "prover_template_name": "sp1-groth16-reference-v1",
            },
        )

        profile = build_prover_profile(wallet, [{"prover_sample_hex": sample["prover_sample_hex"]} for sample in samples])
        decoded_profile = wallet.bridge_decodeproverprofile(profile["prover_profile_hex"])
        assert_equal(decoded_profile["prover_profile"]["sample_count"], 3)
        assert_equal(decoded_profile["prover_profile"]["native_millis_per_settlement"], 650)
        assert_equal(decoded_profile["prover_profile"]["cpu_millis_per_settlement"], 180000)
        assert_equal(decoded_profile["prover_profile"]["gpu_millis_per_settlement"], 12000)
        assert_equal(decoded_profile["prover_profile"]["network_millis_per_settlement"], 4000)
        assert_equal(decoded_profile["prover_profile"]["total_artifact_storage_bytes"], footprint["offchain_storage_bytes"])

        estimate = estimate_capacity(
            wallet,
            footprint,
            {
                "prover": {
                    "prover_profile_hex": profile["prover_profile_hex"],
                    "native": {"workers": 32, "hourly_cost_cents": 35},
                    "cpu": {"workers": 32, "hourly_cost_cents": 250},
                    "gpu": {"workers": 8, "hourly_cost_cents": 1800},
                    "network": {"workers": 16, "parallel_jobs_per_worker": 8, "hourly_cost_cents": 1600},
                },
            },
        )
        assert_equal(estimate["prover"]["artifact_storage_bytes_delta_vs_footprint"], 0)
        assert_equal(estimate["prover"]["native"]["sustainable_users_per_block"], 8418)
        assert_equal(estimate["prover"]["cpu"]["sustainable_users_per_block"], 48)
        assert_equal(estimate["prover"]["gpu"]["sustainable_users_per_block"], 180)
        assert_equal(estimate["prover"]["network"]["sustainable_users_per_block"], 8418)

        sample_bytes = len(bytes.fromhex(samples[0]["prover_sample_hex"]))
        profile_bytes = len(bytes.fromhex(profile["prover_profile_hex"]))
        self.log.info(
            "Modeled prover templates=%d sample=%d bytes profile=%d bytes native/cpu/gpu/network=%d/%d/%d/%d ms",
            len(template_listing["templates"]),
            sample_bytes,
            profile_bytes,
            estimate["prover"]["profile"]["native_millis_per_settlement"],
            estimate["prover"]["profile"]["cpu_millis_per_settlement"],
            estimate["prover"]["profile"]["gpu_millis_per_settlement"],
            estimate["prover"]["profile"]["network_millis_per_settlement"],
        )


if __name__ == "__main__":
    WalletBridgeProverTemplateTest(__file__).main()
