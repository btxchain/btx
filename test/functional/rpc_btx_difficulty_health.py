#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for BTX difficulty-health and MatMul challenge service APIs."""

import copy
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_approx,
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import get_generate_key

EXPECTED_SOLVE_SUCCESS_MAX_TRIES = 5000
EXPECTED_SOLVE_RUNTIME_BUDGET_MS = 10000
EASY_SERVICE_TARGET_SOLVE_TIME_S = 0.001
HARD_SERVICE_TARGET_SOLVE_TIME_S = 600


class BTXDifficultyHealthRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-test=matmulstrict"], ["-test=matmulstrict"]]

    def run_test(self):
        node = self.nodes[0]
        node_other = self.nodes[1]
        self.generate(node, 8)
        self.sync_all()

        health = node.getdifficultyhealth(5)
        network_info = node.getnetworkinfo()
        peerinfo = node.getpeerinfo()
        outbound_peers = len([peer for peer in peerinfo if not peer["inbound"]])
        assert_equal(health["chain"], "regtest")
        assert_equal(health["algorithm"], "matmul")
        assert_equal(health["window_blocks"], 5)
        assert_equal(health["recent"]["count"], 5)
        assert_greater_than(health["recent"]["p99_interval_s"], 0)
        assert_greater_than(health["health_score"], -1)
        assert_equal(health["network"]["connected_peers"], network_info["connections"])
        assert_equal(health["service_challenge_registry"]["status"], "not_loaded")
        assert_equal(health["service_challenge_registry"]["healthy"], True)
        assert_equal(health["service_challenge_registry"]["shared"], False)
        assert_equal(health["service_challenge_registry"]["entries"], 0)
        assert "path" in health["service_challenge_registry"]
        assert "last_checked_at" in health["service_challenge_registry"]
        assert_equal(health["network"]["outbound_peers"], outbound_peers)
        assert health["network"]["synced_outbound_peers"] <= outbound_peers
        assert health["network"]["manual_outbound_peers"] <= outbound_peers
        assert health["network"]["outbound_peers_missing_sync_height"] <= outbound_peers
        assert health["network"]["outbound_peers_beyond_sync_lag"] <= outbound_peers
        assert health["network"]["recent_block_announcing_outbound_peers"] <= outbound_peers
        assert_equal(len(health["network"]["outbound_peer_diagnostics"]), outbound_peers)
        for peer in health["network"]["outbound_peer_diagnostics"]:
            assert "addr" in peer
            assert "connection_type" in peer
            assert "manual" in peer
            assert "sync_height" in peer
            assert "common_height" in peer
            assert "presync_height" in peer
            assert "starting_height" in peer
            assert "sync_lag" in peer
            assert "last_block_announcement" in peer
            assert "counts_as_synced_outbound" in peer
        assert_equal(health["network"]["header_lag"], 0)
        mining_info = node.getmininginfo()
        assert_equal(health["reorg_protection"]["enabled"], False)
        assert_equal(health["reorg_protection"]["active"], False)
        assert_equal(health["reorg_protection"]["current_tip_height"], mining_info["blocks"])
        assert_equal(health["reorg_protection"]["start_height"], -1)
        assert_equal(health["reorg_protection"]["max_reorg_depth"], 0)
        assert_equal(health["reorg_protection"]["rejected_reorgs"], 0)
        assert_equal(health["reorg_protection"]["deepest_rejected_reorg_depth"], 0)
        assert_equal(health["reorg_protection"]["last_rejected_reorg_depth"], 0)
        assert_equal(health["reorg_protection"]["last_rejected_unix"], 0)
        assert_equal(health["consensus_guards"]["freivalds_transcript_binding"]["active"], True)
        assert_equal(health["consensus_guards"]["freivalds_transcript_binding"]["activation_height"], 0)
        assert_equal(health["consensus_guards"]["freivalds_transcript_binding"]["remaining_blocks"], 0)
        assert_equal(health["consensus_guards"]["freivalds_payload_mining"]["enabled"], True)
        assert_equal(health["consensus_guards"]["freivalds_payload_mining"]["required_by_consensus"], True)
        assert_equal(health["consensus_guards"]["freivalds_payload_mining"]["activation_height"], 0)
        assert_equal(health["consensus_guards"]["freivalds_payload_mining"]["remaining_blocks"], 0)
        assert_equal(health["consensus_guards"]["asert_half_life"]["current_s"], 14400)
        assert_equal(health["consensus_guards"]["asert_half_life"]["current_anchor_height"], 0)
        assert_equal(health["consensus_guards"]["asert_half_life"]["upgrade_active"], False)
        assert_equal(health["consensus_guards"]["asert_half_life"]["upgrade_height"], -1)
        assert_equal(health["consensus_guards"]["asert_half_life"]["upgrade_half_life_s"], 14400)
        assert_equal(health["consensus_guards"]["asert_half_life"]["remaining_blocks"], 0)
        assert_equal(health["consensus_guards"]["pre_hash_epsilon_bits"]["current_bits"], 0)
        assert_equal(health["consensus_guards"]["pre_hash_epsilon_bits"]["next_block_bits"], 0)
        assert_equal(health["consensus_guards"]["pre_hash_epsilon_bits"]["upgrade_active"], False)
        assert_equal(health["consensus_guards"]["pre_hash_epsilon_bits"]["upgrade_height"], -1)
        assert_equal(health["consensus_guards"]["pre_hash_epsilon_bits"]["upgrade_bits"], 0)
        assert_equal(health["consensus_guards"]["pre_hash_epsilon_bits"]["remaining_blocks"], 0)
        assert_equal(health["reward_distribution"]["count"], 5)
        assert_equal(health["reward_distribution"]["unique_recipients"], 1)
        assert_equal(health["reward_distribution"]["top_share"], 1.0)
        assert_equal(health["reward_distribution"]["top_recipients"][0]["blocks"], 5)
        assert_equal(health["reward_distribution"]["longest_streak"]["context_window_blocks"], 5)
        assert_equal(health["reward_distribution"]["longest_streak"]["context_recipient_share"], 1.0)
        assert_equal(health["reward_distribution"]["longest_streak"]["context_unique_recipients"], 1)
        assert_equal(health["reward_distribution"]["longest_streak"]["nonstationary_share_suspected"], False)

        block_template = node.getblocktemplate({"rules": ["segwit"]})
        challenge = node.getmatmulchallenge()
        assert_equal(challenge["height"], mining_info["next"]["height"])
        assert_equal(challenge["bits"], mining_info["next"]["bits"])
        assert_equal(challenge["difficulty"], mining_info["next"]["difficulty"])
        assert_equal(challenge["matmul"]["n"], block_template["matmul"]["n"])
        assert_equal(challenge["matmul"]["b"], block_template["matmul"]["b"])
        assert_equal(challenge["matmul"]["r"], block_template["matmul"]["r"])
        assert_equal(challenge["matmul"]["seed_a"], block_template["matmul"]["seed_a"])
        assert_equal(challenge["matmul"]["seed_b"], block_template["matmul"]["seed_b"])
        assert_equal(challenge["header_context"]["version"], block_template["version"])
        assert_equal(challenge["header_context"]["previousblockhash"], challenge["previousblockhash"])
        assert_equal(challenge["header_context"]["bits"], challenge["bits"])
        assert_equal(challenge["header_context"]["matmul_dim"], challenge["matmul"]["n"])
        assert_equal(challenge["header_context"]["seed_a"], challenge["matmul"]["seed_a"])
        assert_equal(challenge["header_context"]["seed_b"], challenge["matmul"]["seed_b"])
        assert_equal(challenge["header_context"]["nonce64_start"], 0)
        assert challenge["header_context"]["time"] >= challenge["mintime"]
        assert_equal(len(challenge["header_context"]["merkleroot"]), 64)
        assert_equal(
            challenge["work_profile"]["pre_hash_epsilon_bits"],
            health["consensus_guards"]["pre_hash_epsilon_bits"]["next_block_bits"],
        )
        for response in (challenge,):
            work_profile = response["work_profile"]
            n = response["matmul"]["n"]
            b = response["matmul"]["b"]
            r = response["matmul"]["r"]
            blocks_per_axis = n // b
            compression_field_muladds = (blocks_per_axis**3) * (b * b)
            noise_low_rank_muladds = 2 * n * n * r
            per_nonce_total_field_muladds_estimate = n**3 + compression_field_muladds + noise_low_rank_muladds
            assert_equal(work_profile["field_element_bytes"], 4)
            assert_equal(work_profile["matrix_elements"], n * n)
            assert_equal(work_profile["matrix_bytes"], n * n * 4)
            assert_equal(work_profile["matrix_generation_elements_per_seed"], n * n)
            assert_equal(work_profile["transcript_blocks_per_axis"], blocks_per_axis)
            assert_equal(work_profile["transcript_block_multiplications"], blocks_per_axis**3)
            assert_equal(work_profile["transcript_field_muladds"], n**3)
            assert_equal(work_profile["compression_vector_elements"], b * b)
            assert_equal(work_profile["compression_field_muladds"], compression_field_muladds)
            assert_equal(work_profile["noise_elements"], 4 * n * r)
            assert_equal(work_profile["noise_low_rank_muladds"], noise_low_rank_muladds)
            assert_equal(work_profile["denoise_field_muladds"], 5 * n * n * r + 2 * n * r * r)
            assert_equal(work_profile["per_nonce_total_field_muladds_estimate"], per_nonce_total_field_muladds_estimate)
            assert work_profile["oracle_rejection_probability_per_element"] > 0
            assert work_profile["oracle_rejection_probability_per_element"] < Decimal("0.000000001")
            assert work_profile["expected_oracle_retries_per_matrix_seed"] > 0
            assert work_profile["expected_oracle_retries_per_nonce_noise"] > 0
            assert work_profile["pre_hash_epsilon_bits"] >= 0
            reuse_profile = work_profile["cross_nonce_reuse"]
            assert_equal(reuse_profile["seed_scope"], "per_block_template")
            assert_equal(reuse_profile["sigma_scope"], "per_nonce")
            assert_equal(reuse_profile["fixed_instance_reuse_possible"], True)
            assert_equal(reuse_profile["fixed_matrix_generation_elements_upper_bound"], 2 * n * n)
            assert_equal(reuse_profile["fixed_clean_product_field_muladds_upper_bound"], n**3)
            assert_equal(reuse_profile["dynamic_per_nonce_field_muladds_lower_bound"], compression_field_muladds + noise_low_rank_muladds)
            assert abs(reuse_profile["dynamic_per_nonce_share_lower_bound"] - (Decimal(compression_field_muladds + noise_low_rank_muladds) / Decimal(per_nonce_total_field_muladds_estimate))) < Decimal("0.000000001")
            assert abs(reuse_profile["reusable_work_share_upper_bound"] - (Decimal(n**3) / Decimal(per_nonce_total_field_muladds_estimate))) < Decimal("0.000000001")
            assert abs(reuse_profile["amortization_advantage_upper_bound"] - (Decimal(per_nonce_total_field_muladds_estimate) / Decimal(compression_field_muladds + noise_low_rank_muladds))) < Decimal("0.000000001")
            seed_access = work_profile["next_block_seed_access"]
            assert_equal(seed_access["seed_derivation_scope"], "per_parent_block")
            assert_equal(seed_access["seed_derivation_rule"], "sha256(prev_block_hash || height || which)")
            assert_equal(seed_access["winner_knows_next_seeds_first"], True)
            assert_equal(seed_access["publicly_precomputable_before_parent_seen"], False)
            assert_equal(seed_access["public_precompute_horizon_blocks"], 0)
            assert_equal(seed_access["fixed_matrix_generation_elements_upper_bound"], 2 * n * n)
            assert_equal(seed_access["template_mutations_preserve_seed"], ["merkle_root", "nonce", "time"])
            pre_hash_lottery = work_profile["pre_hash_lottery"]
            assert_equal(pre_hash_lottery["consensus_enforced"], True)
            assert_equal(pre_hash_lottery["sigma_rule"], "sigma <= target << epsilon_bits")
            assert_equal(pre_hash_lottery["digest_rule"], "matmul_digest <= target")
            assert_equal(pre_hash_lottery["epsilon_bits"], work_profile["pre_hash_epsilon_bits"])
            expected_multiplier = 1 << int(work_profile["pre_hash_epsilon_bits"])
            assert_equal(pre_hash_lottery["sigma_target_multiplier_vs_digest_target"], expected_multiplier)
            assert pre_hash_lottery["digest_target_probability_per_nonce_estimate"] > 0
            assert pre_hash_lottery["sigma_pass_probability_per_nonce_estimate"] > 0
            assert Decimal(pre_hash_lottery["sigma_pass_probability_per_nonce_estimate"]) >= Decimal(
                pre_hash_lottery["digest_target_probability_per_nonce_estimate"]
            )
            assert Decimal(pre_hash_lottery["expected_sigma_passes_per_digest_hit_estimate"]) >= Decimal(1)
            assert pre_hash_lottery["expected_matmul_invocations_per_1m_nonces_estimate"] > 0
            if not pre_hash_lottery["target_multiplier_saturated"]:
                assert abs(
                    Decimal(pre_hash_lottery["sigma_pass_probability_per_nonce_estimate"])
                    / Decimal(pre_hash_lottery["digest_target_probability_per_nonce_estimate"])
                    - Decimal(expected_multiplier)
                ) < Decimal("0.000001")
                assert abs(
                    Decimal(pre_hash_lottery["expected_sigma_passes_per_digest_hit_estimate"]) - Decimal(expected_multiplier)
                ) < Decimal("0.000001")

        profile = node.getmatmulchallengeprofile(1, 0.25, 0.75)
        assert_equal(profile["service_profile"]["network_target_s"], 90.0)
        assert_equal(profile["service_profile"]["solve_time_target_s"], 1.0)
        assert_equal(profile["service_profile"]["validation_overhead_s"], 0.25)
        assert_equal(profile["service_profile"]["propagation_overhead_s"], 0.75)
        assert_equal(profile["service_profile"]["overhead_target_s"], 1.0)
        assert_equal(profile["service_profile"]["total_target_s"], 2.0)
        assert_equal(profile["service_profile"]["solve_share_pct"], 50.0)
        assert_equal(profile["service_profile"]["validation_share_pct"], 12.5)
        assert_equal(profile["service_profile"]["propagation_share_pct"], 37.5)
        assert_equal(profile["service_profile"]["delta_from_network_s"], -89.0)
        assert_equal(profile["service_profile"]["operator_capacity"]["estimation_basis"], "average_node")
        assert_equal(profile["service_profile"]["operator_capacity"]["solver_parallelism"], 1)
        assert_equal(profile["service_profile"]["operator_capacity"]["solver_duty_cycle_pct"], 100.0)
        assert_equal(profile["service_profile"]["operator_capacity"]["effective_parallelism"], 1.0)
        assert_equal(profile["service_profile"]["operator_capacity"]["budgeted_solver_seconds_per_hour"], 3600.0)
        assert_equal(profile["service_profile"]["operator_capacity"]["estimated_sustained_solves_per_hour"], 1800.0)
        assert_equal(profile["service_profile"]["operator_capacity"]["estimated_sustained_solves_per_day"], 43200.0)
        assert_equal(profile["service_profile"]["operator_capacity"]["estimated_mean_seconds_between_solves"], 2.0)
        assert profile["service_profile"]["runtime_observability"]["solve_pipeline"]["batch_size"] >= 1
        assert profile["service_profile"]["runtime_observability"]["backend_runtime"]["digest_requests"] >= 0
        assert profile["service_profile"]["runtime_observability"]["solve_runtime"]["attempts"] >= 8
        assert profile["service_profile"]["runtime_observability"]["solve_runtime"]["solved_attempts"] >= 8
        assert profile["service_profile"]["runtime_observability"]["solve_runtime"]["last_elapsed_ms"] > 0
        assert profile["service_profile"]["runtime_observability"]["validation_runtime"]["phase2_checks"] >= 8
        assert profile["service_profile"]["runtime_observability"]["validation_runtime"]["freivalds_checks"] >= 8
        assert profile["service_profile"]["runtime_observability"]["validation_runtime"]["successful_checks"] >= 8
        assert profile["service_profile"]["runtime_observability"]["validation_runtime"]["last_phase2_elapsed_ms"] > 0
        assert_equal(profile["service_profile"]["runtime_observability"]["propagation_proxy"]["connected_peers"], network_info["connections"])
        assert profile["service_profile"]["runtime_observability"]["propagation_proxy"]["manual_outbound_peers"] <= outbound_peers
        assert profile["service_profile"]["runtime_observability"]["propagation_proxy"]["outbound_peers_missing_sync_height"] <= outbound_peers
        assert profile["service_profile"]["runtime_observability"]["propagation_proxy"]["outbound_peers_beyond_sync_lag"] <= outbound_peers
        assert profile["service_profile"]["runtime_observability"]["propagation_proxy"]["recent_block_announcing_outbound_peers"] <= outbound_peers
        assert_equal(
            len(profile["service_profile"]["runtime_observability"]["propagation_proxy"]["outbound_peer_diagnostics"]),
            outbound_peers,
        )
        assert_equal(profile["service_profile"]["runtime_observability"]["propagation_proxy"]["header_lag"], 0)
        assert_equal(profile["service_profile"]["runtime_observability"]["reorg_protection"]["enabled"], False)
        assert_equal(profile["service_profile"]["runtime_observability"]["reorg_protection"]["active"], False)
        assert_equal(profile["service_profile"]["runtime_observability"]["reorg_protection"]["max_reorg_depth"], 0)
        assert_equal(profile["service_profile"]["runtime_observability"]["reorg_protection"]["rejected_reorgs"], 0)
        assert_equal(profile["header_context"]["previousblockhash"], profile["previousblockhash"])
        assert_equal(profile["header_context"]["bits"], profile["bits"])
        assert_equal(profile["header_context"]["matmul_dim"], profile["matmul"]["n"])
        assert_equal(profile["header_context"]["seed_a"], profile["matmul"]["seed_a"])
        assert_equal(profile["header_context"]["seed_b"], profile["matmul"]["seed_b"])
        assert_equal(profile["header_context"]["nonce64_start"], 0)
        assert profile["header_context"]["time"] >= profile["mintime"]
        assert_equal(len(profile["header_context"]["merkleroot"]), 64)
        assert_equal(
            profile["work_profile"]["pre_hash_epsilon_bits"],
            health["consensus_guards"]["pre_hash_epsilon_bits"]["next_block_bits"],
        )
        idle_mining_profile = node.getmatmulchallengeprofile(1, 0.25, 0.75, 2, 25)
        assert_equal(idle_mining_profile["service_profile"]["operator_capacity"]["solver_parallelism"], 2)
        assert_equal(idle_mining_profile["service_profile"]["operator_capacity"]["solver_duty_cycle_pct"], 25.0)
        assert_equal(idle_mining_profile["service_profile"]["operator_capacity"]["effective_parallelism"], 0.5)
        assert_equal(idle_mining_profile["service_profile"]["operator_capacity"]["budgeted_solver_seconds_per_hour"], 1800.0)
        assert_equal(idle_mining_profile["service_profile"]["operator_capacity"]["estimated_sustained_solves_per_hour"], 900.0)
        assert_equal(idle_mining_profile["service_profile"]["operator_capacity"]["estimated_sustained_solves_per_day"], 21600.0)
        assert_equal(idle_mining_profile["service_profile"]["operator_capacity"]["estimated_mean_seconds_between_solves"], 4.0)
        work_profile = profile["work_profile"]
        n = profile["matmul"]["n"]
        b = profile["matmul"]["b"]
        r = profile["matmul"]["r"]
        blocks_per_axis = n // b
        compression_field_muladds = (blocks_per_axis**3) * (b * b)
        noise_low_rank_muladds = 2 * n * n * r
        per_nonce_total_field_muladds_estimate = n**3 + compression_field_muladds + noise_low_rank_muladds
        assert_equal(work_profile["field_element_bytes"], 4)
        assert_equal(work_profile["matrix_elements"], n * n)
        assert_equal(work_profile["matrix_bytes"], n * n * 4)
        assert_equal(work_profile["matrix_generation_elements_per_seed"], n * n)
        assert_equal(work_profile["transcript_blocks_per_axis"], blocks_per_axis)
        assert_equal(work_profile["transcript_block_multiplications"], blocks_per_axis**3)
        assert_equal(work_profile["transcript_field_muladds"], n**3)
        assert_equal(work_profile["compression_vector_elements"], b * b)
        assert_equal(work_profile["compression_field_muladds"], compression_field_muladds)
        assert_equal(work_profile["noise_elements"], 4 * n * r)
        assert_equal(work_profile["noise_low_rank_muladds"], noise_low_rank_muladds)
        assert_equal(work_profile["denoise_field_muladds"], 5 * n * n * r + 2 * n * r * r)
        assert_equal(work_profile["per_nonce_total_field_muladds_estimate"], per_nonce_total_field_muladds_estimate)
        assert work_profile["oracle_rejection_probability_per_element"] > 0
        assert work_profile["oracle_rejection_probability_per_element"] < Decimal("0.000000001")
        assert work_profile["expected_oracle_retries_per_matrix_seed"] > 0
        assert work_profile["expected_oracle_retries_per_nonce_noise"] > 0
        assert work_profile["pre_hash_epsilon_bits"] >= 0
        reuse_profile = work_profile["cross_nonce_reuse"]
        assert_equal(reuse_profile["seed_scope"], "per_block_template")
        assert_equal(reuse_profile["sigma_scope"], "per_nonce")
        assert_equal(reuse_profile["fixed_instance_reuse_possible"], True)
        assert_equal(reuse_profile["fixed_matrix_generation_elements_upper_bound"], 2 * n * n)
        assert_equal(reuse_profile["fixed_clean_product_field_muladds_upper_bound"], n**3)
        assert_equal(reuse_profile["dynamic_per_nonce_field_muladds_lower_bound"], compression_field_muladds + noise_low_rank_muladds)
        assert abs(reuse_profile["dynamic_per_nonce_share_lower_bound"] - (Decimal(compression_field_muladds + noise_low_rank_muladds) / Decimal(per_nonce_total_field_muladds_estimate))) < Decimal("0.000000001")
        assert abs(reuse_profile["reusable_work_share_upper_bound"] - (Decimal(n**3) / Decimal(per_nonce_total_field_muladds_estimate))) < Decimal("0.000000001")
        assert abs(reuse_profile["amortization_advantage_upper_bound"] - (Decimal(per_nonce_total_field_muladds_estimate) / Decimal(compression_field_muladds + noise_low_rank_muladds))) < Decimal("0.000000001")
        seed_access = work_profile["next_block_seed_access"]
        assert_equal(seed_access["seed_derivation_scope"], "per_parent_block")
        assert_equal(seed_access["seed_derivation_rule"], "sha256(prev_block_hash || height || which)")
        assert_equal(seed_access["winner_knows_next_seeds_first"], True)
        assert_equal(seed_access["publicly_precomputable_before_parent_seen"], False)
        assert_equal(seed_access["public_precompute_horizon_blocks"], 0)
        assert_equal(seed_access["fixed_matrix_generation_elements_upper_bound"], 2 * n * n)
        assert_equal(seed_access["template_mutations_preserve_seed"], ["merkle_root", "nonce", "time"])
        pre_hash_lottery = work_profile["pre_hash_lottery"]
        assert_equal(pre_hash_lottery["consensus_enforced"], True)
        assert_equal(pre_hash_lottery["sigma_rule"], "sigma <= target << epsilon_bits")
        assert_equal(pre_hash_lottery["digest_rule"], "matmul_digest <= target")
        assert_equal(pre_hash_lottery["epsilon_bits"], work_profile["pre_hash_epsilon_bits"])
        expected_multiplier = 1 << int(work_profile["pre_hash_epsilon_bits"])
        assert_equal(pre_hash_lottery["sigma_target_multiplier_vs_digest_target"], expected_multiplier)
        assert pre_hash_lottery["digest_target_probability_per_nonce_estimate"] > 0
        assert pre_hash_lottery["sigma_pass_probability_per_nonce_estimate"] > 0
        assert Decimal(pre_hash_lottery["sigma_pass_probability_per_nonce_estimate"]) >= Decimal(
            pre_hash_lottery["digest_target_probability_per_nonce_estimate"]
        )
        assert Decimal(pre_hash_lottery["expected_sigma_passes_per_digest_hit_estimate"]) >= Decimal(1)
        assert pre_hash_lottery["expected_matmul_invocations_per_1m_nonces_estimate"] > 0
        if not pre_hash_lottery["target_multiplier_saturated"]:
            assert abs(
                Decimal(pre_hash_lottery["sigma_pass_probability_per_nonce_estimate"])
                / Decimal(pre_hash_lottery["digest_target_probability_per_nonce_estimate"])
                - Decimal(expected_multiplier)
            ) < Decimal("0.000001")
            assert abs(
                Decimal(pre_hash_lottery["expected_sigma_passes_per_digest_hit_estimate"]) - Decimal(expected_multiplier)
            ) < Decimal("0.000001")

        challenge_profile = challenge["service_profile"]
        assert_equal(challenge_profile["network_target_s"], 90.0)
        assert_equal(challenge_profile["solve_share_pct"], 100.0)
        assert_equal(challenge_profile["validation_share_pct"], 0.0)
        assert_equal(challenge_profile["propagation_share_pct"], 0.0)
        assert challenge_profile["runtime_observability"]["solve_pipeline"]["batch_size"] >= 1
        assert challenge_profile["runtime_observability"]["solve_runtime"]["attempts"] >= 8
        assert challenge_profile["runtime_observability"]["validation_runtime"]["phase2_checks"] >= 8
        assert_equal(challenge_profile["runtime_observability"]["reorg_protection"]["enabled"], False)
        assert_equal(challenge_profile["runtime_observability"]["reorg_protection"]["max_reorg_depth"], 0)
        assert profile["bits"] != challenge["bits"]

        addr_a = get_generate_key().p2wpkh_addr
        addr_b = get_generate_key().p2wpkh_addr
        addr_c = get_generate_key().p2wpkh_addr
        self.generatetoaddress(node, 3, addr_a, 1_000_000)
        self.generatetoaddress(node, 2, addr_b, 1_000_000)
        self.generatetoaddress(node, 1, addr_c, 1_000_000)

        distribution = node.getdifficultyhealth(6)["reward_distribution"]
        assert_equal(distribution["count"], 6)
        assert_equal(distribution["unique_recipients"], 3)
        assert_equal(distribution["unknown_recipients"], 0)
        assert_equal(distribution["top_share"], 0.5)
        assert abs(distribution["top3_share"] - Decimal("1.0")) < Decimal("0.000000001")
        assert_equal(distribution["top_recipients"][0]["recipient"], addr_a)
        assert_equal(distribution["top_recipients"][0]["blocks"], 3)
        assert_equal(distribution["top_recipients"][1]["recipient"], addr_b)
        assert_equal(distribution["top_recipients"][1]["blocks"], 2)
        assert_equal(distribution["top_recipients"][2]["recipient"], addr_c)
        assert_equal(distribution["top_recipients"][2]["blocks"], 1)
        assert_equal(distribution["longest_streak"]["recipient"], addr_a)
        assert_equal(distribution["longest_streak"]["blocks"], 3)
        assert_equal(distribution["longest_streak"]["block_share"], 0.5)
        assert_equal(distribution["longest_streak"]["recipient_share"], 0.5)
        assert abs(distribution["longest_streak"]["probability_at_least_observed"] - Decimal("0.3125")) < Decimal("0.000000001")
        assert abs(distribution["longest_streak"]["probability_upper_bound"] - Decimal("0.5")) < Decimal("0.000000001")
        assert_equal(distribution["longest_streak"]["statistically_improbable"], False)
        assert_equal(distribution["longest_streak"]["context_window_blocks"], 6)
        assert_equal(distribution["longest_streak"]["context_start_height"], 9)
        assert_equal(distribution["longest_streak"]["context_end_height"], 14)
        assert_equal(distribution["longest_streak"]["context_recipient_share"], 0.5)
        assert_equal(distribution["longest_streak"]["context_unique_recipients"], 3)
        assert_equal(distribution["longest_streak"]["nonstationary_share_suspected"], False)

        spaced_time = node.getblockheader(node.getbestblockhash())["time"]
        node.setmocktime(spaced_time)
        for _ in range(4):
            spaced_time += 180
            node.setmocktime(spaced_time)
            self.generatetoaddress(node, 1, addr_a, 1_000_000)
        self.sync_all()
        node.setmocktime(0)
        node_other.setmocktime(0)

        adaptive_profile = node.getmatmulservicechallengeprofile(
            "balanced",
            0.25,
            0.75,
            0.25,
            6,
            1,
            "adaptive_window",
            4,
            4,
            25,
        )
        assert_equal(adaptive_profile["profile"]["recommended_target_solve_time_s"], 2.0)
        assert_equal(adaptive_profile["profile"]["resolved_target_solve_time_s"], 4.0)
        assert_equal(adaptive_profile["profile"]["difficulty_resolution"]["mode"], "adaptive_window")
        assert_equal(adaptive_profile["profile"]["difficulty_resolution"]["window_blocks"], 4)
        assert_equal(adaptive_profile["profile"]["difficulty_resolution"]["observed_interval_count"], 4)
        assert_equal(adaptive_profile["profile"]["difficulty_resolution"]["observed_mean_interval_s"], 180.0)
        assert_equal(adaptive_profile["profile"]["difficulty_resolution"]["interval_scale"], 2.0)
        assert_equal(adaptive_profile["profile"]["issue_defaults"]["difficulty_policy"], "adaptive_window")
        assert_equal(adaptive_profile["profile"]["issue_defaults"]["difficulty_window_blocks"], 4)
        assert_equal(adaptive_profile["profile"]["difficulty_label"], "normal")
        assert_equal(adaptive_profile["profile"]["effort_tier"], 2)
        assert_equal(adaptive_profile["profile"]["estimated_average_node_total_time_s"], 5.0)
        assert_equal(adaptive_profile["profile"]["operator_capacity"]["solver_parallelism"], 4)
        assert_equal(adaptive_profile["profile"]["operator_capacity"]["solver_duty_cycle_pct"], 25.0)
        assert_equal(adaptive_profile["profile"]["operator_capacity"]["effective_parallelism"], 1.0)
        assert_equal(adaptive_profile["profile"]["operator_capacity"]["budgeted_solver_seconds_per_hour"], 3600.0)
        assert_equal(adaptive_profile["profile"]["operator_capacity"]["estimated_sustained_solves_per_hour"], 720.0)
        assert_equal(adaptive_profile["profile"]["operator_capacity"]["estimated_sustained_solves_per_day"], 17280.0)
        assert_equal(adaptive_profile["profile"]["operator_capacity"]["estimated_mean_seconds_between_solves"], 5.0)
        assert_equal(adaptive_profile["profile"]["issue_defaults"]["solver_parallelism"], 4)
        assert_equal(adaptive_profile["profile"]["issue_defaults"]["solver_duty_cycle_pct"], 25.0)
        assert_equal(adaptive_profile["profile"]["issue_defaults"]["resolved_target_solve_time_s"], 4.0)
        assert_equal(adaptive_profile["profile"]["profile_issue_defaults"]["rpc"], "issuematmulservicechallengeprofile")
        assert_equal(adaptive_profile["profile"]["profile_issue_defaults"]["resolved_target_solve_time_s"], 4.0)
        assert_equal(adaptive_profile["profile"]["profile_issue_defaults"]["solver_parallelism"], 4)
        assert_equal(adaptive_profile["profile"]["profile_issue_defaults"]["solver_duty_cycle_pct"], 25.0)
        assert_equal(adaptive_profile["challenge_profile"]["service_profile"]["solve_time_target_s"], 4.0)
        assert_equal(adaptive_profile["challenge_profile"]["service_profile"]["operator_capacity"]["solver_parallelism"], 4)
        assert_equal(adaptive_profile["challenge_profile"]["service_profile"]["operator_capacity"]["solver_duty_cycle_pct"], 25.0)

        throughput_plan = node.getmatmulservicechallengeplan(
            "solves_per_hour",
            1200,
            0.25,
            0.75,
            "fixed",
            24,
            0.25,
            30,
            4,
            25,
        )
        assert_equal(throughput_plan["objective"]["mode"], "solves_per_hour")
        assert_equal(throughput_plan["objective"]["requested_sustained_solves_per_hour"], 1200.0)
        assert_equal(throughput_plan["objective"]["requested_total_target_s"], 3.0)
        assert_equal(throughput_plan["objective"]["requested_resolved_solve_time_s"], 2.0)
        assert_equal(throughput_plan["plan"]["objective_satisfied"], True)
        assert_equal(throughput_plan["plan"]["requested_base_solve_time_s"], 2.0)
        assert_equal(throughput_plan["plan"]["resolved_target_solve_time_s"], 2.0)
        assert_equal(throughput_plan["plan"]["resolved_total_target_s"], 3.0)
        assert_equal(throughput_plan["plan"]["operator_capacity"]["estimated_sustained_solves_per_hour"], 1200.0)
        assert_equal(throughput_plan["plan"]["objective_gap"]["headroom_pct"], 0.0)
        assert_equal(throughput_plan["plan"]["issue_defaults"]["rpc"], "getmatmulservicechallenge")
        assert_equal(throughput_plan["plan"]["issue_defaults"]["target_solve_time_s"], 2.0)
        assert_equal(throughput_plan["plan"]["issue_defaults"]["resolved_target_solve_time_s"], 2.0)
        assert_equal(throughput_plan["recommended_profile"]["name"], "balanced")
        assert_equal(throughput_plan["recommended_profile"]["solve_time_multiplier"], 1.0)
        assert_equal(throughput_plan["recommended_profile"]["issue_defaults"]["resolved_target_solve_time_s"], 2.0)
        assert_equal(throughput_plan["recommended_profile"]["profile_issue_defaults"]["resolved_target_solve_time_s"], 2.0)
        assert_equal(throughput_plan["candidate_profiles"][0]["name"], "balanced")
        assert_equal(len(throughput_plan["candidate_profiles"]), 4)
        assert_equal(throughput_plan["challenge_profile"]["service_profile"]["solve_time_target_s"], 2.0)

        clamped_fixed_plan = node.getmatmulservicechallengeplan(
            "solves_per_hour",
            1200,
            0.25,
            0.75,
            "fixed",
            24,
            0.25,
            1.0,
            4,
            25,
        )
        assert_equal(clamped_fixed_plan["objective"]["requested_resolved_solve_time_s"], 2.0)
        assert_equal(clamped_fixed_plan["plan"]["resolved_target_solve_time_s"], 1.0)
        assert_equal(clamped_fixed_plan["plan"]["resolved_total_target_s"], 2.0)
        assert_equal(clamped_fixed_plan["plan"]["difficulty_resolution"]["mode"], "fixed")
        assert_equal(clamped_fixed_plan["plan"]["difficulty_resolution"]["clamped"], True)
        assert_equal(clamped_fixed_plan["plan"]["difficulty_resolution"]["adjusted_solve_time_s"], 2.0)
        assert_equal(clamped_fixed_plan["plan"]["difficulty_resolution"]["resolved_solve_time_s"], 1.0)
        assert_equal(clamped_fixed_plan["plan"]["issue_defaults"]["target_solve_time_s"], 2.0)
        assert_equal(clamped_fixed_plan["plan"]["issue_defaults"]["resolved_target_solve_time_s"], 1.0)
        assert_equal(clamped_fixed_plan["plan"]["objective_gap"]["actual_sustained_solves_per_hour"], 1800.0)

        plan_issue_defaults = throughput_plan["plan"]["issue_defaults"]
        issued_from_plan = node.getmatmulservicechallenge(
            "rate_limit",
            "plan:/v1/messages",
            "user:plan@example.com",
            float(plan_issue_defaults["target_solve_time_s"]),
            300,
            float(plan_issue_defaults["validation_overhead_s"]),
            float(plan_issue_defaults["propagation_overhead_s"]),
            plan_issue_defaults["difficulty_policy"],
            int(plan_issue_defaults["difficulty_window_blocks"]),
            float(plan_issue_defaults["min_solve_time_s"]),
            float(plan_issue_defaults["max_solve_time_s"]),
            int(plan_issue_defaults["solver_parallelism"]),
            float(plan_issue_defaults["solver_duty_cycle_pct"]),
        )
        assert_equal(issued_from_plan["challenge"]["service_profile"]["solve_time_target_s"], 2.0)

        plan_profile_defaults = throughput_plan["recommended_profile"]["profile_issue_defaults"]
        issued_from_plan_profile = node.issuematmulservicechallengeprofile(
            "rate_limit",
            "plan:/v1/profile",
            "user:plan-profile@example.com",
            plan_profile_defaults["profile_name"],
            300,
            float(plan_profile_defaults["validation_overhead_s"]),
            float(plan_profile_defaults["propagation_overhead_s"]),
            float(plan_profile_defaults["min_solve_time_s"]),
            float(plan_profile_defaults["max_solve_time_s"]),
            float(plan_profile_defaults["solve_time_multiplier"]),
            plan_profile_defaults["difficulty_policy"],
            int(plan_profile_defaults["difficulty_window_blocks"]),
            int(plan_profile_defaults["solver_parallelism"]),
            float(plan_profile_defaults["solver_duty_cycle_pct"]),
        )
        assert_equal(issued_from_plan_profile["profile"]["name"], "balanced")
        assert_equal(issued_from_plan_profile["service_challenge"]["challenge"]["service_profile"]["solve_time_target_s"], 2.0)

        adaptive_plan = node.getmatmulservicechallengeplan(
            "solves_per_hour",
            450,
            0.25,
            0.75,
            "adaptive_window",
            4,
            0.25,
            30,
            1,
            100,
        )
        assert_equal(adaptive_plan["objective"]["requested_total_target_s"], 8.0)
        assert_equal(adaptive_plan["objective"]["requested_resolved_solve_time_s"], 7.0)
        assert_equal(adaptive_plan["plan"]["requested_base_solve_time_s"], 3.5)
        assert_equal(adaptive_plan["plan"]["resolved_target_solve_time_s"], 7.0)
        assert_equal(adaptive_plan["plan"]["difficulty_resolution"]["mode"], "adaptive_window")
        assert_equal(adaptive_plan["plan"]["difficulty_resolution"]["interval_scale"], 2.0)
        assert_equal(adaptive_plan["plan"]["difficulty_resolution"]["observed_interval_count"], 4)
        assert_equal(adaptive_plan["plan"]["issue_defaults"]["target_solve_time_s"], 3.5)
        assert_equal(adaptive_plan["plan"]["issue_defaults"]["resolved_target_solve_time_s"], 7.0)
        assert_equal(adaptive_plan["recommended_profile"]["name"], "strict")
        assert_approx(adaptive_plan["recommended_profile"]["solve_time_multiplier"], Decimal("0.7"), Decimal("0.000000001"))
        assert_equal(adaptive_plan["recommended_profile"]["profile_issue_defaults"]["resolved_target_solve_time_s"], 7.0)

        per_day_plan = node.getmatmulservicechallengeplan(
            "challenges_per_day",
            28800,
            0.25,
            0.75,
            "fixed",
            24,
            0.25,
            30,
            4,
            25,
        )
        assert_equal(per_day_plan["objective"]["mode"], "solves_per_day")
        assert_equal(per_day_plan["objective"]["requested_sustained_solves_per_hour"], 1200.0)
        assert_equal(per_day_plan["objective"]["requested_total_target_s"], 3.0)
        assert_equal(per_day_plan["plan"]["resolved_target_solve_time_s"], 2.0)

        spacing_plan = node.getmatmulservicechallengeplan(
            "mean_seconds_between_challenges",
            3,
            0.25,
            0.75,
            "fixed",
            24,
            0.25,
            30,
            4,
            25,
        )
        assert_equal(spacing_plan["objective"]["mode"], "mean_seconds_between_solves")
        assert_equal(spacing_plan["objective"]["requested_sustained_solves_per_hour"], 1200.0)
        assert_equal(spacing_plan["objective"]["requested_total_target_s"], 3.0)
        assert_equal(spacing_plan["plan"]["requested_base_solve_time_s"], 2.0)
        assert_equal(spacing_plan["plan"]["resolved_target_solve_time_s"], 2.0)

        profile_catalog = node.listmatmulservicechallengeprofiles(
            0.25,
            0.75,
            0.25,
            6,
            1,
            "adaptive_window",
            4,
            4,
            25,
        )
        assert_equal(profile_catalog["default_profile"], "balanced")
        assert_equal(profile_catalog["default_difficulty_label"], "normal")
        assert_equal([entry["difficulty_label"] for entry in profile_catalog["profiles"]], ["easy", "normal", "hard", "idle"])
        assert_equal(profile_catalog["profiles"][1]["name"], "balanced")
        assert_equal(profile_catalog["profiles"][1]["resolved_target_solve_time_s"], 4.0)
        assert_equal(profile_catalog["profiles"][1]["operator_capacity"]["solver_parallelism"], 4)
        assert_equal(profile_catalog["profiles"][1]["operator_capacity"]["solver_duty_cycle_pct"], 25.0)

        issued_from_profile = node.issuematmulservicechallengeprofile(
            "rate_limit",
            "signup:/v1/profile",
            "user:profile@example.com",
            "normal",
            300,
            0,
            0,
            0.001,
            0.001,
            0.0001,
            "fixed",
            24,
            4,
            25,
        )
        assert_equal(issued_from_profile["profile"]["name"], "balanced")
        assert_equal(issued_from_profile["profile"]["difficulty_label"], "normal")
        assert_equal(issued_from_profile["profile"]["operator_capacity"]["solver_parallelism"], 4)
        assert_equal(issued_from_profile["profile"]["operator_capacity"]["solver_duty_cycle_pct"], 25.0)
        assert_approx(
            issued_from_profile["service_challenge"]["challenge"]["service_profile"]["solve_time_target_s"],
            Decimal("0.001"),
            Decimal("0.000000001"),
        )
        assert_equal(
            issued_from_profile["service_challenge"]["challenge"]["service_profile"]["operator_capacity"]["solver_parallelism"],
            4,
        )
        assert_equal(
            issued_from_profile["service_challenge"]["challenge"]["service_profile"]["operator_capacity"]["solver_duty_cycle_pct"],
            25.0,
        )
        issued_solution = node.solvematmulservicechallenge(
            issued_from_profile["service_challenge"],
            EXPECTED_SOLVE_SUCCESS_MAX_TRIES,
        )
        assert_equal(issued_solution["solved"], True)
        issued_redeem = node.redeemmatmulserviceproof(
            issued_from_profile["service_challenge"],
            issued_solution["nonce64_hex"],
            issued_solution["digest_hex"],
        )
        assert_equal(issued_redeem["valid"], True)
        assert_equal(issued_redeem["reason"], "ok")

        clamped_adaptive_service = node.getmatmulservicechallenge(
            "rate_limit",
            "signup:/v1/clamped",
            "user:clamped@example.com",
            2,
            300,
            0.25,
            0.75,
            "adaptive_window",
            4,
            0.25,
            3,
        )
        assert_equal(clamped_adaptive_service["challenge"]["service_profile"]["solve_time_target_s"], 3.0)
        assert_equal(clamped_adaptive_service["challenge"]["service_profile"]["difficulty_resolution"]["adjusted_solve_time_s"], 4.0)
        assert_equal(clamped_adaptive_service["challenge"]["service_profile"]["difficulty_resolution"]["resolved_solve_time_s"], 3.0)
        assert_equal(clamped_adaptive_service["challenge"]["service_profile"]["difficulty_resolution"]["clamped"], True)

        service = node.getmatmulservicechallenge(
            "rate_limit",
            "signup:/v1/messages",
            "user:alice@example.com",
            2,
            300,
            0.25,
            0.75,
            "fixed",
            24,
            0.25,
            30,
            4,
            25,
        )
        assert_equal(service["kind"], "matmul_service_challenge_v1")
        assert_equal(len(service["challenge_id"]), 64)
        assert_equal(service["expires_in_s"], 300)
        assert service["expires_at"] > service["issued_at"]
        binding = service["binding"]
        assert_equal(binding["purpose"], "rate_limit")
        assert_equal(binding["resource"], "signup:/v1/messages")
        assert_equal(binding["subject"], "user:alice@example.com")
        assert_equal(len(binding["resource_hash"]), 64)
        assert_equal(len(binding["subject_hash"]), 64)
        assert_equal(len(binding["salt"]), 64)
        assert_equal(service["challenge"]["service_profile"]["operator_capacity"]["solver_parallelism"], 4)
        assert_equal(service["challenge"]["service_profile"]["operator_capacity"]["solver_duty_cycle_pct"], 25.0)
        assert_equal(service["challenge"]["service_profile"]["operator_capacity"]["effective_parallelism"], 1.0)
        assert_equal(service["challenge"]["service_profile"]["operator_capacity"]["budgeted_solver_seconds_per_hour"], 3600.0)
        assert_equal(service["challenge"]["service_profile"]["operator_capacity"]["estimated_sustained_solves_per_hour"], 1200.0)
        assert_equal(service["challenge"]["service_profile"]["operator_capacity"]["estimated_sustained_solves_per_day"], 28800.0)
        assert_equal(service["challenge"]["service_profile"]["operator_capacity"]["estimated_mean_seconds_between_solves"], 3.0)
        assert_equal(binding["anchor_height"], node.getblockcount())
        assert_equal(binding["anchor_hash"], node.getbestblockhash())
        assert_equal(binding["challenge_id_rule"], "sha256(domain || binding_hash || salt || anchor_hash || anchor_height || issued_at || expires_at || target_solve_ms || validation_overhead_ms || propagation_overhead_ms)")
        assert_equal(binding["seed_derivation_rule"], "sha256(challenge_id || anchor_hash || label)")
        proof_policy = service["proof_policy"]
        assert_equal(proof_policy["verification_rule"], "matmul_digest <= target && transcript_hash == digest")
        assert_equal(proof_policy["sigma_gate_applied"], False)
        assert_equal(proof_policy["expiration_enforced"], True)
        assert_equal(proof_policy["challenge_id_required"], True)
        assert_equal(proof_policy["replay_protection"], "redeemmatmulserviceproof")
        assert_equal(proof_policy["redeem_rpc"], "redeemmatmulserviceproof")
        assert_equal(proof_policy["solve_rpc"], "solvematmulservicechallenge")
        assert_equal(proof_policy["locally_issued_required"], True)
        assert_equal(proof_policy["issued_challenge_store"], "local_persistent_file")
        assert_equal(proof_policy["issued_challenge_scope"], "node_local")
        service_challenge = service["challenge"]
        assert_equal(service_challenge["algorithm"], "matmul")
        assert_equal(service_challenge["service_profile"]["solve_time_target_s"], 2.0)
        assert_equal(service_challenge["service_profile"]["difficulty_resolution"]["mode"], "fixed")
        assert_equal(service_challenge["service_profile"]["validation_overhead_s"], 0.25)
        assert_equal(service_challenge["service_profile"]["propagation_overhead_s"], 0.75)
        assert_equal(service_challenge["service_profile"]["total_target_s"], 3.0)
        assert_equal(service_challenge["header_context"]["previousblockhash"], binding["anchor_hash"])
        assert service_challenge["header_context"]["seed_a"] != challenge["header_context"]["seed_a"]
        assert service_challenge["header_context"]["seed_b"] != challenge["header_context"]["seed_b"]
        second_service = node.getmatmulservicechallenge(
            "rate_limit",
            "signup:/v1/messages",
            "user:alice@example.com",
            2,
            300,
            0.25,
            0.75,
        )
        assert second_service["challenge_id"] != service["challenge_id"]
        assert second_service["binding"]["salt"] != binding["salt"]
        invalid_service_proof = node.verifymatmulserviceproof(
            service,
            "0000000000000000",
            "00" * 32,
        )
        assert_equal(invalid_service_proof["challenge_id"], service["challenge_id"])
        assert_equal(invalid_service_proof["valid"], False)
        assert_equal(invalid_service_proof["expired"], False)
        assert_equal(invalid_service_proof["reason"], "invalid_proof")
        assert_equal(invalid_service_proof["issued_by_local_node"], True)
        assert_equal(invalid_service_proof["redeemed"], False)
        assert_equal(invalid_service_proof["redeemable"], True)
        assert_equal(invalid_service_proof["proof"]["nonce64_hex"], "0000000000000000")
        assert_equal(invalid_service_proof["proof"]["digest"], "00" * 32)
        assert_equal(invalid_service_proof["proof"]["transcript_valid"], False)
        assert_equal(invalid_service_proof["proof"]["commitment_valid"], True)
        assert_equal(invalid_service_proof["proof"]["meets_target"], True)
        assert_equal(len(invalid_service_proof["proof"]["sigma"]), 64)
        assert "mismatch_field" not in invalid_service_proof

        tampered_service = copy.deepcopy(service)
        tampered_service["challenge"]["bits"] = "207fffff"
        tampered_service["challenge"]["target"] = "7fffff0000000000000000000000000000000000000000000000000000000000"
        tampered_service["challenge"]["header_context"]["bits"] = "207fffff"
        tampered_service_proof = node.verifymatmulserviceproof(
            tampered_service,
            "0000000000000000",
            "00" * 32,
        )
        assert_equal(tampered_service_proof["valid"], False)
        assert_equal(tampered_service_proof["reason"], "challenge_mismatch")
        assert_equal(tampered_service_proof["mismatch_field"], "challenge.bits")

        unknown_service_redeem = node_other.redeemmatmulserviceproof(
            service,
            "0000000000000000",
            "00" * 32,
        )
        assert_equal(unknown_service_redeem["valid"], False)
        assert_equal(unknown_service_redeem["expired"], False)
        assert_equal(unknown_service_redeem["reason"], "unknown_challenge")
        assert_equal(unknown_service_redeem["issued_by_local_node"], False)
        assert_equal(unknown_service_redeem["redeemed"], False)
        assert_equal(unknown_service_redeem["redeemable"], False)
        assert "proof" not in unknown_service_redeem

        expiring_service = node.getmatmulservicechallenge(
            "rate_limit",
            "signup:/v1/expired",
            "user:expired@example.com",
            0.001,
            1,
            0,
            0,
        )
        node.setmocktime(expiring_service["expires_at"] + 1)
        node_other.setmocktime(expiring_service["expires_at"] + 1)
        expired_verify = node.verifymatmulserviceproof(
            expiring_service,
            "0000000000000000",
            "00" * 32,
        )
        assert_equal(expired_verify["valid"], False)
        assert_equal(expired_verify["expired"], True)
        assert_equal(expired_verify["reason"], "expired")
        expired_redeem = node.redeemmatmulserviceproof(
            expiring_service,
            "0000000000000000",
            "00" * 32,
        )
        assert_equal(expired_redeem["valid"], False)
        assert_equal(expired_redeem["expired"], True)
        assert_equal(expired_redeem["reason"], "expired")
        node.setmocktime(0)
        node_other.setmocktime(0)

        self.restart_node(0)
        node = self.nodes[0]

        post_restart_verify = node.verifymatmulserviceproof(
            service,
            "0000000000000000",
            "00" * 32,
        )
        assert_equal(post_restart_verify["valid"], False)
        assert_equal(post_restart_verify["expired"], False)
        assert_equal(post_restart_verify["reason"], "invalid_proof")
        assert_equal(post_restart_verify["issued_by_local_node"], True)
        assert_equal(post_restart_verify["redeemed"], False)
        assert_equal(post_restart_verify["redeemable"], True)

        post_restart_redeem = node.redeemmatmulserviceproof(
            service,
            "0000000000000000",
            "00" * 32,
        )
        assert_equal(post_restart_redeem["valid"], False)
        assert_equal(post_restart_redeem["expired"], False)
        assert_equal(post_restart_redeem["reason"], "invalid_proof")
        assert_equal(post_restart_redeem["issued_by_local_node"], True)
        assert_equal(post_restart_redeem["redeemed"], False)
        assert_equal(post_restart_redeem["redeemable"], True)
        assert_equal(post_restart_redeem["proof"]["nonce64_hex"], "0000000000000000")

        shared_registry = os.path.join(self.options.tmpdir, "shared-matmul-service.dat")
        shared_registry_arg = f"-matmulservicechallengefile={shared_registry}"
        self.restart_node(0, self.extra_args[0] + [shared_registry_arg])
        self.restart_node(1, self.extra_args[1] + [shared_registry_arg])
        self.sync_all()
        node = self.nodes[0]
        node_other = self.nodes[1]

        shared_service = node.getmatmulservicechallenge(
            "rate_limit",
            "shared:/v1/messages",
            "user:shared@example.com",
            EASY_SERVICE_TARGET_SOLVE_TIME_S,
            300,
            0,
            0,
            "fixed",
            24,
            EASY_SERVICE_TARGET_SOLVE_TIME_S,
            EASY_SERVICE_TARGET_SOLVE_TIME_S,
        )
        assert_equal(shared_service["proof_policy"]["issued_challenge_store"], "shared_file_lock_store")
        assert_equal(shared_service["proof_policy"]["issued_challenge_scope"], "shared_file")
        shared_solution = node_other.solvematmulservicechallenge(
            shared_service,
            EXPECTED_SOLVE_SUCCESS_MAX_TRIES,
        )
        assert_equal(shared_solution["solved"], True)
        assert shared_solution["attempts"] >= 1
        shared_nonce = shared_solution["nonce64_hex"]
        shared_digest = shared_solution["digest_hex"]

        shared_verify = node_other.verifymatmulserviceproof(
            shared_service,
            shared_nonce,
            shared_digest,
        )
        assert_equal(shared_verify["valid"], True)
        assert_equal(shared_verify["expired"], False)
        assert_equal(shared_verify["reason"], "ok")
        assert_equal(shared_verify["issued_by_local_node"], True)
        assert_equal(shared_verify["redeemed"], False)
        assert_equal(shared_verify["redeemable"], True)
        shared_health = node.getdifficultyhealth(5)["service_challenge_registry"]
        assert_equal(shared_health["status"], "ok")
        assert_equal(shared_health["healthy"], True)
        assert_equal(shared_health["shared"], True)
        assert_equal(shared_health["path"], shared_registry)
        assert "last_success_at" in shared_health

        shared_redeem = node_other.redeemmatmulserviceproof(
            shared_service,
            shared_nonce,
            shared_digest,
        )
        assert_equal(shared_redeem["valid"], True)
        assert_equal(shared_redeem["expired"], False)
        assert_equal(shared_redeem["reason"], "ok")
        assert_equal(shared_redeem["issued_by_local_node"], True)
        assert_equal(shared_redeem["redeemed"], True)
        assert_equal(shared_redeem["redeemable"], False)

        shared_redeem_again = node.redeemmatmulserviceproof(
            shared_service,
            shared_nonce,
            shared_digest,
        )
        assert_equal(shared_redeem_again["valid"], False)
        assert_equal(shared_redeem_again["reason"], "already_redeemed")
        assert_equal(shared_redeem_again["issued_by_local_node"], True)
        assert_equal(shared_redeem_again["redeemed"], True)
        assert_equal(shared_redeem_again["redeemable"], False)

        concurrent_shared_service = node.getmatmulservicechallenge(
            "rate_limit",
            "shared:/v1/concurrent",
            "user:concurrent@example.com",
            EASY_SERVICE_TARGET_SOLVE_TIME_S,
            300,
            0,
            0,
            "fixed",
            24,
            EASY_SERVICE_TARGET_SOLVE_TIME_S,
            EASY_SERVICE_TARGET_SOLVE_TIME_S,
        )
        concurrent_solution = node.solvematmulservicechallenge(
            concurrent_shared_service,
            EXPECTED_SOLVE_SUCCESS_MAX_TRIES,
        )
        assert_equal(concurrent_solution["solved"], True)
        concurrent_barrier = threading.Barrier(2)

        def redeem_concurrently(client):
            concurrent_barrier.wait()
            return client.redeemmatmulserviceproof(
                concurrent_shared_service,
                concurrent_solution["nonce64_hex"],
                concurrent_solution["digest_hex"],
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            concurrent_results = list(executor.map(redeem_concurrently, [node, node_other]))

        assert_equal(sum(1 for result in concurrent_results if result["valid"]), 1)
        assert_equal(sum(1 for result in concurrent_results if not result["valid"]), 1)
        assert_equal(
            sorted(result["reason"] for result in concurrent_results),
            ["already_redeemed", "ok"],
        )

        self.restart_node(0, self.extra_args[0] + [shared_registry_arg])
        self.restart_node(1, self.extra_args[1] + [shared_registry_arg])
        self.sync_all()
        node = self.nodes[0]
        node_other = self.nodes[1]

        shared_redeem_after_restart = node.redeemmatmulserviceproof(
            shared_service,
            shared_nonce,
            shared_digest,
        )
        assert_equal(shared_redeem_after_restart["valid"], False)
        assert_equal(shared_redeem_after_restart["reason"], "already_redeemed")
        assert_equal(shared_redeem_after_restart["issued_by_local_node"], True)
        assert_equal(shared_redeem_after_restart["redeemed"], True)
        assert_equal(shared_redeem_after_restart["redeemable"], False)

        self.stop_node(0)
        self.stop_node(1)
        with open(shared_registry, "wb") as handle:
            handle.write((1).to_bytes(8, byteorder="little"))
            handle.write(b"corrupt-registry")
        self.start_node(0, self.extra_args[0] + [shared_registry_arg])
        self.start_node(1, self.extra_args[1] + [shared_registry_arg])
        self.connect_nodes(0, 1)
        self.sync_all()
        node = self.nodes[0]
        node_other = self.nodes[1]

        shared_redeem_after_corruption = node.redeemmatmulserviceproof(
            shared_service,
            shared_nonce,
            shared_digest,
        )
        assert_equal(shared_redeem_after_corruption["valid"], False)
        assert_equal(shared_redeem_after_corruption["reason"], "unknown_challenge")
        assert_equal(shared_redeem_after_corruption["issued_by_local_node"], False)
        assert_equal(shared_redeem_after_corruption["redeemed"], False)
        assert_equal(shared_redeem_after_corruption["redeemable"], False)
        corrupt_health = node.getdifficultyhealth(5)["service_challenge_registry"]
        assert_equal(corrupt_health["status"], "corrupt_quarantined")
        assert_equal(corrupt_health["healthy"], False)
        assert_equal(corrupt_health["shared"], True)
        assert_equal(corrupt_health["path"], shared_registry)
        assert_equal(corrupt_health["entries"], 0)
        assert corrupt_health["last_checked_at"] > 0
        assert corrupt_health["last_failure_at"] > 0
        assert "error" in corrupt_health
        assert "quarantine_path" in corrupt_health
        assert corrupt_health["quarantine_path"].startswith(shared_registry)
        assert os.path.exists(corrupt_health["quarantine_path"])
        assert not os.path.exists(shared_registry)

        stateless_verify = node.verifymatmulserviceproof(
            shared_service,
            shared_nonce,
            shared_digest,
            False,
        )
        assert_equal(stateless_verify["valid"], True)
        assert_equal(stateless_verify["reason"], "ok")
        assert_equal(stateless_verify["local_registry_status_checked"], False)
        assert "issued_by_local_node" not in stateless_verify
        assert "redeemed" not in stateless_verify
        assert "redeemable" not in stateless_verify

        tampered_shared_service = copy.deepcopy(shared_service)
        tampered_shared_service["challenge"]["bits"] = "207fffff"
        tampered_shared_service["challenge"]["target"] = "7fffff0000000000000000000000000000000000000000000000000000000000"
        tampered_shared_service["challenge"]["header_context"]["bits"] = "207fffff"
        stateless_verify_batch = node.verifymatmulserviceproofs([
            {
                "challenge": shared_service,
                "nonce64_hex": shared_nonce,
                "digest_hex": shared_digest,
            },
            {
                "challenge": tampered_shared_service,
                "nonce64_hex": shared_nonce,
                "digest_hex": shared_digest,
            },
        ], False)
        assert_equal(stateless_verify_batch["count"], 2)
        assert_equal(stateless_verify_batch["valid"], 1)
        assert_equal(stateless_verify_batch["invalid"], 1)
        assert_equal(stateless_verify_batch["results"][0]["local_registry_status_checked"], False)
        assert "issued_by_local_node" not in stateless_verify_batch["results"][0]
        assert "redeemed" not in stateless_verify_batch["results"][0]
        assert "redeemable" not in stateless_verify_batch["results"][0]
        assert_equal(stateless_verify_batch["results"][1]["reason"], "challenge_mismatch")
        assert_equal(stateless_verify_batch["results"][1]["local_registry_status_checked"], False)
        assert "issued_by_local_node" not in stateless_verify_batch["results"][1]
        assert "redeemed" not in stateless_verify_batch["results"][1]
        assert "redeemable" not in stateless_verify_batch["results"][1]

        verify_batch = node.verifymatmulserviceproofs([
            {
                "challenge": service,
                "nonce64_hex": "0000000000000000",
                "digest_hex": "00" * 32,
            },
            {
                "challenge": tampered_service,
                "nonce64_hex": "0000000000000000",
                "digest_hex": "00" * 32,
            },
        ])
        assert_equal(verify_batch["count"], 2)
        assert_equal(verify_batch["valid"], 0)
        assert_equal(verify_batch["invalid"], 2)
        assert_equal(verify_batch["by_reason"]["invalid_proof"], 1)
        assert_equal(verify_batch["by_reason"]["challenge_mismatch"], 1)
        assert_equal(verify_batch["results"][0]["index"], 0)
        assert_equal(verify_batch["results"][0]["reason"], "invalid_proof")
        assert_equal(verify_batch["results"][1]["index"], 1)
        assert_equal(verify_batch["results"][1]["reason"], "challenge_mismatch")

        redeem_batch = node_other.redeemmatmulserviceproofs([
            {
                "challenge": service,
                "nonce64_hex": "0000000000000000",
                "digest_hex": "00" * 32,
            },
            {
                "challenge": service,
                "nonce64_hex": "0000000000000000",
                "digest_hex": "00" * 32,
            },
        ])
        assert_equal(redeem_batch["count"], 2)
        assert_equal(redeem_batch["valid"], 0)
        assert_equal(redeem_batch["invalid"], 2)
        assert_equal(redeem_batch["by_reason"]["unknown_challenge"], 2)
        assert_equal(redeem_batch["results"][0]["index"], 0)
        assert_equal(redeem_batch["results"][0]["reason"], "unknown_challenge")
        assert_equal(redeem_batch["results"][1]["index"], 1)
        assert_equal(redeem_batch["results"][1]["reason"], "unknown_challenge")

        fresh_service = node.getmatmulservicechallenge(
            "rate_limit",
            "signup:/v1/fresh",
            "user:fresh@example.com",
            1,
            300,
            0,
            0,
        )
        exhausted_service = node.getmatmulservicechallenge(
            "rate_limit",
            "signup:/v1/exhausted",
            "user:exhausted@example.com",
            HARD_SERVICE_TARGET_SOLVE_TIME_S,
            300,
            0,
            0,
            "fixed",
            24,
            HARD_SERVICE_TARGET_SOLVE_TIME_S,
            HARD_SERVICE_TARGET_SOLVE_TIME_S,
        )
        exhausted_result = node.solvematmulservicechallenge(exhausted_service, 1)
        assert_equal(exhausted_result["solved"], False)
        assert_equal(exhausted_result["reason"], "max_tries_exhausted")
        assert_equal(exhausted_result["attempts"], 1)
        assert_equal(exhausted_result["remaining_tries"], 0)
        runtime_control_service = node.getmatmulservicechallenge(
            "rate_limit",
            "signup:/v1/runtime-controls",
            "user:runtime@example.com",
            EASY_SERVICE_TARGET_SOLVE_TIME_S,
            300,
            0,
            0,
            "fixed",
            24,
            EASY_SERVICE_TARGET_SOLVE_TIME_S,
            EASY_SERVICE_TARGET_SOLVE_TIME_S,
        )
        runtime_control_result = node.solvematmulservicechallenge(
            runtime_control_service,
            EXPECTED_SOLVE_SUCCESS_MAX_TRIES,
            EXPECTED_SOLVE_RUNTIME_BUDGET_MS,
            1,
        )
        assert_equal(runtime_control_result["solved"], True)
        assert_equal(runtime_control_result["reason"], "ok")
        assert_equal(runtime_control_result["time_budget_ms"], EXPECTED_SOLVE_RUNTIME_BUDGET_MS)
        assert_equal(runtime_control_result["solver_threads"], 1)
        assert_raises_rpc_error(-8, "window_blocks must be positive", node.getdifficultyhealth, 0)
        assert_raises_rpc_error(-8, "target_solve_time_s must be positive", node.getmatmulchallengeprofile, 0)
        assert_raises_rpc_error(-8, "validation_overhead_s must be non-negative", node.getmatmulchallengeprofile, 1, -1)
        assert_raises_rpc_error(-8, "propagation_overhead_s must be non-negative", node.getmatmulchallengeprofile, 1, 0, -1)
        assert_raises_rpc_error(-8, "solver_parallelism must be positive", node.getmatmulchallengeprofile, 1, 0, 0, 0)
        assert_raises_rpc_error(-8, "solver_duty_cycle_pct must be greater than 0 and less than or equal to 100", node.getmatmulchallengeprofile, 1, 0, 0, 1, 0)
        assert_raises_rpc_error(-8, "purpose must be non-empty", node.getmatmulservicechallenge, "", "signup", "user")
        assert_raises_rpc_error(-8, "resource must be non-empty", node.getmatmulservicechallenge, "rate_limit", "", "user")
        assert_raises_rpc_error(-8, "subject must be non-empty", node.getmatmulservicechallenge, "rate_limit", "signup", "")
        assert_raises_rpc_error(-8, "purpose must be at most 256 bytes", node.getmatmulservicechallenge, "p" * 257, "signup", "user")
        assert_raises_rpc_error(-8, "resource must be at most 256 bytes", node.getmatmulservicechallenge, "rate_limit", "r" * 257, "user")
        assert_raises_rpc_error(-8, "subject must be at most 256 bytes", node.getmatmulservicechallenge, "rate_limit", "signup", "s" * 257)
        assert_raises_rpc_error(-8, "target_solve_time_s must be positive", node.getmatmulservicechallenge, "rate_limit", "signup", "user", 0)
        assert_raises_rpc_error(-8, "expires_in_s must be between 1 and 86400", node.getmatmulservicechallenge, "rate_limit", "signup", "user", 1, 0)
        assert_raises_rpc_error(-8, "expires_in_s must be between 1 and 86400", node.getmatmulservicechallenge, "rate_limit", "signup", "user", 1, 86401)
        assert_raises_rpc_error(-8, "validation_overhead_s must be non-negative", node.getmatmulservicechallenge, "rate_limit", "signup", "user", 1, 300, -1)
        assert_raises_rpc_error(-8, "propagation_overhead_s must be non-negative", node.getmatmulservicechallenge, "rate_limit", "signup", "user", 1, 300, 0, -1)
        assert_raises_rpc_error(-8, "unknown difficulty_policy 'nope' (expected fixed or adaptive_window)", node.getmatmulservicechallenge, "rate_limit", "signup", "user", 1, 300, 0, 0, "nope")
        assert_raises_rpc_error(-8, "difficulty_window_blocks must be positive", node.getmatmulservicechallenge, "rate_limit", "signup", "user", 1, 300, 0, 0, "adaptive_window", 0)
        assert_raises_rpc_error(-8, "solver_parallelism must be positive", node.getmatmulservicechallenge, "rate_limit", "signup", "user", 1, 300, 0, 0, "fixed", 24, 0.25, 30, 0)
        assert_raises_rpc_error(-8, "solver_duty_cycle_pct must be greater than 0 and less than or equal to 100", node.getmatmulservicechallenge, "rate_limit", "signup", "user", 1, 300, 0, 0, "fixed", 24, 0.25, 30, 1, 101)
        assert_raises_rpc_error(-8, "unknown difficulty_policy 'nope' (expected fixed or adaptive_window)", node.getmatmulservicechallengeprofile, "balanced", 0, 0, 0.25, 6, 1, "nope")
        assert_raises_rpc_error(-8, "difficulty_window_blocks must be positive", node.getmatmulservicechallengeprofile, "balanced", 0, 0, 0.25, 6, 1, "adaptive_window", 0)
        assert_raises_rpc_error(-8, "solver_parallelism must be positive", node.getmatmulservicechallengeprofile, "balanced", 0, 0, 0.25, 6, 1, "fixed", 24, 0)
        assert_raises_rpc_error(-8, "solver_duty_cycle_pct must be greater than 0 and less than or equal to 100", node.getmatmulservicechallengeprofile, "balanced", 0, 0, 0.25, 6, 1, "fixed", 24, 1, 0)
        assert_raises_rpc_error(-8, "unknown objective_mode 'nope' (expected solves_per_hour, solves_per_day, or mean_seconds_between_solves)", node.getmatmulservicechallengeplan, "nope", 1)
        assert_raises_rpc_error(-8, "objective_value leaves no positive solve budget after validation_overhead_s and propagation_overhead_s", node.getmatmulservicechallengeplan, "mean_seconds_between_solves", 1, 0.75, 0.5)
        assert_raises_rpc_error(-8, "unknown difficulty_policy 'nope' (expected fixed or adaptive_window)", node.listmatmulservicechallengeprofiles, 0, 0, 0.25, 6, 1, "nope")
        assert_raises_rpc_error(-8, "solver_parallelism must be positive", node.listmatmulservicechallengeprofiles, 0, 0, 0.25, 6, 1, "fixed", 24, 0)
        assert_raises_rpc_error(-8, "solver_duty_cycle_pct must be greater than 0 and less than or equal to 100", node.listmatmulservicechallengeprofiles, 0, 0, 0.25, 6, 1, "fixed", 24, 1, 101)
        assert_raises_rpc_error(-8, "unknown service challenge profile", node.issuematmulservicechallengeprofile, "rate_limit", "signup", "user", "not-a-profile")
        assert_raises_rpc_error(-8, "solver_parallelism must be positive", node.issuematmulservicechallengeprofile, "rate_limit", "signup", "user", "balanced", 300, 0, 0, 0.25, 6, 1, "fixed", 24, 0)
        assert_raises_rpc_error(-8, "solver_duty_cycle_pct must be greater than 0 and less than or equal to 100", node.issuematmulservicechallengeprofile, "rate_limit", "signup", "user", "balanced", 300, 0, 0, 0.25, 6, 1, "fixed", 24, 1, 0)
        assert_raises_rpc_error(-8, "max_tries must be positive", node.solvematmulservicechallenge, fresh_service, 0)
        assert_raises_rpc_error(-8, "time_budget_ms must be non-negative", node.solvematmulservicechallenge, fresh_service, 1, -1)
        assert_raises_rpc_error(-8, "solver_threads must be non-negative", node.solvematmulservicechallenge, fresh_service, 1, 0, -1)
        assert_raises_rpc_error(-8, "nonce64_hex must be exactly 16 hex characters", node.verifymatmulserviceproof, fresh_service, "nothex", "00" * 32)
        assert_raises_rpc_error(-8, "digest_hex must be exactly 64 hex characters", node.verifymatmulserviceproof, fresh_service, "0000000000000000", "nothex")
        assert_raises_rpc_error(-8, "challenge.kind must be matmul_service_challenge_v1", node.verifymatmulserviceproof, {"kind": "wrong"}, "0000000000000000", "00" * 32)
        assert_raises_rpc_error(-8, "nonce64_hex must be exactly 16 hex characters", node.redeemmatmulserviceproof, fresh_service, "nothex", "00" * 32)
        assert_raises_rpc_error(-8, "digest_hex must be exactly 64 hex characters", node.redeemmatmulserviceproof, fresh_service, "0000000000000000", "nothex")
        assert_raises_rpc_error(-8, "challenge.kind must be matmul_service_challenge_v1", node.redeemmatmulserviceproof, {"kind": "wrong"}, "0000000000000000", "00" * 32)
        assert_raises_rpc_error(-8, "proofs must contain between 1 and 256 entries", node.verifymatmulserviceproofs, [])
        assert_raises_rpc_error(-8, "proofs must contain between 1 and 256 entries", node.redeemmatmulserviceproofs, [])
        assert_raises_rpc_error(-8, "proofs must contain between 1 and 256 entries", node.verifymatmulserviceproofs, [{}] * 257)
        assert_raises_rpc_error(-8, "proofs[0].challenge.kind must be matmul_service_challenge_v1", node.verifymatmulserviceproofs, [{"challenge": {"kind": "wrong"}, "nonce64_hex": "0000000000000000", "digest_hex": "00" * 32}])
        assert_raises_rpc_error(-8, "proofs[0].nonce64_hex must be exactly 16 hex characters", node.redeemmatmulserviceproofs, [{"challenge": fresh_service, "nonce64_hex": "nothex", "digest_hex": "00" * 32}])


if __name__ == "__main__":
    BTXDifficultyHealthRPCTest(__file__).main()
