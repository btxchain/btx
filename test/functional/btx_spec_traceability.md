# BTX Spec Traceability Manifest

This manifest maps spec `TEST:` IDs to concrete unit/functional checks and readiness scripts.

TEST: benchmark_compression_overhead — `scripts/matmul_pow_benchmark.sh`, `test/benchmark/matmul_phase2_bench.cpp`
TEST: benchmark_host_sha256 — `scripts/matmul_pow_benchmark.sh`
TEST: benchmark_kernel_n512_b16 — `scripts/matmul_pow_benchmark.sh`, `test/benchmark/matmul_phase2_bench.cpp`
TEST: benchmark_option_a_vs_option_b — `scripts/matmul_pow_benchmark.sh`
TEST: benchmark_transfer_overhead — `scripts/matmul_pow_benchmark.sh`

TEST: block_capacity_params_sane_sizes — `src/test/matmul_block_capacity_tests.cpp`
TEST: block_capacity_sigops_validation — `src/test/matmul_block_capacity_tests.cpp`, `test/functional/p2p_segwit.py`
TEST: block_capacity_weight_validation — `src/test/matmul_block_capacity_tests.cpp`, `test/functional/p2p_segwit.py`
TEST: block_serialized_size_over_limit_rejected — `test/functional/feature_block.py`
TEST: block_sigops_over_limit_rejected — `test/functional/p2p_segwit.py`
TEST: block_weight_over_limit_rejected — `test/functional/p2p_segwit.py`
TEST: block_weight_under_limit_accepted — `test/functional/p2p_segwit.py`

TEST: compress_block_different_blocks_differ — `src/test/matmul_transcript_tests.cpp`
TEST: compress_block_matches_manual_dot_product — `src/test/matmul_transcript_tests.cpp`

TEST: consensus_node_validates_all_new_tips — `src/test/matmul_trust_model_tests.cpp`
TEST: consensus_node_with_assumevalid_override — `test/functional/feature_btx_matmul_consensus.py`
TEST: economic_node_accepts_all_headers — `src/test/matmul_trust_model_tests.cpp`
TEST: economic_node_never_runs_phase2 — `src/test/matmul_trust_model_tests.cpp`
TEST: economic_node_window_boundary_steady_state — `src/test/matmul_trust_model_tests.cpp`
TEST: spv_node_validates_headers_only — `src/test/matmul_trust_model_tests.cpp`

TEST: cross_platform_cuda_vs_cpu — `src/test/matmul_noise_tests.cpp`
TEST: cross_platform_cuda_vs_metal — `src/test/matmul_noise_tests.cpp`
TEST: cross_platform_metal_vs_cpu — `src/test/matmul_noise_tests.cpp`, `scripts/m11_metal_mining_validation.sh`
TEST: cross_platform_pinned_test_vector — `src/test/matmul_field_tests.cpp`, `src/test/matmul_noise_tests.cpp`

TEST: dgw_adjusts_after_window — `src/test/matmul_dgw_tests.cpp`
TEST: dgw_first_180_blocks_use_genesis_difficulty — `src/test/matmul_dgw_tests.cpp`
TEST: dgw_genesis_difficulty_not_powlimit — `src/test/matmul_dgw_tests.cpp`
TEST: dgw_hashrate_step_down — `src/test/matmul_dgw_tests.cpp`
TEST: dgw_hashrate_step_up — `src/test/matmul_dgw_tests.cpp`

TEST: field_dot_product_worst_case_exceeds_modulus — `src/test/matmul_field_tests.cpp`
TEST: from_oracle_rejection_boundary — `src/test/matmul_field_tests.cpp`

TEST: gpu_compress_all_max — `src/test/matmul_transcript_tests.cpp`
TEST: gpu_compress_known_vector — `src/test/matmul_transcript_tests.cpp`
TEST: gpu_compress_matches_cpu — `src/test/matmul_transcript_tests.cpp`
TEST: gpu_compress_option_a_matches_option_b — `src/test/matmul_transcript_tests.cpp`
TEST: gpu_madd_matches_cpu — `src/test/matmul_field_tests.cpp`
TEST: gpu_reduce64_double_fold_required — `src/test/matmul_field_tests.cpp`
TEST: gpu_reduce64_matches_cpu — `src/test/matmul_field_tests.cpp`
TEST: gpu_reduce64_max_uint64 — `src/test/matmul_field_tests.cpp`

TEST: header_setNull_clears_all — `src/test/matmul_header_tests.cpp`
TEST: ibd_after_assumevalid_runs_phase2 — `src/test/matmul_trust_model_tests.cpp`
TEST: ibd_with_assumevalid_skips_phase2 — `src/test/matmul_trust_model_tests.cpp`

TEST: kernel_c_prime_output_correct — `src/test/matmul_transcript_tests.cpp`
TEST: kernel_deterministic_across_launches — `src/test/matmul_transcript_tests.cpp`
TEST: kernel_n512_b16_digest_matches_header — `src/test/matmul_header_tests.cpp`
TEST: kernel_n512_b16_matches_cpu — `test/benchmark/matmul_phase2_bench.cpp`
TEST: kernel_n64_b8_matches_cpu — `src/test/matmul_transcript_tests.cpp`
TEST: kernel_small_n8_b4_matches_cpu — `src/test/matmul_transcript_tests.cpp`

TEST: mining_node_implicitly_tier0 — `src/test/validation_chainstatemanager_tests.cpp`
TEST: seed_changes_with_matrix_seed — `src/test/matmul_header_tests.cpp`
TEST: seed_reconstruction_matches — `src/test/matmul_header_tests.cpp`

TEST: stress_concurrent_streams — `scripts/m8_pow_scaling_suite.sh`
TEST: stress_max_dimension — `scripts/m8_pow_scaling_suite.sh`
TEST: stress_repeated_solve — `scripts/m8_pow_scaling_suite.sh`

TEST: tier1_resume_after_long_offline — `src/test/matmul_trust_model_tests.cpp`
TEST: tier_config_flag_sets_behavior — `src/test/validation_chainstatemanager_tests.cpp`

TEST: transcript_compressed_bytes_bounded — `src/test/matmul_transcript_tests.cpp`
TEST: transcript_compressed_hash_deterministic — `src/test/matmul_transcript_tests.cpp`
TEST: transcript_compressed_hash_differs_naive — `src/test/matmul_transcript_tests.cpp`
TEST: transcript_compression_binding — `src/test/matmul_transcript_tests.cpp`
TEST: transcript_domain_separation — `src/test/matmul_transcript_tests.cpp`
TEST: transcript_hasher_takes_sigma — `src/test/matmul_transcript_tests.cpp`

TEST: validation_max_concurrent_verifications — `src/test/matmul_trust_model_tests.cpp`
TEST: validation_window_change_requires_resync — `src/test/matmul_trust_model_tests.cpp`
