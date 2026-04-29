// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_ACCEL_H
#define BITCOIN_CUDA_MATMUL_ACCEL_H

#include <cuda/cuda_context.h>
#include <matmul/field.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

namespace btx::cuda {

struct MatMulGeneratedInputsDevice;

enum class MatMulCompressedWordsMode : uint8_t {
    TRANSCRIPT_PREFIXES,
    PRODUCT_FINAL_BLOCKS,
};

struct MatMulAccelerationProbe {
    bool available{false};
    std::string reason;
    std::string device_name;
    uint32_t compute_capability_major{0};
    uint32_t compute_capability_minor{0};
    uint64_t global_memory_bytes{0};
    uint32_t multiprocessor_count{0};
    uint32_t driver_api_version{0};
    uint32_t runtime_version{0};
};

struct MatMulBufferPoolStats {
    bool available{false};
    bool initialized{false};
    uint64_t allocation_events{0};
    uint64_t reuse_events{0};
    uint64_t wait_events{0};
    uint64_t completed_submissions{0};
    uint32_t slot_count{0};
    uint32_t active_slots{0};
    uint32_t high_water_slots{0};
    uint32_t inflight_submissions{0};
    uint32_t peak_inflight_submissions{0};
    uint32_t n{0};
    uint32_t b{0};
    uint32_t r{0};
    std::string reason;
};

struct MatMulDispatchConfig {
    bool available{false};
    uint32_t build_perturbed_threads{0};
    uint32_t finalize_max_threads{0};
    uint32_t finalize_threads_b4{0};
    uint32_t finalize_threads_b8{0};
    uint32_t finalize_threads_b16{0};
    uint32_t max_supported_block_size{0};
    bool nonblocking_streams{false};
    std::string reason;
};

struct MatMulKernelProfile {
    bool available{false};
    bool low_rank_perturbation_kernel{false};
    bool fused_compressed_words_finalize{false};
    bool pinned_host_staging{false};
    bool base_matrix_cache{false};
    bool shared_buffer_pool{false};
    bool nonblocking_streams{false};
    bool device_prepared_inputs_supported{false};
    bool device_prepared_inputs_default{false};
    bool device_prepared_inputs_enabled{false};
    std::string execution_model;
    std::string staging_strategy;
    std::string device_prepared_inputs_policy;
    std::string reason;
};

struct MatMulProfilingStats {
    bool available{false};
    uint64_t samples{0};
    uint32_t last_n{0};
    uint32_t last_b{0};
    uint32_t last_r{0};
    uint32_t last_batch_size{0};
    double last_host_stage_us{0.0};
    double last_submit_h2d_us{0.0};
    double last_submit_d2d_us{0.0};
    double last_stream_wait_event_us{0.0};
    double last_launch_build_perturbed_us{0.0};
    double last_launch_finalize_us{0.0};
    double last_submit_d2h_us{0.0};
    double last_stream_sync_us{0.0};
    double last_total_wall_ms{0.0};
    bool last_used_low_rank_path{false};
    bool last_used_device_prepared_inputs{false};
    bool last_used_pinned_host_staging{false};
    bool last_base_matrix_cache_hit{false};
    std::string last_mode;
    std::string reason;
};

struct MatMulCompressedWordsRequest {
    uint32_t n{0};
    uint32_t b{0};
    const matmul::field::Element* matrix_a_perturbed{nullptr};
    const matmul::field::Element* matrix_b_perturbed{nullptr};
    const matmul::field::Element* compress_vec{nullptr};
};

struct MatMulCompressedWordsResult {
    bool available{false};
    bool success{false};
    std::vector<matmul::field::Element> words;
    std::string error;
};

struct MatMulCompressedWordsBatchRequest {
    uint32_t n{0};
    uint32_t b{0};
    uint32_t batch_size{0};
    const matmul::field::Element* const* matrix_a_perturbed{nullptr};
    const matmul::field::Element* const* matrix_b_perturbed{nullptr};
    const matmul::field::Element* const* compress_vec{nullptr};
};

struct MatMulCompressedWordsBatchResult {
    bool available{false};
    bool success{false};
    uint32_t words_per_request{0};
    std::vector<matmul::field::Element> words;
    std::string error;
};

struct MatMulLowRankCompressedWordsBatchRequest {
    uint32_t n{0};
    uint32_t b{0};
    uint32_t r{0};
    uint32_t batch_size{0};
    const matmul::field::Element* matrix_a{nullptr};
    const matmul::field::Element* matrix_b{nullptr};
    const uint256* matrix_a_cache_key{nullptr};
    const uint256* matrix_b_cache_key{nullptr};
    const matmul::field::Element* const* noise_e_l{nullptr};
    const matmul::field::Element* const* noise_e_r{nullptr};
    const matmul::field::Element* const* noise_f_l{nullptr};
    const matmul::field::Element* const* noise_f_r{nullptr};
    const matmul::field::Element* const* compress_vec{nullptr};
};

struct MatMulLowRankCompressedWordsDeviceBatchRequest {
    uint32_t n{0};
    uint32_t b{0};
    uint32_t r{0};
    uint32_t batch_size{0};
    const matmul::field::Element* matrix_a{nullptr};
    const matmul::field::Element* matrix_b{nullptr};
    const uint256* matrix_a_cache_key{nullptr};
    const uint256* matrix_b_cache_key{nullptr};
    const MatMulGeneratedInputsDevice* const* generated_inputs{nullptr};
};

MatMulAccelerationProbe ProbeMatMulDigestAcceleration();
MatMulBufferPoolStats ProbeMatMulBufferPool();
MatMulDispatchConfig ProbeMatMulDispatchConfig();
MatMulKernelProfile ProbeMatMulKernelProfile();
MatMulProfilingStats ProbeMatMulProfilingStats();
MatMulCompressedWordsResult ComputeCompressedWords(const MatMulCompressedWordsRequest& request,
                                                  MatMulCompressedWordsMode mode);
MatMulCompressedWordsBatchResult ComputeCompressedWordsBatch(const MatMulCompressedWordsBatchRequest& request,
                                                            MatMulCompressedWordsMode mode);
MatMulCompressedWordsBatchResult ComputeCompressedWordsLowRankBatch(
    const MatMulLowRankCompressedWordsBatchRequest& request,
    MatMulCompressedWordsMode mode);
MatMulCompressedWordsBatchResult ComputeCompressedWordsLowRankDeviceBatch(
    const MatMulLowRankCompressedWordsDeviceBatchRequest& request,
    MatMulCompressedWordsMode mode);

} // namespace btx::cuda

#endif // BITCOIN_CUDA_MATMUL_ACCEL_H
