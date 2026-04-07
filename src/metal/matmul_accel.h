// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_METAL_MATMUL_ACCEL_H
#define BITCOIN_METAL_MATMUL_ACCEL_H

#include <matmul/field.h>
#include <uint256.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace btx::metal {

struct MatMulAccelerationProbe {
    bool available{false};
    std::string reason;
};

struct MatMulBaseMatricesRequest {
    uint32_t n{0};
    const matmul::field::Element* matrix_a{nullptr};
    const matmul::field::Element* matrix_b{nullptr};
};

struct MatMulBaseMatricesResult {
    bool available{false};
    bool success{false};
    std::string error;
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
    uint32_t build_prefix_threads{0};
    uint32_t compress_prefix_threads{0};
    std::string reason;
};

struct MatMulKernelProfile {
    bool available{false};
    bool tiled_build_prefix{false};
    bool fused_prefix_compress{false};
    bool gpu_transcript_hash{false};
    bool function_constant_specialization{false};
    bool cooperative_tensor_prepared{false};
    bool cooperative_tensor_active{false};
    bool uses_prefix_buffer{true};
    uint32_t specialized_shape_count{0};
    uint32_t build_prefix_threadgroup_width{0};
    uint32_t build_prefix_threadgroup_height{0};
    uint32_t fused_prefix_threadgroup_threads{0};
    std::string specialization_reason;
    std::string cooperative_tensor_reason;
    std::string library_source;
    std::string reason;
};

struct MatMulProfilingStats {
    bool available{false};
    bool capture_supported{false};
    uint64_t samples{0};
    double last_encode_build_perturbed_us{0.0};
    double last_encode_fused_prefix_compress_us{0.0};
    double last_encode_transcript_sha256_us{0.0};
    double last_submit_wait_us{0.0};
    double last_gpu_execution_ms{0.0};
    double last_cpu_finalize_us{0.0};
    bool last_zero_copy_inputs{false};
    bool last_async_submission{false};
    std::string reason;
};

enum class MatMulDigestMode : uint8_t {
    TRANSCRIPT,
    PRODUCT_COMMITTED,
};

struct MatMulDigestRequest {
    uint32_t n{0};
    uint32_t b{0};
    uint32_t r{0};
    MatMulDigestMode digest_mode{MatMulDigestMode::TRANSCRIPT};
    uint256 sigma;

    const matmul::field::Element* matrix_a{nullptr};
    const matmul::field::Element* matrix_b{nullptr};
    bool use_uploaded_base_matrices{false};

    const matmul::field::Element* noise_e_l{nullptr};
    const matmul::field::Element* noise_e_r{nullptr};
    const matmul::field::Element* noise_f_l{nullptr};
    const matmul::field::Element* noise_f_r{nullptr};

    const matmul::field::Element* compress_vec{nullptr};
};

struct MatMulDigestResult {
    bool available{false};
    bool success{false};
    uint256 digest;
    std::string error;
};

struct MatMulDigestSubmission {
    bool available{false};
    bool submitted{false};
    std::string error;
    std::shared_ptr<void> opaque;
};

struct MatMulDigestBatchRequest {
    uint32_t n{0};
    uint32_t b{0};
    uint32_t r{0};
    uint32_t batch_size{0};
    MatMulDigestMode digest_mode{MatMulDigestMode::TRANSCRIPT};
    const uint256* sigmas{nullptr};

    const matmul::field::Element* matrix_a{nullptr};
    const matmul::field::Element* matrix_b{nullptr};
    bool use_uploaded_base_matrices{false};

    const matmul::field::Element* const* noise_e_l{nullptr};
    const matmul::field::Element* const* noise_e_r{nullptr};
    const matmul::field::Element* const* noise_f_l{nullptr};
    const matmul::field::Element* const* noise_f_r{nullptr};

    const matmul::field::Element* const* compress_vec{nullptr};
};

struct MatMulDigestBatchResult {
    bool available{false};
    bool success{false};
    std::vector<uint256> digests;
    std::string error;
};

struct MatMulDigestBatchSubmission {
    bool available{false};
    bool submitted{false};
    std::string error;
    std::shared_ptr<void> opaque;
};

MatMulAccelerationProbe ProbeMatMulDigestAcceleration();
MatMulBaseMatricesResult UploadBaseMatrices(const MatMulBaseMatricesRequest& request);
MatMulBufferPoolStats ProbeMatMulBufferPool();
MatMulDispatchConfig ProbeMatMulDispatchConfig();
MatMulKernelProfile ProbeMatMulKernelProfile();
MatMulProfilingStats ProbeMatMulProfilingStats();
bool ShouldUseFunctionConstantSpecializationPolicy(uint32_t n, bool use_legacy_pipeline);
MatMulDigestSubmission SubmitCanonicalTranscriptDigest(const MatMulDigestRequest& request);
bool IsCanonicalTranscriptDigestSubmissionReady(const MatMulDigestSubmission& submission);
MatMulDigestResult WaitForCanonicalTranscriptDigestSubmission(MatMulDigestSubmission&& submission);
MatMulDigestResult ComputeCanonicalTranscriptDigest(const MatMulDigestRequest& request);
MatMulDigestBatchSubmission SubmitCanonicalTranscriptDigestBatch(const MatMulDigestBatchRequest& request);
bool IsCanonicalTranscriptDigestBatchSubmissionReady(const MatMulDigestBatchSubmission& submission);
MatMulDigestBatchResult WaitForCanonicalTranscriptDigestBatchSubmission(MatMulDigestBatchSubmission&& submission);
MatMulDigestBatchResult ComputeCanonicalTranscriptDigestBatch(const MatMulDigestBatchRequest& request);

} // namespace btx::metal

#endif // BITCOIN_METAL_MATMUL_ACCEL_H
