// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MATMUL_ACCELERATED_SOLVER_H
#define BTX_MATMUL_ACCELERATED_SOLVER_H

#include <matmul/backend_capabilities.h>
#include <matmul/noise.h>
#include <uint256.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

class CBlockHeader;

namespace btx::cuda {
struct MatMulGeneratedInputsDevice;
}

namespace matmul {

class Matrix;

namespace accelerated {

enum class DigestScheme {
    TRANSCRIPT,
    PRODUCT_COMMITTED,
};

struct DigestResult {
    uint256 digest;
    backend::Kind backend{backend::Kind::CPU};
    bool accelerated{false};
    bool ok{false};
    std::string error;
};

struct PreparedDigestInputs {
    uint256 sigma;
    std::optional<noise::NoisePair> noise;
    std::vector<field::Element> compress_vec;
    std::shared_ptr<const btx::cuda::MatMulGeneratedInputsDevice> cuda_generated_inputs;
};

struct BackendRuntimeStats {
    uint64_t digest_requests{0};
    uint64_t requested_cpu{0};
    uint64_t requested_metal{0};
    uint64_t requested_cuda{0};
    uint64_t requested_unknown{0};
    uint64_t metal_successes{0};
    uint64_t metal_fallbacks_to_cpu{0};
    uint64_t metal_digest_mismatches{0};
    uint64_t metal_retry_without_uploaded_base_attempts{0};
    uint64_t metal_retry_without_uploaded_base_successes{0};
    uint64_t cuda_successes{0};
    uint64_t cuda_fallbacks_to_cpu{0};
    uint64_t gpu_input_generation_attempts{0};
    uint64_t gpu_input_generation_successes{0};
    uint64_t gpu_input_generation_failures{0};
    uint64_t gpu_input_auto_disabled_skips{0};
    bool gpu_input_auto_disabled{false};
    std::string last_metal_fallback_error{};
    std::string last_cuda_fallback_error{};
    std::string last_gpu_input_error{};
};

struct DigestBatchSubmission {
    bool submitted{false};
    backend::Kind backend{backend::Kind::CPU};
    uint32_t batch_size{0};
    std::string error;
    std::shared_ptr<void> opaque;
};

backend::Selection ResolveMiningBackendFromEnvironment();
bool ShouldUseGpuGeneratedInputsForBackend(backend::Kind backend);
bool ShouldUseGpuGeneratedInputsForShape(backend::Kind backend,
                                         uint32_t n,
                                         uint32_t transcript_block_size,
                                         uint32_t noise_rank);
bool ShouldDisableGpuInputAutoModeForError(std::string_view error);
bool ShouldRetryMetalDigestWithoutUploadedBase(std::string_view error);
BackendRuntimeStats ProbeMatMulBackendRuntimeStats();
void ResetMatMulBackendRuntimeStats();

uint256 ComputeMatMulDigestCPU(const CBlockHeader& block,
                               const Matrix& A,
                               const Matrix& B,
                               uint32_t transcript_block_size,
                               uint32_t noise_rank,
                               DigestScheme digest_scheme = DigestScheme::TRANSCRIPT);

/** Compute digest from already-prepared inputs using the CPU canonical path.
 *  This avoids regenerating noise/compress_vec, so the result is guaranteed
 *  to be consistent with whatever inputs were provided. */
uint256 ComputeDigestCpuFromPreparedInputs(const Matrix& A,
                                           const Matrix& B,
                                           const PreparedDigestInputs& prepared,
                                           uint32_t transcript_block_size,
                                           DigestScheme digest_scheme = DigestScheme::TRANSCRIPT);
noise::NoisePair ResolvePreparedNoiseForCpu(const PreparedDigestInputs& prepared,
                                            uint32_t n,
                                            uint32_t noise_rank);

PreparedDigestInputs PrepareMatMulDigestInputs(const CBlockHeader& block,
                                               uint32_t transcript_block_size,
                                               uint32_t noise_rank);

PreparedDigestInputs PrepareMatMulDigestInputsForBackend(const CBlockHeader& block,
                                                         uint32_t transcript_block_size,
                                                         uint32_t noise_rank,
                                                         backend::Kind preferred_backend,
                                                         DigestScheme digest_scheme = DigestScheme::TRANSCRIPT);

DigestResult ComputeMatMulDigestPrepared(const CBlockHeader& block,
                                         const Matrix& A,
                                         const Matrix& B,
                                         uint32_t transcript_block_size,
                                         uint32_t noise_rank,
                                         const PreparedDigestInputs& prepared,
                                         backend::Kind preferred_backend,
                                         DigestScheme digest_scheme = DigestScheme::TRANSCRIPT);

/** Submit a mining-style digest batch without blocking for GPU completion.
 *  The returned submission borrows `blocks`, `A`, `B`, and `prepared_batch`
 *  until `WaitForSubmittedMatMulDigestBatch()` is called.
 */
DigestBatchSubmission SubmitMatMulDigestPreparedBatchForMining(const std::vector<CBlockHeader>& blocks,
                                                              const Matrix& A,
                                                              const Matrix& B,
                                                              uint32_t transcript_block_size,
                                                              uint32_t noise_rank,
                                                              const std::vector<PreparedDigestInputs>& prepared_batch,
                                                              backend::Kind preferred_backend,
                                                              DigestScheme digest_scheme = DigestScheme::TRANSCRIPT);

std::vector<DigestResult> WaitForSubmittedMatMulDigestBatch(DigestBatchSubmission&& submission);

std::vector<DigestResult> ComputeMatMulDigestPreparedBatch(const std::vector<CBlockHeader>& blocks,
                                                           const Matrix& A,
                                                           const Matrix& B,
                                                           uint32_t transcript_block_size,
                                                           uint32_t noise_rank,
                                                           const std::vector<PreparedDigestInputs>& prepared_batch,
                                                           backend::Kind preferred_backend,
                                                           DigestScheme digest_scheme = DigestScheme::TRANSCRIPT);

DigestResult ComputeMatMulDigest(const CBlockHeader& block,
                                 const Matrix& A,
                                 const Matrix& B,
                                 uint32_t transcript_block_size,
                                 uint32_t noise_rank,
                                 backend::Kind preferred_backend,
                                 DigestScheme digest_scheme = DigestScheme::TRANSCRIPT);

} // namespace accelerated
} // namespace matmul

#endif // BTX_MATMUL_ACCELERATED_SOLVER_H
