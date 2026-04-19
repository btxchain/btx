// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/accelerated_solver.h>

#include <cuda/matmul_accel.h>
#include <cuda/oracle_accel.h>
#include <matmul/matmul_pow.h>
#include <matmul/noise.h>
#include <matmul/transcript.h>
#include <metal/matmul_accel.h>
#include <metal/oracle_accel.h>
#include <primitives/block.h>
#include <logging.h>

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace matmul::accelerated {
namespace {

uint256 ComputeDigestCpuFromPrepared(const Matrix& A,
                                     const Matrix& B,
                                     const noise::NoisePair& np,
                                     uint32_t transcript_block_size,
                                     const uint256& sigma,
                                     DigestScheme digest_scheme)
{
    const auto A_prime = A + (np.E_L * np.E_R);
    const auto B_prime = B + (np.F_L * np.F_R);
    if (digest_scheme == DigestScheme::PRODUCT_COMMITTED) {
        return transcript::ComputeProductCommittedDigestFromPerturbed(
            A_prime,
            B_prime,
            transcript_block_size,
            sigma);
    }
    const auto result = transcript::CanonicalMatMul(
        A_prime,
        B_prime,
        transcript_block_size,
        sigma);
    return result.transcript_hash;
}

btx::metal::MatMulDigestMode ToMetalDigestMode(DigestScheme digest_scheme)
{
    return digest_scheme == DigestScheme::PRODUCT_COMMITTED
        ? btx::metal::MatMulDigestMode::PRODUCT_COMMITTED
        : btx::metal::MatMulDigestMode::TRANSCRIPT;
}

btx::cuda::MatMulCompressedWordsMode ToCudaCompressedWordsMode(DigestScheme digest_scheme)
{
    return digest_scheme == DigestScheme::PRODUCT_COMMITTED
        ? btx::cuda::MatMulCompressedWordsMode::PRODUCT_FINAL_BLOCKS
        : btx::cuda::MatMulCompressedWordsMode::TRANSCRIPT_PREFIXES;
}

std::string DefaultBackendRequest()
{
#if defined(__APPLE__)
    return "metal";
#else
    return "cpu";
#endif
}

void LogBackendFallbackOnce(std::atomic_bool& once_flag, const char* backend, const std::string& reason)
{
    bool expected{false};
    if (once_flag.compare_exchange_strong(expected, true)) {
        LogPrintf("MATMUL WARNING: %s backend fallback to CPU (%s)\n", backend, reason);
    }
}

std::atomic_bool g_logged_cuda_fallback{false};
std::atomic_bool g_logged_metal_fallback{false};
std::atomic_bool g_logged_metal_gpu_input_generation_fallback{false};
std::atomic_bool g_logged_cuda_gpu_input_generation_fallback{false};
// g_logged_gpu_input_generation_auto_mode removed: AUTO mode no longer
// enables GPU input generation (see ShouldUseGpuGeneratedInputsForShape).
#if defined(DEBUG)
std::atomic_bool g_logged_metal_mismatch{false};
#endif
std::atomic_bool g_logged_unknown_backend{false};

std::atomic<uint64_t> g_digest_requests{0};
std::atomic<uint64_t> g_requested_cpu{0};
std::atomic<uint64_t> g_requested_metal{0};
std::atomic<uint64_t> g_requested_cuda{0};
std::atomic<uint64_t> g_requested_unknown{0};
std::atomic<uint64_t> g_metal_successes{0};
std::atomic<uint64_t> g_metal_fallbacks_to_cpu{0};
std::atomic<uint64_t> g_metal_digest_mismatches{0};
std::atomic<uint64_t> g_metal_retry_without_uploaded_base_attempts{0};
std::atomic<uint64_t> g_metal_retry_without_uploaded_base_successes{0};
std::atomic<uint64_t> g_cuda_successes{0};
std::atomic<uint64_t> g_cuda_fallbacks_to_cpu{0};
std::atomic<uint64_t> g_gpu_input_generation_attempts{0};
std::atomic<uint64_t> g_gpu_input_generation_successes{0};
std::atomic<uint64_t> g_gpu_input_generation_failures{0};
std::atomic<uint64_t> g_gpu_input_auto_disabled_skips{0};
std::atomic_bool g_gpu_input_auto_disabled{false};
std::mutex g_backend_runtime_stats_mutex;
std::string g_last_metal_fallback_error;
std::string g_last_cuda_fallback_error;
std::string g_last_gpu_input_error;

struct DigestBatchSubmissionState {
    const std::vector<CBlockHeader>* blocks{nullptr};
    const Matrix* matrix_a{nullptr};
    const Matrix* matrix_b{nullptr};
    uint32_t transcript_block_size{0};
    uint32_t noise_rank{0};
    DigestScheme digest_scheme{DigestScheme::TRANSCRIPT};
    const std::vector<PreparedDigestInputs>* prepared_batch{nullptr};
    backend::Kind preferred_backend{backend::Kind::CPU};
    struct MetalSubmissionSlice {
        size_t start_index{0};
        size_t count{0};
        std::optional<btx::metal::MatMulDigestSubmission> single_submission;
        std::optional<btx::metal::MatMulDigestBatchSubmission> batch_submission;
    };
    std::vector<MetalSubmissionSlice> metal_submissions;
    std::future<std::vector<DigestResult>> cuda_batch_future;
    std::vector<DigestResult> immediate_results;
};

enum class GpuInputGenerationPolicy {
    FORCED_OFF,
    FORCED_ON,
    AUTO,
};

GpuInputGenerationPolicy ResolveGpuInputGenerationPolicy()
{
    const char* env = std::getenv("BTX_MATMUL_GPU_INPUTS");
    if (env == nullptr || env[0] == '\0') {
        return GpuInputGenerationPolicy::AUTO;
    }
    if (env[0] == '0') {
        return GpuInputGenerationPolicy::FORCED_OFF;
    }
    return GpuInputGenerationPolicy::FORCED_ON;
}

Matrix MatrixFromRowMajorWords(uint32_t rows,
                               uint32_t cols,
                               const std::vector<field::Element>& words)
{
    Matrix out(rows, cols);
    const size_t expected = static_cast<size_t>(rows) * cols;
    if (words.size() != expected) {
        LogPrintf("MATMUL WARNING: MatrixFromRowMajorWords size mismatch: expected %zu, got %zu (rows=%u, cols=%u); returning zero matrix\n",
                  expected, words.size(), rows, cols);
        return out;
    }
    std::memcpy(out.data(), words.data(), expected * sizeof(field::Element));
    return out;
}

bool PreparedInputsMatchShape(const PreparedDigestInputs& prepared,
                              uint32_t n,
                              uint32_t transcript_block_size,
                              uint32_t noise_rank)
{
    const size_t expected_compress_words = static_cast<size_t>(transcript_block_size) * transcript_block_size;
    const bool host_noise_matches = prepared.noise.has_value() &&
        prepared.noise->E_L.rows() == n &&
        prepared.noise->E_L.cols() == noise_rank &&
        prepared.noise->E_R.rows() == noise_rank &&
        prepared.noise->E_R.cols() == n &&
        prepared.noise->F_L.rows() == n &&
        prepared.noise->F_L.cols() == noise_rank &&
        prepared.noise->F_R.rows() == noise_rank &&
        prepared.noise->F_R.cols() == n;
    const bool cuda_inputs_match = prepared.cuda_generated_inputs != nullptr &&
        prepared.cuda_generated_inputs->n == n &&
        prepared.cuda_generated_inputs->b == transcript_block_size &&
        prepared.cuda_generated_inputs->r == noise_rank;
    const bool host_compress_matches = prepared.compress_vec.size() == expected_compress_words;
    const bool cuda_compress_matches = prepared.compress_vec.empty() || host_compress_matches;
    return (host_noise_matches && host_compress_matches) ||
        (cuda_inputs_match && cuda_compress_matches);
}

bool PreparedInputsHaveHostNoise(const PreparedDigestInputs& prepared,
                                 uint32_t n,
                                 uint32_t noise_rank)
{
    return prepared.noise.has_value() &&
        prepared.noise->E_L.rows() == n &&
        prepared.noise->E_L.cols() == noise_rank &&
        prepared.noise->E_R.rows() == noise_rank &&
        prepared.noise->E_R.cols() == n &&
        prepared.noise->F_L.rows() == n &&
        prepared.noise->F_L.cols() == noise_rank &&
        prepared.noise->F_R.rows() == noise_rank &&
        prepared.noise->F_R.cols() == n;
}

std::atomic_bool& GpuInputFallbackLogFlag(backend::Kind backend_kind)
{
    if (backend_kind == backend::Kind::CUDA) {
        return g_logged_cuda_gpu_input_generation_fallback;
    }
    return g_logged_metal_gpu_input_generation_fallback;
}

const char* GpuInputFallbackLabel(backend::Kind backend_kind)
{
    if (backend_kind == backend::Kind::CUDA) {
        return "CUDA-GPU-INPUTS";
    }
    return "METAL-GPU-INPUTS";
}

bool ShouldAutoUseCudaGpuGeneratedInputs(uint32_t n,
                                         uint32_t transcript_block_size,
                                         uint32_t noise_rank)
{
    return (n >= 512 && transcript_block_size >= 16 && noise_rank >= 8) ||
        (n >= 256 && transcript_block_size >= 8 && noise_rank >= 4);
}

bool ShouldUseCudaDevicePreparedInputsFastPath()
{
    const char* policy_env = std::getenv("BTX_MATMUL_CUDA_DEVICE_PREPARED_INPUTS");
    return policy_env != nullptr && policy_env[0] != '\0' && policy_env[0] != '0';
}

void SetLastMetalFallbackError(const std::string& error)
{
    std::lock_guard<std::mutex> lock(g_backend_runtime_stats_mutex);
    g_last_metal_fallback_error = error;
}

void SetLastCudaFallbackError(const std::string& error)
{
    std::lock_guard<std::mutex> lock(g_backend_runtime_stats_mutex);
    g_last_cuda_fallback_error = error;
}

void SetLastGpuInputError(const std::string& error)
{
    std::lock_guard<std::mutex> lock(g_backend_runtime_stats_mutex);
    g_last_gpu_input_error = error;
}

void RecordMetalFallback(const std::string& error, uint64_t count = 1)
{
    g_metal_fallbacks_to_cpu.fetch_add(count, std::memory_order_relaxed);
    SetLastMetalFallbackError(error);
}

void RecordCudaFallback(const std::string& error, uint64_t count = 1)
{
    g_cuda_fallbacks_to_cpu.fetch_add(count, std::memory_order_relaxed);
    SetLastCudaFallbackError(error);
}

std::vector<DigestResult> ComputeCudaDigestBatchFallbackResults(const std::vector<CBlockHeader>& blocks,
                                                                const Matrix& A,
                                                                const Matrix& B,
                                                                uint32_t transcript_block_size,
                                                                const std::vector<PreparedDigestInputs>& prepared_batch,
                                                                DigestScheme digest_scheme,
                                                                std::string error,
                                                                std::string_view error_prefix)
{
    if (!error.empty()) {
        LogBackendFallbackOnce(g_logged_cuda_fallback, "CUDA", error);
        RecordCudaFallback(error, blocks.size());
    }

    std::vector<DigestResult> results;
    results.reserve(blocks.size());
    for (size_t i = 0; i < blocks.size(); ++i) {
        DigestResult result;
        result.digest = ComputeDigestCpuFromPreparedInputs(
            A,
            B,
            prepared_batch[i],
            transcript_block_size,
            digest_scheme);
        result.backend = backend::Kind::CPU;
        result.accelerated = false;
        result.ok = true;
        result.error = std::string(error_prefix) + error;
        results.push_back(std::move(result));
    }
    return results;
}

std::vector<DigestResult> ComputeCudaDigestsPreparedBatch(const std::vector<CBlockHeader>& blocks,
                                                          const Matrix& A,
                                                          const Matrix& B,
                                                          uint32_t transcript_block_size,
                                                          uint32_t noise_rank,
                                                          const std::vector<PreparedDigestInputs>& prepared_batch,
                                                          DigestScheme digest_scheme)
{
    if (blocks.empty()) {
        return {};
    }

    const auto capability = backend::CapabilityFor(backend::Kind::CUDA);
    if (!capability.available) {
        return ComputeCudaDigestBatchFallbackResults(
            blocks,
            A,
            B,
            transcript_block_size,
            prepared_batch,
            digest_scheme,
            capability.reason,
            "cuda_batch_backend_fallback_to_cpu:");
    }

    try {
        bool all_cuda_generated{true};
        bool all_host_noise{true};
        for (const auto& prepared : prepared_batch) {
            if (!PreparedInputsMatchShape(
                    prepared,
                    blocks.front().matmul_dim,
                    transcript_block_size,
                    noise_rank)) {
                return ComputeCudaDigestBatchFallbackResults(
                    blocks,
                    A,
                    B,
                    transcript_block_size,
                    prepared_batch,
                    digest_scheme,
                    "cuda_prepared_inputs_shape_mismatch",
                    "cuda_batch_backend_fallback_to_cpu:");
            }
            all_cuda_generated &= prepared.cuda_generated_inputs != nullptr;
            all_host_noise &= prepared.noise.has_value();
        }

        btx::cuda::MatMulCompressedWordsBatchResult cuda_result;
        if (all_cuda_generated) {
            std::vector<const btx::cuda::MatMulGeneratedInputsDevice*> generated_inputs;
            generated_inputs.reserve(prepared_batch.size());
            for (const auto& prepared : prepared_batch) {
                generated_inputs.push_back(prepared.cuda_generated_inputs.get());
            }
            cuda_result = btx::cuda::ComputeCompressedWordsLowRankDeviceBatch(
                {
                    .n = blocks.front().matmul_dim,
                    .b = transcript_block_size,
                    .r = noise_rank,
                    .batch_size = static_cast<uint32_t>(prepared_batch.size()),
                    .matrix_a = A.data(),
                    .matrix_b = B.data(),
                    .generated_inputs = generated_inputs.data(),
                },
                ToCudaCompressedWordsMode(digest_scheme));
        } else if (all_host_noise) {
            std::vector<const field::Element*> noise_e_l_ptrs;
            std::vector<const field::Element*> noise_e_r_ptrs;
            std::vector<const field::Element*> noise_f_l_ptrs;
            std::vector<const field::Element*> noise_f_r_ptrs;
            std::vector<const field::Element*> compress_ptrs;
            noise_e_l_ptrs.reserve(prepared_batch.size());
            noise_e_r_ptrs.reserve(prepared_batch.size());
            noise_f_l_ptrs.reserve(prepared_batch.size());
            noise_f_r_ptrs.reserve(prepared_batch.size());
            compress_ptrs.reserve(prepared_batch.size());
            for (const auto& prepared : prepared_batch) {
                noise_e_l_ptrs.push_back(prepared.noise->E_L.data());
                noise_e_r_ptrs.push_back(prepared.noise->E_R.data());
                noise_f_l_ptrs.push_back(prepared.noise->F_L.data());
                noise_f_r_ptrs.push_back(prepared.noise->F_R.data());
                compress_ptrs.push_back(prepared.compress_vec.data());
            }

            cuda_result = btx::cuda::ComputeCompressedWordsLowRankBatch(
                {
                    .n = blocks.front().matmul_dim,
                    .b = transcript_block_size,
                    .r = noise_rank,
                    .batch_size = static_cast<uint32_t>(prepared_batch.size()),
                    .matrix_a = A.data(),
                    .matrix_b = B.data(),
                    .noise_e_l = noise_e_l_ptrs.data(),
                    .noise_e_r = noise_e_r_ptrs.data(),
                    .noise_f_l = noise_f_l_ptrs.data(),
                    .noise_f_r = noise_f_r_ptrs.data(),
                    .compress_vec = compress_ptrs.data(),
                },
                ToCudaCompressedWordsMode(digest_scheme));
        } else {
            return ComputeCudaDigestBatchFallbackResults(
                blocks,
                A,
                B,
                transcript_block_size,
                prepared_batch,
                digest_scheme,
                "cuda_prepared_inputs_representation_mismatch",
                "cuda_batch_backend_fallback_to_cpu:");
        }

        if (!cuda_result.success) {
            const std::string cuda_error = cuda_result.error.empty() ? "cuda_batch_digest_failed" : cuda_result.error;
            return ComputeCudaDigestBatchFallbackResults(
                blocks,
                A,
                B,
                transcript_block_size,
                prepared_batch,
                digest_scheme,
                cuda_error,
                "cuda_batch_backend_fallback_to_cpu:");
        }

        const uint32_t expected_words_per_request =
            digest_scheme == DigestScheme::PRODUCT_COMMITTED
                ? (blocks.front().matmul_dim / transcript_block_size) * (blocks.front().matmul_dim / transcript_block_size)
                : (blocks.front().matmul_dim / transcript_block_size) * (blocks.front().matmul_dim / transcript_block_size) *
                    (blocks.front().matmul_dim / transcript_block_size);
        if (cuda_result.words_per_request != expected_words_per_request ||
            cuda_result.words.size() != static_cast<size_t>(prepared_batch.size()) * expected_words_per_request) {
            return ComputeCudaDigestBatchFallbackResults(
                blocks,
                A,
                B,
                transcript_block_size,
                prepared_batch,
                digest_scheme,
                "cuda_batch_digest_size_mismatch",
                "cuda_batch_backend_fallback_to_cpu:");
        }

        std::vector<DigestResult> results;
        results.reserve(prepared_batch.size());
        for (size_t i = 0; i < prepared_batch.size(); ++i) {
            const auto words = Span<const field::Element>{
                cuda_result.words.data() + i * expected_words_per_request,
                expected_words_per_request,
            };
            DigestResult result;
            result.digest = digest_scheme == DigestScheme::PRODUCT_COMMITTED
                ? transcript::ComputeProductCommittedDigestFromWords(
                      words,
                      prepared_batch[i].sigma,
                      blocks[i].matmul_dim,
                      transcript_block_size)
                : transcript::FinalizeTranscriptDigestFromWords(words);
            result.backend = backend::Kind::CUDA;
            result.accelerated = true;
            result.ok = true;
            results.push_back(std::move(result));
        }
        g_cuda_successes.fetch_add(results.size(), std::memory_order_relaxed);
        return results;
    } catch (const std::exception& e) {
        return ComputeCudaDigestBatchFallbackResults(
            blocks,
            A,
            B,
            transcript_block_size,
            prepared_batch,
            digest_scheme,
            std::string("cuda_batch_backend_exception:") + e.what(),
            "cuda_batch_backend_fallback_to_cpu:");
    } catch (...) {
        return ComputeCudaDigestBatchFallbackResults(
            blocks,
            A,
            B,
            transcript_block_size,
            prepared_batch,
            digest_scheme,
            "cuda_batch_backend_unknown_exception",
            "cuda_batch_backend_fallback_to_cpu:");
    }
}

void DisableGpuInputAutoMode(const std::string& reason)
{
    bool expected{false};
    if (g_gpu_input_auto_disabled.compare_exchange_strong(expected, true, std::memory_order_relaxed)) {
        LogPrintf("MATMUL WARNING: disabling BTX_MATMUL_GPU_INPUTS auto mode after failure (%s)\n", reason);
    }
}

uint32_t ResolveMetalDigestSliceSize(uint32_t batch_size)
{
    if (batch_size <= 1) {
        return 1;
    }

    const char* env = std::getenv("BTX_MATMUL_DIGEST_SLICE_SIZE");
    if (env != nullptr && env[0] != '\0') {
        int32_t parsed{0};
        if (ParseInt32(env, &parsed) && parsed > 0) {
            return std::min<uint32_t>(static_cast<uint32_t>(parsed), batch_size);
        }
        return 1;
    }

    if (batch_size <= 2) {
        return 1;
    }
    return 2;
}

} // namespace

backend::Selection ResolveMiningBackendFromEnvironment()
{
    const char* const env_backend = std::getenv("BTX_MATMUL_BACKEND");
    const std::string requested = (env_backend != nullptr && env_backend[0] != '\0')
        ? std::string{env_backend}
        : DefaultBackendRequest();
    return backend::ResolveRequestedBackend(requested);
}

bool ShouldUseGpuGeneratedInputsForBackend(backend::Kind backend_kind)
{
    return ShouldUseGpuGeneratedInputsForShape(backend_kind, 0, 0, 0);
}

bool ShouldUseGpuGeneratedInputsForShape(backend::Kind backend_kind,
                                         uint32_t n,
                                         uint32_t transcript_block_size,
                                         uint32_t noise_rank)
{
    if (backend_kind != backend::Kind::METAL &&
        backend_kind != backend::Kind::CUDA) {
        return false;
    }

    const auto policy = ResolveGpuInputGenerationPolicy();
    if (policy == GpuInputGenerationPolicy::FORCED_OFF) {
        return false;
    }
    if (policy == GpuInputGenerationPolicy::FORCED_ON) {
        return true;
    }

    if (g_gpu_input_auto_disabled.load(std::memory_order_relaxed)) {
        g_gpu_input_auto_disabled_skips.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    if (backend_kind == backend::Kind::CUDA) {
        return ShouldAutoUseCudaGpuGeneratedInputs(n, transcript_block_size, noise_rank);
    }

#if defined(__APPLE__)
    // AUTO mode defaults to OFF. The GPU oracle path is deterministic and is
    // covered by unit tests, but local mining benchmarks still show it losing
    // to CPU input generation for mainnet-like shapes on this machine because
    // the extra Metal dispatches cost more than the CPU oracle work they
    // replace. Keep it available behind BTX_MATMUL_GPU_INPUTS for explicit
    // experimentation, but do not spend mining throughput on it by default.
    (void)n;
    (void)transcript_block_size;
    (void)noise_rank;
    return false;
#else
    return false;
#endif
}

bool ShouldDisableGpuInputAutoModeForError(std::string_view error)
{
    if (error.empty()) return false;

    return error.find("invalid dimensions for GPU input generation") != std::string_view::npos ||
        error.find("noise rank exceeds matrix dimension") != std::string_view::npos ||
        error.find("matrix dimension must be divisible by transcript block size") != std::string_view::npos ||
        error.find("input generation dimensions exceed supported bounds") != std::string_view::npos ||
        error.find("Metal context initialization failed") != std::string_view::npos ||
        error.find("cuda_runtime_unavailable:") != std::string_view::npos ||
        error.find("cudaSetDevice failed:") != std::string_view::npos ||
        error.find("device_compute_capability_too_old:") != std::string_view::npos ||
        error.find("no_supported_device") != std::string_view::npos;
}

bool ShouldRetryMetalDigestWithoutUploadedBase(std::string_view error)
{
    if (error.empty()) return false;
    return error.find("uploaded base matrices are unavailable or stale for requested dimension") != std::string_view::npos;
}

BackendRuntimeStats ProbeMatMulBackendRuntimeStats()
{
    BackendRuntimeStats stats;
    stats.digest_requests = g_digest_requests.load(std::memory_order_relaxed);
    stats.requested_cpu = g_requested_cpu.load(std::memory_order_relaxed);
    stats.requested_metal = g_requested_metal.load(std::memory_order_relaxed);
    stats.requested_cuda = g_requested_cuda.load(std::memory_order_relaxed);
    stats.requested_unknown = g_requested_unknown.load(std::memory_order_relaxed);
    stats.metal_successes = g_metal_successes.load(std::memory_order_relaxed);
    stats.metal_fallbacks_to_cpu = g_metal_fallbacks_to_cpu.load(std::memory_order_relaxed);
    stats.metal_digest_mismatches = g_metal_digest_mismatches.load(std::memory_order_relaxed);
    stats.metal_retry_without_uploaded_base_attempts = g_metal_retry_without_uploaded_base_attempts.load(std::memory_order_relaxed);
    stats.metal_retry_without_uploaded_base_successes = g_metal_retry_without_uploaded_base_successes.load(std::memory_order_relaxed);
    stats.cuda_successes = g_cuda_successes.load(std::memory_order_relaxed);
    stats.cuda_fallbacks_to_cpu = g_cuda_fallbacks_to_cpu.load(std::memory_order_relaxed);
    stats.gpu_input_generation_attempts = g_gpu_input_generation_attempts.load(std::memory_order_relaxed);
    stats.gpu_input_generation_successes = g_gpu_input_generation_successes.load(std::memory_order_relaxed);
    stats.gpu_input_generation_failures = g_gpu_input_generation_failures.load(std::memory_order_relaxed);
    stats.gpu_input_auto_disabled_skips = g_gpu_input_auto_disabled_skips.load(std::memory_order_relaxed);
    stats.gpu_input_auto_disabled = g_gpu_input_auto_disabled.load(std::memory_order_relaxed);

    std::lock_guard<std::mutex> lock(g_backend_runtime_stats_mutex);
    stats.last_metal_fallback_error = g_last_metal_fallback_error;
    stats.last_cuda_fallback_error = g_last_cuda_fallback_error;
    stats.last_gpu_input_error = g_last_gpu_input_error;
    return stats;
}

void ResetMatMulBackendRuntimeStats()
{
    g_digest_requests.store(0, std::memory_order_relaxed);
    g_requested_cpu.store(0, std::memory_order_relaxed);
    g_requested_metal.store(0, std::memory_order_relaxed);
    g_requested_cuda.store(0, std::memory_order_relaxed);
    g_requested_unknown.store(0, std::memory_order_relaxed);
    g_metal_successes.store(0, std::memory_order_relaxed);
    g_metal_fallbacks_to_cpu.store(0, std::memory_order_relaxed);
    g_metal_digest_mismatches.store(0, std::memory_order_relaxed);
    g_metal_retry_without_uploaded_base_attempts.store(0, std::memory_order_relaxed);
    g_metal_retry_without_uploaded_base_successes.store(0, std::memory_order_relaxed);
    g_cuda_successes.store(0, std::memory_order_relaxed);
    g_cuda_fallbacks_to_cpu.store(0, std::memory_order_relaxed);
    g_gpu_input_generation_attempts.store(0, std::memory_order_relaxed);
    g_gpu_input_generation_successes.store(0, std::memory_order_relaxed);
    g_gpu_input_generation_failures.store(0, std::memory_order_relaxed);
    g_gpu_input_auto_disabled_skips.store(0, std::memory_order_relaxed);
    g_gpu_input_auto_disabled.store(false, std::memory_order_relaxed);

    std::lock_guard<std::mutex> lock(g_backend_runtime_stats_mutex);
    g_last_metal_fallback_error.clear();
    g_last_cuda_fallback_error.clear();
    g_last_gpu_input_error.clear();
}

uint256 ComputeMatMulDigestCPU(const CBlockHeader& block,
                               const Matrix& A,
                               const Matrix& B,
                               uint32_t transcript_block_size,
                               uint32_t noise_rank,
                               DigestScheme digest_scheme)
{
    const auto prepared = PrepareMatMulDigestInputs(block, transcript_block_size, noise_rank);
    return ComputeDigestCpuFromPreparedInputs(
        A,
        B,
        prepared,
        transcript_block_size,
        digest_scheme);
}

uint256 ComputeDigestCpuFromPreparedInputs(const Matrix& A,
                                           const Matrix& B,
                                           const PreparedDigestInputs& prepared,
                                           uint32_t transcript_block_size,
                                           DigestScheme digest_scheme)
{
    if (prepared.noise.has_value()) {
        return ComputeDigestCpuFromPrepared(
            A,
            B,
            *prepared.noise,
            transcript_block_size,
            prepared.sigma,
            digest_scheme);
    }

    const uint32_t n = A.rows();
    const uint32_t noise_rank = prepared.cuda_generated_inputs != nullptr
        ? prepared.cuda_generated_inputs->r
        : 0;
    const auto regenerated = ResolvePreparedNoiseForCpu(prepared, n, noise_rank);
    return ComputeDigestCpuFromPrepared(
        A,
        B,
        regenerated,
        transcript_block_size,
        prepared.sigma,
        digest_scheme);
}

noise::NoisePair ResolvePreparedNoiseForCpu(const PreparedDigestInputs& prepared,
                                            uint32_t n,
                                            uint32_t noise_rank)
{
    if (PreparedInputsHaveHostNoise(prepared, n, noise_rank)) {
        return *prepared.noise;
    }
    return noise::Generate(prepared.sigma, n, noise_rank);
}

PreparedDigestInputs PrepareMatMulDigestInputs(const CBlockHeader& block,
                                               uint32_t transcript_block_size,
                                               uint32_t noise_rank)
{
    return PrepareMatMulDigestInputsForBackend(
        block,
        transcript_block_size,
        noise_rank,
        backend::Kind::CPU);
}

PreparedDigestInputs PrepareMatMulDigestInputsForBackend(const CBlockHeader& block,
                                                         uint32_t transcript_block_size,
                                                         uint32_t noise_rank,
                                                         backend::Kind preferred_backend)
{
    const uint32_t n = block.matmul_dim;
    const uint256 sigma = DeriveSigma(block);
    const auto gpu_policy = ResolveGpuInputGenerationPolicy();

    if (ShouldUseGpuGeneratedInputsForShape(preferred_backend, n, transcript_block_size, noise_rank)) {
        g_gpu_input_generation_attempts.fetch_add(1, std::memory_order_relaxed);
        try {
            if (preferred_backend == backend::Kind::METAL) {
                const auto generated = btx::metal::GenerateMatMulInputsGPU({
                    .n = n,
                    .b = transcript_block_size,
                    .r = noise_rank,
                    .sigma = sigma,
                });

                if (generated.success) {
                    g_gpu_input_generation_successes.fetch_add(1, std::memory_order_relaxed);
                    return PreparedDigestInputs{
                        .sigma = sigma,
                        .noise = noise::NoisePair{
                            .E_L = MatrixFromRowMajorWords(n, noise_rank, generated.noise_e_l),
                            .E_R = MatrixFromRowMajorWords(noise_rank, n, generated.noise_e_r),
                            .F_L = MatrixFromRowMajorWords(n, noise_rank, generated.noise_f_l),
                            .F_R = MatrixFromRowMajorWords(noise_rank, n, generated.noise_f_r),
                        },
                        .compress_vec = generated.compress_vec,
                        .cuda_generated_inputs = nullptr,
                    };
                }

                g_gpu_input_generation_failures.fetch_add(1, std::memory_order_relaxed);
                const std::string gpu_error = generated.error.empty() ? "gpu_input_generation_failed" : generated.error;
                SetLastGpuInputError(gpu_error);

                if (gpu_policy == GpuInputGenerationPolicy::AUTO &&
                    ShouldDisableGpuInputAutoModeForError(gpu_error)) {
                    DisableGpuInputAutoMode(gpu_error);
                }

                if (!generated.error.empty()) {
                    LogBackendFallbackOnce(
                        GpuInputFallbackLogFlag(preferred_backend),
                        GpuInputFallbackLabel(preferred_backend),
                        generated.error);
                }
            } else if (preferred_backend == backend::Kind::CUDA) {
                if (ShouldUseCudaDevicePreparedInputsFastPath()) {
                    const auto generated = btx::cuda::GenerateMatMulInputsGPUDevice({
                        .n = n,
                        .b = transcript_block_size,
                        .r = noise_rank,
                        .sigma = sigma,
                    });

                    if (generated.success) {
                        g_gpu_input_generation_successes.fetch_add(1, std::memory_order_relaxed);
                        return PreparedDigestInputs{
                            .sigma = sigma,
                            .noise = std::nullopt,
                            .compress_vec = {},
                            .cuda_generated_inputs = generated.inputs,
                        };
                    }
                }

                const auto generated = btx::cuda::GenerateMatMulInputsGPU({
                    .n = n,
                    .b = transcript_block_size,
                    .r = noise_rank,
                    .sigma = sigma,
                });

                if (generated.success) {
                    g_gpu_input_generation_successes.fetch_add(1, std::memory_order_relaxed);
                    return PreparedDigestInputs{
                        .sigma = sigma,
                        .noise = noise::NoisePair{
                            .E_L = MatrixFromRowMajorWords(n, noise_rank, generated.noise_e_l),
                            .E_R = MatrixFromRowMajorWords(noise_rank, n, generated.noise_e_r),
                            .F_L = MatrixFromRowMajorWords(n, noise_rank, generated.noise_f_l),
                            .F_R = MatrixFromRowMajorWords(noise_rank, n, generated.noise_f_r),
                        },
                        .compress_vec = generated.compress_vec,
                        .cuda_generated_inputs = nullptr,
                    };
                }

                g_gpu_input_generation_failures.fetch_add(1, std::memory_order_relaxed);
                const std::string gpu_error = generated.error.empty() ? "gpu_input_generation_failed" : generated.error;
                SetLastGpuInputError(gpu_error);

                if (gpu_policy == GpuInputGenerationPolicy::AUTO &&
                    ShouldDisableGpuInputAutoModeForError(gpu_error)) {
                    DisableGpuInputAutoMode(gpu_error);
                }

                if (!generated.error.empty()) {
                    LogBackendFallbackOnce(
                        GpuInputFallbackLogFlag(preferred_backend),
                        GpuInputFallbackLabel(preferred_backend),
                        generated.error);
                }
            }
        } catch (const std::exception& e) {
            g_gpu_input_generation_failures.fetch_add(1, std::memory_order_relaxed);
            const std::string gpu_error = std::string("gpu_input_generation_exception:") + e.what();
            SetLastGpuInputError(gpu_error);
            LogBackendFallbackOnce(
                GpuInputFallbackLogFlag(preferred_backend),
                GpuInputFallbackLabel(preferred_backend),
                gpu_error);
            if (gpu_policy == GpuInputGenerationPolicy::AUTO) {
                DisableGpuInputAutoMode(gpu_error);
            }
        } catch (...) {
            g_gpu_input_generation_failures.fetch_add(1, std::memory_order_relaxed);
            const std::string gpu_error = "gpu_input_generation_unknown_exception";
            SetLastGpuInputError(gpu_error);
            LogBackendFallbackOnce(
                GpuInputFallbackLogFlag(preferred_backend),
                GpuInputFallbackLabel(preferred_backend),
                gpu_error);
            if (gpu_policy == GpuInputGenerationPolicy::AUTO) {
                DisableGpuInputAutoMode(gpu_error);
            }
        }
    }

    return PreparedDigestInputs{
        .sigma = sigma,
        .noise = noise::Generate(sigma, n, noise_rank),
        .compress_vec = transcript::DeriveCompressionVector(sigma, transcript_block_size),
        .cuda_generated_inputs = nullptr,
    };
}

DigestResult ComputeMatMulDigestPrepared(const CBlockHeader& block,
                                         const Matrix& A,
                                         const Matrix& B,
                                         uint32_t transcript_block_size,
                                         uint32_t noise_rank,
                                         const PreparedDigestInputs& prepared,
                                         backend::Kind preferred_backend,
                                         DigestScheme digest_scheme)
{
    DigestResult result;
    result.backend = preferred_backend;
    g_digest_requests.fetch_add(1, std::memory_order_relaxed);

    if (preferred_backend == backend::Kind::CPU) {
        g_requested_cpu.fetch_add(1, std::memory_order_relaxed);
        result.digest = ComputeDigestCpuFromPreparedInputs(
            A,
            B,
            prepared,
            transcript_block_size,
            digest_scheme);
        result.ok = true;
        return result;
    }

    if (preferred_backend == backend::Kind::CUDA) {
        g_requested_cuda.fetch_add(1, std::memory_order_relaxed);
        const auto capability = backend::CapabilityFor(backend::Kind::CUDA);
        if (!capability.available) {
            LogBackendFallbackOnce(g_logged_cuda_fallback, "CUDA", capability.reason);
            RecordCudaFallback(capability.reason);
            result.digest = ComputeDigestCpuFromPreparedInputs(
                A,
                B,
                prepared,
                transcript_block_size,
                digest_scheme);
            result.backend = backend::Kind::CPU;
            result.accelerated = false;
            result.ok = true;
            result.error = "cuda_backend_fallback_to_cpu:" + capability.reason;
            return result;
        }

        try {
            if (!PreparedInputsMatchShape(
                    prepared,
                    block.matmul_dim,
                    transcript_block_size,
                    noise_rank)) {
                const std::string cuda_error = "cuda_prepared_inputs_shape_mismatch";
                LogBackendFallbackOnce(g_logged_cuda_fallback, "CUDA", cuda_error);
                RecordCudaFallback(cuda_error);
                result.digest = ComputeDigestCpuFromPreparedInputs(
                    A,
                    B,
                    prepared,
                    transcript_block_size,
                    digest_scheme);
                result.backend = backend::Kind::CPU;
                result.accelerated = false;
                result.ok = true;
                result.error = "cuda_backend_fallback_to_cpu:" + cuda_error;
                return result;
            }

            btx::cuda::MatMulCompressedWordsBatchResult cuda_result;
            if (prepared.cuda_generated_inputs != nullptr) {
                const btx::cuda::MatMulGeneratedInputsDevice* generated_inputs[] = {prepared.cuda_generated_inputs.get()};
                cuda_result = btx::cuda::ComputeCompressedWordsLowRankDeviceBatch(
                    {
                        .n = block.matmul_dim,
                        .b = transcript_block_size,
                        .r = noise_rank,
                        .batch_size = 1,
                        .matrix_a = A.data(),
                        .matrix_b = B.data(),
                        .generated_inputs = generated_inputs,
                    },
                    ToCudaCompressedWordsMode(digest_scheme));
            } else {
                const field::Element* noise_e_l_ptrs[] = {prepared.noise->E_L.data()};
                const field::Element* noise_e_r_ptrs[] = {prepared.noise->E_R.data()};
                const field::Element* noise_f_l_ptrs[] = {prepared.noise->F_L.data()};
                const field::Element* noise_f_r_ptrs[] = {prepared.noise->F_R.data()};
                const field::Element* compress_ptrs[] = {prepared.compress_vec.data()};

                cuda_result = btx::cuda::ComputeCompressedWordsLowRankBatch(
                    {
                        .n = block.matmul_dim,
                        .b = transcript_block_size,
                        .r = noise_rank,
                        .batch_size = 1,
                        .matrix_a = A.data(),
                        .matrix_b = B.data(),
                        .noise_e_l = noise_e_l_ptrs,
                        .noise_e_r = noise_e_r_ptrs,
                        .noise_f_l = noise_f_l_ptrs,
                        .noise_f_r = noise_f_r_ptrs,
                        .compress_vec = compress_ptrs,
                    },
                    ToCudaCompressedWordsMode(digest_scheme));
            }

            if (cuda_result.success) {
                const uint32_t blocks_per_axis = block.matmul_dim / transcript_block_size;
                const uint32_t expected_words =
                    digest_scheme == DigestScheme::PRODUCT_COMMITTED
                        ? blocks_per_axis * blocks_per_axis
                        : blocks_per_axis * blocks_per_axis * blocks_per_axis;
                if (cuda_result.words_per_request != expected_words ||
                    cuda_result.words.size() != expected_words) {
                    const std::string cuda_error = "cuda_digest_size_mismatch";
                    LogBackendFallbackOnce(g_logged_cuda_fallback, "CUDA", cuda_error);
                    RecordCudaFallback(cuda_error);
                    result.digest = ComputeDigestCpuFromPreparedInputs(
                        A,
                        B,
                        prepared,
                        transcript_block_size,
                        digest_scheme);
                    result.backend = backend::Kind::CPU;
                    result.accelerated = false;
                    result.ok = true;
                    result.error = "cuda_backend_fallback_to_cpu:" + cuda_error;
                    return result;
                }

                const auto words = Span<const field::Element>{cuda_result.words.data(), cuda_result.words.size()};
                result.digest = digest_scheme == DigestScheme::PRODUCT_COMMITTED
                    ? transcript::ComputeProductCommittedDigestFromWords(
                          words,
                          prepared.sigma,
                          block.matmul_dim,
                          transcript_block_size)
                    : transcript::FinalizeTranscriptDigestFromWords(words);
                g_cuda_successes.fetch_add(1, std::memory_order_relaxed);
                result.backend = backend::Kind::CUDA;
                result.accelerated = true;
                result.ok = true;
                return result;
            }

            const std::string cuda_error = cuda_result.error.empty() ? "cuda_digest_failed" : cuda_result.error;
            LogBackendFallbackOnce(g_logged_cuda_fallback, "CUDA", cuda_error);
            RecordCudaFallback(cuda_error);
            result.digest = ComputeDigestCpuFromPreparedInputs(
                A,
                B,
                prepared,
                transcript_block_size,
                digest_scheme);
            result.backend = backend::Kind::CPU;
            result.accelerated = false;
            result.ok = true;
            result.error = "cuda_backend_fallback_to_cpu:" + cuda_error;
            return result;
        } catch (const std::exception& e) {
            const std::string cuda_error = std::string("cuda_backend_exception:") + e.what();
            LogBackendFallbackOnce(g_logged_cuda_fallback, "CUDA", cuda_error);
            RecordCudaFallback(cuda_error);
            result.digest = ComputeDigestCpuFromPreparedInputs(
                A,
                B,
                prepared,
                transcript_block_size,
                digest_scheme);
            result.backend = backend::Kind::CPU;
            result.accelerated = false;
            result.ok = true;
            result.error = "cuda_backend_fallback_to_cpu:" + cuda_error;
            return result;
        } catch (...) {
            const std::string cuda_error = "cuda_backend_unknown_exception";
            LogBackendFallbackOnce(g_logged_cuda_fallback, "CUDA", cuda_error);
            RecordCudaFallback(cuda_error);
            result.digest = ComputeDigestCpuFromPreparedInputs(
                A,
                B,
                prepared,
                transcript_block_size,
                digest_scheme);
            result.backend = backend::Kind::CPU;
            result.accelerated = false;
            result.ok = true;
            result.error = "cuda_backend_fallback_to_cpu:" + cuda_error;
            return result;
        }
    }

    if (preferred_backend == backend::Kind::METAL) {
        g_requested_metal.fetch_add(1, std::memory_order_relaxed);
        try {
            const uint32_t n = block.matmul_dim;
            const auto uploaded_base = btx::metal::UploadBaseMatrices({
                .n = n,
                .matrix_a = A.data(),
                .matrix_b = B.data(),
            });
            const bool use_uploaded_base = uploaded_base.success;

            btx::metal::MatMulDigestRequest request{
                .n = n,
                .b = transcript_block_size,
                .r = noise_rank,
                .digest_mode = ToMetalDigestMode(digest_scheme),
                .sigma = prepared.sigma,
                .matrix_a = use_uploaded_base ? nullptr : A.data(),
                .matrix_b = use_uploaded_base ? nullptr : B.data(),
                .use_uploaded_base_matrices = use_uploaded_base,
                .noise_e_l = prepared.noise->E_L.data(),
                .noise_e_r = prepared.noise->E_R.data(),
                .noise_f_l = prepared.noise->F_L.data(),
                .noise_f_r = prepared.noise->F_R.data(),
                .compress_vec = prepared.compress_vec.data(),
            };

            auto metal_result = btx::metal::ComputeCanonicalTranscriptDigest(request);
            if (!metal_result.success &&
                use_uploaded_base &&
                ShouldRetryMetalDigestWithoutUploadedBase(metal_result.error)) {
                g_metal_retry_without_uploaded_base_attempts.fetch_add(1, std::memory_order_relaxed);
                request.matrix_a = A.data();
                request.matrix_b = B.data();
                request.use_uploaded_base_matrices = false;
                const auto retry_result = btx::metal::ComputeCanonicalTranscriptDigest(request);
                if (retry_result.success) {
                    g_metal_retry_without_uploaded_base_successes.fetch_add(1, std::memory_order_relaxed);
                    g_metal_successes.fetch_add(1, std::memory_order_relaxed);
                    result.digest = retry_result.digest;
                    result.backend = backend::Kind::METAL;
                    result.accelerated = true;
                    result.ok = true;
                    return result;
                }
                if (!retry_result.error.empty()) {
                    metal_result.error = metal_result.error + "; retry_without_uploaded_base:" + retry_result.error;
                }
            }

            if (metal_result.success) {
#ifdef DEBUG
                const auto cpu_digest = ComputeDigestCpuFromPreparedInputs(
                    A,
                    B,
                    prepared,
                    transcript_block_size,
                    digest_scheme);
                if (cpu_digest != metal_result.digest) {
                    g_metal_digest_mismatches.fetch_add(1, std::memory_order_relaxed);
                    RecordMetalFallback("digest mismatch");
                    LogBackendFallbackOnce(g_logged_metal_mismatch, "METAL", "digest mismatch");
                    result.digest = cpu_digest;
                    result.backend = backend::Kind::CPU;
                    result.accelerated = false;
                    result.ok = true;
                    result.error = "metal_backend_digest_mismatch_fallback_to_cpu";
                    return result;
                }
#endif
                g_metal_successes.fetch_add(1, std::memory_order_relaxed);
                result.digest = metal_result.digest;
                result.backend = backend::Kind::METAL;
                result.accelerated = true;
                result.ok = true;
                return result;
            }

            LogBackendFallbackOnce(g_logged_metal_fallback, "METAL", metal_result.error);
            RecordMetalFallback(metal_result.error);
            result.digest = ComputeDigestCpuFromPreparedInputs(
                A,
                B,
                prepared,
                transcript_block_size,
                digest_scheme);
            result.backend = backend::Kind::CPU;
            result.accelerated = false;
            result.ok = true;
            result.error = "metal_backend_fallback_to_cpu:" + metal_result.error;
            return result;
        } catch (const std::exception& e) {
            const std::string metal_error = std::string("metal_backend_exception:") + e.what();
            LogBackendFallbackOnce(g_logged_metal_fallback, "METAL", metal_error);
            RecordMetalFallback(metal_error);
            result.digest = ComputeDigestCpuFromPreparedInputs(
                A,
                B,
                prepared,
                transcript_block_size,
                digest_scheme);
            result.backend = backend::Kind::CPU;
            result.accelerated = false;
            result.ok = true;
            result.error = "metal_backend_fallback_to_cpu:" + metal_error;
            return result;
        } catch (...) {
            const std::string metal_error = "metal_backend_unknown_exception";
            LogBackendFallbackOnce(g_logged_metal_fallback, "METAL", metal_error);
            RecordMetalFallback(metal_error);
            result.digest = ComputeDigestCpuFromPreparedInputs(
                A,
                B,
                prepared,
                transcript_block_size,
                digest_scheme);
            result.backend = backend::Kind::CPU;
            result.accelerated = false;
            result.ok = true;
            result.error = "metal_backend_fallback_to_cpu:" + metal_error;
            return result;
        }
    }

    g_requested_unknown.fetch_add(1, std::memory_order_relaxed);
    LogBackendFallbackOnce(g_logged_unknown_backend, "UNKNOWN", "unsupported selection");
    result.digest = ComputeDigestCpuFromPreparedInputs(
        A,
        B,
        prepared,
        transcript_block_size,
        digest_scheme);
    result.backend = backend::Kind::CPU;
    result.accelerated = false;
    result.ok = true;
    result.error = "unknown_backend_fallback_to_cpu";
    return result;
}

DigestBatchSubmission SubmitMatMulDigestPreparedBatchForMining(const std::vector<CBlockHeader>& blocks,
                                                              const Matrix& A,
                                                              const Matrix& B,
                                                              uint32_t transcript_block_size,
                                                              uint32_t noise_rank,
                                                              const std::vector<PreparedDigestInputs>& prepared_batch,
                                                              backend::Kind preferred_backend,
                                                              DigestScheme digest_scheme)
{
    DigestBatchSubmission submission;
    submission.backend = preferred_backend;
    submission.batch_size = static_cast<uint32_t>(blocks.size());

    auto state = std::make_shared<DigestBatchSubmissionState>();
    state->blocks = &blocks;
    state->matrix_a = &A;
    state->matrix_b = &B;
    state->transcript_block_size = transcript_block_size;
    state->noise_rank = noise_rank;
    state->digest_scheme = digest_scheme;
    state->prepared_batch = &prepared_batch;
    state->preferred_backend = preferred_backend;

    if (blocks.empty()) {
        submission.submitted = true;
        submission.opaque = state;
        return submission;
    }

    if (blocks.size() != prepared_batch.size()) {
        state->immediate_results.resize(blocks.size());
        for (auto& item : state->immediate_results) {
            item.backend = backend::Kind::CPU;
            item.accelerated = false;
            item.ok = false;
            item.error = "prepared_batch_size_mismatch";
        }
        submission.submitted = true;
        submission.opaque = state;
        return submission;
    }

    if (preferred_backend == backend::Kind::CUDA) {
        const uint32_t n = blocks.front().matmul_dim;
        for (const auto& block : blocks) {
            if (block.matmul_dim != n) {
                state->immediate_results.reserve(blocks.size());
                for (size_t i = 0; i < blocks.size(); ++i) {
                    state->immediate_results.push_back(ComputeMatMulDigestPrepared(
                        blocks[i],
                        A,
                        B,
                        transcript_block_size,
                        noise_rank,
                        prepared_batch[i],
                        preferred_backend,
                        digest_scheme));
                }
                submission.submitted = true;
                submission.opaque = state;
                return submission;
            }
        }

        g_digest_requests.fetch_add(blocks.size(), std::memory_order_relaxed);
        g_requested_cuda.fetch_add(blocks.size(), std::memory_order_relaxed);
        try {
            state->cuda_batch_future = std::async(std::launch::async, [state]() {
                return ComputeCudaDigestsPreparedBatch(
                    *state->blocks,
                    *state->matrix_a,
                    *state->matrix_b,
                    state->transcript_block_size,
                    state->noise_rank,
                    *state->prepared_batch,
                    state->digest_scheme);
            });
        } catch (const std::exception& e) {
            state->immediate_results = ComputeCudaDigestBatchFallbackResults(
                blocks,
                A,
                B,
                transcript_block_size,
                prepared_batch,
                digest_scheme,
                std::string("cuda_batch_submission_exception:") + e.what(),
                "cuda_batch_backend_fallback_to_cpu:");
        } catch (...) {
            state->immediate_results = ComputeCudaDigestBatchFallbackResults(
                blocks,
                A,
                B,
                transcript_block_size,
                prepared_batch,
                digest_scheme,
                "cuda_batch_submission_unknown_exception",
                "cuda_batch_backend_fallback_to_cpu:");
        }
        submission.submitted = true;
        submission.opaque = state;
        return submission;
    }

    if (preferred_backend != backend::Kind::METAL) {
        state->immediate_results.reserve(blocks.size());
        for (size_t i = 0; i < blocks.size(); ++i) {
            state->immediate_results.push_back(ComputeMatMulDigestPrepared(
                blocks[i],
                A,
                B,
                transcript_block_size,
                noise_rank,
                prepared_batch[i],
                preferred_backend,
                digest_scheme));
        }
        submission.submitted = true;
        submission.opaque = state;
        return submission;
    }

    const uint32_t n = blocks.front().matmul_dim;
    for (const auto& block : blocks) {
        if (block.matmul_dim != n) {
            state->immediate_results.reserve(blocks.size());
            for (size_t i = 0; i < blocks.size(); ++i) {
                state->immediate_results.push_back(ComputeMatMulDigestPrepared(
                    blocks[i],
                    A,
                    B,
                    transcript_block_size,
                    noise_rank,
                    prepared_batch[i],
                    preferred_backend,
                    digest_scheme));
            }
            submission.submitted = true;
            submission.opaque = state;
            return submission;
        }
    }

    g_digest_requests.fetch_add(blocks.size(), std::memory_order_relaxed);
    g_requested_metal.fetch_add(blocks.size(), std::memory_order_relaxed);

    const auto uploaded_base = btx::metal::UploadBaseMatrices({
        .n = n,
        .matrix_a = A.data(),
        .matrix_b = B.data(),
    });
    const bool use_uploaded_base = uploaded_base.success;

    std::vector<const field::Element*> noise_e_l_ptrs;
    std::vector<const field::Element*> noise_e_r_ptrs;
    std::vector<const field::Element*> noise_f_l_ptrs;
    std::vector<const field::Element*> noise_f_r_ptrs;
    std::vector<const field::Element*> compress_ptrs;
    std::vector<uint256> sigmas;
    noise_e_l_ptrs.reserve(blocks.size());
    noise_e_r_ptrs.reserve(blocks.size());
    noise_f_l_ptrs.reserve(blocks.size());
    noise_f_r_ptrs.reserve(blocks.size());
    compress_ptrs.reserve(blocks.size());
    sigmas.reserve(blocks.size());
    for (const auto& prepared : prepared_batch) {
        noise_e_l_ptrs.push_back(prepared.noise->E_L.data());
        noise_e_r_ptrs.push_back(prepared.noise->E_R.data());
        noise_f_l_ptrs.push_back(prepared.noise->F_L.data());
        noise_f_r_ptrs.push_back(prepared.noise->F_R.data());
        compress_ptrs.push_back(prepared.compress_vec.data());
        sigmas.push_back(prepared.sigma);
    }

    const uint32_t slice_size = ResolveMetalDigestSliceSize(static_cast<uint32_t>(blocks.size()));
    std::vector<DigestBatchSubmissionState::MetalSubmissionSlice> metal_submissions;
    metal_submissions.reserve((blocks.size() + slice_size - 1) / slice_size);
    for (size_t start = 0; start < blocks.size(); start += slice_size) {
        const size_t count = std::min<size_t>(slice_size, blocks.size() - start);
        DigestBatchSubmissionState::MetalSubmissionSlice slice;
        slice.start_index = start;
        slice.count = count;
        if (count == 1) {
            slice.single_submission = btx::metal::SubmitCanonicalTranscriptDigest({
                .n = n,
                .b = transcript_block_size,
                .r = noise_rank,
                .digest_mode = ToMetalDigestMode(digest_scheme),
                .sigma = prepared_batch[start].sigma,
                .matrix_a = use_uploaded_base ? nullptr : A.data(),
                .matrix_b = use_uploaded_base ? nullptr : B.data(),
                .use_uploaded_base_matrices = use_uploaded_base,
                .noise_e_l = prepared_batch[start].noise->E_L.data(),
                .noise_e_r = prepared_batch[start].noise->E_R.data(),
                .noise_f_l = prepared_batch[start].noise->F_L.data(),
                .noise_f_r = prepared_batch[start].noise->F_R.data(),
                .compress_vec = prepared_batch[start].compress_vec.data(),
            });
            if (!slice.single_submission->submitted) {
                submission.error = slice.single_submission->error;
                break;
            }
        } else {
            slice.batch_submission = btx::metal::SubmitCanonicalTranscriptDigestBatch({
                .n = n,
                .b = transcript_block_size,
                .r = noise_rank,
                .batch_size = static_cast<uint32_t>(count),
                .digest_mode = ToMetalDigestMode(digest_scheme),
                .sigmas = sigmas.data() + start,
                .matrix_a = use_uploaded_base ? nullptr : A.data(),
                .matrix_b = use_uploaded_base ? nullptr : B.data(),
                .use_uploaded_base_matrices = use_uploaded_base,
                .noise_e_l = noise_e_l_ptrs.data() + start,
                .noise_e_r = noise_e_r_ptrs.data() + start,
                .noise_f_l = noise_f_l_ptrs.data() + start,
                .noise_f_r = noise_f_r_ptrs.data() + start,
                .compress_vec = compress_ptrs.data() + start,
            });
            if (!slice.batch_submission->submitted) {
                submission.error = slice.batch_submission->error;
                break;
            }
        }
        metal_submissions.push_back(std::move(slice));
    }
    if (!submission.error.empty()) {
        return submission;
    }
    state->metal_submissions = std::move(metal_submissions);
    submission.submitted = true;
    submission.opaque = state;
    return submission;
}

std::vector<DigestResult> WaitForSubmittedMatMulDigestBatch(DigestBatchSubmission&& submission)
{
    std::vector<DigestResult> results;
    if (!submission.submitted || !submission.opaque) {
        return results;
    }

    auto state = std::static_pointer_cast<DigestBatchSubmissionState>(submission.opaque);
    const auto& blocks = *state->blocks;
    const auto& A = *state->matrix_a;
    const auto& B = *state->matrix_b;
    const auto& prepared_batch = *state->prepared_batch;
    const uint32_t transcript_block_size = state->transcript_block_size;
    const uint32_t noise_rank = state->noise_rank;
    const DigestScheme digest_scheme = state->digest_scheme;

    if (!state->immediate_results.empty() || blocks.empty()) {
        return state->immediate_results;
    }

    if (state->cuda_batch_future.valid()) {
        try {
            return state->cuda_batch_future.get();
        } catch (const std::exception& e) {
            return ComputeCudaDigestBatchFallbackResults(
                blocks,
                A,
                B,
                transcript_block_size,
                prepared_batch,
                digest_scheme,
                std::string("cuda_batch_wait_exception:") + e.what(),
                "cuda_batch_backend_fallback_to_cpu:");
        } catch (...) {
            return ComputeCudaDigestBatchFallbackResults(
                blocks,
                A,
                B,
                transcript_block_size,
                prepared_batch,
                digest_scheme,
                "cuda_batch_wait_unknown_exception",
                "cuda_batch_backend_fallback_to_cpu:");
        }
    }

    results.reserve(blocks.size());
    const uint32_t n = blocks.front().matmul_dim;
    const auto emit_single_result = [&](size_t index, const btx::metal::MatMulDigestResult& metal_result) -> DigestResult {
        DigestResult result;
        if (metal_result.success) {
            result.backend = backend::Kind::METAL;
            result.accelerated = true;
            result.ok = true;
            result.digest = metal_result.digest;
#ifdef DEBUG
            const auto cpu_digest = ComputeDigestCpuFromPreparedInputs(
                A,
                B,
                prepared_batch[index],
                transcript_block_size,
                digest_scheme);
            if (cpu_digest != result.digest) {
                g_metal_digest_mismatches.fetch_add(1, std::memory_order_relaxed);
                RecordMetalFallback("digest mismatch");
                LogBackendFallbackOnce(g_logged_metal_mismatch, "METAL", "digest mismatch");
                result.backend = backend::Kind::CPU;
                result.accelerated = false;
                result.digest = cpu_digest;
                result.error = "metal_backend_digest_mismatch_fallback_to_cpu";
            } else {
                g_metal_successes.fetch_add(1, std::memory_order_relaxed);
            }
#else
            g_metal_successes.fetch_add(1, std::memory_order_relaxed);
#endif
            return result;
        }

        LogBackendFallbackOnce(g_logged_metal_fallback, "METAL", metal_result.error);
        RecordMetalFallback(metal_result.error);
        result.digest = ComputeDigestCpuFromPreparedInputs(
            A,
            B,
            prepared_batch[index],
            transcript_block_size,
            digest_scheme);
        result.backend = backend::Kind::CPU;
        result.accelerated = false;
        result.ok = true;
        result.error = "metal_backend_fallback_to_cpu:" + metal_result.error;
        return result;
    };

    const auto emit_batch_fallback_results = [&](size_t start_index,
                                                 size_t count,
                                                 std::string error) {
        if (!error.empty()) {
            LogBackendFallbackOnce(g_logged_metal_fallback, "METAL", error);
            RecordMetalFallback(error, count);
        }
        for (size_t i = 0; i < count; ++i) {
            DigestResult result;
            result.digest = ComputeDigestCpuFromPreparedInputs(
                A,
                B,
                prepared_batch[start_index + i],
                transcript_block_size,
                digest_scheme);
            result.backend = backend::Kind::CPU;
            result.accelerated = false;
            result.ok = true;
            result.error = "metal_batch_backend_fallback_to_cpu:" + error;
            results.push_back(std::move(result));
        }
    };

    for (auto slice : state->metal_submissions) {
        if (slice.count == 0) {
            continue;
        }

        if (slice.count == 1) {
            auto metal_result = btx::metal::WaitForCanonicalTranscriptDigestSubmission(std::move(*slice.single_submission));
            if (!metal_result.success &&
                ShouldRetryMetalDigestWithoutUploadedBase(metal_result.error)) {
                g_metal_retry_without_uploaded_base_attempts.fetch_add(1, std::memory_order_relaxed);
                auto retry_submission = btx::metal::SubmitCanonicalTranscriptDigest({
                    .n = n,
                    .b = transcript_block_size,
                    .r = noise_rank,
                    .digest_mode = ToMetalDigestMode(digest_scheme),
                    .sigma = prepared_batch[slice.start_index].sigma,
                    .matrix_a = A.data(),
                    .matrix_b = B.data(),
                    .use_uploaded_base_matrices = false,
                    .noise_e_l = prepared_batch[slice.start_index].noise->E_L.data(),
                    .noise_e_r = prepared_batch[slice.start_index].noise->E_R.data(),
                    .noise_f_l = prepared_batch[slice.start_index].noise->F_L.data(),
                    .noise_f_r = prepared_batch[slice.start_index].noise->F_R.data(),
                    .compress_vec = prepared_batch[slice.start_index].compress_vec.data(),
                });
                auto retry_result = btx::metal::WaitForCanonicalTranscriptDigestSubmission(std::move(retry_submission));
                if (retry_result.success) {
                    g_metal_retry_without_uploaded_base_successes.fetch_add(1, std::memory_order_relaxed);
                    metal_result = std::move(retry_result);
                } else if (!retry_result.error.empty()) {
                    metal_result.error = metal_result.error + "; retry_without_uploaded_base:" + retry_result.error;
                }
            }

            results.push_back(emit_single_result(slice.start_index, metal_result));
            continue;
        }

        auto batch_result = btx::metal::WaitForCanonicalTranscriptDigestBatchSubmission(std::move(*slice.batch_submission));
        if (!batch_result.success &&
            ShouldRetryMetalDigestWithoutUploadedBase(batch_result.error)) {
            g_metal_retry_without_uploaded_base_attempts.fetch_add(1, std::memory_order_relaxed);
            std::vector<const field::Element*> noise_e_l_ptrs;
            std::vector<const field::Element*> noise_e_r_ptrs;
            std::vector<const field::Element*> noise_f_l_ptrs;
            std::vector<const field::Element*> noise_f_r_ptrs;
            std::vector<const field::Element*> compress_ptrs;
            std::vector<uint256> sigmas;
            noise_e_l_ptrs.reserve(slice.count);
            noise_e_r_ptrs.reserve(slice.count);
            noise_f_l_ptrs.reserve(slice.count);
            noise_f_r_ptrs.reserve(slice.count);
            compress_ptrs.reserve(slice.count);
            sigmas.reserve(slice.count);
            for (size_t i = 0; i < slice.count; ++i) {
                const auto& prepared = prepared_batch[slice.start_index + i];
                noise_e_l_ptrs.push_back(prepared.noise->E_L.data());
                noise_e_r_ptrs.push_back(prepared.noise->E_R.data());
                noise_f_l_ptrs.push_back(prepared.noise->F_L.data());
                noise_f_r_ptrs.push_back(prepared.noise->F_R.data());
                compress_ptrs.push_back(prepared.compress_vec.data());
                sigmas.push_back(prepared.sigma);
            }

            auto retry_submission = btx::metal::SubmitCanonicalTranscriptDigestBatch({
                .n = n,
                .b = transcript_block_size,
                .r = noise_rank,
                .batch_size = static_cast<uint32_t>(slice.count),
                .digest_mode = ToMetalDigestMode(digest_scheme),
                .sigmas = sigmas.data(),
                .matrix_a = A.data(),
                .matrix_b = B.data(),
                .use_uploaded_base_matrices = false,
                .noise_e_l = noise_e_l_ptrs.data(),
                .noise_e_r = noise_e_r_ptrs.data(),
                .noise_f_l = noise_f_l_ptrs.data(),
                .noise_f_r = noise_f_r_ptrs.data(),
                .compress_vec = compress_ptrs.data(),
            });
            auto retry_result = btx::metal::WaitForCanonicalTranscriptDigestBatchSubmission(std::move(retry_submission));
            if (retry_result.success) {
                g_metal_retry_without_uploaded_base_successes.fetch_add(1, std::memory_order_relaxed);
                batch_result = std::move(retry_result);
            } else if (!retry_result.error.empty()) {
                batch_result.error = batch_result.error + "; retry_without_uploaded_base:" + retry_result.error;
            }
        }

        if (batch_result.success && batch_result.digests.size() == slice.count) {
            size_t metal_successes{0};
            for (size_t i = 0; i < slice.count; ++i) {
                DigestResult result;
                result.backend = backend::Kind::METAL;
                result.accelerated = true;
                result.ok = true;
                result.digest = batch_result.digests[i];
#ifdef DEBUG
                const auto cpu_digest = ComputeDigestCpuFromPreparedInputs(
                    A,
                    B,
                    prepared_batch[slice.start_index + i],
                    transcript_block_size,
                    digest_scheme);
                if (cpu_digest != result.digest) {
                    g_metal_digest_mismatches.fetch_add(1, std::memory_order_relaxed);
                    RecordMetalFallback("digest mismatch");
                    LogBackendFallbackOnce(g_logged_metal_mismatch, "METAL", "digest mismatch");
                    result.backend = backend::Kind::CPU;
                    result.accelerated = false;
                    result.digest = cpu_digest;
                    result.error = "metal_backend_digest_mismatch_fallback_to_cpu";
                } else {
                    ++metal_successes;
                }
#else
                ++metal_successes;
#endif
                results.push_back(std::move(result));
            }
            if (metal_successes > 0) {
                g_metal_successes.fetch_add(metal_successes, std::memory_order_relaxed);
            }
            continue;
        }

        if (batch_result.success && batch_result.digests.size() != slice.count) {
            batch_result.error = "metal_batch_digest_size_mismatch";
        }
        emit_batch_fallback_results(slice.start_index, slice.count, batch_result.error);
    }

    return results;
}

std::vector<DigestResult> ComputeMatMulDigestPreparedBatch(const std::vector<CBlockHeader>& blocks,
                                                           const Matrix& A,
                                                           const Matrix& B,
                                                           uint32_t transcript_block_size,
                                                           uint32_t noise_rank,
                                                           const std::vector<PreparedDigestInputs>& prepared_batch,
                                                           backend::Kind preferred_backend,
                                                           DigestScheme digest_scheme)
{
    auto submission = SubmitMatMulDigestPreparedBatchForMining(
        blocks,
        A,
        B,
        transcript_block_size,
        noise_rank,
        prepared_batch,
        preferred_backend,
        digest_scheme);
    return WaitForSubmittedMatMulDigestBatch(std::move(submission));
}

DigestResult ComputeMatMulDigest(const CBlockHeader& block,
                                 const Matrix& A,
                                 const Matrix& B,
                                 uint32_t transcript_block_size,
                                 uint32_t noise_rank,
                                 backend::Kind preferred_backend,
                                 DigestScheme digest_scheme)
{
    const auto prepared = PrepareMatMulDigestInputsForBackend(
        block,
        transcript_block_size,
        noise_rank,
        preferred_backend);
    return ComputeMatMulDigestPrepared(
        block,
        A,
        B,
        transcript_block_size,
        noise_rank,
        prepared,
        preferred_backend,
        digest_scheme);
}

} // namespace matmul::accelerated
