// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/accelerated_solver.h>

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
#include <memory>
#include <mutex>
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
std::atomic_bool g_logged_gpu_input_generation_fallback{false};
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
std::atomic<uint64_t> g_gpu_input_generation_attempts{0};
std::atomic<uint64_t> g_gpu_input_generation_successes{0};
std::atomic<uint64_t> g_gpu_input_generation_failures{0};
std::atomic<uint64_t> g_gpu_input_auto_disabled_skips{0};
std::atomic_bool g_gpu_input_auto_disabled{false};
std::mutex g_backend_runtime_stats_mutex;
std::string g_last_metal_fallback_error;
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
    bool use_metal_single{false};
    std::optional<btx::metal::MatMulDigestSubmission> single_submission;
    std::optional<btx::metal::MatMulDigestBatchSubmission> batch_submission;
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

void SetLastMetalFallbackError(const std::string& error)
{
    std::lock_guard<std::mutex> lock(g_backend_runtime_stats_mutex);
    g_last_metal_fallback_error = error;
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

void DisableGpuInputAutoMode(const std::string& reason)
{
    bool expected{false};
    if (g_gpu_input_auto_disabled.compare_exchange_strong(expected, true, std::memory_order_relaxed)) {
        LogPrintf("MATMUL WARNING: disabling BTX_MATMUL_GPU_INPUTS auto mode after failure (%s)\n", reason);
    }
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
    if (backend_kind != backend::Kind::METAL) {
        return false;
    }

    const auto policy = ResolveGpuInputGenerationPolicy();
    if (policy == GpuInputGenerationPolicy::FORCED_OFF) {
        return false;
    }
    if (policy == GpuInputGenerationPolicy::FORCED_ON) {
        return true;
    }

#if defined(__APPLE__)
    if (g_gpu_input_auto_disabled.load(std::memory_order_relaxed)) {
        g_gpu_input_auto_disabled_skips.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

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
        error.find("Metal context initialization failed") != std::string_view::npos;
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
    stats.gpu_input_generation_attempts = g_gpu_input_generation_attempts.load(std::memory_order_relaxed);
    stats.gpu_input_generation_successes = g_gpu_input_generation_successes.load(std::memory_order_relaxed);
    stats.gpu_input_generation_failures = g_gpu_input_generation_failures.load(std::memory_order_relaxed);
    stats.gpu_input_auto_disabled_skips = g_gpu_input_auto_disabled_skips.load(std::memory_order_relaxed);
    stats.gpu_input_auto_disabled = g_gpu_input_auto_disabled.load(std::memory_order_relaxed);

    std::lock_guard<std::mutex> lock(g_backend_runtime_stats_mutex);
    stats.last_metal_fallback_error = g_last_metal_fallback_error;
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
    g_gpu_input_generation_attempts.store(0, std::memory_order_relaxed);
    g_gpu_input_generation_successes.store(0, std::memory_order_relaxed);
    g_gpu_input_generation_failures.store(0, std::memory_order_relaxed);
    g_gpu_input_auto_disabled_skips.store(0, std::memory_order_relaxed);
    g_gpu_input_auto_disabled.store(false, std::memory_order_relaxed);

    std::lock_guard<std::mutex> lock(g_backend_runtime_stats_mutex);
    g_last_metal_fallback_error.clear();
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
    return ComputeDigestCpuFromPrepared(
        A,
        B,
        prepared.noise,
        transcript_block_size,
        prepared.sigma,
        digest_scheme);
}

uint256 ComputeDigestCpuFromPreparedInputs(const Matrix& A,
                                           const Matrix& B,
                                           const PreparedDigestInputs& prepared,
                                           uint32_t transcript_block_size,
                                           DigestScheme digest_scheme)
{
    return ComputeDigestCpuFromPrepared(
        A,
        B,
        prepared.noise,
        transcript_block_size,
        prepared.sigma,
        digest_scheme);
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
                LogBackendFallbackOnce(g_logged_gpu_input_generation_fallback,
                                       "METAL-GPU-INPUTS",
                                       generated.error);
            }
        } catch (const std::exception& e) {
            g_gpu_input_generation_failures.fetch_add(1, std::memory_order_relaxed);
            const std::string gpu_error = std::string("gpu_input_generation_exception:") + e.what();
            SetLastGpuInputError(gpu_error);
            LogBackendFallbackOnce(g_logged_gpu_input_generation_fallback, "METAL-GPU-INPUTS", gpu_error);
            if (gpu_policy == GpuInputGenerationPolicy::AUTO) {
                DisableGpuInputAutoMode(gpu_error);
            }
        } catch (...) {
            g_gpu_input_generation_failures.fetch_add(1, std::memory_order_relaxed);
            const std::string gpu_error = "gpu_input_generation_unknown_exception";
            SetLastGpuInputError(gpu_error);
            LogBackendFallbackOnce(g_logged_gpu_input_generation_fallback, "METAL-GPU-INPUTS", gpu_error);
            if (gpu_policy == GpuInputGenerationPolicy::AUTO) {
                DisableGpuInputAutoMode(gpu_error);
            }
        }
    }

    return PreparedDigestInputs{
        .sigma = sigma,
        .noise = noise::Generate(sigma, n, noise_rank),
        .compress_vec = transcript::DeriveCompressionVector(sigma, transcript_block_size),
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
        result.digest = ComputeDigestCpuFromPrepared(
            A,
            B,
            prepared.noise,
            transcript_block_size,
            prepared.sigma,
            digest_scheme);
        result.ok = true;
        return result;
    }

    if (preferred_backend == backend::Kind::CUDA) {
        g_requested_cuda.fetch_add(1, std::memory_order_relaxed);
        const auto capability = backend::CapabilityFor(backend::Kind::CUDA);
        LogBackendFallbackOnce(g_logged_cuda_fallback, "CUDA", capability.reason);
        result.digest = ComputeDigestCpuFromPrepared(
            A,
            B,
            prepared.noise,
            transcript_block_size,
            prepared.sigma,
            digest_scheme);
        result.backend = backend::Kind::CPU;
        result.accelerated = false;
        result.ok = true;
        result.error = "cuda_backend_fallback_to_cpu:" + capability.reason;
        return result;
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
                .noise_e_l = prepared.noise.E_L.data(),
                .noise_e_r = prepared.noise.E_R.data(),
                .noise_f_l = prepared.noise.F_L.data(),
                .noise_f_r = prepared.noise.F_R.data(),
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
                const auto cpu_digest = ComputeDigestCpuFromPrepared(
                    A,
                    B,
                    prepared.noise,
                    transcript_block_size,
                    prepared.sigma,
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
            result.digest = ComputeDigestCpuFromPrepared(
                A,
                B,
                prepared.noise,
                transcript_block_size,
                prepared.sigma,
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
            result.digest = ComputeDigestCpuFromPrepared(
                A,
                B,
                prepared.noise,
                transcript_block_size,
                prepared.sigma,
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
            result.digest = ComputeDigestCpuFromPrepared(
                A,
                B,
                prepared.noise,
                transcript_block_size,
                prepared.sigma,
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
    result.digest = ComputeDigestCpuFromPrepared(
        A,
        B,
        prepared.noise,
        transcript_block_size,
        prepared.sigma,
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

    if (blocks.size() == 1) {
        state->use_metal_single = true;
        state->single_submission = btx::metal::SubmitCanonicalTranscriptDigest({
            .n = n,
            .b = transcript_block_size,
            .r = noise_rank,
            .digest_mode = ToMetalDigestMode(digest_scheme),
            .sigma = prepared_batch[0].sigma,
            .matrix_a = use_uploaded_base ? nullptr : A.data(),
            .matrix_b = use_uploaded_base ? nullptr : B.data(),
            .use_uploaded_base_matrices = use_uploaded_base,
            .noise_e_l = prepared_batch[0].noise.E_L.data(),
            .noise_e_r = prepared_batch[0].noise.E_R.data(),
            .noise_f_l = prepared_batch[0].noise.F_L.data(),
            .noise_f_r = prepared_batch[0].noise.F_R.data(),
            .compress_vec = prepared_batch[0].compress_vec.data(),
        });
        if (!state->single_submission->submitted) {
            submission.error = state->single_submission->error;
        }
        submission.submitted = true;
        submission.opaque = state;
        return submission;
    }

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
        noise_e_l_ptrs.push_back(prepared.noise.E_L.data());
        noise_e_r_ptrs.push_back(prepared.noise.E_R.data());
        noise_f_l_ptrs.push_back(prepared.noise.F_L.data());
        noise_f_r_ptrs.push_back(prepared.noise.F_R.data());
        compress_ptrs.push_back(prepared.compress_vec.data());
        sigmas.push_back(prepared.sigma);
    }

    state->batch_submission = btx::metal::SubmitCanonicalTranscriptDigestBatch({
        .n = n,
        .b = transcript_block_size,
        .r = noise_rank,
        .batch_size = static_cast<uint32_t>(blocks.size()),
        .digest_mode = ToMetalDigestMode(digest_scheme),
        .sigmas = sigmas.data(),
        .matrix_a = use_uploaded_base ? nullptr : A.data(),
        .matrix_b = use_uploaded_base ? nullptr : B.data(),
        .use_uploaded_base_matrices = use_uploaded_base,
        .noise_e_l = noise_e_l_ptrs.data(),
        .noise_e_r = noise_e_r_ptrs.data(),
        .noise_f_l = noise_f_l_ptrs.data(),
        .noise_f_r = noise_f_r_ptrs.data(),
        .compress_vec = compress_ptrs.data(),
    });
    if (!state->batch_submission->submitted) {
        submission.error = state->batch_submission->error;
    }
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

    results.reserve(blocks.size());
    const uint32_t n = blocks.front().matmul_dim;
    const auto use_uploaded_base_retry = [&](auto&& retry_call) {
        if (!ShouldRetryMetalDigestWithoutUploadedBase(retry_call.error)) {
            return retry_call;
        }
        g_metal_retry_without_uploaded_base_attempts.fetch_add(1, std::memory_order_relaxed);
        return retry_call;
    };
    (void)use_uploaded_base_retry;

    if (state->use_metal_single) {
        auto metal_result = btx::metal::WaitForCanonicalTranscriptDigestSubmission(std::move(*state->single_submission));
        if (!metal_result.success &&
            ShouldRetryMetalDigestWithoutUploadedBase(metal_result.error)) {
            g_metal_retry_without_uploaded_base_attempts.fetch_add(1, std::memory_order_relaxed);
            auto retry_submission = btx::metal::SubmitCanonicalTranscriptDigest({
                .n = n,
                .b = transcript_block_size,
                .r = noise_rank,
                .digest_mode = ToMetalDigestMode(digest_scheme),
                .sigma = prepared_batch[0].sigma,
                .matrix_a = A.data(),
                .matrix_b = B.data(),
                .use_uploaded_base_matrices = false,
                .noise_e_l = prepared_batch[0].noise.E_L.data(),
                .noise_e_r = prepared_batch[0].noise.E_R.data(),
                .noise_f_l = prepared_batch[0].noise.F_L.data(),
                .noise_f_r = prepared_batch[0].noise.F_R.data(),
                .compress_vec = prepared_batch[0].compress_vec.data(),
            });
            auto retry_result = btx::metal::WaitForCanonicalTranscriptDigestSubmission(std::move(retry_submission));
            if (retry_result.success) {
                g_metal_retry_without_uploaded_base_successes.fetch_add(1, std::memory_order_relaxed);
                metal_result = std::move(retry_result);
            } else if (!retry_result.error.empty()) {
                metal_result.error = metal_result.error + "; retry_without_uploaded_base:" + retry_result.error;
            }
        }

        DigestResult result;
        if (metal_result.success) {
            result.backend = backend::Kind::METAL;
            result.accelerated = true;
            result.ok = true;
            result.digest = metal_result.digest;
#ifdef DEBUG
            const auto cpu_digest = ComputeDigestCpuFromPrepared(
                A,
                B,
                prepared_batch[0].noise,
                transcript_block_size,
                prepared_batch[0].sigma,
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
            results.push_back(std::move(result));
            return results;
        }

        LogBackendFallbackOnce(g_logged_metal_fallback, "METAL", metal_result.error);
        RecordMetalFallback(metal_result.error);
        result.digest = ComputeDigestCpuFromPrepared(
            A,
            B,
            prepared_batch[0].noise,
            transcript_block_size,
            prepared_batch[0].sigma,
            digest_scheme);
        result.backend = backend::Kind::CPU;
        result.accelerated = false;
        result.ok = true;
        result.error = "metal_backend_fallback_to_cpu:" + metal_result.error;
        results.push_back(std::move(result));
        return results;
    }

    auto batch_result = btx::metal::WaitForCanonicalTranscriptDigestBatchSubmission(std::move(*state->batch_submission));
    if (!batch_result.success &&
        ShouldRetryMetalDigestWithoutUploadedBase(batch_result.error)) {
        g_metal_retry_without_uploaded_base_attempts.fetch_add(1, std::memory_order_relaxed);
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
            noise_e_l_ptrs.push_back(prepared.noise.E_L.data());
            noise_e_r_ptrs.push_back(prepared.noise.E_R.data());
            noise_f_l_ptrs.push_back(prepared.noise.F_L.data());
            noise_f_r_ptrs.push_back(prepared.noise.F_R.data());
            compress_ptrs.push_back(prepared.compress_vec.data());
            sigmas.push_back(prepared.sigma);
        }

        auto retry_submission = btx::metal::SubmitCanonicalTranscriptDigestBatch({
            .n = n,
            .b = transcript_block_size,
            .r = noise_rank,
            .batch_size = static_cast<uint32_t>(blocks.size()),
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

    if (batch_result.success && batch_result.digests.size() == blocks.size()) {
        size_t metal_successes{0};
        for (size_t i = 0; i < blocks.size(); ++i) {
            DigestResult result;
            result.backend = backend::Kind::METAL;
            result.accelerated = true;
            result.ok = true;
            result.digest = batch_result.digests[i];
#ifdef DEBUG
            const auto cpu_digest = ComputeDigestCpuFromPrepared(
                A,
                B,
                prepared_batch[i].noise,
                transcript_block_size,
                prepared_batch[i].sigma,
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
        return results;
    }

    if (batch_result.success && batch_result.digests.size() != blocks.size()) {
        batch_result.error = "metal_batch_digest_size_mismatch";
    }
    LogBackendFallbackOnce(g_logged_metal_fallback, "METAL", batch_result.error);
    RecordMetalFallback(batch_result.error, blocks.size());
    for (size_t i = 0; i < blocks.size(); ++i) {
        DigestResult result;
        result.digest = ComputeDigestCpuFromPrepared(
            A,
            B,
            prepared_batch[i].noise,
            transcript_block_size,
            prepared_batch[i].sigma,
            digest_scheme);
        result.backend = backend::Kind::CPU;
        result.accelerated = false;
        result.ok = true;
        result.error = "metal_batch_backend_fallback_to_cpu:" + batch_result.error;
        results.push_back(std::move(result));
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
