// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <threadsafety.h>
#include <chain.h>
#include <crypto/kawpow.h>
#include <cuda/cuda_context.h>
#include <cuda/oracle_accel.h>
#include <cuda/cuda_scheduler.h>
#include <cuda/matmul_accel.h>
#include <hash.h>
#include <logging.h>
#include <matmul/accel_v4.h>
#include <matmul/accelerated_solver.h>
#include <matmul/field.h>
#include <matmul/freivalds.h>
#include <matmul/matmul_pow.h>
#include <matmul/matmul_v4_batch.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_bmx4_batch.h>
#include <matmul/noise.h>
#include <matmul/pow_v4.h>
#include <matmul/transcript.h>
#include <metal/matmul_accel.h>
#include <metal/oracle_accel.h>
#include <primitives/block.h>
#include <sync.h>
#include <uint256.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <deque>
#include <functional>
#include <future>
#include <limits>
#include <mutex>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

uint256 DeterministicMatMulSeed(const uint256& prev_block_hash, uint32_t height, uint8_t which,
                                std::optional<uint64_t> nonce)
{
    HashWriter hw;
    hw << prev_block_hash << height << which;
    // e1 fix (nonce-fold, flag-day gated): when a nonce is supplied, fold it into the seed so the
    // dense A*B product is nonce-DEPENDENT and cannot be precomputed once per tip and reused across
    // the whole nonce range (the ~12.8x amortization). The nonce is APPENDED so that the legacy
    // (no-nonce) derivation is byte-identical to before -- pre-activation blocks and genesis keep
    // their exact historical seeds. Callers pass the nonce only when IsMatMulNonceSeedActive(height).
    if (nonce.has_value()) {
        hw << *nonce;
    }
    return hw.GetSHA256();
}

uint256 DeterministicMatMulSeedV2(const CBlockHeader& block, uint32_t height, uint8_t which)
{
    HashWriter hw;
    hw << std::string{"BTX_MATMUL_SEED_V2"}
       << block.hashPrevBlock
       << height
       << block.nVersion
       << block.hashMerkleRoot
       << block.nTime
       << block.nBits
       << block.nNonce64
       << block.matmul_dim
       << which;
    return hw.GetSHA256();
}

uint256 DeterministicMatMulSeedV3(const CBlockHeader& block, uint32_t height, int64_t parent_median_time_past, uint8_t which)
{
    HashWriter hw;
    hw << std::string{"BTX_MATMUL_SEED_V3"}
       << block.hashPrevBlock
       << parent_median_time_past
       << height
       << block.nVersion
       << block.hashMerkleRoot
       << block.nTime
       << block.nBits
       << block.nNonce64
       << block.matmul_dim
       << which;
    return hw.GetSHA256();
}

bool SetDeterministicMatMulSeeds(
    CBlockHeader& block,
    const Consensus::Params& params,
    int32_t block_height,
    std::optional<int64_t> parent_median_time_past)
{
    if (block_height < 0) {
        block.seed_a.SetNull();
        block.seed_b.SetNull();
        return true;
    }
    // MatMul v4 (spec §H.4): seeds are unconditionally nonce- and parent-MTP-
    // bound at and above the v4 fork height, regardless of the legacy
    // nMatMulNonceSeedHeight / nMatMulParentMtpSeedHeight gates -- those are
    // subsumed by v4 activation (spec §G.3: "V4 seed rule is unconditionally
    // nonce- and parent-MTP-bound"). v4 reuses the existing V3 seed preimage
    // (prevhash, parent MTP, height, version, merkle, time, bits, nonce64,
    // dim, which) rather than introducing a new domain-separated scheme:
    // v3 and v4 heights are disjoint by construction (v4 only activates
    // above v3 history) and matmul_dim differs between every v3 network's
    // configured dimension and the v4 dimension, so no cross-version seed
    // collision is possible despite the shared "BTX_MATMUL_SEED_V3" label.
    if (params.IsMatMulV4Active(block_height)) {
        if (!parent_median_time_past.has_value()) {
            block.seed_a.SetNull();
            block.seed_b.SetNull();
            return false;
        }
        // MatMul v4.2 / ENC-BMX4C: the header seed FIELDS are pinned the SAME
        // self-reference-free way as ENC-S8 (DeterministicMatMulSeedV3 below),
        // which is idempotent, so ContextualCheckBlockHeader's recompute-and-
        // compare (bad-matmul-seeds) validates them. The ENC-BMX4C operand
        // DERIVATION (template-scoped A, nonce-fresh B, V4.2 domain tags) is a
        // SEPARATE step applied at digest/verify time by the bmx4 reference
        // (DeriveOperandSeedBMX4C) — it is NOT the header-field pinning.
        //
        // Audit W-1 (consensus-critical): pinning the header fields TO the operand
        // seeds is a self-reference bug. DeriveOperandSeedBMX4C(B) hashes the FULL
        // header including seed_b (ComputeMatMulHeaderHash, matmul_pow.cpp:240), so
        // seed_b := f(H(…, seed_b)) has no fixed point; the verifier recomputes a
        // different value and rejects EVERY honestly-mined block (a reject-all
        // liveness break on an enforcing network). Both profiles therefore pin the
        // fields via V3; operand A stays template-scoped regardless (its template
        // hash zeroes the seed fields), operand B binds the V3-pinned (nonce- and
        // parent-fresh) seed fields via the full header hash.
        block.seed_a = DeterministicMatMulSeedV3(block, static_cast<uint32_t>(block_height), *parent_median_time_past, 0);
        block.seed_b = DeterministicMatMulSeedV3(block, static_cast<uint32_t>(block_height), *parent_median_time_past, 1);
        return true;
    }
    if (params.IsMatMulParentMtpSeedActive(block_height)) {
        if (!parent_median_time_past.has_value()) {
            block.seed_a.SetNull();
            block.seed_b.SetNull();
            return false;
        }
        block.seed_a = DeterministicMatMulSeedV3(block, static_cast<uint32_t>(block_height), *parent_median_time_past, 0);
        block.seed_b = DeterministicMatMulSeedV3(block, static_cast<uint32_t>(block_height), *parent_median_time_past, 1);
        return true;
    }
    if (params.IsMatMulNonceSeedActive(block_height)) {
        block.seed_a = DeterministicMatMulSeedV2(block, static_cast<uint32_t>(block_height), 0);
        block.seed_b = DeterministicMatMulSeedV2(block, static_cast<uint32_t>(block_height), 1);
        return true;
    }

    block.seed_a = DeterministicMatMulSeed(block.hashPrevBlock, static_cast<uint32_t>(block_height), 0);
    block.seed_b = DeterministicMatMulSeed(block.hashPrevBlock, static_cast<uint32_t>(block_height), 1);
    return true;
}

namespace {
constexpr int64_t DGW_PAST_BLOCKS{180};
constexpr uint32_t DEFAULT_MINER_HEADER_TIME_REFRESH_ATTEMPTS{4'096U};
constexpr uint64_t MATMUL_V2_ABS_MAX_DIM{2048};
constexpr uint64_t MATMUL_V2_MAX_PAYLOAD_WORDS{MATMUL_V2_ABS_MAX_DIM * MATMUL_V2_ABS_MAX_DIM};
// MatMul v4 (spec §G.4 invariant #7 / §H.3): DoS-bound cap for the v4 sketch
// payload word count. The sketch profile (default; spec §0.7-(3)) is far
// smaller than n^2 words (~8 MiB at n=4096, b=4), so this remains a generous
// upper bound rather than a tight one; it exists only to reject an obviously
// oversized relayed payload before further processing.
constexpr uint64_t MATMUL_V4_ABS_MAX_DIM{8192};
// Tightened (audit F-L4): the sketch payload is exactly m*m F_q words at
// m = dim/b (b = matmul_v4::kTileB = 4), each F_q serialized as 2 uint32 words,
// so the maximum relayed word count is 2*(MATMUL_V4_ABS_MAX_DIM/4)^2 =
// 8,388,608 -- not dim^2 (which was 8x loose). ParseSketch's exact-size reject
// (payload.size() != m*m*8 bytes) remains the real gate; this is the coarse
// pre-parse DoS backstop, now sized to the true bound.
constexpr uint64_t MATMUL_V4_MAX_PAYLOAD_WORDS{
    2 * (MATMUL_V4_ABS_MAX_DIM / 4) * (MATMUL_V4_ABS_MAX_DIM / 4)};

// Byte<->word packing for the v4 sketch payload channel. matmul_v4::ComputeDigest
// / VerifySketch operate on a flat little-endian byte buffer (per the
// matmul_v4 API), but CBlock's existing trailing-payload relay field
// (matrix_c_data, reused per spec §H.2) is a vector<uint32_t>. These helpers
// are the one serialization seam between this file and src/matmul/pow_v4.h;
// mining (SolveMatMulV4) and verification (CheckMatMulProofOfWork_V4ProductCommitted)
// must use the same packing, which they do by sharing these functions.
std::vector<uint32_t> PackMatMulV4SketchBytesToWords(const std::vector<unsigned char>& bytes)
{
    std::vector<uint32_t> words((bytes.size() + 3) / 4, 0);
    for (size_t i = 0; i < bytes.size(); ++i) {
        words[i / 4] |= static_cast<uint32_t>(bytes[i]) << (8 * (i % 4));
    }
    return words;
}

std::vector<unsigned char> UnpackMatMulV4SketchWordsToBytes(const std::vector<uint32_t>& words)
{
    std::vector<unsigned char> bytes;
    bytes.reserve(words.size() * 4);
    for (uint32_t w : words) {
        bytes.push_back(static_cast<unsigned char>(w & 0xFF));
        bytes.push_back(static_cast<unsigned char>((w >> 8) & 0xFF));
        bytes.push_back(static_cast<unsigned char>((w >> 16) & 0xFF));
        bytes.push_back(static_cast<unsigned char>((w >> 24) & 0xFF));
    }
    return bytes;
}
constexpr int64_t WARMUP_HARDENING_MIN_NUM{5};
constexpr int64_t WARMUP_HARDENING_MIN_DEN{6};
constexpr int64_t WARMUP_EASING_MAX_NUM{3};
constexpr int64_t WARMUP_EASING_MAX_DEN{1};
constexpr int64_t NORMAL_LEGACY_HARDENING_MIN_NUM{2};
constexpr int64_t NORMAL_LEGACY_HARDENING_MIN_DEN{3};
constexpr int64_t NORMAL_LEGACY_EASING_MAX_NUM{3};
constexpr int64_t NORMAL_LEGACY_EASING_MAX_DEN{2};
constexpr int64_t NORMAL_HARDENED_HARDENING_MIN_NUM{3};
constexpr int64_t NORMAL_HARDENED_HARDENING_MIN_DEN{4};
constexpr int64_t NORMAL_HARDENED_EASING_MAX_NUM{2};
constexpr int64_t NORMAL_HARDENED_EASING_MAX_DEN{1};
constexpr int64_t NORMAL_BOOSTED_EASING_MAX_NUM{3};
constexpr int64_t NORMAL_BOOSTED_EASING_MAX_DEN{1};
constexpr unsigned int NORMAL_SLEW_GUARD_SHIFT{2}; // 4x max change per block
constexpr uint8_t ASERT_RADIX_BITS{16};
// aserti3-2d fixed-point cubic approximation coefficients.
//
// For frac in [0, 2^16):
//   factor = 2^16 + ((C1*frac + C2*frac^2 + C3*frac^3 + 2^47) >> 48)
//
// This approximates 2^(frac / 2^16) deterministically with integer arithmetic.
// The constants match the BCH reference implementation and avoid floating point
// behavior in consensus code.
constexpr uint64_t ASERT_POLY_COEFF_1{195766423245049ULL};
constexpr uint64_t ASERT_POLY_COEFF_2{971821376ULL};
constexpr uint64_t ASERT_POLY_COEFF_3{5127ULL};
constexpr int64_t WARMUP_RESTART_GAP_THRESHOLD_MULTIPLIER{2};
constexpr int64_t WARMUP_RESTART_GAP_DAMPING_DIVISOR{2};
std::atomic<uint64_t> g_matmul_prepared_inputs{0};
std::atomic<uint64_t> g_matmul_overlapped_prepares{0};
std::atomic<uint64_t> g_matmul_prefetched_batches{0};
std::atomic<uint64_t> g_matmul_prefetched_inputs{0};
std::atomic<uint32_t> g_matmul_prefetch_depth{1};
std::atomic<uint32_t> g_matmul_batch_size{1};
std::atomic<uint64_t> g_matmul_batched_digest_requests{0};
std::atomic<uint64_t> g_matmul_batched_nonce_attempts{0};
std::atomic_bool g_matmul_parallel_solver_enabled{false};
std::atomic<uint32_t> g_matmul_parallel_solver_threads{1};
std::atomic_bool g_matmul_async_prepare_enabled{false};
std::atomic<uint64_t> g_matmul_async_prepare_submissions{0};
std::atomic<uint64_t> g_matmul_async_prepare_completions{0};
std::atomic<uint32_t> g_matmul_async_prepare_worker_threads{0};
std::atomic_bool g_matmul_cpu_confirm_candidates{false};
std::atomic_bool g_matmul_digest_compare_enabled{false};
std::atomic<uint64_t> g_matmul_digest_compare_attempts{0};
std::atomic_bool g_matmul_digest_compare_first_divergence{false};
std::atomic_bool g_logged_backend_requirement_failure{false};
std::atomic_bool g_logged_cuda_nonce_seed_scan_fallback{false};
std::atomic_bool g_logged_metal_nonce_seed_scan_fallback{false};
std::atomic<uint64_t> g_matmul_gpu_prehash_scan_attempts{0};
std::atomic<uint64_t> g_matmul_gpu_prehash_scan_successes{0};
std::atomic<uint64_t> g_matmul_gpu_prehash_scan_failures{0};
std::atomic<uint64_t> g_matmul_metal_nonce_seed_scan_fallbacks{0};
std::atomic<uint64_t> g_matmul_cuda_nonce_seed_scan_fallbacks{0};
std::atomic<uint64_t> g_matmul_solve_attempts{0};
std::atomic<uint64_t> g_matmul_solve_successes{0};
std::atomic<uint64_t> g_matmul_solve_failures{0};
std::atomic<uint64_t> g_matmul_solve_total_elapsed_us{0};
std::atomic<uint64_t> g_matmul_solve_last_elapsed_us{0};
std::atomic<uint64_t> g_matmul_solve_max_elapsed_us{0};
std::atomic<uint64_t> g_matmul_validation_phase2_checks{0};
std::atomic<uint64_t> g_matmul_validation_freivalds_checks{0};
std::atomic<uint64_t> g_matmul_validation_transcript_checks{0};
std::atomic<uint64_t> g_matmul_validation_successes{0};
std::atomic<uint64_t> g_matmul_validation_failures{0};
std::atomic<uint64_t> g_matmul_validation_total_phase2_elapsed_us{0};
std::atomic<uint64_t> g_matmul_validation_total_freivalds_elapsed_us{0};
std::atomic<uint64_t> g_matmul_validation_total_transcript_elapsed_us{0};
std::atomic<uint64_t> g_matmul_validation_last_phase2_elapsed_us{0};
std::atomic<uint64_t> g_matmul_validation_last_freivalds_elapsed_us{0};
std::atomic<uint64_t> g_matmul_validation_last_transcript_elapsed_us{0};
std::atomic<uint64_t> g_matmul_validation_max_phase2_elapsed_us{0};
std::atomic<uint64_t> g_matmul_validation_max_freivalds_elapsed_us{0};
std::atomic<uint64_t> g_matmul_validation_max_transcript_elapsed_us{0};
std::mutex g_matmul_digest_compare_mutex;
uint64_t g_matmul_digest_compare_nonce64{0};
uint32_t g_matmul_digest_compare_nonce32{0};
std::string g_matmul_digest_compare_header_hash;
std::string g_matmul_digest_compare_backend_digest;
std::string g_matmul_digest_compare_cpu_digest;
std::mutex g_matmul_gpu_prehash_scan_mutex;
std::string g_matmul_gpu_prehash_scan_last_backend;
std::string g_matmul_gpu_prehash_scan_last_error;
GlobalMutex g_matmul_global_phase2_mutex;
uint32_t g_matmul_global_phase2_this_minute GUARDED_BY(g_matmul_global_phase2_mutex){0};
int64_t g_matmul_global_phase2_window_start_sec GUARDED_BY(g_matmul_global_phase2_mutex){0};

enum class MatMulValidationPath {
    FREIVALDS,
    TRANSCRIPT,
};

void UpdateMaxAtomic(std::atomic<uint64_t>& target, uint64_t candidate)
{
    uint64_t observed = target.load(std::memory_order_relaxed);
    while (observed < candidate &&
           !target.compare_exchange_weak(
               observed,
               candidate,
               std::memory_order_relaxed,
               std::memory_order_relaxed)) {}
}

uint64_t DurationMicros(std::chrono::steady_clock::duration elapsed)
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
}

void RegisterMatMulSolveRuntimeSample(bool solved, std::chrono::steady_clock::duration elapsed)
{
    const uint64_t elapsed_us = DurationMicros(elapsed);
    g_matmul_solve_attempts.fetch_add(1, std::memory_order_relaxed);
    if (solved) {
        g_matmul_solve_successes.fetch_add(1, std::memory_order_relaxed);
    } else {
        g_matmul_solve_failures.fetch_add(1, std::memory_order_relaxed);
    }
    g_matmul_solve_total_elapsed_us.fetch_add(elapsed_us, std::memory_order_relaxed);
    g_matmul_solve_last_elapsed_us.store(elapsed_us, std::memory_order_relaxed);
    UpdateMaxAtomic(g_matmul_solve_max_elapsed_us, elapsed_us);
}

void LogMatMulBackendRequirementFailureOnce(const std::string& reason)
{
    bool expected{false};
    if (g_logged_backend_requirement_failure.compare_exchange_strong(expected, true)) {
        LogPrintf("MATMUL ERROR: required mining backend not satisfied (%s)\n", reason);
    }
}

bool CheckRequiredMatMulBackend(const matmul::accelerated::BackendRequirement& requirement,
                                const matmul::backend::Selection& selection,
                                const char* context)
{
    if (matmul::accelerated::IsBackendRequirementSatisfied(requirement, selection)) {
        return true;
    }

    const std::string requested_label = selection.requested_known
        ? matmul::backend::ToString(selection.requested)
        : selection.requested_input;
    const std::string reason = strprintf(
        "context=%s required=%s valid=%s requested=%s active=%s selection_reason=%s requirement_reason=%s",
        context,
        requirement.input,
        requirement.valid ? "true" : "false",
        requested_label,
        matmul::backend::ToString(selection.active),
        selection.reason,
        requirement.reason);
    LogMatMulBackendRequirementFailureOnce(reason);
    return false;
}

bool CheckRequiredMatMulDigestBackend(const matmul::accelerated::BackendRequirement& requirement,
                                      const matmul::accelerated::DigestResult& digest_result,
                                      const char* context)
{
    if (!requirement.enabled || !requirement.valid) {
        return true;
    }
    if (digest_result.backend == requirement.required) {
        return true;
    }

    const std::string reason = strprintf(
        "context=%s required=%s result_backend=%s digest_error=%s",
        context,
        matmul::backend::ToString(requirement.required),
        matmul::backend::ToString(digest_result.backend),
        digest_result.error);
    LogMatMulBackendRequirementFailureOnce(reason);
    return false;
}

void RegisterMatMulValidationRuntimeSample(
    MatMulValidationPath path,
    bool passed,
    std::chrono::steady_clock::duration elapsed)
{
    const uint64_t elapsed_us = DurationMicros(elapsed);
    g_matmul_validation_phase2_checks.fetch_add(1, std::memory_order_relaxed);
    g_matmul_validation_total_phase2_elapsed_us.fetch_add(elapsed_us, std::memory_order_relaxed);
    g_matmul_validation_last_phase2_elapsed_us.store(elapsed_us, std::memory_order_relaxed);
    UpdateMaxAtomic(g_matmul_validation_max_phase2_elapsed_us, elapsed_us);

    if (path == MatMulValidationPath::FREIVALDS) {
        g_matmul_validation_freivalds_checks.fetch_add(1, std::memory_order_relaxed);
        g_matmul_validation_total_freivalds_elapsed_us.fetch_add(elapsed_us, std::memory_order_relaxed);
        g_matmul_validation_last_freivalds_elapsed_us.store(elapsed_us, std::memory_order_relaxed);
        UpdateMaxAtomic(g_matmul_validation_max_freivalds_elapsed_us, elapsed_us);
    } else {
        g_matmul_validation_transcript_checks.fetch_add(1, std::memory_order_relaxed);
        g_matmul_validation_total_transcript_elapsed_us.fetch_add(elapsed_us, std::memory_order_relaxed);
        g_matmul_validation_last_transcript_elapsed_us.store(elapsed_us, std::memory_order_relaxed);
        UpdateMaxAtomic(g_matmul_validation_max_transcript_elapsed_us, elapsed_us);
    }

    if (passed) {
        g_matmul_validation_successes.fetch_add(1, std::memory_order_relaxed);
    } else {
        g_matmul_validation_failures.fetch_add(1, std::memory_order_relaxed);
    }
}

uint32_t ResolveCudaMultiprocessorCountForHeuristics()
{
    static const uint32_t sm_count = [] {
        const auto probe = btx::cuda::ProbeMatMulDigestAcceleration();
        return probe.available ? probe.multiprocessor_count : 0U;
    }();
    return sm_count;
}

uint32_t ExpandCudaAutoBatchSizeForSelectedDevices(uint32_t batch_size)
{
    const auto topology = btx::cuda::ProbeCudaTopology();
    return btx::cuda::ExpandCudaBatchSizeForSelectedDevices(batch_size, topology.selected_devices.size());
}

std::optional<int32_t> ResolveEnvInt32Override(const char* name)
{
    const char* env = std::getenv(name);
    if (env == nullptr || env[0] == '\0') {
        return std::nullopt;
    }

    int32_t parsed{0};
    if (!ParseInt32(env, &parsed)) {
        return std::nullopt;
    }
    return parsed;
}

int32_t ResolveApplePerformanceLogicalCpuCount()
{
    if (const auto override = ResolveEnvInt32Override("BTX_MATMUL_APPLE_PERFLEVEL0_LOGICALCPU_OVERRIDE")) {
        return *override;
    }

#if defined(__APPLE__)
    int32_t perf_level0_logicalcpu{0};
    size_t perf_level0_size{sizeof(perf_level0_logicalcpu)};
    if (sysctlbyname("hw.perflevel0.logicalcpu",
                     &perf_level0_logicalcpu,
                     &perf_level0_size,
                     nullptr,
                     0) == 0 &&
        perf_level0_size == sizeof(perf_level0_logicalcpu) &&
        perf_level0_logicalcpu > 0) {
        return perf_level0_logicalcpu;
    }
#endif
    return 0;
}

bool IsHighPerfAppleMetalHost(int32_t perf_level0_logicalcpu)
{
    return perf_level0_logicalcpu >= 10;
}

bool IsConservativeAppleMetalHost(int32_t perf_level0_logicalcpu)
{
    return perf_level0_logicalcpu > 0 && perf_level0_logicalcpu <= 4;
}

uint32_t ResolveMetalGpuCoreCountForHeuristics()
{
    if (const auto override = ResolveEnvInt32Override("BTX_MATMUL_METAL_GPU_CORES_OVERRIDE")) {
        return *override > 0 ? static_cast<uint32_t>(*override) : 0U;
    }

    static const uint32_t gpu_core_count = [] {
        const auto info = btx::metal::ProbeMatMulDeviceInfo();
        return info.available ? info.gpu_core_count : 0U;
    }();
    return gpu_core_count;
}

int32_t ResolveDefaultMatMulPrepareWorkerCount()
{
#if defined(__APPLE__)
    const int32_t perf_level0_logicalcpu = ResolveApplePerformanceLogicalCpuCount();
    if (perf_level0_logicalcpu > 0) {
        // High-end Apple Silicon desktops still benefit from leaving some
        // performance cores for the foreground solve threads and Metal command
        // submission rather than consuming the whole perf cluster with prepare
        // workers.
        if (IsHighPerfAppleMetalHost(perf_level0_logicalcpu)) {
            return 5;
        }

        // Keep one performance core free for the foreground solve loop and
        // let the async prepare pool consume only the remaining performance
        // cores. Local Apple Silicon mining benchmarks consistently beat the
        // old hw-1 heuristic with this split.
        return std::clamp<int32_t>(perf_level0_logicalcpu - 1, 1, 4);
    }
#endif

    const uint32_t hw = std::thread::hardware_concurrency();
    const auto backend_selection = matmul::accelerated::ResolveMiningBackendFromEnvironment();
    if (backend_selection.active == matmul::backend::Kind::CUDA) {
        const uint32_t cuda_sm_count = ResolveCudaMultiprocessorCountForHeuristics();
        if (cuda_sm_count >= 96 && hw >= 16) {
            return std::clamp<int32_t>(static_cast<int32_t>(hw / 2), 2, 8);
        }
        if (cuda_sm_count >= 64 && hw >= 12) {
            return std::clamp<int32_t>(static_cast<int32_t>((hw + 1) / 3), 2, 6);
        }
        if (cuda_sm_count >= 48 && hw >= 8) {
            return std::clamp<int32_t>(static_cast<int32_t>((hw + 1) / 4), 2, 5);
        }
    }
    if (hw <= 1) return 1;
    if (hw == 2) return 2;
    return std::min<uint32_t>(hw - 1, 4);
}

int32_t ResolveMetalAutoSolverThreadCount()
{
#if defined(__APPLE__)
    const int32_t perf_level0_logicalcpu = ResolveApplePerformanceLogicalCpuCount();
    if (perf_level0_logicalcpu > 0) {
        if (IsHighPerfAppleMetalHost(perf_level0_logicalcpu)) {
            return 6;
        }

        if (IsConservativeAppleMetalHost(perf_level0_logicalcpu)) {
            return 1;
        }

        // Mirror the Apple prepare-worker split so the default Metal policy
        // keeps solver fanout and host-side preparation in the same range.
        return std::clamp<int32_t>(perf_level0_logicalcpu - 1, 1, 4);
    }
#endif

    const uint32_t hw = std::thread::hardware_concurrency();
    if (hw >= 12) {
        return 4;
    }
    if (hw >= 8) {
        return 3;
    }
    if (hw >= 4) {
        return 2;
    }
    return 1;
}

int32_t ResolveMatMulSolverThreadCount();

int32_t ResolveMatMulPrepareWorkerCount()
{
    const char* env = std::getenv("BTX_MATMUL_PREPARE_WORKERS");
    if (env != nullptr && env[0] != '\0') {
        int32_t parsed{0};
        if (ParseInt32(env, &parsed) && parsed > 0) {
            return std::min<int32_t>(parsed, 16);
        }
    }

    const int32_t default_workers = ResolveDefaultMatMulPrepareWorkerCount();
    const auto backend_selection = matmul::accelerated::ResolveMiningBackendFromEnvironment();
    if (backend_selection.active == matmul::backend::Kind::METAL) {
        const int32_t solver_threads = ResolveMatMulSolverThreadCount();
        if (solver_threads > 1) {
            return std::min(default_workers, solver_threads);
        }
    }
    return default_workers;
}

int32_t ResolveMatMulSolverThreadCount()
{
    const char* env = std::getenv("BTX_MATMUL_SOLVER_THREADS");
    if (env != nullptr && env[0] != '\0') {
        int32_t parsed{0};
        if (!ParseInt32(env, &parsed) || parsed <= 0) {
            return 1;
        }
        return std::clamp<int32_t>(parsed, 1, 32);
    }

    const auto backend_selection = matmul::accelerated::ResolveMiningBackendFromEnvironment();
    if (backend_selection.active == matmul::backend::Kind::METAL) {
        return ResolveMetalAutoSolverThreadCount();
    }
    if (backend_selection.active == matmul::backend::Kind::CUDA) {
        const uint32_t cuda_sm_count = ResolveCudaMultiprocessorCountForHeuristics();
        const uint32_t hw = std::thread::hardware_concurrency();
        if (cuda_sm_count >= 96) {
            if (hw >= 24) {
                return 8;
            }
            if (hw >= 16) {
                return 6;
            }
            if (hw >= 12) {
                return 5;
            }
        }
        if (cuda_sm_count >= 64) {
            if (hw >= 16) {
                return 6;
            }
            if (hw >= 12) {
                return 5;
            }
            if (hw >= 8) {
                return 4;
            }
        }
        if (cuda_sm_count >= 48) {
            if (hw >= 16) {
                return 5;
            }
            if (hw >= 12) {
                return 4;
            }
            if (hw >= 8) {
                return 3;
            }
        }
        if (hw >= 16) {
            return 4;
        }
        if (hw >= 12) {
            return 3;
        }
        if (hw >= 8) {
            return 2;
        }
        return 1;
    }

    return 1;
}

bool HasExplicitMatMulSolverThreadOverride()
{
    const char* env = std::getenv("BTX_MATMUL_SOLVER_THREADS");
    return env != nullptr && env[0] != '\0';
}

bool ShouldAutoEnableMetalParallelSolver(uint32_t n,
                                         uint32_t transcript_block_size,
                                         uint32_t noise_rank,
                                         bool product_digest_active)
{
    return product_digest_active &&
        n >= 512 &&
        transcript_block_size >= 16 &&
        noise_rank >= 8;
}

bool ShouldEnableParallelMatMulSolve(matmul::backend::Kind backend,
                                     uint32_t solver_threads,
                                     uint32_t n,
                                     uint32_t transcript_block_size,
                                     uint32_t noise_rank,
                                     bool product_digest_active)
{
    if (solver_threads <= 1) {
        return false;
    }
    if (backend != matmul::backend::Kind::METAL) {
        return true;
    }
    if (HasExplicitMatMulSolverThreadOverride()) {
        return true;
    }
    return ShouldAutoEnableMetalParallelSolver(
        n,
        transcript_block_size,
        noise_rank,
        product_digest_active);
}

class MatMulPrepareExecutor
{
public:
    explicit MatMulPrepareExecutor(size_t worker_count)
    {
        EnsureWorkerCount(worker_count);
    }

    ~MatMulPrepareExecutor()
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stopping = true;
        }
        m_cv.notify_all();
        for (auto& worker : m_workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        g_matmul_async_prepare_worker_threads.store(0, std::memory_order_relaxed);
    }

    std::future<matmul::accelerated::PreparedDigestInputs> Submit(
        std::function<matmul::accelerated::PreparedDigestInputs()> task)
    {
        QueueItem item;
        item.task = std::move(task);
        std::future<matmul::accelerated::PreparedDigestInputs> future = item.promise.get_future();
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_stopping) {
                throw std::runtime_error("MatMulPrepareExecutor is stopping");
            }
            m_queue.emplace_back(std::move(item));
        }
        g_matmul_async_prepare_submissions.fetch_add(1, std::memory_order_relaxed);
        m_cv.notify_one();
        return future;
    }

    void EnsureWorkerCount(size_t worker_count)
    {
        worker_count = std::max<size_t>(worker_count, 1);
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_stopping) {
            throw std::runtime_error("MatMulPrepareExecutor is stopping");
        }
        if (worker_count <= m_workers.size()) {
            g_matmul_async_prepare_worker_threads.store(
                static_cast<uint32_t>(m_workers.size()),
                std::memory_order_relaxed);
            return;
        }
        m_workers.reserve(worker_count);
        while (m_workers.size() < worker_count) {
            m_workers.emplace_back([this] { WorkerLoop(); });
        }
        g_matmul_async_prepare_worker_threads.store(
            static_cast<uint32_t>(m_workers.size()),
            std::memory_order_relaxed);
    }

private:
    struct QueueItem {
        std::function<matmul::accelerated::PreparedDigestInputs()> task;
        std::promise<matmul::accelerated::PreparedDigestInputs> promise;
    };

    void WorkerLoop()
    {
        while (true) {
            QueueItem item;
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait(lock, [this] { return m_stopping || !m_queue.empty(); });
                if (m_stopping && m_queue.empty()) return;
                item = std::move(m_queue.front());
                m_queue.pop_front();
            }

            try {
                item.promise.set_value(item.task());
            } catch (...) {
                item.promise.set_exception(std::current_exception());
            }
            g_matmul_async_prepare_completions.fetch_add(1, std::memory_order_relaxed);
        }
    }

    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<QueueItem> m_queue;
    std::vector<std::thread> m_workers;
    bool m_stopping{false};
};

MatMulPrepareExecutor& GetMatMulPrepareExecutor()
{
    static MatMulPrepareExecutor executor{static_cast<size_t>(ResolveMatMulPrepareWorkerCount())};
    executor.EnsureWorkerCount(static_cast<size_t>(ResolveMatMulPrepareWorkerCount()));
    return executor;
}

thread_local bool g_matmul_parallel_worker_context{false};

class ScopedMatMulParallelWorkerContext
{
public:
    ScopedMatMulParallelWorkerContext()
        : m_previous(g_matmul_parallel_worker_context)
    {
        g_matmul_parallel_worker_context = true;
    }

    ~ScopedMatMulParallelWorkerContext()
    {
        g_matmul_parallel_worker_context = m_previous;
    }

private:
    bool m_previous;
};

arith_uint256 SaturatingLeftShift256(const arith_uint256& val, unsigned int shift)
{
    if (shift == 0 || val == arith_uint256(0)) return val;
    if (shift >= 256) return (val == arith_uint256(0)) ? arith_uint256(0) : ~arith_uint256(0);
    arith_uint256 mask = ~arith_uint256(0);
    mask >>= shift;
    if (val > mask) return ~arith_uint256(0);  // saturate
    return val << shift;
}

uint64_t EstimatePreHashGateSpacing(const arith_uint256& pre_hash_target)
{
    if (pre_hash_target == arith_uint256(0)) {
        return std::numeric_limits<uint64_t>::max();
    }
    const arith_uint256 quotient = ~arith_uint256(0) / pre_hash_target;
    if (quotient.bits() > 63) {
        return std::numeric_limits<uint64_t>::max();
    }
    return std::max<uint64_t>(uint64_t{1}, quotient.GetLow64() + uint64_t{1});
}

arith_uint256 ClampRetargetResult(arith_uint256 target, const arith_uint256& pow_limit)
{
    // Never emit an unencodable/invalid compact target.
    if (target == 0) {
        target = arith_uint256{1};
    }
    if (target > pow_limit) {
        target = pow_limit;
    }
    return target;
}

arith_uint256 SaturatingMultiplyByUint32(const arith_uint256& value, uint32_t factor)
{
    if (value == 0 || factor == 0) {
        return arith_uint256{0};
    }
    const arith_uint256 max_uint{~arith_uint256{}};
    if (value > (max_uint / factor)) {
        return max_uint;
    }
    return value * factor;
}

arith_uint256 ScaleTargetByTimespan(const arith_uint256& target, int64_t actual_timespan, int64_t target_timespan)
{
    if (actual_timespan <= 0) {
        LogWarning("ScaleTargetByTimespan: actual_timespan=%lld is non-positive, clamping to 1\n",
                   static_cast<long long>(actual_timespan));
        actual_timespan = 1;
    }
    if (target_timespan <= 0) {
        LogWarning("ScaleTargetByTimespan: target_timespan=%lld is non-positive, clamping to 1\n",
                   static_cast<long long>(target_timespan));
        target_timespan = 1;
    }
    if (actual_timespan > std::numeric_limits<uint32_t>::max()) {
        LogWarning("ScaleTargetByTimespan: actual_timespan=%lld exceeds uint32_t max, clamping\n",
                   static_cast<long long>(actual_timespan));
        actual_timespan = std::numeric_limits<uint32_t>::max();
    }
    if (target_timespan > std::numeric_limits<uint32_t>::max()) {
        LogWarning("ScaleTargetByTimespan: target_timespan=%lld exceeds uint32_t max, clamping\n",
                   static_cast<long long>(target_timespan));
        target_timespan = std::numeric_limits<uint32_t>::max();
    }

    const uint32_t actual_u{static_cast<uint32_t>(actual_timespan)};
    const uint32_t target_u{static_cast<uint32_t>(target_timespan)};

    // Compute floor(target * actual / target_timespan) without intermediate
    // overflow in the 256-bit multiply step.
    const arith_uint256 max_uint{~arith_uint256{}};
    arith_uint256 quotient{target};
    quotient /= target_u;

    arith_uint256 remainder{target - (quotient * target_u)};
    if (quotient > (max_uint / actual_u)) {
        return max_uint;
    }

    arith_uint256 scaled{quotient * actual_u};
    remainder *= actual_u;
    remainder /= target_u;

    if (scaled > (max_uint - remainder)) {
        return max_uint;
    }
    scaled += remainder;
    return scaled;
}

} // namespace

// AUDIT D1/D3: these two helpers are declared in pow.h and referenced from other
// translation units (chainparams.cpp for construction-time validation, unit
// tests), so they must have EXTERNAL linkage -- keep them OUTSIDE the anonymous
// namespace that wraps the rest of pow.cpp's internals.
bool ReduceRescaleRatioToU32(int64_t num, int64_t den, uint32_t& out_num, uint32_t& out_den)
{
    // AUDIT D3: reduce a one-time ASERT rescale ratio num/den to lowest terms and
    // confirm BOTH reduced terms fit in uint32. ScaleTargetByTimespan clamps each
    // of its two scale arguments to UINT32_MAX independently, so a large but
    // exactly-valued ratio -- e.g. 2^40 / 2^39 (= 2) -- would otherwise be mangled
    // into UINT32_MAX / UINT32_MAX (= 1), silently distorting a calibrated fork
    // rescale. GCD reduction makes such ratios exact; a ratio that is STILL larger
    // than UINT32_MAX after reduction (an irreducible >4.29e9 rational) is not a
    // usable difficulty calibration and is rejected. Callers treat rejection as a
    // fatal construction error / consensus-halt condition, NEVER as powLimit.
    if (num <= 0 || den <= 0) return false;
    const int64_t g{std::gcd(num, den)};
    const int64_t rn{num / g};
    const int64_t rd{den / g};
    if (rn > std::numeric_limits<uint32_t>::max() || rd > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    out_num = static_cast<uint32_t>(rn);
    out_den = static_cast<uint32_t>(rd);
    return true;
}

unsigned int MatMulAsertFailClosedBits()
{
    // AUDIT D1: a runtime ASERT-configuration invariant breach must NOT weaken
    // difficulty. Returning powLimit (the EASIEST target) is fail-OPEN and
    // directly exploitable -- a malformed (even future-dated) parameter set would
    // collapse CURRENT difficulty the moment the binary starts. Return the hardest
    // representable target instead so the calculation fails CLOSED: mining halts
    // (a loud, safe liveness stop) rather than difficulty collapsing. This path is
    // UNREACHABLE in a validly-configured node because the immutable ASERT
    // parameters are validated fatally at chain-parameter construction
    // (AssertBMX4CConstructionInvariants -> ValidateMatMulAsertParams); it exists purely as a
    // defence-in-depth backstop that cannot be turned into a difficulty-weakening
    // exploit.
    return arith_uint256{1}.GetCompact();
}

namespace {

arith_uint256 ApplyDgwSlewGuard(
    arith_uint256 candidate_target,
    const arith_uint256& parent_target,
    int32_t next_height,
    const Consensus::Params& params)
{
    if (next_height < params.nDgwSlewGuardHeight) {
        return candidate_target;
    }

    // Limit easing: next target cannot become more than 4x easier than parent.
    const arith_uint256 max_ease_target = SaturatingLeftShift256(parent_target, NORMAL_SLEW_GUARD_SHIFT);
    if (candidate_target > max_ease_target) {
        candidate_target = max_ease_target;
    }

    // Limit hardening: next target cannot become more than 4x harder than parent.
    arith_uint256 min_harden_target = parent_target;
    min_harden_target >>= NORMAL_SLEW_GUARD_SHIFT;
    if (min_harden_target == 0) {
        min_harden_target = arith_uint256{1};
    }
    if (candidate_target < min_harden_target) {
        candidate_target = min_harden_target;
    }

    return candidate_target;
}

bool IsDisabledHeight(int32_t h)
{
    return h == std::numeric_limits<int32_t>::max();
}

bool IsMatMulAsertHalfLifeUpgradeConfigured(const Consensus::Params& params)
{
    return !IsDisabledHeight(params.nMatMulAsertHalfLifeUpgradeHeight);
}

bool IsMatMulPreHashEpsilonBitsUpgradeConfigured(const Consensus::Params& params)
{
    return !IsDisabledHeight(params.nMatMulPreHashEpsilonBitsUpgradeHeight);
}

int32_t LatestMatMulAsertPreUpgradeAnchorHeight(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    int32_t anchor_height = params.nMatMulAsertHeight;
    if (pindexLast == nullptr) {
        return anchor_height;
    }
    if (params.nMatMulAsertRetune2Height >= params.nMatMulAsertHeight &&
        pindexLast->nHeight >= params.nMatMulAsertRetune2Height) {
        anchor_height = params.nMatMulAsertRetune2Height;
    } else if (params.nMatMulAsertRetuneHeight >= params.nMatMulAsertHeight &&
               pindexLast->nHeight >= params.nMatMulAsertRetuneHeight) {
        anchor_height = params.nMatMulAsertRetuneHeight;
    }
    // MatMul v4 (spec §I.4): the one-time v4 rescale re-anchors ASERT at
    // nMatMulV4Height, mechanically identical to the retune2 anchor above.
    // v4 is always the latest chronological hard fork on any network that
    // activates it, so this unconditionally wins over any earlier retune/
    // retune2 anchor once the tip has passed it.
    if (!IsDisabledHeight(params.nMatMulV4Height) &&
        pindexLast->nHeight >= params.nMatMulV4Height &&
        params.nMatMulV4Height > anchor_height) {
        anchor_height = params.nMatMulV4Height;
    }
    // MatMul v4.2 / ENC-BMX4C (B2b): the one-time BMX4-C rescale re-anchors
    // ASERT at nMatMulBMX4CHeight, mechanically identical to the v4 anchor
    // above. ENC-BMX4C forks strictly above the v4 height by construction, so
    // once the tip passes it, it is the latest chronological fork and wins over
    // any earlier v4/retune/retune2 anchor.
    if (!IsDisabledHeight(params.nMatMulBMX4CHeight) &&
        pindexLast->nHeight >= params.nMatMulBMX4CHeight &&
        params.nMatMulBMX4CHeight > anchor_height) {
        anchor_height = params.nMatMulBMX4CHeight;
    }
    return anchor_height;
}

MatMulAsertHalfLifeInfo ResolveMatMulAsertHalfLifeInfo(
    const CBlockIndex* pindexLast,
    const Consensus::Params& params)
{
    MatMulAsertHalfLifeInfo info;
    info.current_half_life_s = params.nMatMulAsertHalfLife;
    info.current_anchor_height = LatestMatMulAsertPreUpgradeAnchorHeight(pindexLast, params);
    info.upgrade_configured = IsMatMulAsertHalfLifeUpgradeConfigured(params);
    info.upgrade_height = info.upgrade_configured ? params.nMatMulAsertHalfLifeUpgradeHeight : -1;
    info.upgrade_half_life_s = info.upgrade_configured ? params.nMatMulAsertHalfLifeUpgrade : params.nMatMulAsertHalfLife;

    if (info.upgrade_configured &&
        pindexLast != nullptr &&
        pindexLast->nHeight >= params.nMatMulAsertHalfLifeUpgradeHeight) {
        info.upgrade_active = true;
        info.current_half_life_s = params.nMatMulAsertHalfLifeUpgrade;
        // Audit C4: the ASERT ANCHOR is the LATEST re-anchor point the tip has
        // passed. The half-life upgrade re-anchors at its own height, but a v4 or
        // BMX4C rescale that forks AFTER it is a later re-anchor and must win --
        // previously this unconditionally overrode to the upgrade height,
        // discarding a later rescale (unwinding a calibrated fork target). Take
        // the max so any legal ordering (upgrade before OR after the rescales) is
        // handled without a restrictive validation guard. The half-life VALUE is
        // orthogonal and correctly upgrades once the tip passes the upgrade height.
        info.current_anchor_height =
            std::max(info.current_anchor_height, params.nMatMulAsertHalfLifeUpgradeHeight);
    }

    return info;
}

MatMulPreHashEpsilonBitsInfo ResolveMatMulPreHashEpsilonBitsInfo(
    int32_t current_tip_height,
    const Consensus::Params& params)
{
    MatMulPreHashEpsilonBitsInfo info;
    info.current_bits = params.GetMatMulPreHashEpsilonBitsForHeight(current_tip_height);
    const int32_t next_height =
        current_tip_height < std::numeric_limits<int32_t>::max() ? current_tip_height + 1 : current_tip_height;
    info.next_block_bits = params.GetMatMulPreHashEpsilonBitsForHeight(next_height);
    info.upgrade_configured = IsMatMulPreHashEpsilonBitsUpgradeConfigured(params);
    info.upgrade_active = params.IsMatMulPreHashEpsilonBitsUpgradeActive(current_tip_height);
    info.upgrade_height = info.upgrade_configured ? params.nMatMulPreHashEpsilonBitsUpgradeHeight : -1;
    info.upgrade_bits = info.upgrade_configured ? params.nMatMulPreHashEpsilonBitsUpgrade : params.nMatMulPreHashEpsilonBits;
    return info;
}

} // namespace

// AUDIT D1: ValidateMatMulAsertParams is declared in pow.h and invoked from
// chainparams.cpp at construction time (fatal-on-invalid startup), so it needs
// EXTERNAL linkage -- keep it outside the anonymous namespace. It still freely
// calls the internal-linkage helpers defined above it in this TU.
bool ValidateMatMulAsertParams(const Consensus::Params& params, int32_t next_height)
{
    if (params.nMatMulAsertHalfLife <= 0) {
        LogWarning("MatMulAsert: invalid half-life=%lld at height %d, invalid immutable ASERT config (fatal at construction; runtime fail-closed)\n",
                   static_cast<long long>(params.nMatMulAsertHalfLife), next_height);
        return false;
    }
    if (params.nPowTargetSpacing <= 0) {
        LogWarning("MatMulAsert: invalid target spacing=%lld at height %d, invalid immutable ASERT config (fatal at construction; runtime fail-closed)\n",
                   static_cast<long long>(params.nPowTargetSpacing), next_height);
        return false;
    }
    if (params.nMatMulAsertBootstrapFactor == 0) {
        LogWarning("MatMulAsert: bootstrap factor is zero at height %d, invalid immutable ASERT config (fatal at construction; runtime fail-closed)\n",
                   next_height);
        return false;
    }
    if (params.nMatMulAsertRetuneHardeningFactor == 0) {
        LogWarning("MatMulAsert: retune hardening factor is zero at height %d, invalid immutable ASERT config (fatal at construction; runtime fail-closed)\n",
                   next_height);
        return false;
    }
    if (params.nMatMulAsertRetune2TargetNum == 0 || params.nMatMulAsertRetune2TargetDen == 0) {
        LogWarning("MatMulAsert: retune2 ratio is invalid (num=%u den=%u) at height %d, invalid immutable ASERT config (fatal at construction; runtime fail-closed)\n",
                   params.nMatMulAsertRetune2TargetNum, params.nMatMulAsertRetune2TargetDen, next_height);
        return false;
    }
    {
        // AUDIT D3: the ratio must be strictly positive AND reduce to a 32-bit
        // rational, otherwise ScaleTargetByTimespan's independent per-term uint32
        // clamp would silently distort a large but exact calibration (e.g. 2/1
        // expressed as 2^40/2^39).
        uint32_t v4_rn, v4_rd;
        if (!ReduceRescaleRatioToU32(params.nMatMulV4AsertRescaleNum, params.nMatMulV4AsertRescaleDen, v4_rn, v4_rd)) {
            LogWarning("MatMulAsert: v4 rescale ratio is invalid (num=%lld den=%lld; must be positive and reduce to a 32-bit rational) at height %d, failing closed\n",
                       static_cast<long long>(params.nMatMulV4AsertRescaleNum),
                       static_cast<long long>(params.nMatMulV4AsertRescaleDen), next_height);
            return false;
        }
    }
    if (!IsDisabledHeight(params.nMatMulV4Height) && params.nMatMulV4Height < params.nMatMulAsertHeight) {
        LogWarning("MatMulAsert: v4 height=%d is below ASERT activation=%d at height %d, invalid immutable ASERT config (fatal at construction; runtime fail-closed)\n",
                   params.nMatMulV4Height, params.nMatMulAsertHeight, next_height);
        return false;
    }
    // MatMul v4.2 / ENC-BMX4C (B2b): mirror the v4 rescale-ratio and ordering
    // guards for the BMX4-C one-time rescale. The ratio must be strictly
    // positive (num/den), the fork must not sit below ASERT activation, and --
    // since ENC-BMX4C is a profile of the v4 machine (exactly one profile live
    // at any height, no dual-profile window) -- it must fork strictly ABOVE the
    // v4 height whenever both are configured.
    {
        // AUDIT D3 (mirror of the v4 check): positive and 32-bit-reducible.
        uint32_t bmx4c_rn, bmx4c_rd;
        if (!ReduceRescaleRatioToU32(params.nMatMulBMX4CAsertRescaleNum, params.nMatMulBMX4CAsertRescaleDen, bmx4c_rn, bmx4c_rd)) {
            LogWarning("MatMulAsert: BMX4C rescale ratio is invalid (num=%lld den=%lld; must be positive and reduce to a 32-bit rational) at height %d, failing closed\n",
                       static_cast<long long>(params.nMatMulBMX4CAsertRescaleNum),
                       static_cast<long long>(params.nMatMulBMX4CAsertRescaleDen), next_height);
            return false;
        }
    }
    if (!IsDisabledHeight(params.nMatMulBMX4CHeight) && params.nMatMulBMX4CHeight < params.nMatMulAsertHeight) {
        LogWarning("MatMulAsert: BMX4C height=%d is below ASERT activation=%d at height %d, invalid immutable ASERT config (fatal at construction; runtime fail-closed)\n",
                   params.nMatMulBMX4CHeight, params.nMatMulAsertHeight, next_height);
        return false;
    }
    // Single-activation: BMX4C may fork AT (unified flag day) or above (staged)
    // the v4 height, never strictly below. At equality the MatMulAsert cascade
    // guards the v4-rescale branch out so the BMX4C rescale fires (see above).
    if (!IsDisabledHeight(params.nMatMulBMX4CHeight) && !IsDisabledHeight(params.nMatMulV4Height) &&
        params.nMatMulBMX4CHeight < params.nMatMulV4Height) {
        LogWarning("MatMulAsert: BMX4C height=%d must be at or above v4 height=%d at height %d, invalid immutable ASERT config (fatal at construction; runtime fail-closed)\n",
                   params.nMatMulBMX4CHeight, params.nMatMulV4Height, next_height);
        return false;
    }
    // When unified (bmx4c == v4), the v4 rescale branch never fires (guarded out
    // in MatMulAsert), so its ratio MUST be the inert 1/1 -- a non-1/1 v4 ratio
    // signals a miscalibrated two-phase config mistakenly collapsed to one height.
    if (!IsDisabledHeight(params.nMatMulBMX4CHeight) && !IsDisabledHeight(params.nMatMulV4Height) &&
        params.nMatMulBMX4CHeight == params.nMatMulV4Height &&
        params.nMatMulV4AsertRescaleNum != params.nMatMulV4AsertRescaleDen) {
        LogWarning("MatMulAsert: unified activation (bmx4c==v4=%d) requires the v4 rescale ratio to be 1/1 "
                   "(got %lld/%lld); use the BMX4C rescale for the v3->BMX4C shift. Failing closed.\n",
                   params.nMatMulV4Height,
                   static_cast<long long>(params.nMatMulV4AsertRescaleNum),
                   static_cast<long long>(params.nMatMulV4AsertRescaleDen));
        return false;
    }

    // Audit C5: the MatMulAsert cascade dispatches special one-time-rescale heights
    // in a fixed order (asert -> retune -> retune2 -> v4 -> bmx4c) and returns on
    // the FIRST match. A NON-inert (!= 1/1) rescale whose height collides with an
    // EARLIER branch is silently shadowed (its calibrated re-anchor never applies).
    // Reject such collisions at construction/validation so a misconfiguration fails
    // LOUD; a 1/1 rescale shadowed is a no-op and stays legal. (bmx4c == v4 is the
    // unified flag day -- the v4 branch is guarded out there so bmx4c is NOT
    // shadowed; that case is handled by the v4-ratio-1/1 check above.)
    {
        const auto shadowed_by_earlier = [&](int32_t h) -> bool {
            return (!IsDisabledHeight(params.nMatMulAsertHeight) && h == params.nMatMulAsertHeight) ||
                   (!IsDisabledHeight(params.nMatMulAsertRetuneHeight) && h == params.nMatMulAsertRetuneHeight) ||
                   (!IsDisabledHeight(params.nMatMulAsertRetune2Height) && h == params.nMatMulAsertRetune2Height);
        };
        if (!IsDisabledHeight(params.nMatMulV4Height) &&
            params.nMatMulV4AsertRescaleNum != params.nMatMulV4AsertRescaleDen &&
            shadowed_by_earlier(params.nMatMulV4Height)) {
            LogWarning("MatMulAsert: non-inert v4 rescale height=%d collides with an earlier ASERT branch "
                       "(rescale would be silently skipped) at height %d, invalid immutable ASERT config (fatal at construction; runtime fail-closed)\n",
                       params.nMatMulV4Height, next_height);
            return false;
        }
        if (!IsDisabledHeight(params.nMatMulBMX4CHeight) &&
            params.nMatMulBMX4CAsertRescaleNum != params.nMatMulBMX4CAsertRescaleDen &&
            shadowed_by_earlier(params.nMatMulBMX4CHeight)) {
            LogWarning("MatMulAsert: non-inert BMX4C rescale height=%d collides with an earlier ASERT branch "
                       "(rescale would be silently skipped) at height %d, invalid immutable ASERT config (fatal at construction; runtime fail-closed)\n",
                       params.nMatMulBMX4CHeight, next_height);
            return false;
        }
    }

    const bool retune_enabled = !IsDisabledHeight(params.nMatMulAsertRetuneHeight);
    const bool retune2_enabled = !IsDisabledHeight(params.nMatMulAsertRetune2Height);
    if (retune_enabled && params.nMatMulAsertRetuneHeight < params.nMatMulAsertHeight) {
        LogWarning("MatMulAsert: retune height=%d is below ASERT activation=%d at height %d, invalid immutable ASERT config (fatal at construction; runtime fail-closed)\n",
                   params.nMatMulAsertRetuneHeight, params.nMatMulAsertHeight, next_height);
        return false;
    }
    if (retune2_enabled && params.nMatMulAsertRetune2Height < params.nMatMulAsertHeight) {
        LogWarning("MatMulAsert: retune2 height=%d is below ASERT activation=%d at height %d, invalid immutable ASERT config (fatal at construction; runtime fail-closed)\n",
                   params.nMatMulAsertRetune2Height, params.nMatMulAsertHeight, next_height);
        return false;
    }
    if (retune_enabled && retune2_enabled &&
        params.nMatMulAsertRetune2Height < params.nMatMulAsertRetuneHeight) {
        LogWarning("MatMulAsert: retune2 height=%d is below retune height=%d at height %d, invalid immutable ASERT config (fatal at construction; runtime fail-closed)\n",
                   params.nMatMulAsertRetune2Height, params.nMatMulAsertRetuneHeight, next_height);
        return false;
    }
    // AUDIT D2: complete the branch-collision coverage. The cascade dispatches in
    // the fixed order asert -> retune -> retune2 -> v4 -> bmx4c and returns on the
    // FIRST height match, so a later branch whose height EQUALS an earlier branch's
    // height is silently shadowed. The v4/bmx4c-vs-earlier collisions are rejected
    // in the C5 block above; here reject the remaining retune-family EQUALITY
    // collisions when the SHADOWED operation is NON-inert (an inert no-op is safe
    // to shadow). retune is non-inert iff its hardening factor > 1 (the branch only
    // divides when factor > 1); retune2 is non-inert iff num != den.
    {
        const bool retune_non_inert{retune_enabled && params.nMatMulAsertRetuneHardeningFactor > 1};
        const bool retune2_non_inert{retune2_enabled &&
            params.nMatMulAsertRetune2TargetNum != params.nMatMulAsertRetune2TargetDen};
        if (retune_non_inert && params.nMatMulAsertRetuneHeight == params.nMatMulAsertHeight) {
            LogWarning("MatMulAsert: non-inert retune height=%d collides with the ASERT activation height "
                       "(retune would be silently skipped) at height %d, failing closed\n",
                       params.nMatMulAsertRetuneHeight, next_height);
            return false;
        }
        if (retune2_non_inert && params.nMatMulAsertRetune2Height == params.nMatMulAsertHeight) {
            LogWarning("MatMulAsert: non-inert retune2 height=%d collides with the ASERT activation height "
                       "(retune2 would be silently skipped) at height %d, failing closed\n",
                       params.nMatMulAsertRetune2Height, next_height);
            return false;
        }
        if (retune2_non_inert && retune_enabled &&
            params.nMatMulAsertRetune2Height == params.nMatMulAsertRetuneHeight) {
            LogWarning("MatMulAsert: non-inert retune2 height=%d collides with the retune height "
                       "(retune2 would be silently skipped) at height %d, failing closed\n",
                       params.nMatMulAsertRetune2Height, next_height);
            return false;
        }
    }
    if (IsMatMulAsertHalfLifeUpgradeConfigured(params)) {
        if (params.nMatMulAsertHalfLifeUpgrade <= 0) {
            LogWarning("MatMulAsert: half-life upgrade value=%lld is invalid at height %d, invalid immutable ASERT config (fatal at construction; runtime fail-closed)\n",
                       static_cast<long long>(params.nMatMulAsertHalfLifeUpgrade), next_height);
            return false;
        }

        int32_t latest_pre_upgrade_anchor = params.nMatMulAsertHeight;
        if (retune_enabled) {
            latest_pre_upgrade_anchor = std::max(latest_pre_upgrade_anchor, params.nMatMulAsertRetuneHeight);
        }
        if (retune2_enabled) {
            latest_pre_upgrade_anchor = std::max(latest_pre_upgrade_anchor, params.nMatMulAsertRetune2Height);
        }
        // Audit C4: do NOT fold the v4/BMX4C rescale heights into this guard. The
        // anchor is now selected monotonically (ResolveMatMulAsertHalfLifeInfo takes
        // the LATEST of the pre-upgrade anchor and the half-life-upgrade height), so
        // a half-life upgrade BEFORE a later v4/BMX4C rescale is a valid, safe
        // configuration (the later rescale wins as anchor). Requiring the upgrade to
        // sit above the rescales would reject that valid config and fail difficulty
        // closed to powLimit. Only the base/retune ordering below is constrained.
        if (params.nMatMulAsertHalfLifeUpgradeHeight <= latest_pre_upgrade_anchor) {
            LogWarning("MatMulAsert: half-life upgrade height=%d must be above latest prior anchor=%d at height %d, invalid immutable ASERT config (fatal at construction; runtime fail-closed)\n",
                       params.nMatMulAsertHalfLifeUpgradeHeight, latest_pre_upgrade_anchor, next_height);
            return false;
        }
    }
    return true;
}

namespace {

bool ShouldEnableAsyncPrepare(matmul::backend::Kind backend, uint32_t configured_batch_size)
{
    const char* env = std::getenv("BTX_MATMUL_PIPELINE_ASYNC");
    if (env != nullptr && env[0] != '\0') {
        return env[0] != '0';
    }
    if (backend == matmul::backend::Kind::CUDA) {
        (void)configured_batch_size;
        return true;
    }
    if (backend != matmul::backend::Kind::METAL) {
        return false;
    }

    (void)configured_batch_size;
    // Even at batch-size 1, SolveMatMul can overlap next-window input
    // preparation with the current Metal digest through the prefetch path.
    // Live-like mining benchmarks on this Apple Silicon machine show that
    // default-on async preparation still improves end-to-end throughput.
    return true;
}

uint32_t ResolvePreparePrefetchDepth(matmul::backend::Kind backend, uint32_t configured_batch_size)
{
    const char* env = std::getenv("BTX_MATMUL_PREPARE_PREFETCH_DEPTH");
    if (env != nullptr && env[0] != '\0') {
        int32_t parsed{0};
        if (ParseInt32(env, &parsed)) {
            return static_cast<uint32_t>(std::clamp<int32_t>(parsed, 0, 8));
        }
    }

    if (backend == matmul::backend::Kind::CUDA) {
        const uint32_t cuda_sm_count = ResolveCudaMultiprocessorCountForHeuristics();
        if (configured_batch_size <= 1) {
            return 1;
        }
        if (cuda_sm_count >= 96) {
            return configured_batch_size >= 6 ? 5 : 4;
        }
        if (cuda_sm_count >= 64) {
            return configured_batch_size >= 4 ? 4 : 3;
        }
        if (cuda_sm_count >= 48) {
            return 3;
        }
        return ResolveMatMulSolverThreadCount() >= 5 ? 3 : 2;
    }
    if (backend != matmul::backend::Kind::METAL) {
        return 0;
    }
    if (configured_batch_size <= 1) {
        return 1;
    }
    // Keep only one outstanding prefetched batch on Metal. High-tier Apple
    // hosts already benchmark best with the shallower queue, and generic Apple
    // hosts can trigger repeated command-buffer hang/recovery fallbacks when a
    // deeper queue keeps the digest path continuously saturated.
    return 1;
}

uint32_t ResolveSolveBatchSize(matmul::backend::Kind backend,
                               uint32_t n,
                               uint32_t transcript_block_size,
                               uint32_t noise_rank,
                               bool product_digest_active)
{
    const char* env = std::getenv("BTX_MATMUL_SOLVE_BATCH_SIZE");
    if (env != nullptr && env[0] != '\0') {
        int32_t parsed{0};
        if (ParseInt32(env, &parsed) && parsed > 1) {
            return static_cast<uint32_t>(std::min<int32_t>(parsed, 64));
        }
        return 1;
    }

    if (backend == matmul::backend::Kind::CUDA) {
        const uint32_t cuda_sm_count = ResolveCudaMultiprocessorCountForHeuristics();
        const int32_t solver_threads = ResolveMatMulSolverThreadCount();
        uint32_t batch_size{1};
        if (n >= 512 && transcript_block_size >= 16 && noise_rank >= 8) {
            if (product_digest_active) {
                if (cuda_sm_count >= 96) {
                    batch_size = solver_threads >= 6 ? 8 : 4;
                } else if (cuda_sm_count >= 64) {
                    batch_size = solver_threads >= 5 ? 6 : 4;
                } else {
                    batch_size = solver_threads >= 5 ? 4 : 2;
                }
            } else {
                batch_size = solver_threads >= 5 ? 4 : 2;
            }
            return ExpandCudaAutoBatchSizeForSelectedDevices(batch_size);
        }
        if (n >= 256 && transcript_block_size >= 8 && noise_rank >= 4) {
            if (product_digest_active && cuda_sm_count >= 64) {
                batch_size = solver_threads >= 5 ? 6 : 4;
            } else {
                batch_size = solver_threads >= 4 ? 4 : 2;
            }
            return ExpandCudaAutoBatchSizeForSelectedDevices(batch_size);
        }
        return ExpandCudaAutoBatchSizeForSelectedDevices(batch_size);
    }
    if (backend != matmul::backend::Kind::METAL) {
        return 1;
    }
    const bool has_parallel_solver_support = ResolveMatMulSolverThreadCount() > 1;
    const bool conservative_apple_metal_host = IsConservativeAppleMetalHost(
        ResolveApplePerformanceLogicalCpuCount());
    if (n >= 512 && transcript_block_size >= 16 && noise_rank >= 8) {
        // Mainnet/product mining benefits from a small bounded batch window
        // once the threaded Metal solve path is active. On conservative Apple
        // hosts, keep the two-nonce batch even after reducing auto solver
        // fanout to a single lane; long-run validation shows that pairing the
        // batch with single-lane solve and shallow prefetch avoids recurring
        // Metal hang/recovery fallbacks.
        return (product_digest_active &&
                (has_parallel_solver_support || conservative_apple_metal_host)) ? 2 : 1;
    }
    if (n >= 256 && transcript_block_size >= 8 && noise_rank >= 4) {
        return has_parallel_solver_support ? 2 : 1;
    }
    return 1;
}

std::optional<uint32_t> ParseBatchSizeEnvValue(const char* value, uint32_t max_value)
{
    if (value == nullptr || value[0] == '\0') {
        return std::nullopt;
    }
    int32_t parsed{0};
    if (!ParseInt32(value, &parsed) || parsed <= 0) {
        return 1U;
    }
    return static_cast<uint32_t>(std::min<int32_t>(parsed, static_cast<int32_t>(max_value)));
}

std::optional<uint32_t> ParseBoundedPercentEnvValue(const char* name)
{
    const char* value = std::getenv(name);
    if (value == nullptr || value[0] == '\0') {
        return std::nullopt;
    }
    int32_t parsed{0};
    if (!ParseInt32(value, &parsed)) {
        return std::nullopt;
    }
    return static_cast<uint32_t>(std::clamp<int32_t>(parsed, 1, 90));
}

uint32_t ResolveCudaNonceSeedMemoryPercent()
{
    return ParseBoundedPercentEnvValue("BTX_MATMUL_CUDA_NONCE_SEED_MEMORY_PERCENT").value_or(25U);
}

uint32_t ResolveCudaNonceSeedSmTierBatchSize(uint32_t multiprocessor_count,
                                             uint32_t base_batch_size)
{
    if (multiprocessor_count == 0) {
        return base_batch_size;
    }
    if (multiprocessor_count >= 160) {
        return base_batch_size * 8U;
    }
    if (multiprocessor_count >= 128) {
        return base_batch_size * 6U;
    }
    if (multiprocessor_count >= 96) {
        return base_batch_size * 4U;
    }
    if (multiprocessor_count >= 64) {
        return base_batch_size * 2U;
    }
    if (multiprocessor_count >= 24) {
        return base_batch_size;
    }
    return std::max<uint32_t>(base_batch_size / 2U, 16U);
}

uint32_t EstimateCudaNonceSeedBatchMemoryCap(const btx::cuda::CudaDeviceInfo& device,
                                             uint32_t n,
                                             uint32_t transcript_block_size,
                                             uint32_t noise_rank,
                                             uint32_t memory_percent,
                                             uint32_t max_batch_size)
{
    if (device.global_memory_bytes == 0 || n == 0 || max_batch_size == 0) {
        return max_batch_size;
    }

    const uint64_t matrix_elements = static_cast<uint64_t>(n) * n;
    const uint64_t matrix_pair_bytes = 2U * matrix_elements * sizeof(matmul::field::Element);
    const uint64_t generated_input_bytes =
        (4U * static_cast<uint64_t>(n) * noise_rank +
         static_cast<uint64_t>(transcript_block_size) * transcript_block_size) *
        sizeof(matmul::field::Element);
    const uint64_t per_entry_bytes = matrix_pair_bytes + generated_input_bytes;
    if (per_entry_bytes == 0) {
        return max_batch_size;
    }

    const uint64_t budget_bytes =
        (device.global_memory_bytes / 100U) * static_cast<uint64_t>(memory_percent);
    if (budget_bytes < per_entry_bytes) {
        return 1U;
    }
    return static_cast<uint32_t>(
        std::clamp<uint64_t>(budget_bytes / per_entry_bytes, 1U, max_batch_size));
}

uint32_t ResolveCudaNonceSeedBatchSize(uint32_t n,
                                       uint32_t transcript_block_size,
                                       uint32_t noise_rank,
                                       bool product_digest_active,
                                       uint32_t max_batch_size)
{
    uint32_t base_batch_size{16};
    if (n >= 512 && transcript_block_size >= 16 && noise_rank >= 8) {
        base_batch_size = product_digest_active ? 256U : 128U;
    } else if (n >= 256 && transcript_block_size >= 8 && noise_rank >= 4) {
        base_batch_size = product_digest_active ? 128U : 64U;
    }

    const auto topology = btx::cuda::ProbeCudaTopology();
    if (!topology.available || topology.selected_devices.empty()) {
        return std::min<uint32_t>(base_batch_size, max_batch_size);
    }

    const auto& primary_device = topology.selected_devices.front();
    uint32_t sm_tier_batch_size = ResolveCudaNonceSeedSmTierBatchSize(
        primary_device.multiprocessor_count,
        base_batch_size);
    if (product_digest_active &&
        n >= 512 &&
        transcript_block_size >= 16 &&
        noise_rank >= 8 &&
        primary_device.multiprocessor_count >= 24 &&
        primary_device.multiprocessor_count < 64) {
        sm_tier_batch_size = std::max<uint32_t>(sm_tier_batch_size, 512U);
    }
    const uint32_t memory_cap = EstimateCudaNonceSeedBatchMemoryCap(
        primary_device,
        n,
        transcript_block_size,
        noise_rank,
        ResolveCudaNonceSeedMemoryPercent(),
        max_batch_size);
    return std::clamp<uint32_t>(sm_tier_batch_size, 1U, memory_cap);
}

uint32_t ResolveMetalNonceSeedBatchSize(uint32_t n,
                                        uint32_t transcript_block_size,
                                        uint32_t noise_rank,
                                        bool product_digest_active)
{
    const uint32_t gpu_core_count = ResolveMetalGpuCoreCountForHeuristics();
    const bool gpu_core_count_available = gpu_core_count > 0;

    if (n >= 512 && transcript_block_size >= 16 && noise_rank >= 8) {
        if (product_digest_active) {
            if (!gpu_core_count_available) {
                return IsHighPerfAppleMetalHost(ResolveApplePerformanceLogicalCpuCount()) ? 128U : 64U;
            }
            if (gpu_core_count >= 60) return 256U;
            if (gpu_core_count >= 30) return 192U;
            if (gpu_core_count >= 18) return 128U;
            if (gpu_core_count >= 10) return 64U;
            return 32U;
        }

        if (!gpu_core_count_available) return 32U;
        if (gpu_core_count >= 60) return 128U;
        if (gpu_core_count >= 30) return 96U;
        if (gpu_core_count >= 18) return 64U;
        if (gpu_core_count >= 10) return 32U;
        return 16U;
    }

    if (n >= 256 && transcript_block_size >= 8 && noise_rank >= 4) {
        if (product_digest_active) {
            if (!gpu_core_count_available) return 32U;
            if (gpu_core_count >= 60) return 128U;
            if (gpu_core_count >= 30) return 96U;
            if (gpu_core_count >= 18) return 64U;
            if (gpu_core_count >= 10) return 32U;
            return 16U;
        }

        if (!gpu_core_count_available) return 16U;
        if (gpu_core_count >= 60) return 64U;
        if (gpu_core_count >= 30) return 48U;
        if (gpu_core_count >= 18) return 32U;
        if (gpu_core_count >= 10) return 16U;
        return 8U;
    }

    if (gpu_core_count_available && gpu_core_count >= 30) {
        return 32U;
    }
    return 16U;
}

uint32_t ResolveGpuNonceSeedBatchSize(matmul::backend::Kind backend,
                                      uint32_t n,
                                      uint32_t transcript_block_size,
                                      uint32_t noise_rank,
                                      bool product_digest_active)
{
    constexpr uint32_t kMaxNonceSeedBatchSize{4096};
    if (const auto override_value = ParseBatchSizeEnvValue(
            std::getenv("BTX_MATMUL_NONCE_SEED_BATCH_SIZE"),
            kMaxNonceSeedBatchSize)) {
        return *override_value;
    }
    if (const auto override_value = ParseBatchSizeEnvValue(
            std::getenv("BTX_MATMUL_SOLVE_BATCH_SIZE"),
            kMaxNonceSeedBatchSize)) {
        return *override_value;
    }

    if (backend == matmul::backend::Kind::METAL) {
        return std::min<uint32_t>(
            ResolveMetalNonceSeedBatchSize(n, transcript_block_size, noise_rank, product_digest_active),
            kMaxNonceSeedBatchSize);
    }

    if (backend != matmul::backend::Kind::CUDA) {
        return 1U;
    }

    return ResolveCudaNonceSeedBatchSize(
        n,
        transcript_block_size,
        noise_rank,
        product_digest_active,
        kMaxNonceSeedBatchSize);
}

uint32_t ResolveNonceSeedScanSafetyMultiplier()
{
    const char* env = std::getenv("BTX_MATMUL_NONCE_SEED_SCAN_MULTIPLIER");
    if (env == nullptr || env[0] == '\0') {
        return 1U;
    }

    int32_t parsed{0};
    if (!ParseInt32(env, &parsed) || parsed <= 0) {
        return 1U;
    }
    return static_cast<uint32_t>(std::clamp<int32_t>(parsed, 1, 8));
}

bool ShouldEnableCpuVsMetalDigestCompare(matmul::backend::Kind backend)
{
    if (backend != matmul::backend::Kind::METAL) {
        return false;
    }
    const char* env = std::getenv("BTX_MATMUL_DIAG_COMPARE_CPU_METAL");
    return env != nullptr && env[0] != '\0' && env[0] != '0';
}

bool ShouldCpuConfirmSolvedMatMulCandidates(matmul::backend::Kind backend, const Consensus::Params& params)
{
    // For strict validation networks, treat accelerated backend hits as
    // candidates and only accept after CPU canonical digest confirmation.
    if ((backend != matmul::backend::Kind::METAL && backend != matmul::backend::Kind::CUDA) ||
        params.fSkipMatMulValidation) {
        return false;
    }
    const char* env = std::getenv("BTX_MATMUL_CPU_CONFIRM");
    if (env != nullptr && env[0] != '\0') {
        return env[0] != '0';
    }
    return true;
}

uint32_t ResolveMinerHeaderTimeRefreshAttempts()
{
    const char* env = std::getenv("BTX_MINER_HEADER_TIME_REFRESH_ATTEMPTS");
    if (env != nullptr && env[0] != '\0') {
        int64_t parsed{0};
        if (ParseInt64(env, &parsed) && parsed > 0 && parsed <= std::numeric_limits<uint32_t>::max()) {
            return static_cast<uint32_t>(parsed);
        }
    }
    return DEFAULT_MINER_HEADER_TIME_REFRESH_ATTEMPTS;
}

void MaybeRefreshMinerHeaderTime(
    CBlockHeader& block,
    uint32_t& attempts_since_refresh,
    uint32_t refresh_attempt_interval,
    bool allow_min_difficulty)
{
    if (allow_min_difficulty || refresh_attempt_interval == 0 || attempts_since_refresh < refresh_attempt_interval) {
        return;
    }

    attempts_since_refresh = 0;
    const int64_t now_seconds{GetTime()};
    if (now_seconds <= static_cast<int64_t>(block.nTime)) {
        return;
    }

    block.nTime = static_cast<uint32_t>(std::min<int64_t>(now_seconds, std::numeric_limits<uint32_t>::max()));
}

struct MatMulNonceBatchWindow {
    std::vector<CBlockHeader> headers;
    std::vector<uint256> sigmas;
    uint32_t nonces_scanned{0};
    uint32_t attempts_since_time_refresh_after{0};
    bool nonce_space_exhausted{false};
    bool header_time_refresh_due{false};
};

struct MatMulPrefetchedBatch {
    MatMulNonceBatchWindow window;
    std::vector<std::future<matmul::accelerated::PreparedDigestInputs>> futures;
    CBlockHeader next_block;
    uint64_t remaining_max_tries_after{0};
};

MatMulNonceBatchWindow BuildMatMulNonceBatchWindow(const CBlockHeader& block,
                                                   uint64_t max_tries,
                                                   uint32_t configured_batch_size,
                                                   uint32_t pre_hash_epsilon_bits,
                                                   const arith_uint256& target,
                                                   uint32_t attempts_since_time_refresh,
                                                   uint32_t header_time_refresh_interval,
                                                   bool allow_min_difficulty)
{
    MatMulNonceBatchWindow window;

    const uint32_t prehash_expansion = pre_hash_epsilon_bits > 0
        ? (1U << std::min<uint32_t>(pre_hash_epsilon_bits, 20U))
        : 1U;
    uint32_t scan_limit = static_cast<uint32_t>(std::min<uint64_t>(
        std::min<uint64_t>(static_cast<uint64_t>(configured_batch_size) * prehash_expansion, max_tries),
        std::numeric_limits<uint32_t>::max()));
    if (scan_limit == 0) {
        return window;
    }

    const uint64_t max_nonce_delta = std::numeric_limits<uint64_t>::max() - block.nNonce64;
    if (static_cast<uint64_t>(scan_limit - 1) > max_nonce_delta) {
        scan_limit = static_cast<uint32_t>(max_nonce_delta + 1);
    }
    if (scan_limit == 0) {
        window.nonce_space_exhausted = true;
        return window;
    }

    arith_uint256 pre_hash_target = target;
    if (pre_hash_epsilon_bits > 0) {
        pre_hash_target = SaturatingLeftShift256(pre_hash_target, pre_hash_epsilon_bits);
    }

    window.headers.reserve(configured_batch_size);
    for (uint32_t i = 0; i < scan_limit && window.headers.size() < configured_batch_size; ++i) {
        CBlockHeader header{block};
        header.nNonce64 = block.nNonce64 + i;
        header.nNonce = static_cast<uint32_t>(header.nNonce64);

        if (pre_hash_epsilon_bits > 0) {
            const uint256 sigma = matmul::DeriveSigma(header);
            if (UintToArith256(sigma) > pre_hash_target) {
                ++window.nonces_scanned;
                continue;
            }
        }

        window.headers.push_back(header);
        ++window.nonces_scanned;
    }

    if (attempts_since_time_refresh >
        std::numeric_limits<uint32_t>::max() - window.nonces_scanned) {
        window.attempts_since_time_refresh_after = std::numeric_limits<uint32_t>::max();
    } else {
        window.attempts_since_time_refresh_after = attempts_since_time_refresh + window.nonces_scanned;
    }
    window.header_time_refresh_due =
        !allow_min_difficulty &&
        header_time_refresh_interval != 0 &&
        window.attempts_since_time_refresh_after >= header_time_refresh_interval;
    return window;
}

void LogGpuNonceSeedScanFallbackOnce(matmul::backend::Kind backend, const std::string& reason)
{
    std::atomic_bool& flag = backend == matmul::backend::Kind::METAL
        ? g_logged_metal_nonce_seed_scan_fallback
        : g_logged_cuda_nonce_seed_scan_fallback;
    const char* label = backend == matmul::backend::Kind::METAL ? "Metal" : "CUDA";
    bool expected{false};
    if (flag.compare_exchange_strong(expected, true)) {
        LogPrintf("MATMUL WARNING: %s nonce-seed pre-hash scan fallback to CPU (%s)\n", label, reason);
    }
}

void RegisterGpuNonceSeedPreHashScanFailure(matmul::backend::Kind backend, const std::string& reason)
{
    g_matmul_gpu_prehash_scan_failures.fetch_add(1, std::memory_order_relaxed);
    if (backend == matmul::backend::Kind::METAL) {
        g_matmul_metal_nonce_seed_scan_fallbacks.fetch_add(1, std::memory_order_relaxed);
    } else if (backend == matmul::backend::Kind::CUDA) {
        g_matmul_cuda_nonce_seed_scan_fallbacks.fetch_add(1, std::memory_order_relaxed);
    }

    std::lock_guard<std::mutex> lock(g_matmul_gpu_prehash_scan_mutex);
    g_matmul_gpu_prehash_scan_last_backend = matmul::backend::ToString(backend);
    g_matmul_gpu_prehash_scan_last_error = reason;
}

std::optional<MatMulNonceBatchWindow> BuildMatMulNonceSeededGpuPreHashBatchWindow(
    const CBlockHeader& block,
    const Consensus::Params& params,
    int32_t block_height,
    matmul::backend::Kind backend,
    uint64_t max_tries,
    uint32_t configured_batch_size,
    uint32_t pre_hash_epsilon_bits,
    const arith_uint256& target,
    uint32_t attempts_since_time_refresh,
    uint32_t header_time_refresh_interval,
    std::optional<int64_t> parent_median_time_past,
    bool allow_min_difficulty)
{
    if (configured_batch_size == 0 || pre_hash_epsilon_bits == 0 || block_height < 0) {
        return std::nullopt;
    }
    const bool use_parent_mtp_seed = params.IsMatMulParentMtpSeedActive(block_height);
    if (use_parent_mtp_seed &&
        (!parent_median_time_past.has_value() || *parent_median_time_past < 0)) {
        return std::nullopt;
    }
    const uint32_t seed_version = use_parent_mtp_seed ? 3U : 2U;
    const int64_t scan_parent_mtp = use_parent_mtp_seed ? *parent_median_time_past : 0;

    MatMulNonceBatchWindow window;
    arith_uint256 pre_hash_target = target;
    pre_hash_target = SaturatingLeftShift256(pre_hash_target, pre_hash_epsilon_bits);

    const uint64_t scan_safety_multiplier = ResolveNonceSeedScanSafetyMultiplier();
    const uint64_t estimated_spacing = EstimatePreHashGateSpacing(pre_hash_target);
    uint64_t desired_scan_count = max_tries;
    if (estimated_spacing <= std::numeric_limits<uint64_t>::max() / scan_safety_multiplier &&
        configured_batch_size <= std::numeric_limits<uint64_t>::max() / (estimated_spacing * scan_safety_multiplier)) {
        desired_scan_count = static_cast<uint64_t>(configured_batch_size) *
            estimated_spacing *
            scan_safety_multiplier;
    }
    uint32_t scan_limit = static_cast<uint32_t>(std::min<uint64_t>(
        std::min<uint64_t>(desired_scan_count, max_tries),
        std::numeric_limits<uint32_t>::max()));
    if (scan_limit == 0) {
        return window;
    }

    const uint64_t max_nonce_delta = std::numeric_limits<uint64_t>::max() - block.nNonce64;
    if (static_cast<uint64_t>(scan_limit - 1) > max_nonce_delta) {
        scan_limit = static_cast<uint32_t>(max_nonce_delta + 1);
    }
    if (scan_limit == 0) {
        window.nonce_space_exhausted = true;
        return window;
    }

    struct ScanResultView {
        bool success{false};
        uint32_t scanned_count{0};
        bool compact_pass_offsets{false};
        std::vector<uint8_t> pass_flags;
        std::vector<uint32_t> pass_offsets;
        std::vector<btx::cuda::MatMulNonceSeedPreHashPassRecord> pass_records;
        std::string error;
    } scan;

    g_matmul_gpu_prehash_scan_attempts.fetch_add(1, std::memory_order_relaxed);
    if (backend == matmul::backend::Kind::CUDA) {
        const auto cuda_scan = btx::cuda::ScanMatMulNonceSeedPreHashGPU({
            .version = block.nVersion,
            .previous_block_hash = block.hashPrevBlock,
            .merkle_root = block.hashMerkleRoot,
            .time = block.nTime,
            .bits = block.nBits,
            .start_nonce = block.nNonce64,
            .matmul_dim = block.matmul_dim,
            .block_height = static_cast<uint32_t>(block_height),
            .scan_count = scan_limit,
            .pre_hash_target = ArithToUint256(pre_hash_target),
            .seed_version = seed_version,
            .parent_median_time_past = scan_parent_mtp,
            .compact_pass_offsets = true,
            .compact_pass_records = true,
        });
        scan.success = cuda_scan.success;
        scan.scanned_count = cuda_scan.scanned_count;
        scan.compact_pass_offsets = true;
        scan.pass_offsets = std::move(cuda_scan.pass_offsets);
        scan.pass_records = std::move(cuda_scan.pass_records);
        scan.error = cuda_scan.error;
    } else if (backend == matmul::backend::Kind::METAL) {
        const auto metal_scan = btx::metal::ScanMatMulNonceSeedPreHashGPU({
            .version = block.nVersion,
            .previous_block_hash = block.hashPrevBlock,
            .merkle_root = block.hashMerkleRoot,
            .time = block.nTime,
            .bits = block.nBits,
            .start_nonce = block.nNonce64,
            .matmul_dim = block.matmul_dim,
            .block_height = static_cast<uint32_t>(block_height),
            .scan_count = scan_limit,
            .pre_hash_target = ArithToUint256(pre_hash_target),
            .seed_version = seed_version,
            .parent_median_time_past = scan_parent_mtp,
        });
        scan.success = metal_scan.success;
        scan.scanned_count = metal_scan.scanned_count;
        scan.pass_flags = std::move(metal_scan.pass_flags);
        scan.error = metal_scan.error;
    } else {
        return std::nullopt;
    }

    const bool scan_result_shape_valid = scan.compact_pass_offsets
        ? scan.pass_offsets.size() <= scan.scanned_count &&
            (scan.pass_records.empty() || scan.pass_records.size() == scan.pass_offsets.size())
        : scan.pass_flags.size() == scan.scanned_count;
    if (!scan.success || !scan_result_shape_valid) {
        const std::string reason = scan.error.empty() ? "scan_failed" : scan.error;
        RegisterGpuNonceSeedPreHashScanFailure(backend, reason);
        LogGpuNonceSeedScanFallbackOnce(
            backend,
            reason);
        return std::nullopt;
    }
    g_matmul_gpu_prehash_scan_successes.fetch_add(1, std::memory_order_relaxed);

    window.headers.reserve(configured_batch_size);
    auto append_header_for_offset = [&](
        uint32_t offset,
        const btx::cuda::MatMulNonceSeedPreHashPassRecord* pass_record = nullptr) -> bool {
        if (offset >= scan.scanned_count) {
            return false;
        }

        CBlockHeader header{block};
        header.nNonce64 = block.nNonce64 + offset;
        header.nNonce = static_cast<uint32_t>(header.nNonce64);
        if (pass_record != nullptr) {
            header.seed_a = pass_record->seed_a;
            header.seed_b = pass_record->seed_b;
        } else {
            if (!SetDeterministicMatMulSeeds(header, params, block_height, parent_median_time_past)) {
                return false;
            }
        }
        header.matmul_digest.SetNull();

        window.headers.push_back(std::move(header));
        if (pass_record != nullptr) {
            window.sigmas.push_back(pass_record->sigma);
        }
        return true;
    };

    if (scan.compact_pass_offsets) {
        const bool use_pass_records = scan.pass_records.size() == scan.pass_offsets.size();
        uint32_t previous_offset{0};
        bool have_previous_offset{false};
        for (size_t i = 0; i < scan.pass_offsets.size(); ++i) {
            const uint32_t offset = scan.pass_offsets[i];
            const auto* pass_record = use_pass_records ? &scan.pass_records[i] : nullptr;
            if (offset >= scan.scanned_count ||
                (have_previous_offset && offset <= previous_offset)) {
                RegisterGpuNonceSeedPreHashScanFailure(backend, "compact_scan_offsets_out_of_order");
                return std::nullopt;
            }
            if (pass_record != nullptr && pass_record->offset != offset) {
                RegisterGpuNonceSeedPreHashScanFailure(backend, "compact_scan_records_offset_mismatch");
                return std::nullopt;
            }
            window.nonces_scanned = offset + 1U;
            if (!append_header_for_offset(offset, pass_record)) {
                return std::nullopt;
            }
            previous_offset = offset;
            have_previous_offset = true;
            if (window.headers.size() >= configured_batch_size) {
                break;
            }
        }
        if (window.headers.size() < configured_batch_size) {
            window.nonces_scanned = scan.scanned_count;
        }
    } else {
        for (uint32_t i = 0; i < scan.scanned_count; ++i) {
            ++window.nonces_scanned;
            if (scan.pass_flags[i] == 0) {
                continue;
            }
            if (!append_header_for_offset(i)) {
                return std::nullopt;
            }
            if (window.headers.size() >= configured_batch_size) {
                break;
            }
        }
    }

    if (attempts_since_time_refresh >
        std::numeric_limits<uint32_t>::max() - window.nonces_scanned) {
        window.attempts_since_time_refresh_after = std::numeric_limits<uint32_t>::max();
    } else {
        window.attempts_since_time_refresh_after = attempts_since_time_refresh + window.nonces_scanned;
    }
    window.header_time_refresh_due =
        !allow_min_difficulty &&
        header_time_refresh_interval != 0 &&
        window.attempts_since_time_refresh_after >= header_time_refresh_interval;
    return window;
}

template <typename PrepareFn>
std::vector<std::future<matmul::accelerated::PreparedDigestInputs>> SubmitPreparedBatch(
    const std::vector<CBlockHeader>& headers,
    PrepareFn prepare_inputs)
{
    std::vector<std::future<matmul::accelerated::PreparedDigestInputs>> futures;
    futures.reserve(headers.size());
    auto& prepare_executor = GetMatMulPrepareExecutor();
    for (const auto& header : headers) {
        futures.push_back(prepare_executor.Submit([prepare_inputs, header]() {
            return prepare_inputs(header);
        }));
    }
    return futures;
}

std::vector<matmul::accelerated::PreparedDigestInputs> CollectPreparedBatchFutures(
    std::vector<std::future<matmul::accelerated::PreparedDigestInputs>>& futures)
{
    std::vector<matmul::accelerated::PreparedDigestInputs> prepared_batch;
    prepared_batch.reserve(futures.size());
    for (auto& future : futures) {
        prepared_batch.push_back(future.get());
        g_matmul_prepared_inputs.fetch_add(1, std::memory_order_relaxed);
    }
    return prepared_batch;
}

const CBlockIndex* FindGenesisBlockIndex(const CBlockIndex* tip)
{
    if (tip == nullptr || tip->nHeight < 0) {
        return nullptr;
    }

    // Avoid GetAncestor(0) on malformed/unlinked index chains. Header-sync
    // side branches can contain inconsistent pointers while being validated.
    const CBlockIndex* cursor = tip;
    int remaining_steps = tip->nHeight;
    while (cursor != nullptr && cursor->nHeight > 0) {
        const CBlockIndex* prev = cursor->pprev;
        if (prev == nullptr) {
            return nullptr;
        }
        if (prev->nHeight >= cursor->nHeight) {
            return nullptr;
        }
        cursor = prev;
        if (--remaining_steps < 0) {
            return nullptr;
        }
    }

    if (cursor == nullptr) return nullptr;
    if (cursor->nHeight != 0) return nullptr;
    if (cursor->pprev != nullptr) return nullptr;
    return cursor;
}

uint32_t FastMineBootstrapBits(const CBlockIndex* genesis, const Consensus::Params& params)
{
    assert(genesis != nullptr);

    const arith_uint256 pow_limit = UintToArith256(params.powLimit);
    arith_uint256 bootstrap_target;
    bootstrap_target.SetCompact(genesis->nBits);

    const uint32_t scale = std::max<uint32_t>(params.nFastMineDifficultyScale, 1U);
    if (scale > 1) {
        const arith_uint256 max_without_overflow = pow_limit / scale;
        if (bootstrap_target > max_without_overflow) {
            bootstrap_target = pow_limit;
        } else {
            bootstrap_target *= scale;
        }
    }

    bootstrap_target = ClampRetargetResult(bootstrap_target, pow_limit);
    return bootstrap_target.GetCompact();
}

int64_t DampenWarmupTimespanForRestartGap(int64_t observed_timespan, int64_t target_timespan)
{
    assert(target_timespan > 0);
    assert(WARMUP_RESTART_GAP_THRESHOLD_MULTIPLIER > 0);
    assert(WARMUP_RESTART_GAP_DAMPING_DIVISOR > 0);

    const int64_t threshold = target_timespan > std::numeric_limits<int64_t>::max() / WARMUP_RESTART_GAP_THRESHOLD_MULTIPLIER
        ? std::numeric_limits<int64_t>::max()
        : target_timespan * WARMUP_RESTART_GAP_THRESHOLD_MULTIPLIER;
    if (observed_timespan <= threshold) {
        return observed_timespan;
    }

    const int64_t excess = observed_timespan - target_timespan;
    return target_timespan + (excess / WARMUP_RESTART_GAP_DAMPING_DIVISOR);
}

arith_uint256 CalculateMatMulAsertTarget(
    const arith_uint256& anchor_target,
    int64_t time_diff,
    int64_t height_diff,
    int64_t half_life,
    const Consensus::Params& params)
{
    const arith_uint256 pow_limit{UintToArith256(params.powLimit)};
    if (anchor_target == 0 || anchor_target > pow_limit) {
        return pow_limit;
    }
    // AUDIT D1: these are "cannot happen on a valid chain" invariant breaches
    // (a negative height delta, or half-life/spacing that are validated fatally at
    // construction). Fail CLOSED to the hardest representable target rather than
    // OPEN to powLimit, so a breach can never weaken difficulty.
    const arith_uint256 hardest_target{1};
    if (height_diff < 0) {
        LogWarning("CalculateMatMulAsertTarget: height_diff=%lld is negative, failing closed (hardest target)\n",
                   static_cast<long long>(height_diff));
        return hardest_target;
    }
    if (half_life <= 0 || params.nPowTargetSpacing <= 0) {
        LogWarning("CalculateMatMulAsertTarget: invalid parameters (half_life=%lld target_spacing=%lld), failing closed (hardest target)\n",
                   static_cast<long long>(half_life),
                   static_cast<long long>(params.nPowTargetSpacing));
        return hardest_target;
    }

    const int64_t target_spacing = params.nPowTargetSpacing;

    // aserti3-2d exponent:
    //   exponent = ((time_diff - target_spacing * (height_diff + 1)) * 2^16) / half_life
    const __int128 ideal_delta = static_cast<__int128>(target_spacing) *
        static_cast<__int128>(height_diff + 1);
    const __int128 exponent_input = static_cast<__int128>(time_diff) - ideal_delta;
    const __int128 exponent_scaled = exponent_input << ASERT_RADIX_BITS;
    const __int128 exponent_q = exponent_scaled / static_cast<__int128>(half_life);
    int64_t exponent;
    if (exponent_q > std::numeric_limits<int64_t>::max()) {
        exponent = std::numeric_limits<int64_t>::max();
    } else if (exponent_q < std::numeric_limits<int64_t>::min()) {
        exponent = std::numeric_limits<int64_t>::min();
    } else {
        exponent = static_cast<int64_t>(exponent_q);
    }

    const int64_t shifts = exponent >> ASERT_RADIX_BITS;
    const uint32_t frac = static_cast<uint32_t>(exponent) & ((1U << ASERT_RADIX_BITS) - 1U);

    const __int128 poly = static_cast<__int128>(ASERT_POLY_COEFF_1) * frac
        + static_cast<__int128>(ASERT_POLY_COEFF_2) * frac * frac
        + static_cast<__int128>(ASERT_POLY_COEFF_3) * frac * frac * frac
        + (static_cast<__int128>(1) << 47);
    const uint32_t factor = (1U << ASERT_RADIX_BITS) + static_cast<uint32_t>(poly >> 48);

    const int64_t net_shift = shifts - ASERT_RADIX_BITS;
    arith_uint256 next_target{};
    if (net_shift <= -256) {
        next_target = arith_uint256{0};
    } else if (net_shift < 0) {
        const unsigned int right_shift = static_cast<unsigned int>(-net_shift);
        const arith_uint256 max_uint{~arith_uint256{}};
        if (anchor_target > (max_uint / factor)) {
            // Near powLimit, anchor_target*factor can overflow 256 bits even
            // though the final right-shifted value is representable. Shift
            // first in that case to avoid saturation artifacts.
            arith_uint256 shifted_anchor{anchor_target};
            shifted_anchor >>= right_shift;
            next_target = SaturatingMultiplyByUint32(shifted_anchor, factor);
        } else {
            next_target = SaturatingMultiplyByUint32(anchor_target, factor);
            next_target >>= right_shift;
        }
    } else if (net_shift >= 256) {
        next_target = ~arith_uint256{};
    } else {
        next_target = SaturatingMultiplyByUint32(anchor_target, factor);
        if (net_shift > 0) {
            next_target = SaturatingLeftShift256(next_target, static_cast<unsigned int>(net_shift));
        }
    }

    if (next_target == 0) {
        next_target = arith_uint256{1};
    }
    return ClampRetargetResult(next_target, pow_limit);
}

unsigned int DarkGravityWaveLegacy(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);

    if (pindexLast->nHeight < DGW_PAST_BLOCKS) {
        return bnPowLimit.GetCompact();
    }

    const CBlockIndex* pindex = pindexLast;
    arith_uint256 bnPastTargetAvg;

    for (unsigned int nCountBlocks = 1; nCountBlocks <= DGW_PAST_BLOCKS; ++nCountBlocks) {
        if (pindex == nullptr) {
            return bnPowLimit.GetCompact();
        }

        const arith_uint256 bnTarget = arith_uint256{}.SetCompact(pindex->nBits);
        if (nCountBlocks == 1) {
            bnPastTargetAvg = bnTarget;
        } else {
            bnPastTargetAvg = (bnPastTargetAvg * nCountBlocks + bnTarget) / (nCountBlocks + 1);
        }

        if (nCountBlocks != DGW_PAST_BLOCKS) {
            if (pindex->pprev == nullptr) {
                return bnPowLimit.GetCompact();
            }
            pindex = pindex->pprev;
        }
    }

    arith_uint256 bnNew{bnPastTargetAvg};

    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindex->GetBlockTime();
    const int64_t nTargetTimespan = DGW_PAST_BLOCKS * params.nPowTargetSpacing;

    if (nTargetTimespan <= 0) {
        LogWarning("DarkGravityWaveLegacy: nTargetTimespan=%lld is non-positive (nPowTargetSpacing=%lld), returning powLimit\n",
                   static_cast<long long>(nTargetTimespan), static_cast<long long>(params.nPowTargetSpacing));
        return bnPowLimit.GetCompact();
    }

    if (nActualTimespan < nTargetTimespan / 3) nActualTimespan = nTargetTimespan / 3;
    if (nActualTimespan > nTargetTimespan * 3) nActualTimespan = nTargetTimespan * 3;

    bnNew = ScaleTargetByTimespan(bnNew, nActualTimespan, nTargetTimespan);
    bnNew = ClampRetargetResult(bnNew, bnPowLimit);
    return bnNew.GetCompact();
}

[[maybe_unused]] unsigned int DarkGravityWaveMatMul(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);

    const CBlockIndex* genesis = FindGenesisBlockIndex(pindexLast);
    if (genesis == nullptr) {
        return bnPowLimit.GetCompact();
    }
    const int64_t next_height64 = static_cast<int64_t>(pindexLast->nHeight) + 1;
    if (next_height64 < 0 || next_height64 > std::numeric_limits<int32_t>::max()) {
        return bnPowLimit.GetCompact();
    }
    const int32_t next_height = static_cast<int32_t>(next_height64);

    const uint32_t bootstrap_bits = FastMineBootstrapBits(genesis, params);

    // Fast-mining bootstrap intentionally runs at fixed bootstrap difficulty.
    // DGW retargeting begins once the network enters normal spacing.
    if (next_height < params.nFastMineHeight) {
        return bootstrap_bits;
    }

    // Fresh-genesis MatMul networks hold bootstrap difficulty for heights 1..180.
    if (pindexLast->nHeight < DGW_PAST_BLOCKS) {
        return bootstrap_bits;
    }

    // Transition warmup: retarget from the immediate parent so difficulty can
    // converge quickly from fast bootstrap cadence toward the 90s normal target.
    if (next_height >= params.nFastMineHeight &&
        next_height < params.nFastMineHeight + 2 * DGW_PAST_BLOCKS) {
        if (next_height == params.nFastMineHeight) {
            return pindexLast->nBits;
        }

        arith_uint256 bnNew = arith_uint256{}.SetCompact(pindexLast->nBits);
        int64_t nActualTimespan = pindexLast->pprev
            ? pindexLast->GetBlockTime() - pindexLast->pprev->GetBlockTime()
            : params.nPowTargetSpacingNormal;
        const int64_t nTargetTimespan = params.nPowTargetSpacingNormal;
        const int64_t min_timespan = std::max<int64_t>(
            1,
            (nTargetTimespan * WARMUP_HARDENING_MIN_NUM) / WARMUP_HARDENING_MIN_DEN);
        const int64_t max_timespan = std::max<int64_t>(
            min_timespan,
            (nTargetTimespan * WARMUP_EASING_MAX_NUM) / WARMUP_EASING_MAX_DEN);

        // Damp parent-gap shocks (common after miner/node downtime) before
        // clamping to warmup bounds.
        nActualTimespan = DampenWarmupTimespanForRestartGap(nActualTimespan, nTargetTimespan);

        // Asymmetric warmup clamps: harden more slowly on fast blocks, but
        // ease faster on slow blocks so post-restart recovery does not stall.
        if (nActualTimespan < min_timespan) nActualTimespan = min_timespan;
        if (nActualTimespan > max_timespan) nActualTimespan = max_timespan;

        bnNew = ScaleTargetByTimespan(bnNew, nActualTimespan, nTargetTimespan);
        // Never allow warmup retargeting to become easier than the fast-phase
        // bootstrap target.
        arith_uint256 warmup_floor{};
        warmup_floor.SetCompact(bootstrap_bits);
        if (bnNew > warmup_floor) {
            bnNew = warmup_floor;
        }
        bnNew = ClampRetargetResult(bnNew, bnPowLimit);
        return bnNew.GetCompact();
    }

    const CBlockIndex* pindex = pindexLast;
    arith_uint256 bnPastTargetAvg;

    for (unsigned int nCountBlocks = 1; nCountBlocks <= DGW_PAST_BLOCKS; ++nCountBlocks) {
        if (pindex == nullptr) {
            return bnPowLimit.GetCompact();
        }

        const arith_uint256 bnTarget = arith_uint256{}.SetCompact(pindex->nBits);
        if (nCountBlocks == 1) {
            bnPastTargetAvg = bnTarget;
        } else {
            bnPastTargetAvg = (bnPastTargetAvg * nCountBlocks + bnTarget) / (nCountBlocks + 1);
        }

        if (nCountBlocks != DGW_PAST_BLOCKS) {
            if (pindex->pprev == nullptr) {
                return bnPowLimit.GetCompact();
            }
            pindex = pindex->pprev;
        }
    }

    arith_uint256 bnNew{bnPastTargetAvg};

    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindex->GetBlockTime();
    const int64_t nTargetTimespan = ExpectedDgwTimespan(next_height, params);
    if (nTargetTimespan <= 0) {
        LogWarning("DarkGravityWaveMatMul: nTargetTimespan=%lld is non-positive at height %d, returning powLimit\n",
                   static_cast<long long>(nTargetTimespan), next_height);
        return bnPowLimit.GetCompact();
    }

    // Normal-phase DGW clamp profile:
    // - legacy: 2/3..3/2 (historic behavior)
    // - hardened v1: 3/4..2/1
    // - hardened v2: 3/4..3/1 (easing boost to reduce long slow tails after
    //   hashrate shock departures while preserving hardening floor).
    int64_t min_num = NORMAL_LEGACY_HARDENING_MIN_NUM;
    int64_t min_den = NORMAL_LEGACY_HARDENING_MIN_DEN;
    int64_t max_num = NORMAL_LEGACY_EASING_MAX_NUM;
    int64_t max_den = NORMAL_LEGACY_EASING_MAX_DEN;
    if (next_height >= params.nDgwAsymmetricClampHeight) {
        min_num = NORMAL_HARDENED_HARDENING_MIN_NUM;
        min_den = NORMAL_HARDENED_HARDENING_MIN_DEN;
        max_num = NORMAL_HARDENED_EASING_MAX_NUM;
        max_den = NORMAL_HARDENED_EASING_MAX_DEN;
        if (next_height >= params.nDgwEasingBoostHeight) {
            max_num = NORMAL_BOOSTED_EASING_MAX_NUM;
            max_den = NORMAL_BOOSTED_EASING_MAX_DEN;
        }
    }
    const int64_t min_timespan = std::max<int64_t>(1, (nTargetTimespan * min_num) / min_den);
    const int64_t max_timespan = std::max<int64_t>(min_timespan, (nTargetTimespan * max_num) / max_den);
    if (nActualTimespan < min_timespan) nActualTimespan = min_timespan;
    if (nActualTimespan > max_timespan) nActualTimespan = max_timespan;

    bnNew = ScaleTargetByTimespan(bnNew, nActualTimespan, nTargetTimespan);
    const arith_uint256 parent_target = arith_uint256{}.SetCompact(pindexLast->nBits);
    bnNew = ApplyDgwSlewGuard(bnNew, parent_target, next_height, params);
    bnNew = ClampRetargetResult(bnNew, bnPowLimit);
    return bnNew.GetCompact();
}

// DESIGN INVARIANT: MatMul networks use ASERT exclusively for difficulty
// adjustment. DarkGravityWave (DGW) must NOT be used for MatMul mining.
// The fast-mining bootstrap phase (blocks 0..nFastMineHeight-1) uses a fixed
// genesis-derived difficulty. From nFastMineHeight (== nMatMulAsertHeight)
// onward, ASERT governs all retargeting. This design was chosen because
// ASERT's stateless, path-independent algorithm avoids the convergence,
// oscillation, and warmup issues inherent to DGW. Do not modify this
// algorithm selection without explicit project approval.
unsigned int MatMulAsert(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    const arith_uint256 pow_limit{UintToArith256(params.powLimit)};

    const int64_t next_height64 = static_cast<int64_t>(pindexLast->nHeight) + 1;
    if (next_height64 < 0 || next_height64 > std::numeric_limits<int32_t>::max()) {
        return pow_limit.GetCompact();
    }
    const int32_t next_height = static_cast<int32_t>(next_height64);

    // Fast-mining bootstrap phase: hold fixed genesis-derived difficulty.
    // This replaces the former DGW-based warmup/transition logic.
    if (next_height < params.nMatMulAsertHeight) {
        const CBlockIndex* genesis = FindGenesisBlockIndex(pindexLast);
        if (genesis == nullptr) {
            return pow_limit.GetCompact();
        }
        return FastMineBootstrapBits(genesis, params);
    }

    if (!ValidateMatMulAsertParams(params, next_height)) {
        // AUDIT D1: fail CLOSED (hardest target), never open to powLimit. Immutable
        // ASERT params are validated fatally at construction, so this is an
        // unreachable defence-in-depth backstop for a validly-started node.
        return MatMulAsertFailClosedBits();
    }

    const uint32_t bootstrap_factor = params.nMatMulAsertBootstrapFactor;
    if (next_height == params.nMatMulAsertHeight) {
        arith_uint256 parent_target{};
        parent_target.SetCompact(pindexLast->nBits);
        arith_uint256 bootstrap_target{parent_target};
        if (bootstrap_factor > 1) {
            bootstrap_target = SaturatingMultiplyByUint32(bootstrap_target, bootstrap_factor);
        }
        bootstrap_target = ClampRetargetResult(bootstrap_target, pow_limit);
        return bootstrap_target.GetCompact();
    }

    const uint32_t retune_hardening_factor = params.nMatMulAsertRetuneHardeningFactor;
    if (next_height == params.nMatMulAsertRetuneHeight) {
        arith_uint256 parent_target{};
        parent_target.SetCompact(pindexLast->nBits);
        arith_uint256 retune_target{parent_target};
        if (retune_hardening_factor > 1) {
            retune_target /= retune_hardening_factor;
        }
        retune_target = ClampRetargetResult(retune_target, pow_limit);
        return retune_target.GetCompact();
    }

    const uint32_t retune2_num = params.nMatMulAsertRetune2TargetNum;
    const uint32_t retune2_den = params.nMatMulAsertRetune2TargetDen;
    if (next_height == params.nMatMulAsertRetune2Height) {
        arith_uint256 parent_target{};
        parent_target.SetCompact(pindexLast->nBits);
        arith_uint256 retune2_target = ScaleTargetByTimespan(
            parent_target,
            static_cast<int64_t>(retune2_num),
            static_cast<int64_t>(retune2_den));
        retune2_target = ClampRetargetResult(retune2_target, pow_limit);
        return retune2_target.GetCompact();
    }

    // MatMul v4 (spec §I.4): one-time ASERT rescale at the v4 fork height,
    // mechanically identical to the retune2 mechanism above --
    // next_target = parent_target * Num/Den, then ASERT re-anchors on this
    // block (LatestMatMulAsertPreUpgradeAnchorHeight, above). The v4 per-nonce
    // work unit (a dense INT8 GEMM) differs sharply in cost from the v3
    // pre-hash-gated transcript work unit it replaces, so attempts/s can drop
    // by a large hardware-dependent factor exactly at the fork; Num/Den must
    // be calibrated empirically pre-release per network (nMatMulV4AsertRescaleNum/
    // Den, default 1/1 = no rescale for fresh chains that bootstrap nBits
    // directly for the v4 work unit).
    // Single-activation (audit wave-3): when the whole upgrade activates on ONE
    // flag day, nMatMulV4Height == nMatMulBMX4CHeight and the LIVE profile at the
    // fork is ENC-BMX4C (GetMatMulEncodingProfile returns ENC_BMX4C at that
    // height) -- so the BMX4C rescale (calibrated for the actual v3->BMX4C work
    // shift) must fire, NOT the v4/ENC-S8 one. Guard the v4 branch out at
    // equality so control falls through to the BMX4C branch below. In the staged
    // two-phase config (v4 < bmx4c) the heights differ and this changes nothing.
    if (next_height == params.nMatMulV4Height && next_height != params.nMatMulBMX4CHeight) {
        arith_uint256 parent_target{};
        parent_target.SetCompact(pindexLast->nBits);
        // AUDIT D3: apply the GCD-reduced 32-bit ratio so a large-but-exact
        // calibration is not distorted by ScaleTargetByTimespan's per-term clamp.
        uint32_t v4_rn, v4_rd;
        if (!ReduceRescaleRatioToU32(params.nMatMulV4AsertRescaleNum, params.nMatMulV4AsertRescaleDen, v4_rn, v4_rd)) {
            return MatMulAsertFailClosedBits();  // D1: unreachable post-construction; never powLimit
        }
        arith_uint256 v4_target = ScaleTargetByTimespan(parent_target, v4_rn, v4_rd);
        v4_target = ClampRetargetResult(v4_target, pow_limit);
        return v4_target.GetCompact();
    }

    // MatMul v4.2 / ENC-BMX4C (B2b): one-time ASERT rescale at the ENC-BMX4C
    // encoding-profile fork height, mechanically identical to the v4 rescale
    // above -- next_target = parent_target * Num/Den, then ASERT re-anchors on
    // this block (LatestMatMulAsertPreUpgradeAnchorHeight, above). The ENC-BMX4C
    // marginal per-nonce work unit differs from ENC-S8's (~28% less XOF work;
    // per-class GEMM rates shift), so attempts/s can move at the profile fork;
    // Num/Den must be calibrated empirically pre-release per network from the
    // measured marginal nonce/s (nMatMulBMX4CAsertRescaleNum/Den, default 1/1 =
    // no rescale = target continuous across the boundary).
    if (next_height == params.nMatMulBMX4CHeight) {
        arith_uint256 parent_target{};
        parent_target.SetCompact(pindexLast->nBits);
        // AUDIT D3: GCD-reduced 32-bit ratio (see the v4 branch).
        uint32_t bmx4c_rn, bmx4c_rd;
        if (!ReduceRescaleRatioToU32(params.nMatMulBMX4CAsertRescaleNum, params.nMatMulBMX4CAsertRescaleDen, bmx4c_rn, bmx4c_rd)) {
            return MatMulAsertFailClosedBits();  // D1: unreachable post-construction; never powLimit
        }
        arith_uint256 bmx4c_target = ScaleTargetByTimespan(parent_target, bmx4c_rn, bmx4c_rd);
        bmx4c_target = ClampRetargetResult(bmx4c_target, pow_limit);
        return bmx4c_target.GetCompact();
    }

    if (next_height == params.nMatMulAsertHalfLifeUpgradeHeight) {
        arith_uint256 parent_target{};
        parent_target.SetCompact(pindexLast->nBits);
        parent_target = ClampRetargetResult(parent_target, pow_limit);
        return parent_target.GetCompact();
    }

    // ASERT anchor:
    // - base anchor is first ASERT block (activation block itself)
    // - after optional target retunes, re-anchor on the latest retune block to
    //   preserve one-time adjustments as the ASERT baseline
    // - after the optional half-life upgrade, re-anchor on the upgrade block so
    //   the new half-life applies prospectively instead of retroactively.
    const MatMulAsertHalfLifeInfo half_life_info = ResolveMatMulAsertHalfLifeInfo(pindexLast, params);
    const int32_t anchor_height = half_life_info.current_anchor_height;
    if (anchor_height < 0 || pindexLast->nHeight < anchor_height) {
        return pow_limit.GetCompact();
    }
    const CBlockIndex* anchor = pindexLast->GetAncestor(anchor_height);
    if (anchor == nullptr) {
        return pow_limit.GetCompact();
    }

    arith_uint256 anchor_target{};
    anchor_target.SetCompact(anchor->nBits);
    if (anchor_target == 0 || anchor_target > pow_limit) {
        anchor_target = pow_limit;
    }
    const int64_t time_diff = pindexLast->GetBlockTime() - anchor->GetBlockTime();
    const int64_t height_diff = static_cast<int64_t>(pindexLast->nHeight) - anchor->nHeight;
    const arith_uint256 next_target = CalculateMatMulAsertTarget(
        anchor_target,
        time_diff,
        height_diff,
        half_life_info.current_half_life_s,
        params);
    return next_target.GetCompact();
}
} // namespace

MatMulAsertHalfLifeInfo GetMatMulAsertHalfLifeInfo(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    return ResolveMatMulAsertHalfLifeInfo(pindexLast, params);
}

uint32_t GetMatMulPreHashEpsilonBitsForHeight(const Consensus::Params& params, int32_t block_height)
{
    return params.GetMatMulPreHashEpsilonBitsForHeight(block_height);
}

MatMulPreHashEpsilonBitsInfo GetMatMulPreHashEpsilonBitsInfo(int32_t current_tip_height, const Consensus::Params& params)
{
    return ResolveMatMulPreHashEpsilonBitsInfo(current_tip_height, params);
}

MatMulSolvePipelineStats ProbeMatMulSolvePipelineStats()
{
    MatMulSolvePipelineStats stats;
    stats.parallel_solver_enabled = g_matmul_parallel_solver_enabled.load(std::memory_order_relaxed);
    stats.parallel_solver_threads = g_matmul_parallel_solver_threads.load(std::memory_order_relaxed);
    stats.async_prepare_enabled = g_matmul_async_prepare_enabled.load(std::memory_order_relaxed);
    stats.cpu_confirm_candidates = g_matmul_cpu_confirm_candidates.load(std::memory_order_relaxed);
    stats.prepared_inputs = g_matmul_prepared_inputs.load(std::memory_order_relaxed);
    stats.overlapped_prepares = g_matmul_overlapped_prepares.load(std::memory_order_relaxed);
    stats.prefetched_batches = g_matmul_prefetched_batches.load(std::memory_order_relaxed);
    stats.prefetched_inputs = g_matmul_prefetched_inputs.load(std::memory_order_relaxed);
    stats.async_prepare_submissions = g_matmul_async_prepare_submissions.load(std::memory_order_relaxed);
    stats.async_prepare_completions = g_matmul_async_prepare_completions.load(std::memory_order_relaxed);
    stats.async_prepare_worker_threads = g_matmul_async_prepare_worker_threads.load(std::memory_order_relaxed);
    stats.prefetch_depth = g_matmul_prefetch_depth.load(std::memory_order_relaxed);
    stats.batch_size = g_matmul_batch_size.load(std::memory_order_relaxed);
    stats.batched_digest_requests = g_matmul_batched_digest_requests.load(std::memory_order_relaxed);
    stats.batched_nonce_attempts = g_matmul_batched_nonce_attempts.load(std::memory_order_relaxed);
    return stats;
}

void ResetMatMulSolvePipelineStats()
{
    g_matmul_parallel_solver_enabled.store(false, std::memory_order_relaxed);
    g_matmul_parallel_solver_threads.store(1U, std::memory_order_relaxed);
    g_matmul_prepared_inputs.store(0, std::memory_order_relaxed);
    g_matmul_overlapped_prepares.store(0, std::memory_order_relaxed);
    g_matmul_prefetched_batches.store(0, std::memory_order_relaxed);
    g_matmul_prefetched_inputs.store(0, std::memory_order_relaxed);
    g_matmul_prefetch_depth.store(1, std::memory_order_relaxed);
    g_matmul_batch_size.store(1, std::memory_order_relaxed);
    g_matmul_batched_digest_requests.store(0, std::memory_order_relaxed);
    g_matmul_batched_nonce_attempts.store(0, std::memory_order_relaxed);
    g_matmul_async_prepare_submissions.store(0, std::memory_order_relaxed);
    g_matmul_async_prepare_completions.store(0, std::memory_order_relaxed);
    g_matmul_async_prepare_enabled.store(false, std::memory_order_relaxed);
    g_matmul_cpu_confirm_candidates.store(false, std::memory_order_relaxed);
}

MatMulGpuPreHashScanStats ProbeMatMulGpuPreHashScanStats()
{
    MatMulGpuPreHashScanStats stats;
    stats.attempts = g_matmul_gpu_prehash_scan_attempts.load(std::memory_order_relaxed);
    stats.successes = g_matmul_gpu_prehash_scan_successes.load(std::memory_order_relaxed);
    stats.failures = g_matmul_gpu_prehash_scan_failures.load(std::memory_order_relaxed);
    stats.metal_fallbacks_to_cpu = g_matmul_metal_nonce_seed_scan_fallbacks.load(std::memory_order_relaxed);
    stats.cuda_fallbacks_to_cpu = g_matmul_cuda_nonce_seed_scan_fallbacks.load(std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(g_matmul_gpu_prehash_scan_mutex);
    stats.last_backend = g_matmul_gpu_prehash_scan_last_backend;
    stats.last_error = g_matmul_gpu_prehash_scan_last_error;
    return stats;
}

void ResetMatMulGpuPreHashScanStats()
{
    g_matmul_gpu_prehash_scan_attempts.store(0, std::memory_order_relaxed);
    g_matmul_gpu_prehash_scan_successes.store(0, std::memory_order_relaxed);
    g_matmul_gpu_prehash_scan_failures.store(0, std::memory_order_relaxed);
    g_matmul_metal_nonce_seed_scan_fallbacks.store(0, std::memory_order_relaxed);
    g_matmul_cuda_nonce_seed_scan_fallbacks.store(0, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(g_matmul_gpu_prehash_scan_mutex);
    g_matmul_gpu_prehash_scan_last_backend.clear();
    g_matmul_gpu_prehash_scan_last_error.clear();
}

MatMulDigestCompareStats ProbeMatMulDigestCompareStats()
{
    MatMulDigestCompareStats stats;
    stats.enabled = g_matmul_digest_compare_enabled.load(std::memory_order_relaxed);
    stats.compared_attempts = g_matmul_digest_compare_attempts.load(std::memory_order_relaxed);
    stats.first_divergence_captured = g_matmul_digest_compare_first_divergence.load(std::memory_order_relaxed);
    if (!stats.first_divergence_captured) {
        return stats;
    }

    std::lock_guard<std::mutex> lock(g_matmul_digest_compare_mutex);
    stats.first_divergence_nonce64 = g_matmul_digest_compare_nonce64;
    stats.first_divergence_nonce32 = g_matmul_digest_compare_nonce32;
    stats.first_divergence_header_hash = g_matmul_digest_compare_header_hash;
    stats.first_divergence_backend_digest = g_matmul_digest_compare_backend_digest;
    stats.first_divergence_cpu_digest = g_matmul_digest_compare_cpu_digest;
    return stats;
}

void ResetMatMulDigestCompareStats()
{
    g_matmul_digest_compare_enabled.store(false, std::memory_order_relaxed);
    g_matmul_digest_compare_attempts.store(0, std::memory_order_relaxed);
    g_matmul_digest_compare_first_divergence.store(false, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(g_matmul_digest_compare_mutex);
    g_matmul_digest_compare_nonce64 = 0;
    g_matmul_digest_compare_nonce32 = 0;
    g_matmul_digest_compare_header_hash.clear();
    g_matmul_digest_compare_backend_digest.clear();
    g_matmul_digest_compare_cpu_digest.clear();
}

MatMulSolveRuntimeStats ProbeMatMulSolveRuntimeStats()
{
    MatMulSolveRuntimeStats stats;
    stats.attempts = g_matmul_solve_attempts.load(std::memory_order_relaxed);
    stats.solved_attempts = g_matmul_solve_successes.load(std::memory_order_relaxed);
    stats.failed_attempts = g_matmul_solve_failures.load(std::memory_order_relaxed);
    stats.total_elapsed_us = g_matmul_solve_total_elapsed_us.load(std::memory_order_relaxed);
    stats.last_elapsed_us = g_matmul_solve_last_elapsed_us.load(std::memory_order_relaxed);
    stats.max_elapsed_us = g_matmul_solve_max_elapsed_us.load(std::memory_order_relaxed);
    return stats;
}

void ResetMatMulSolveRuntimeStats()
{
    g_matmul_solve_attempts.store(0, std::memory_order_relaxed);
    g_matmul_solve_successes.store(0, std::memory_order_relaxed);
    g_matmul_solve_failures.store(0, std::memory_order_relaxed);
    g_matmul_solve_total_elapsed_us.store(0, std::memory_order_relaxed);
    g_matmul_solve_last_elapsed_us.store(0, std::memory_order_relaxed);
    g_matmul_solve_max_elapsed_us.store(0, std::memory_order_relaxed);
}

MatMulValidationRuntimeStats ProbeMatMulValidationRuntimeStats()
{
    MatMulValidationRuntimeStats stats;
    stats.phase2_checks = g_matmul_validation_phase2_checks.load(std::memory_order_relaxed);
    stats.freivalds_checks = g_matmul_validation_freivalds_checks.load(std::memory_order_relaxed);
    stats.transcript_checks = g_matmul_validation_transcript_checks.load(std::memory_order_relaxed);
    stats.successful_checks = g_matmul_validation_successes.load(std::memory_order_relaxed);
    stats.failed_checks = g_matmul_validation_failures.load(std::memory_order_relaxed);
    stats.total_phase2_elapsed_us = g_matmul_validation_total_phase2_elapsed_us.load(std::memory_order_relaxed);
    stats.total_freivalds_elapsed_us = g_matmul_validation_total_freivalds_elapsed_us.load(std::memory_order_relaxed);
    stats.total_transcript_elapsed_us = g_matmul_validation_total_transcript_elapsed_us.load(std::memory_order_relaxed);
    stats.last_phase2_elapsed_us = g_matmul_validation_last_phase2_elapsed_us.load(std::memory_order_relaxed);
    stats.last_freivalds_elapsed_us = g_matmul_validation_last_freivalds_elapsed_us.load(std::memory_order_relaxed);
    stats.last_transcript_elapsed_us = g_matmul_validation_last_transcript_elapsed_us.load(std::memory_order_relaxed);
    stats.max_phase2_elapsed_us = g_matmul_validation_max_phase2_elapsed_us.load(std::memory_order_relaxed);
    stats.max_freivalds_elapsed_us = g_matmul_validation_max_freivalds_elapsed_us.load(std::memory_order_relaxed);
    stats.max_transcript_elapsed_us = g_matmul_validation_max_transcript_elapsed_us.load(std::memory_order_relaxed);
    return stats;
}

void ResetMatMulValidationRuntimeStats()
{
    g_matmul_validation_phase2_checks.store(0, std::memory_order_relaxed);
    g_matmul_validation_freivalds_checks.store(0, std::memory_order_relaxed);
    g_matmul_validation_transcript_checks.store(0, std::memory_order_relaxed);
    g_matmul_validation_successes.store(0, std::memory_order_relaxed);
    g_matmul_validation_failures.store(0, std::memory_order_relaxed);
    g_matmul_validation_total_phase2_elapsed_us.store(0, std::memory_order_relaxed);
    g_matmul_validation_total_freivalds_elapsed_us.store(0, std::memory_order_relaxed);
    g_matmul_validation_total_transcript_elapsed_us.store(0, std::memory_order_relaxed);
    g_matmul_validation_last_phase2_elapsed_us.store(0, std::memory_order_relaxed);
    g_matmul_validation_last_freivalds_elapsed_us.store(0, std::memory_order_relaxed);
    g_matmul_validation_last_transcript_elapsed_us.store(0, std::memory_order_relaxed);
    g_matmul_validation_max_phase2_elapsed_us.store(0, std::memory_order_relaxed);
    g_matmul_validation_max_freivalds_elapsed_us.store(0, std::memory_order_relaxed);
    g_matmul_validation_max_transcript_elapsed_us.store(0, std::memory_order_relaxed);
}

void RegisterMatMulDigestCompareAttempt(const CBlockHeader& block,
                                        const uint256& backend_digest,
                                        const uint256& cpu_digest,
                                        const char* backend_label)
{
    g_matmul_digest_compare_attempts.fetch_add(1, std::memory_order_relaxed);
    if (backend_digest == cpu_digest) {
        return;
    }

    bool expected{false};
    if (!g_matmul_digest_compare_first_divergence.compare_exchange_strong(
            expected,
            true,
            std::memory_order_relaxed,
            std::memory_order_relaxed)) {
        return;
    }

    const std::string header_hash = block.GetHash().GetHex();
    const std::string backend_hex = backend_digest.GetHex();
    const std::string cpu_hex = cpu_digest.GetHex();
    const char* label = backend_label != nullptr && backend_label[0] != '\0'
        ? backend_label
        : "backend";
    {
        std::lock_guard<std::mutex> lock(g_matmul_digest_compare_mutex);
        g_matmul_digest_compare_nonce64 = block.nNonce64;
        g_matmul_digest_compare_nonce32 = block.nNonce;
        g_matmul_digest_compare_header_hash = header_hash;
        g_matmul_digest_compare_backend_digest = backend_hex;
        g_matmul_digest_compare_cpu_digest = cpu_hex;
    }
    LogPrintf(
        "MATMUL WARNING: cpu/%s digest divergence at nonce64=%llu nonce32=%u header=%s %s=%s cpu=%s\n",
        label,
        static_cast<unsigned long long>(block.nNonce64),
        block.nNonce,
        header_hash.c_str(),
        label,
        backend_hex.c_str(),
        cpu_hex.c_str());
}

int64_t ExpectedDgwTimespan(int32_t height, const Consensus::Params& params)
{
    const int64_t interval_count =
        (height >= params.nDgwWindowAlignmentHeight && DGW_PAST_BLOCKS > 1)
        ? (DGW_PAST_BLOCKS - 1)
        : DGW_PAST_BLOCKS;
    if (height < params.nFastMineHeight) {
        return (interval_count * params.nPowTargetSpacingFastMs) / 1000;
    }
    return interval_count * params.nPowTargetSpacingNormal;
}

bool EnforceTimewarpProtectionAtHeight(const Consensus::Params& params, int32_t block_height)
{
    if (!params.enforce_BIP94 || block_height <= 0) {
        return false;
    }

    // Per-block retargeting engines need per-block timestamp protection.
    if (!params.fPowNoRetargeting) {
        if (params.fMatMulPOW) {
            return true;
        }
        if (params.fKAWPOW && block_height >= params.nKAWPOWHeight) {
            return true;
        }
    }

    return block_height % params.DifficultyAdjustmentInterval() == 0;
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
    const int64_t next_height = static_cast<int64_t>(pindexLast->nHeight) + 1;
    if (next_height < 0 || next_height > std::numeric_limits<int>::max()) {
        return nProofOfWorkLimit;
    }

    if (params.fPowNoRetargeting) {
        return pindexLast->nBits;
    }

    if (params.fMatMulPOW) {
        // DESIGN INVARIANT: MatMul networks use ASERT exclusively for all
        // difficulty adjustment after the fast-mining bootstrap phase.
        // DarkGravityWave (DGW) is NOT used for MatMul mining. Do not
        // reintroduce DGW routing here -- it was deliberately replaced by
        // ASERT to avoid convergence and oscillation issues inherent to DGW.
        return MatMulAsert(pindexLast, params);
    }

    if (params.fKAWPOW && next_height >= params.nKAWPOWHeight) {
        return DarkGravityWaveLegacy(pindexLast, params);
    }

    // Only change once per difficulty adjustment interval
    if (next_height % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;

    // Special difficulty rule for Testnet4
    if (params.enforce_BIP94) {
        // Here we use the first block of the difficulty period. This way
        // the real difficulty is always preserved in the first block as
        // it is not allowed to use the min-difficulty exception.
        int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
        const CBlockIndex* pindexFirst = nHeightFirst >= 0 ? pindexLast->GetAncestor(nHeightFirst) : nullptr;
        bnNew.SetCompact((pindexFirst != nullptr ? pindexFirst : pindexLast)->nBits);
    } else {
        bnNew.SetCompact(pindexLast->nBits);
    }

    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    bnNew = ClampRetargetResult(bnNew, bnPowLimit);

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fMatMulPOW) {
        auto old_target = DeriveTarget(old_nbits, params.powLimit);
        auto new_target = DeriveTarget(new_nbits, params.powLimit);
        if (!old_target || !new_target) return false;

        // Presync sanity bounds for ASERT headers: do not allow per-block jumps
        // beyond 4x in either direction.
        const arith_uint256 pow_limit = UintToArith256(params.powLimit);

        arith_uint256 easier_bound{*old_target};
        if (easier_bound > (pow_limit / 4)) {
            easier_bound = pow_limit;
        } else {
            easier_bound *= 4;
        }
        // Compare against the compact-rounded bound because headers encode
        // difficulty via compact nBits.
        arith_uint256 max_new_target;
        max_new_target.SetCompact(easier_bound.GetCompact());
        if (*new_target > max_new_target) return false;

        arith_uint256 harder_bound{*old_target};
        harder_bound /= 4;
        if (harder_bound == 0) harder_bound = arith_uint256{1};
        arith_uint256 min_new_target;
        min_new_target.SetCompact(harder_bound.GetCompact());
        if (*new_target < min_new_target) return false;

        return true;
    }

    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most significant bit of the last byte of the hash is set.
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if constexpr (G_FUZZING) return (hash.data()[31] & 0x80) == 0;
    return CheckProofOfWorkImpl(hash, nBits, params);
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    auto bnTarget{DeriveTarget(nBits, params.powLimit)};
    if (!bnTarget) return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

bool CheckMatMulProofOfWork_Phase1(const CBlockHeader& block, const Consensus::Params& params)
{
    // Genesis is statically embedded and does not carry mined MatMul transcript
    // fields. Reject synthetic headers that only mimic a genesis prevhash.
    if (block.hashPrevBlock.IsNull()) {
        return block.GetHash() == params.hashGenesisBlock;
    }

    // MatMul v4 (spec §I.1): height is not available at this context-free
    // layer -- CheckBlockHeader/CheckBlock in validation.cpp both call this
    // before the block index (and hence height) is resolved. Accept EITHER
    // the legacy v3 dimension or the v4 dimension (only when a v4 fork
    // height is actually configured on this network); the height-gated
    // exact-match enforcement runs contextually in ContextualCheckBlockHeader,
    // exactly mirroring how the rest of the v3 cascade (Phase2/Freivalds/
    // ProductCommitted, and now CheckMatMulProofOfWork_V4ProductCommitted)
    // already defers to ContextualCheckBlock for full block-index context.
    const bool v4_configured = params.nMatMulV4Height != std::numeric_limits<int32_t>::max();
    const bool matches_v4_dim = v4_configured && block.matmul_dim == params.nMatMulV4Dimension;
    if (matches_v4_dim) {
        if (params.nMatMulV4TranscriptBlockSize == 0) return false;
        if (block.matmul_dim % params.nMatMulV4TranscriptBlockSize != 0) return false;
    } else {
        if (params.nMatMulTranscriptBlockSize == 0) return false;
        if (block.matmul_dim != params.nMatMulDimension) return false;
        if (block.matmul_dim < params.nMatMulMinDimension) return false;
        if (block.matmul_dim > params.nMatMulMaxDimension) return false;
        if (block.matmul_dim % params.nMatMulTranscriptBlockSize != 0) return false;
        if (params.nMatMulNoiseRank == 0 || params.nMatMulNoiseRank > block.matmul_dim) return false;
    }
    if (block.seed_a.IsNull() || block.seed_b.IsNull()) return false;

    auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
    if (!bnTarget) return false;
    if (UintToArith256(block.matmul_digest) > *bnTarget) return false;

    return true;
}

std::optional<arith_uint256> DeriveMatMulHeaderPoWGateTarget(
    unsigned int nBits, uint32_t discount_bits, const uint256& pow_limit)
{
    // AUDIT H4: the PURE gate-target derivation, extracted so it can be unit-tested
    // directly with fixed vectors (no header, no hashing). Returns the throttle
    // target a header claiming difficulty `nBits` must hash at or under, or
    // std::nullopt when the throttle does not apply / is misconfigured, namely:
    //   - discount_bits == UINT32_MAX (the "disabled" sentinel), or
    //   - discount_bits > 255 (AUDIT H2: an out-of-range discount that would force
    //     the target to powLimit regardless of nBits, recreating the fixed-cost
    //     C2 gate), or
    //   - nBits does not decode to a valid target.
    // The target is the block's OWN nBits-derived target shifted EASIER by
    // `discount_bits`, saturating at powLimit -- so forging cost stays PROPORTIONAL
    // to the claimed chainwork (audit C2), never a fixed constant.
    if (discount_bits == std::numeric_limits<uint32_t>::max()) return std::nullopt; // disabled
    if (discount_bits > Consensus::Params::MATMUL_HEADER_POW_MAX_DISCOUNT_BITS) return std::nullopt; // H2
    const auto block_target{DeriveTarget(nBits, pow_limit)};
    if (!block_target) return std::nullopt;
    const arith_uint256 limit{UintToArith256(pow_limit)};
    arith_uint256 gate_target{*block_target};
    if (discount_bits != 0) {
        // Saturate at powLimit if the left-shift would overflow 256 bits.
        if ((gate_target >> (256 - discount_bits)) != arith_uint256{0}) {
            gate_target = limit;
        } else {
            gate_target <<= discount_bits;
            if (gate_target > limit) gate_target = limit;
        }
    }
    return gate_target;
}

bool CheckMatMulHeaderSpamGate(const CBlockHeader& block, const Consensus::Params& params)
{
    // Audit F1/C1/C2: header-PoW THROTTLE bound to nBits. The preimage is the block
    // hash (which commits every consensus header field, incl. the self-declared
    // matmul_digest) concatenated with the DECOUPLED grinding nonce `nNonce`. Since
    // nNonce is NOT part of ComputeMatMulHeaderHash, an honest miner grinds it
    // WITHOUT recomputing the matmul. The throttle target is the block's OWN
    // difficulty target (from nBits) shifted EASIER by the discount, so the header
    // hash-work required to forge a header is PROPORTIONAL to the chainwork it
    // claims (audit C2 -- a fixed target would let one easy grind claim arbitrary
    // ASERT-derived work). This is a rate-limiting throttle, NOT full authentication
    // of matmul-calibrated chainwork (audit C1 -- SHA << matmul; see the doc).
    // Disabled sentinel: discount == UINT32_MAX -> always passes.
    if (!params.IsMatMulHeaderPoWEnabled()) return true;
    // AUDIT H2: a discount >= 256 (but != the UINT32_MAX "disabled" sentinel) is an
    // invalid configuration (rejected fatally at chain-parameter construction). If
    // one ever reaches here it is a runtime invariant violation, so FAIL CLOSED
    // (reject the header) rather than fail open to the easiest target. The pure
    // helper below returns nullopt for both the disabled sentinel and any
    // out-of-range/undecodable case, so the explicit check keeps the disabled path
    // (return true, above) distinct from the invalid path (return false, here).
    const auto gate_target{
        DeriveMatMulHeaderPoWGateTarget(block.nBits, params.nMatMulHeaderPoWDiscountBits, params.powLimit)};
    if (!gate_target) return false;
    HashWriter hw;
    hw << block.GetHash() << block.nNonce;
    return UintToArith256(hw.GetHash()) <= *gate_target;
}

bool CheckMatMulPreHashGate(const CBlockHeader& block, const Consensus::Params& params, int32_t block_height)
{
    const uint32_t pre_hash_epsilon_bits = GetMatMulPreHashEpsilonBitsForHeight(params, block_height);
    if (pre_hash_epsilon_bits == 0) return true;

    auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
    if (!bnTarget) return false;
    const arith_uint256 pre_hash_target = SaturatingLeftShift256(*bnTarget, pre_hash_epsilon_bits);
    return UintToArith256(matmul::DeriveSigma(block)) <= pre_hash_target;
}

bool CheckMatMulProofOfWork_Phase2(const CBlockHeader& block, const Consensus::Params& params, int32_t block_height)
{
    const auto start = std::chrono::steady_clock::now();
    const auto finish = [&](bool passed) {
        RegisterMatMulValidationRuntimeSample(
            MatMulValidationPath::TRANSCRIPT,
            passed,
            std::chrono::steady_clock::now() - start);
        return passed;
    };

    if (!CheckMatMulProofOfWork_Phase1(block, params)) return finish(false);
    if (params.nMatMulNoiseRank == 0 || params.nMatMulNoiseRank > block.matmul_dim) return finish(false);
    if (params.nMatMulTranscriptBlockSize == 0 || block.matmul_dim % params.nMatMulTranscriptBlockSize != 0) return finish(false);

    // Pre-hash lottery verification: reject blocks whose sigma doesn't pass the
    // cheap pre-filter, ensuring miners actually ran the pre-hash step.
    if (!CheckMatMulPreHashGate(block, params, block_height)) return finish(false);

    const uint32_t n = block.matmul_dim;
    const auto A = matmul::SharedFromSeed(block.seed_a, n);
    const auto B = matmul::SharedFromSeed(block.seed_b, n);
    const uint256 sigma = matmul::DeriveSigma(block);

    // noise_rank is a consensus parameter (network-global), not a per-block field.
    const auto np = matmul::noise::Generate(sigma, n, params.nMatMulNoiseRank);
    const auto A_prime = *A + (np.E_L * np.E_R);
    const auto B_prime = *B + (np.F_L * np.F_R);

    const auto transcript = matmul::transcript::CanonicalMatMul(
        A_prime,
        B_prime,
        params.nMatMulTranscriptBlockSize,
        sigma);

    return finish(transcript.transcript_hash == block.matmul_digest);
}

bool HasMatMulV2Payload(const CBlock& block)
{
    return !block.matrix_a_data.empty() || !block.matrix_b_data.empty();
}

bool IsMatMulV2PayloadSizeValid(const CBlock& block, const Consensus::Params& params)
{
    if (block.matmul_dim == 0) return false;
    if (block.matmul_dim < params.nMatMulMinDimension) return false;
    if (block.matmul_dim > params.nMatMulMaxDimension) return false;
    if (block.matrix_a_data.size() != block.matrix_b_data.size()) return false;
    const uint64_t n = static_cast<uint64_t>(block.matmul_dim);
    if (n > std::numeric_limits<uint64_t>::max() / n) return false;
    const uint64_t expected_words = n * n;
    if (expected_words > MATMUL_V2_MAX_PAYLOAD_WORDS) return false;
    return block.matrix_a_data.size() == expected_words;
}

std::chrono::milliseconds EffectiveTargetSpacingForHeight(int32_t height, const Consensus::Params& params)
{
    if (params.fMatMulPOW && height < params.nFastMineHeight) {
        return std::chrono::milliseconds{params.nPowTargetSpacingFastMs};
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds{params.nPowTargetSpacing});
}

bool CheckMatMulProofOfWork_Phase2WithPayload(const CBlock& block, const Consensus::Params& params, int32_t block_height)
{
    if (!CheckMatMulProofOfWork_Phase1(block, params)) return false;
    if (!IsMatMulV2PayloadSizeValid(block, params)) return false;
    if (block.matmul_dim < params.nMatMulMinDimension) return false;
    if (block.matmul_dim > params.nMatMulMaxDimension) return false;
    if (params.nMatMulNoiseRank == 0 || params.nMatMulNoiseRank > block.matmul_dim) return false;

    if (params.nMatMulTranscriptBlockSize == 0 || block.matmul_dim % params.nMatMulTranscriptBlockSize != 0) return false;

    // Pre-hash lottery verification (same as Phase2)
    if (!CheckMatMulPreHashGate(block, params, block_height)) return false;

    const uint32_t n = block.matmul_dim;
    matmul::Matrix A(n, n);
    matmul::Matrix B(n, n);
    for (uint32_t row = 0; row < n; ++row) {
        for (uint32_t col = 0; col < n; ++col) {
            const size_t idx = static_cast<size_t>(row) * n + col;
            if (idx >= block.matrix_a_data.size() || idx >= block.matrix_b_data.size()) return false;
            // Reject non-canonical payload values (must be < MODULUS)
            if (block.matrix_a_data[idx] >= matmul::field::MODULUS ||
                block.matrix_b_data[idx] >= matmul::field::MODULUS) {
                return false;
            }
            A.at(row, col) = block.matrix_a_data[idx];
            B.at(row, col) = block.matrix_b_data[idx];
        }
    }
    const uint256 sigma = matmul::DeriveSigma(block);

    // noise_rank is a consensus parameter (network-global), not a per-block field.
    const auto np = matmul::noise::Generate(sigma, n, params.nMatMulNoiseRank);
    const auto A_prime = A + (np.E_L * np.E_R);
    const auto B_prime = B + (np.F_L * np.F_R);

    const auto transcript = matmul::transcript::CanonicalMatMul(
        A_prime,
        B_prime,
        params.nMatMulTranscriptBlockSize,
        sigma);
    return transcript.transcript_hash == block.matmul_digest;
}

bool HasMatMulFreivaldsPayload(const CBlock& block)
{
    return !block.matrix_c_data.empty();
}

bool ShouldIncludeMatMulFreivaldsPayloadForMining(int32_t block_height, const Consensus::Params& params)
{
    // MatMul v4 (spec §G.3): v4 blocks are always product-committed and the
    // C payload is always required, independent of the legacy
    // fMatMulFreivaldsEnabled / fMatMulRequireProductPayload flags.
    if (params.IsMatMulV4Active(block_height)) return true;
    if (!params.fMatMulFreivaldsEnabled) return false;
    if (params.IsMatMulProductPayloadRequired(block_height)) return true;
    return params.IsMatMulFreivaldsBindingActive(block_height);
}

bool IsMatMulFreivaldsPayloadSizeValid(const CBlock& block, const Consensus::Params& params)
{
    if (block.matmul_dim == 0) return false;
    if (block.matmul_dim < params.nMatMulMinDimension) return false;
    if (block.matmul_dim > params.nMatMulMaxDimension) return false;
    const uint64_t n = static_cast<uint64_t>(block.matmul_dim);
    if (n > std::numeric_limits<uint64_t>::max() / n) return false;
    const uint64_t expected_words = n * n;
    if (expected_words > MATMUL_V2_MAX_PAYLOAD_WORDS) return false;
    return block.matrix_c_data.size() == expected_words;
}

bool CheckMatMulProofOfWork_Freivalds(const CBlock& block, const Consensus::Params& params, int32_t block_height)
{
    const auto start = std::chrono::steady_clock::now();
    const auto finish = [&](bool passed) {
        RegisterMatMulValidationRuntimeSample(
            MatMulValidationPath::FREIVALDS,
            passed,
            std::chrono::steady_clock::now() - start);
        return passed;
    };

    if (!params.fMatMulFreivaldsEnabled) return finish(false);
    if (!CheckMatMulProofOfWork_Phase1(block, params)) return finish(false);
    if (!IsMatMulFreivaldsPayloadSizeValid(block, params)) return finish(false);
    if (params.nMatMulFreivaldsRounds == 0) return finish(false);
    if (params.nMatMulNoiseRank == 0 || params.nMatMulNoiseRank > block.matmul_dim) return finish(false);

    // Pre-hash lottery verification (same as Phase2)
    if (!CheckMatMulPreHashGate(block, params, block_height)) return finish(false);

    const uint32_t n = block.matmul_dim;

    // Reconstruct A' and B' from seeds + noise
    const auto A = matmul::SharedFromSeed(block.seed_a, n);
    const auto B = matmul::SharedFromSeed(block.seed_b, n);
    const uint256 sigma = matmul::DeriveSigma(block);
    const auto np = matmul::noise::Generate(sigma, n, params.nMatMulNoiseRank);
    const auto A_prime = *A + (np.E_L * np.E_R);
    const auto B_prime = *B + (np.F_L * np.F_R);

    // Reconstruct claimed C' from payload
    matmul::Matrix C_prime(n, n);
    for (uint32_t row = 0; row < n; ++row) {
        for (uint32_t col = 0; col < n; ++col) {
            const size_t idx = static_cast<size_t>(row) * n + col;
            // Reject non-canonical payload values (must be < MODULUS)
            if (block.matrix_c_data[idx] >= matmul::field::MODULUS) return finish(false);
            C_prime.at(row, col) = block.matrix_c_data[idx];
        }
    }

    // Run Freivalds' verification: O(k * n^2) instead of O(n^3)
    const auto fv_result = matmul::freivalds::Verify(
        A_prime, B_prime, C_prime, sigma, params.nMatMulFreivaldsRounds);

    if (!fv_result.passed) return finish(false);

    // Product-committed digest path: if active, the digest is derived from
    // (sigma, A', B', C') so Freivalds + digest check is sufficient — no
    // O(n^3) transcript recomputation needed.
    if (params.IsMatMulProductDigestActive(block_height)) {
        const uint256 expected_digest = matmul::transcript::ComputeProductCommittedDigest(
            C_prime,
            params.nMatMulTranscriptBlockSize,
            sigma);
        if (expected_digest != block.matmul_digest) return finish(false);
    } else {
        const bool require_transcript_binding =
            params.IsMatMulFreivaldsBindingActive(block_height) ||
            HasMatMulFreivaldsPayload(block);
        if (require_transcript_binding) {
            // Freivalds proves the product payload is internally consistent, but it
            // does not bind matmul_digest to the transcript target on its own.
            //
            // Payload-carrying blocks must therefore always satisfy the legacy
            // transcript check as well. Without that, pre-binding heights can admit
            // alternate valid blocks whose acceptance depends on uncommitted trailing
            // payload bytes and an arbitrarily low digest.
            if (!CheckMatMulProofOfWork_Phase2(block, params, block_height)) return finish(false);
        }
    }

    // Freivalds' confirms A'*B' == C' with error probability < (1/p)^k.
    // With k=2, p=2^31-1: error < 2^-62 (cryptographically negligible).
    //
    // Before the transcript-binding upgrade activates, Freivalds + the C'
    // payload are accepted as the full phase2 proof. After activation, the
    // transcript check above binds matmul_digest to the same claimed work.
    return finish(true);
}

bool CheckMatMulProofOfWork_ProductCommitted(const CBlock& block, const Consensus::Params& params, int32_t block_height)
{
    const auto start = std::chrono::steady_clock::now();
    const auto finish = [&](bool passed) {
        RegisterMatMulValidationRuntimeSample(
            MatMulValidationPath::FREIVALDS,
            passed,
            std::chrono::steady_clock::now() - start);
        return passed;
    };

    if (!params.fMatMulFreivaldsEnabled) return finish(false);
    if (!params.IsMatMulProductDigestActive(block_height)) return finish(false);
    if (!CheckMatMulProofOfWork_Phase1(block, params)) return finish(false);
    if (!IsMatMulFreivaldsPayloadSizeValid(block, params)) return finish(false);
    if (params.nMatMulFreivaldsRounds == 0) return finish(false);
    if (params.nMatMulNoiseRank == 0 || params.nMatMulNoiseRank > block.matmul_dim) return finish(false);

    // Pre-hash lottery verification
    if (!CheckMatMulPreHashGate(block, params, block_height)) return finish(false);

    const uint32_t n = block.matmul_dim;

    // Reconstruct A' and B' from seeds + noise
    const auto A = matmul::SharedFromSeed(block.seed_a, n);
    const auto B = matmul::SharedFromSeed(block.seed_b, n);
    const uint256 sigma = matmul::DeriveSigma(block);
    const auto np = matmul::noise::Generate(sigma, n, params.nMatMulNoiseRank);
    const auto A_prime = *A + (np.E_L * np.E_R);
    const auto B_prime = *B + (np.F_L * np.F_R);

    // Reconstruct claimed C' from payload
    matmul::Matrix C_prime(n, n);
    for (uint32_t row = 0; row < n; ++row) {
        for (uint32_t col = 0; col < n; ++col) {
            const size_t idx = static_cast<size_t>(row) * n + col;
            if (block.matrix_c_data[idx] >= matmul::field::MODULUS) return finish(false);
            C_prime.at(row, col) = block.matrix_c_data[idx];
        }
    }

    // Verify product-committed digest matches block header
    const uint256 expected_digest = matmul::transcript::ComputeProductCommittedDigest(
        C_prime,
        params.nMatMulTranscriptBlockSize,
        sigma);
    if (expected_digest != block.matmul_digest) return finish(false);

    // Freivalds verification: A'*B' == C' with error < 2^-62
    const auto fv_result = matmul::freivalds::Verify(
        A_prime, B_prime, C_prime, sigma, params.nMatMulFreivaldsRounds);

    return finish(fv_result.passed);
}

bool IsMatMulV4PayloadSizeValid(const CBlock& block, const Consensus::Params& params)
{
    if (block.matmul_dim == 0) return false;
    if (block.matmul_dim != params.nMatMulV4Dimension) return false;
    if (block.matrix_c_data.empty()) return false;
    if (block.matrix_c_data.size() > MATMUL_V4_MAX_PAYLOAD_WORDS) return false;
    // Audit F2: the compile-time MATMUL_V4_MAX_PAYLOAD_WORDS cap is keyed to the
    // ABSOLUTE max dim (8192), so at the active dim (nMatMulV4Dimension, 4096 on
    // mainnet) it is ~4x loose -- an attacker could relay a max-size garbage
    // payload on an accepted header, forcing UnpackMatMulV4SketchWordsToBytes to
    // allocate/iterate ~4x the real 8 MB before ParseSketch's exact-size reject.
    // Tighten the coarse pre-parse DoS backstop to the EXACT active-dim word
    // count (m*m F_q words, m = dim/kTileB, each F_q = 2 uint32 words). Since
    // matmul_dim is already pinned to nMatMulV4Dimension above, this is a fixed
    // consensus quantity; ParseSketch's byte-exact check stays the real gate.
    const uint64_t m{static_cast<uint64_t>(params.nMatMulV4Dimension) / matmul_v4::kTileB};
    const uint64_t exact_words{2 * m * m};
    if (block.matrix_c_data.size() > exact_words) return false;
    return true;
}

bool CheckMatMulProofOfWork_V4ProductCommitted(const CBlock& block, const Consensus::Params& params, int32_t block_height)
{
    const auto start = std::chrono::steady_clock::now();
    const auto finish = [&](bool passed) {
        RegisterMatMulValidationRuntimeSample(
            MatMulValidationPath::FREIVALDS,
            passed,
            std::chrono::steady_clock::now() - start);
        return passed;
    };

    if (!params.IsMatMulV4Active(block_height)) return finish(false);
    if (block.matmul_dim != params.nMatMulV4Dimension) return finish(false);
    if (block.seed_a.IsNull() || block.seed_b.IsNull()) return finish(false);
    // v4 blocks are seed-derived only; the legacy v2 arbitrary-matrix payload
    // channels must be empty (spec §H.2: "matrix_a_data, matrix_b_data --
    // must be empty (A,B fully determined by seeds; non-empty -> invalid
    // v4-forbidden-ab-payload)").
    if (!block.matrix_a_data.empty() || !block.matrix_b_data.empty()) return finish(false);
    if (!IsMatMulV4PayloadSizeValid(block, params)) return finish(false);
    if (params.nMatMulV4FreivaldsRounds == 0) return finish(false);

    auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
    if (!bnTarget) return finish(false);

    // Unpack the trailing product-sketch payload (vector<uint32_t> LE words,
    // spec §H.2's reused trailing-payload serialization) into the flat byte
    // buffer matmul_v4::VerifySketch expects.
    const std::vector<unsigned char> sketch_payload = UnpackMatMulV4SketchWordsToBytes(block.matrix_c_data);

    // MatMul v4.2 / ENC-BMX4C profile dispatch (spec §8.2): GetMatMulEncodingProfile
    // is the SINGLE selector. The v4 cascade is structurally unchanged; only the
    // operand ENCODING differs, so at BMX4C heights the verify sketch step routes
    // to the ENC-BMX4C reference. No new reject codes.
    const uint32_t v4_dim = params.nMatMulV4Dimension;
    uint256 digest;
    if (params.GetMatMulEncodingProfile(block_height) == Consensus::MatMulEncodingProfile::ENC_BMX4C) {
        // Structural combine/accumulator preconditions for ENC-BMX4C (spec
        // §2.4/§5.2/§8.2), checked ahead of the O(n^2) verify as defense in
        // depth. (i) The base-2^6 remainder-top decomposition must be total:
        // 288*n <= 2^23-1 (CheckCombineLimbBoundBMX4C). (ii) The full-C per-word
        // magnitude bound |C| <= 2304*n — the ENC-BMX4C successor to the
        // 15,625*n ENC-S8 bound — must stay exact in int32.
        if (!matmul::v4::bmx4::CheckCombineLimbBoundBMX4C(v4_dim)) return finish(false);
        if (static_cast<int64_t>(Consensus::BMX4C_BASE_PRODUCT_BOUND_PER_N) * v4_dim >
            std::numeric_limits<int32_t>::max()) {
            return finish(false);
        }
        // matmul::v4::bmx4::VerifySketchBMX4C runs the full O(n^2) cascade with
        // the ENC-BMX4C M11+E8M0 operand encoding: payload shape/canonicality
        // mod q, regenerating Ahat/Bhat/U/V from the V4.2 seeds, R Freivalds
        // rounds over q = 2^61-1, and recomputing the product-committed digest.
        if (!matmul::v4::bmx4::VerifySketchBMX4C(block, v4_dim, params.nMatMulV4FreivaldsRounds,
                                                 sketch_payload, digest)) {
            return finish(false);
        }
    } else {
        // ENC_S8 (v4.1): the existing path, unchanged.
        //
        // matmul_v4::VerifySketch performs the full O(n^2) v4 cascade (spec §I.2):
        // payload shape/canonicality mod q, regenerating A,B from the header
        // seeds, R deterministic Freivalds rounds over the independent prime
        // q = 2^61-1, and recomputing the product-committed digest. It never
        // recomputes the O(n^3) product.
        if (!matmul_v4::VerifySketch(block, v4_dim, params.nMatMulV4FreivaldsRounds,
                                      sketch_payload, digest)) {
            return finish(false);
        }
    }
    if (digest != block.matmul_digest) return finish(false);
    if (UintToArith256(digest) > *bnTarget) return finish(false);

    return finish(true);
}

bool MatMulV4PayloadMatchesCommitment(const CBlock& block)
{
    // Distinguishes a v4 body mutation (payload does not reconstruct the
    // header's committed digest) from a header-level consensus fault. The
    // sketch payload travels as the trailing matrix_c_data words; unpack it to
    // the flat byte form the digest routine expects. See
    // matmul_v4::PayloadMatchesCommitment for why the caller must treat a
    // false result as a non-permanent mutation.
    const std::vector<unsigned char> sketch_payload = UnpackMatMulV4SketchWordsToBytes(block.matrix_c_data);
    return matmul_v4::PayloadMatchesCommitment(block, sketch_payload);
}

static void SetFreivaldsPayloadFromProduct(std::vector<uint32_t>& payload_out, const matmul::Matrix& C_prime)
{
    const uint32_t rows = C_prime.rows();
    const uint32_t cols = C_prime.cols();
    if (rows == 0 || rows != cols) {
        payload_out.clear();
        return;
    }

    const size_t words = static_cast<size_t>(rows) * cols;
    payload_out.resize(words);
    for (uint32_t row = 0; row < rows; ++row) {
        for (uint32_t col = 0; col < cols; ++col) {
            payload_out[static_cast<size_t>(row) * cols + col] = C_prime.at(row, col);
        }
    }
}

void PopulateFreivaldsPayload(CBlock& block, const Consensus::Params& params)
{
    if (!params.fMatMulFreivaldsEnabled) return;
    if (block.matmul_dim == 0 || block.seed_a.IsNull() || block.seed_b.IsNull()) return;
    if (params.nMatMulNoiseRank == 0 || params.nMatMulNoiseRank > block.matmul_dim) return;

    const uint32_t n = block.matmul_dim;
    const auto A = matmul::SharedFromSeed(block.seed_a, n);
    const auto B = matmul::SharedFromSeed(block.seed_b, n);
    const uint256 sigma = matmul::DeriveSigma(block);
    const auto np = matmul::noise::Generate(sigma, n, params.nMatMulNoiseRank);
    const auto A_prime = *A + (np.E_L * np.E_R);
    const auto B_prime = *B + (np.F_L * np.F_R);

    // Compute C' = A'B'. Use blocked multiplication keyed to transcript
    // block size to reduce cache-miss overhead vs naive row/column multiply.
    const uint32_t tile_size = std::max<uint32_t>(1U, params.nMatMulTranscriptBlockSize);
    const auto C_prime = matmul::MultiplyBlocked(A_prime, B_prime, tile_size);

    SetFreivaldsPayloadFromProduct(block.matrix_c_data, C_prime);

    // SolveMatMul already selected the consensus-active digest for this
    // height. Here we only attach the canonical C' payload so validators can
    // run the Freivalds/product checks without reconstructing it from scratch.
}

int32_t MatMulPhase2ValidationStartHeight(int32_t best_known_height, const Consensus::Params& params)
{
    if (best_known_height <= 0) return 0;
    if (params.nMatMulValidationWindow == 0) return 0;

    const int64_t start =
        static_cast<int64_t>(best_known_height) -
        static_cast<int64_t>(params.nMatMulValidationWindow) + 1;
    return start > 0 ? static_cast<int32_t>(start) : 0;
}

bool ShouldRunMatMulPhase2ForHeight(int32_t block_height, int32_t best_known_height, const Consensus::Params& params)
{
    if (params.fSkipMatMulValidation) return false;
    if (params.IsMatMulProductDigestActive(block_height)) return false;
    if (block_height <= 0) return true;
    return block_height >= MatMulPhase2ValidationStartHeight(best_known_height, params);
}

bool ShouldRunMatMulPhase2Validation(
    int32_t block_height,
    int32_t best_known_height,
    const Consensus::Params& params,
    bool phase2_enabled,
    bool is_ibd)
{
    if (!phase2_enabled) return false;
    if (params.fSkipMatMulValidation) return false;
    if (params.IsMatMulProductDigestActive(block_height)) return false;
    if (is_ibd) return true;
    return ShouldRunMatMulPhase2ForHeight(block_height, best_known_height, params);
}

uint32_t CountMatMulPhase2Checks(
    int64_t first_height,
    size_t header_count,
    int32_t best_known_height,
    const Consensus::Params& params,
    bool phase2_enabled,
    bool is_ibd)
{
    if (!params.fMatMulPOW || params.fSkipMatMulValidation || !phase2_enabled) {
        return 0;
    }
    if (header_count == 0) return 0;
    if (first_height < 0) return std::numeric_limits<uint32_t>::max();

    uint32_t checks{0};
    for (size_t i = 0; i < header_count; ++i) {
        const int64_t offset = static_cast<int64_t>(i);
        if (first_height > std::numeric_limits<int64_t>::max() - offset) {
            return std::numeric_limits<uint32_t>::max();
        }
        const int64_t height64 = first_height + offset;
        if (height64 > std::numeric_limits<int32_t>::max()) {
            return std::numeric_limits<uint32_t>::max();
        }
        const int32_t height = static_cast<int32_t>(height64);
        if (ShouldRunMatMulPhase2Validation(height, best_known_height, params, phase2_enabled, is_ibd)) {
            ++checks;
        }
    }
    return checks;
}

bool ShouldRunMatMulExpensiveVerification(
    int32_t block_height,
    int32_t best_known_height,
    const Consensus::Params& params,
    bool phase2_enabled,
    bool is_ibd)
{
    if (!params.fMatMulPOW || params.fSkipMatMulValidation) return false;
    // Mirror ContextualCheckBlock's should_run_matmul_validation: the legacy phase2 path OR the
    // post-activation product-committed digest path. The product-committed verification runs
    // unconditionally at/after activation (it is not gated on phase2_enabled), so charge it too.
    return ShouldRunMatMulPhase2Validation(block_height, best_known_height, params, phase2_enabled, is_ibd) ||
           params.IsMatMulProductDigestActive(block_height);
}

uint32_t CountMatMulExpensiveVerifyChecks(
    int64_t first_height,
    size_t header_count,
    int32_t best_known_height,
    const Consensus::Params& params,
    bool phase2_enabled,
    bool is_ibd)
{
    if (!params.fMatMulPOW || params.fSkipMatMulValidation) {
        return 0;
    }
    if (header_count == 0) return 0;
    if (first_height < 0) return std::numeric_limits<uint32_t>::max();

    uint32_t checks{0};
    for (size_t i = 0; i < header_count; ++i) {
        const int64_t offset = static_cast<int64_t>(i);
        if (first_height > std::numeric_limits<int64_t>::max() - offset) {
            return std::numeric_limits<uint32_t>::max();
        }
        const int64_t height64 = first_height + offset;
        if (height64 > std::numeric_limits<int32_t>::max()) {
            return std::numeric_limits<uint32_t>::max();
        }
        const int32_t height = static_cast<int32_t>(height64);
        if (ShouldRunMatMulExpensiveVerification(height, best_known_height, params, phase2_enabled, is_ibd)) {
            ++checks;
        }
    }
    return checks;
}

uint32_t EffectivePhase2BanThreshold(const Consensus::Params& params)
{
    const uint32_t never_ban = std::numeric_limits<uint32_t>::max();
    if (params.nMatMulPhase2FailBanThreshold == never_ban) return never_ban;
    if (params.fMatMulStrictPunishment) return 1U;
    if (params.nMatMulPhase2FailBanThreshold == 0) return 1U;
    return params.nMatMulPhase2FailBanThreshold;
}

void MaybeResetMatMulPhase2Window(MatMulPeerVerificationBudget& budget, std::chrono::steady_clock::time_point now)
{
    if (budget.phase2_failures == 0) return;
    if (budget.phase2_first_failure_time == std::chrono::steady_clock::time_point{}) return;
    if (now - budget.phase2_first_failure_time >= std::chrono::hours{24}) {
        budget.phase2_failures = 0;
        budget.phase2_first_failure_time = std::chrono::steady_clock::time_point{};
    }
}

MatMulPhase2Punishment RegisterMatMulPhase2Failure(
    MatMulPeerVerificationBudget& budget,
    const Consensus::Params& params,
    std::chrono::steady_clock::time_point now,
    uint32_t* failures_out)
{
    MaybeResetMatMulPhase2Window(budget, now);

    if (budget.phase2_failures == 0) {
        budget.phase2_first_failure_time = now;
    }
    ++budget.phase2_failures;
    if (failures_out != nullptr) {
        *failures_out = budget.phase2_failures;
    }

    const uint32_t threshold = EffectivePhase2BanThreshold(params);
    if (budget.phase2_failures >= threshold) {
        return MatMulPhase2Punishment::BAN;
    }
    if (budget.phase2_failures >= 2) {
        return MatMulPhase2Punishment::DISCOURAGE;
    }
    return MatMulPhase2Punishment::DISCONNECT;
}

namespace {
// Spec §G.3/§H.4/§I.5: the DoS verify-budget MECHANISM is unchanged across the
// v4 fork; only the value is height-selected. At and above nMatMulV4Height the
// v4 budgets apply, below it the v3 budgets do. v4 disabled (height ==
// INT32_MAX) always yields the v3 value, regardless of reference_height, so an
// INT32_MAX "unknown height" sentinel can never accidentally select v4.
uint32_t SelectMatMulPeerVerifyBudgetBase(const Consensus::Params& params, int32_t reference_height)
{
    if (!IsDisabledHeight(params.nMatMulV4Height) && params.IsMatMulV4Active(reference_height)) {
        return params.nMatMulV4PeerVerifyBudgetPerMin;
    }
    return params.nMatMulPeerVerifyBudgetPerMin;
}
} // namespace

uint32_t EffectiveMatMulGlobalVerifyBudgetPerMin(const Consensus::Params& params, int32_t reference_height)
{
    if (!IsDisabledHeight(params.nMatMulV4Height) && params.IsMatMulV4Active(reference_height)) {
        return params.nMatMulV4GlobalVerifyBudgetPerMin;
    }
    return params.nMatMulGlobalVerifyBudgetPerMin;
}

uint32_t EffectiveMatMulPeerVerifyBudgetPerMin(const Consensus::Params& params, bool is_ibd, int32_t reference_height)
{
    const uint32_t base = SelectMatMulPeerVerifyBudgetBase(params, reference_height);
    if (!is_ibd) return base;
    // IBD needs to process repeated 2000-header batches without disconnect
    // churn. Keep a finite but substantially higher cap than steady-state.
    return std::max<uint32_t>(base, 200'000U);
}

bool ConsumeMatMulPeerVerifyBudget(
    MatMulPeerVerificationBudget& budget,
    const Consensus::Params& params,
    std::chrono::steady_clock::time_point now,
    bool is_ibd,
    int32_t reference_height)
{
    if (budget.window_start == std::chrono::steady_clock::time_point{} ||
        now - budget.window_start >= std::chrono::minutes{1}) {
        budget.window_start = now;
        budget.expensive_verifications_this_minute = 0;
    }

    uint32_t effective_budget = EffectiveMatMulPeerVerifyBudgetPerMin(params, is_ibd, reference_height);
    if (!is_ibd && params.fMatMulPOW) {
        const bool in_fast_phase = reference_height < params.nFastMineHeight;
        const bool rapid_block_context = params.fPowAllowMinDifficultyBlocks || params.fPowNoRetargeting;
        if (in_fast_phase) {
            // Bootstrap fast phase (heights [0, nFastMineHeight)) can require a
            // large number of expensive header checks per minute. If the local
            // node leaves IBD early due tip timestamp heuristics, keep a high
            // finite cap so honest bootstrap peers are not disconnected.
            effective_budget = std::max<uint32_t>(effective_budget, 200'000U);
        } else if (rapid_block_context) {
            // Regtest/test-like chains can legitimately burst. Keep an elevated
            // finite cap in those environments.
            effective_budget = std::max<uint32_t>(effective_budget, 600U);
        }
    }

    if (budget.expensive_verifications_this_minute >= effective_budget) {
        return false;
    }
    ++budget.expensive_verifications_this_minute;
    return true;
}

bool ConsumeGlobalMatMulPhase2Budget(
    uint32_t max_global_per_minute,
    uint32_t count,
    std::chrono::steady_clock::time_point now)
{
    if (count == 0) return true;
    using namespace std::chrono;
    const int64_t now_sec = duration_cast<seconds>(now.time_since_epoch()).count();

    LOCK(g_matmul_global_phase2_mutex);

    if (now_sec - g_matmul_global_phase2_window_start_sec >= 60) {
        g_matmul_global_phase2_window_start_sec = now_sec;
        g_matmul_global_phase2_this_minute = 0;
    }

    if (g_matmul_global_phase2_this_minute + count > max_global_per_minute) {
        return false;
    }
    g_matmul_global_phase2_this_minute += count;
    return true;
}

bool CanStartMatMulVerification(uint32_t pending_verifications, const Consensus::Params& params)
{
    return pending_verifications < params.nMatMulMaxPendingVerifications;
}

bool SolveMatMulNonceSeeded(CBlockHeader& block,
                            const Consensus::Params& params,
                            uint64_t& max_tries,
                            int32_t block_height,
                            const std::atomic<bool>* abort_flag,
                            std::vector<uint32_t>* freivalds_payload_out,
                            const uint256* share_target_override,
                            std::optional<int64_t> parent_median_time_past)
{
    if (freivalds_payload_out != nullptr) {
        freivalds_payload_out->clear();
    }

    auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
    if (!bnTarget) return false;
    // block_bnTarget is the consensus block target. The consensus pre-hash gate (CheckMatMulPreHashGate)
    // independently re-derives it from nBits, so the share override only relaxes the digest early-exit.
    [[maybe_unused]] const arith_uint256 block_bnTarget = *bnTarget;
    arith_uint256 effective_target = *bnTarget;
    if (share_target_override != nullptr) {
        effective_target = UintToArith256(*share_target_override);
        if (effective_target == 0) return false;
    }

    const auto solve_start = std::chrono::steady_clock::now();
    // Pipeline diagnostic stats are set by the top-level SolveMatMul dispatch (which knows whether
    // this run is parallel). A worker chunk must NOT overwrite them, so they are not touched here.

    try {
        arith_uint256 best_digest_seen = ~arith_uint256(0);
        const uint32_t n = block.matmul_dim;
        const uint32_t transcript_block_size = params.nMatMulTranscriptBlockSize;
        const uint32_t noise_rank = params.nMatMulNoiseRank;
        const bool product_digest_active = params.IsMatMulProductDigestActive(block_height);
        const auto backend_selection = matmul::accelerated::ResolveMiningBackendFromEnvironment();
        const auto backend_requirement = matmul::accelerated::ResolveBackendRequirementFromEnvironment();
        if (!CheckRequiredMatMulBackend(backend_requirement, backend_selection, "nonce_seeded_resolve")) {
            RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - solve_start);
            return false;
        }
        const auto active_backend = backend_selection.active;
        const std::string active_backend_label = matmul::backend::ToString(active_backend);
        const bool use_gpu_generated_inputs = matmul::accelerated::ShouldUseGpuGeneratedInputsForShape(
            active_backend,
            n,
            transcript_block_size,
            noise_rank);
        const bool cpu_confirm_candidates = ShouldCpuConfirmSolvedMatMulCandidates(active_backend, params);
        const bool needs_freivalds_payload =
            params.fMatMulFreivaldsEnabled && freivalds_payload_out != nullptr;
        const matmul::accelerated::DigestScheme digest_scheme = product_digest_active
            ? matmul::accelerated::DigestScheme::PRODUCT_COMMITTED
            : matmul::accelerated::DigestScheme::TRANSCRIPT;
        const uint32_t header_time_refresh_interval = ResolveMinerHeaderTimeRefreshAttempts();
        const uint32_t pre_hash_epsilon_bits = GetMatMulPreHashEpsilonBitsForHeight(params, block_height);
        const bool cpu_vs_metal_compare = ShouldEnableCpuVsMetalDigestCompare(active_backend);
        uint32_t attempts_since_time_refresh{0};
        g_matmul_cpu_confirm_candidates.store(cpu_confirm_candidates, std::memory_order_relaxed);
        g_matmul_digest_compare_enabled.store(cpu_vs_metal_compare, std::memory_order_relaxed);

        auto prepare_inputs = [&](const CBlockHeader& header) {
            if (use_gpu_generated_inputs) {
                return matmul::accelerated::PrepareMatMulDigestInputsForBackend(
                    header,
                    transcript_block_size,
                    noise_rank,
                    active_backend,
                    digest_scheme);
            }
            return matmul::accelerated::PrepareMatMulDigestInputs(
                header,
                transcript_block_size,
                noise_rank);
        };

        auto advance_nonce = [&]() -> bool {
            if (block.nNonce64 == std::numeric_limits<uint64_t>::max()) {
                const std::string seed_a_prefix = block.seed_a.GetHex().substr(0, 16);
                const std::string seed_b_prefix = block.seed_b.GetHex().substr(0, 16);
                LogPrintf("MatMul mining: nonce64 exhausted (seed_a=%s seed_b=%s)\n", seed_a_prefix, seed_b_prefix);
                return false;
            }
            ++block.nNonce64;
            block.nNonce = static_cast<uint32_t>(block.nNonce64);
            if (attempts_since_time_refresh != std::numeric_limits<uint32_t>::max()) {
                ++attempts_since_time_refresh;
            }
            MaybeRefreshMinerHeaderTime(
                block,
                attempts_since_time_refresh,
                header_time_refresh_interval,
                params.fPowAllowMinDifficultyBlocks);
            return true;
        };

        auto advance_nonce_window = [&](uint32_t nonces_scanned) -> bool {
            if (nonces_scanned == 0) {
                return true;
            }
            const uint64_t advance_nonce = block.nNonce64 + nonces_scanned - 1;
            if (advance_nonce < block.nNonce64 || advance_nonce == std::numeric_limits<uint64_t>::max()) {
                const std::string seed_a_prefix = block.seed_a.GetHex().substr(0, 16);
                const std::string seed_b_prefix = block.seed_b.GetHex().substr(0, 16);
                LogPrintf("MatMul mining: nonce64 exhausted (seed_a=%s seed_b=%s)\n", seed_a_prefix, seed_b_prefix);
                return false;
            }
            block.nNonce64 = advance_nonce + 1;
            block.nNonce = static_cast<uint32_t>(block.nNonce64);
            if (attempts_since_time_refresh >
                std::numeric_limits<uint32_t>::max() - nonces_scanned) {
                attempts_since_time_refresh = std::numeric_limits<uint32_t>::max();
            } else {
                attempts_since_time_refresh += nonces_scanned;
            }
            MaybeRefreshMinerHeaderTime(
                block,
                attempts_since_time_refresh,
                header_time_refresh_interval,
                params.fPowAllowMinDifficultyBlocks);
            return true;
        };

        enum class DigestCandidateOutcome {
            ERROR,
            MISS,
            SOLVED,
        };

        auto digest_candidate = [&](const CBlockHeader& header, uint256& accepted_digest) -> DigestCandidateOutcome {
            const auto A = matmul::SharedFromSeed(header.seed_a, n);
            const auto B = matmul::SharedFromSeed(header.seed_b, n);
            auto prepared = prepare_inputs(header);
            g_matmul_prepared_inputs.fetch_add(1, std::memory_order_relaxed);

            std::vector<CBlockHeader> headers{header};
            std::vector<matmul::accelerated::PreparedDigestInputs> prepared_batch;
            prepared_batch.push_back(std::move(prepared));
            auto digest_submission = matmul::accelerated::SubmitMatMulDigestPreparedBatchForMining(
                headers,
                *A,
                *B,
                transcript_block_size,
                noise_rank,
                prepared_batch,
                active_backend,
                digest_scheme);
            std::vector<matmul::accelerated::DigestResult> digest_batch =
                matmul::accelerated::WaitForSubmittedMatMulDigestBatch(std::move(digest_submission));
            if (digest_batch.size() != 1 || !digest_batch[0].ok) {
                return DigestCandidateOutcome::ERROR;
            }

            const auto& digest_result = digest_batch[0];
            if (!CheckRequiredMatMulDigestBackend(backend_requirement, digest_result, "nonce_seeded_single_digest")) {
                return DigestCandidateOutcome::ERROR;
            }
            std::optional<uint256> compared_cpu_digest;
            if (cpu_vs_metal_compare && active_backend == matmul::backend::Kind::METAL) {
                compared_cpu_digest = matmul::accelerated::ComputeDigestCpuFromPreparedInputs(
                    *A,
                    *B,
                    prepared_batch[0],
                    transcript_block_size,
                    digest_scheme);
                RegisterMatMulDigestCompareAttempt(
                    header,
                    digest_result.digest,
                    *compared_cpu_digest,
                    active_backend_label.c_str());
            }

            if (const arith_uint256 digest_value = UintToArith256(digest_result.digest); digest_value < best_digest_seen) {
                best_digest_seen = digest_value;
            }
            if (UintToArith256(digest_result.digest) > effective_target) {
                return DigestCandidateOutcome::MISS;
            }
            if (pre_hash_epsilon_bits > 0 && !CheckMatMulPreHashGate(header, params, block_height)) {
                return DigestCandidateOutcome::MISS;
            }

            accepted_digest = digest_result.digest;
            if (cpu_confirm_candidates || needs_freivalds_payload) {
                std::optional<matmul::transcript::CanonicalResult> canonical_cpu_result;
                uint256 cpu_digest;
                if (needs_freivalds_payload) {
                    const auto resolved_noise = matmul::accelerated::ResolvePreparedNoiseForCpu(
                        prepared_batch[0],
                        header.matmul_dim,
                        noise_rank);
                    const auto A_prime =
                        *A + (resolved_noise.E_L * resolved_noise.E_R);
                    const auto B_prime =
                        *B + (resolved_noise.F_L * resolved_noise.F_R);
                    canonical_cpu_result = matmul::transcript::CanonicalMatMul(
                        A_prime,
                        B_prime,
                        transcript_block_size,
                        prepared_batch[0].sigma);
                    cpu_digest = digest_scheme == matmul::accelerated::DigestScheme::PRODUCT_COMMITTED
                        ? matmul::transcript::ComputeProductCommittedDigest(
                            canonical_cpu_result->C_prime,
                            transcript_block_size,
                            prepared_batch[0].sigma)
                        : canonical_cpu_result->transcript_hash;
                } else {
                    cpu_digest = compared_cpu_digest.has_value()
                        ? *compared_cpu_digest
                        : matmul::accelerated::ComputeDigestCpuFromPreparedInputs(
                            *A,
                            *B,
                            prepared_batch[0],
                            transcript_block_size,
                            digest_scheme);
                }

                if (!cpu_vs_metal_compare && cpu_digest != digest_result.digest) {
                    RegisterMatMulDigestCompareAttempt(
                        header,
                        digest_result.digest,
                        cpu_digest,
                        active_backend_label.c_str());
                }

                if (UintToArith256(cpu_digest) > effective_target) {
                    return DigestCandidateOutcome::MISS;
                }
                accepted_digest = cpu_digest;
                if (canonical_cpu_result.has_value()) {
                    SetFreivaldsPayloadFromProduct(*freivalds_payload_out, canonical_cpu_result->C_prime);
                }
            }

            return DigestCandidateOutcome::SOLVED;
        };

        auto evaluate_batched_digest_result = [&](
            const CBlockHeader& header,
            const matmul::accelerated::PreparedDigestInputs& prepared,
            const matmul::accelerated::DigestResult& digest_result,
            uint256& accepted_digest) -> DigestCandidateOutcome {
            if (!digest_result.ok) {
                return DigestCandidateOutcome::ERROR;
            }
            if (!CheckRequiredMatMulDigestBackend(backend_requirement, digest_result, "nonce_seeded_batch_digest")) {
                return DigestCandidateOutcome::ERROR;
            }

            if (const arith_uint256 digest_value = UintToArith256(digest_result.digest); digest_value < best_digest_seen) {
                best_digest_seen = digest_value;
            }
            if (UintToArith256(digest_result.digest) > effective_target) {
                return DigestCandidateOutcome::MISS;
            }

            accepted_digest = digest_result.digest;
            if (cpu_confirm_candidates || needs_freivalds_payload) {
                const auto A = matmul::SharedFromSeed(header.seed_a, n);
                const auto B = matmul::SharedFromSeed(header.seed_b, n);
                std::optional<matmul::transcript::CanonicalResult> canonical_cpu_result;
                uint256 cpu_digest;
                if (needs_freivalds_payload) {
                    const auto resolved_noise = matmul::accelerated::ResolvePreparedNoiseForCpu(
                        prepared,
                        header.matmul_dim,
                        noise_rank);
                    const auto A_prime =
                        *A + (resolved_noise.E_L * resolved_noise.E_R);
                    const auto B_prime =
                        *B + (resolved_noise.F_L * resolved_noise.F_R);
                    canonical_cpu_result = matmul::transcript::CanonicalMatMul(
                        A_prime,
                        B_prime,
                        transcript_block_size,
                        prepared.sigma);
                    cpu_digest = digest_scheme == matmul::accelerated::DigestScheme::PRODUCT_COMMITTED
                        ? matmul::transcript::ComputeProductCommittedDigest(
                            canonical_cpu_result->C_prime,
                            transcript_block_size,
                            prepared.sigma)
                        : canonical_cpu_result->transcript_hash;
                } else {
                    cpu_digest = matmul::accelerated::ComputeDigestCpuFromPreparedInputs(
                        *A,
                        *B,
                        prepared,
                        transcript_block_size,
                        digest_scheme);
                }

                if (cpu_digest != digest_result.digest) {
                    RegisterMatMulDigestCompareAttempt(
                        header,
                        digest_result.digest,
                        cpu_digest,
                        active_backend_label.c_str());
                }

                if (UintToArith256(cpu_digest) > effective_target) {
                    return DigestCandidateOutcome::MISS;
                }
                accepted_digest = cpu_digest;
                if (canonical_cpu_result.has_value()) {
                    SetFreivaldsPayloadFromProduct(*freivalds_payload_out, canonical_cpu_result->C_prime);
                }
            }

            return DigestCandidateOutcome::SOLVED;
        };

        const bool gpu_nonce_seed_scan_enabled =
            (active_backend == matmul::backend::Kind::CUDA ||
             active_backend == matmul::backend::Kind::METAL) &&
            pre_hash_epsilon_bits > 0 &&
            !g_matmul_parallel_worker_context;
        bool gpu_nonce_seed_scan_available = gpu_nonce_seed_scan_enabled;
        const uint32_t configured_batch_size = gpu_nonce_seed_scan_enabled
            ? ResolveGpuNonceSeedBatchSize(
                active_backend,
                n,
                transcript_block_size,
                noise_rank,
                product_digest_active)
            : 1U;

        while (max_tries > 0) {
            if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed)) {
                LogDebug(BCLog::MINING, "SolveMatMulNonceSeeded: abort flag set, stopping with %lu tries remaining\n",
                         static_cast<unsigned long>(max_tries));
                RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - solve_start);
                return false;
            }

            if (gpu_nonce_seed_scan_available) {
                auto scanned_window = BuildMatMulNonceSeededGpuPreHashBatchWindow(
                    block,
                    params,
                    block_height,
                    active_backend,
                    max_tries,
                    configured_batch_size,
                    pre_hash_epsilon_bits,
                    *bnTarget,
                    attempts_since_time_refresh,
                    header_time_refresh_interval,
                    parent_median_time_past,
                    params.fPowAllowMinDifficultyBlocks);
                if (scanned_window.has_value()) {
                    if (scanned_window->nonce_space_exhausted) {
                        break;
                    }
                    if (scanned_window->nonces_scanned == 0) {
                        break;
                    }

                    const uint32_t filtered_nonces =
                        scanned_window->nonces_scanned -
                        static_cast<uint32_t>(scanned_window->headers.size());
                    max_tries -= filtered_nonces;

                    if (!scanned_window->headers.empty()) {
                        if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed)) {
                            LogDebug(BCLog::MINING, "SolveMatMulNonceSeeded: abort flag set while preparing GPU-scanned window, stopping with %lu tries remaining\n",
                                     static_cast<unsigned long>(max_tries));
                            RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - solve_start);
                            return false;
                        }

                        std::vector<matmul::accelerated::PreparedDigestInputs> prepared_batch =
                            scanned_window->sigmas.size() == scanned_window->headers.size()
                                ? matmul::accelerated::PrepareMatMulDigestInputsBatchForBackend(
                                    scanned_window->headers,
                                    scanned_window->sigmas,
                                    transcript_block_size,
                                    noise_rank,
                                    active_backend,
                                    digest_scheme)
                                : matmul::accelerated::PrepareMatMulDigestInputsBatchForBackend(
                                    scanned_window->headers,
                                    transcript_block_size,
                                    noise_rank,
                                    active_backend,
                                    digest_scheme);

                        if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed)) {
                            LogDebug(BCLog::MINING, "SolveMatMulNonceSeeded: abort flag set after preparing GPU-scanned window, stopping with %lu tries remaining\n",
                                     static_cast<unsigned long>(max_tries));
                            RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - solve_start);
                            return false;
                        }
                        g_matmul_prepared_inputs.fetch_add(prepared_batch.size(), std::memory_order_relaxed);
                        g_matmul_batched_digest_requests.fetch_add(1, std::memory_order_relaxed);
                        g_matmul_batched_nonce_attempts.fetch_add(scanned_window->headers.size(), std::memory_order_relaxed);

                        const auto digest_batch = matmul::accelerated::ComputeMatMulDigestPreparedVariableBaseBatchForMining(
                            scanned_window->headers,
                            transcript_block_size,
                            noise_rank,
                            prepared_batch,
                            active_backend,
                            digest_scheme);
                        if (digest_batch.size() != scanned_window->headers.size()) {
                            RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - solve_start);
                            return false;
                        }

                        for (size_t i = 0; i < scanned_window->headers.size(); ++i) {
                            if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed)) {
                                LogDebug(BCLog::MINING, "SolveMatMulNonceSeeded: abort flag set inside GPU-scanned window, stopping with %lu tries remaining\n",
                                         static_cast<unsigned long>(max_tries));
                                RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - solve_start);
                                return false;
                            }

                            uint256 accepted_digest;
                            const DigestCandidateOutcome outcome = evaluate_batched_digest_result(
                                scanned_window->headers[i],
                                prepared_batch[i],
                                digest_batch[i],
                                accepted_digest);
                            if (outcome == DigestCandidateOutcome::ERROR) {
                                RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - solve_start);
                                return false;
                            }
                            --max_tries;
                            if (outcome == DigestCandidateOutcome::SOLVED) {
                                block = scanned_window->headers[i];
                                block.matmul_digest = accepted_digest;
                                RegisterMatMulSolveRuntimeSample(true, std::chrono::steady_clock::now() - solve_start);
                                return true;
                            }
                        }
                    }

                    if (!advance_nonce_window(scanned_window->nonces_scanned)) break;
                    continue;
                }
                if (backend_requirement.enabled && backend_requirement.valid &&
                    backend_requirement.required == active_backend) {
                    LogMatMulBackendRequirementFailureOnce(strprintf(
                        "context=nonce_seeded_gpu_prehash_scan required=%s active=%s reason=gpu_scan_fell_back_to_host",
                        matmul::backend::ToString(backend_requirement.required),
                        active_backend_label));
                    RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - solve_start);
                    return false;
                }
                gpu_nonce_seed_scan_available = false;
            }

            CBlockHeader header{block};
            if (!SetDeterministicMatMulSeeds(header, params, block_height, parent_median_time_past)) {
                RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - solve_start);
                return false;
            }
            header.matmul_digest.SetNull();
            --max_tries;

            if (pre_hash_epsilon_bits > 0 && !CheckMatMulPreHashGate(header, params, block_height)) {
                if (!advance_nonce()) break;
                continue;
            }

            uint256 accepted_digest;
            const DigestCandidateOutcome outcome = digest_candidate(header, accepted_digest);
            if (outcome == DigestCandidateOutcome::ERROR) {
                RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - solve_start);
                return false;
            }
            if (outcome == DigestCandidateOutcome::SOLVED) {
                block = header;
                block.matmul_digest = accepted_digest;
                RegisterMatMulSolveRuntimeSample(true, std::chrono::steady_clock::now() - solve_start);
                return true;
            }

            if (!advance_nonce()) break;
        }

        if (best_digest_seen != ~arith_uint256(0)) {
            const int bits_short = std::max(0, static_cast<int>(best_digest_seen.bits()) - static_cast<int>(effective_target.bits()));
            LogDebug(BCLog::MINING, "SolveMatMulNonceSeeded: exhausted, best_digest=%s target=%s ~%d_bits_short\n",
                     best_digest_seen.GetHex(), effective_target.GetHex(), bits_short);
        }
        RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - solve_start);
        return false;
    } catch (const std::exception& e) {
        RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - solve_start);
        LogWarning("SolveMatMulNonceSeeded: exception during mining: %s\n", e.what());
        return false;
    } catch (...) {
        RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - solve_start);
        LogWarning("SolveMatMulNonceSeeded: unknown exception during mining\n");
        return false;
    }
}

bool SolveMatMulParallel(CBlockHeader& block,
                         const Consensus::Params& params,
                         uint64_t& max_tries,
                         int32_t block_height,
                         const std::atomic<bool>* abort_flag,
                         std::vector<uint32_t>* freivalds_payload_out,
                         uint32_t solver_threads,
                         const uint256* share_target_override,
                         std::optional<int64_t> parent_median_time_past)
{
    if (freivalds_payload_out != nullptr) {
        freivalds_payload_out->clear();
    }
    if (max_tries == 0 || solver_threads <= 1) {
        return false;
    }

    const uint64_t initial_max_tries = max_tries;
    const uint64_t initial_nonce64 = block.nNonce64;
    const uint32_t worker_count = static_cast<uint32_t>(std::min<uint64_t>(solver_threads, initial_max_tries));
    if (worker_count <= 1) {
        return false;
    }

    std::atomic<bool> shared_abort{false};
    std::atomic<uint64_t> tries_consumed{0};
    std::mutex result_mutex;
    bool solved{false};
    CBlockHeader solved_block{};
    std::vector<uint32_t> solved_payload;

    std::optional<std::thread> abort_watcher;
    if (abort_flag != nullptr) {
        abort_watcher.emplace([&shared_abort, abort_flag] {
            while (!shared_abort.load(std::memory_order_relaxed)) {
                if (abort_flag->load(std::memory_order_relaxed)) {
                    shared_abort.store(true, std::memory_order_relaxed);
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
        });
    }

    std::vector<std::thread> workers;
    workers.reserve(worker_count);

    const uint64_t base_chunk = initial_max_tries / worker_count;
    const uint64_t extra_chunks = initial_max_tries % worker_count;

    for (uint32_t worker_index = 0; worker_index < worker_count; ++worker_index) {
        const uint64_t chunk_tries = base_chunk + (worker_index < extra_chunks ? 1U : 0U);
        const uint64_t chunk_offset =
            (base_chunk * worker_index) + std::min<uint64_t>(worker_index, extra_chunks);
        if (chunk_tries == 0) {
            continue;
        }

        workers.emplace_back([&, chunk_tries, chunk_offset] {
            ScopedMatMulParallelWorkerContext worker_scope;

            if (shared_abort.load(std::memory_order_relaxed)) {
                return;
            }

            CBlockHeader local_block{block};
            if (chunk_offset > std::numeric_limits<uint64_t>::max() - initial_nonce64) {
                shared_abort.store(true, std::memory_order_relaxed);
                return;
            }
            local_block.nNonce64 = initial_nonce64 + chunk_offset;
            local_block.nNonce = static_cast<uint32_t>(local_block.nNonce64);
            local_block.matmul_digest.SetNull();

            uint64_t local_tries = chunk_tries;
            std::vector<uint32_t> local_payload;
            const bool local_solved = SolveMatMul(
                local_block,
                params,
                local_tries,
                block_height,
                &shared_abort,
                freivalds_payload_out != nullptr ? &local_payload : nullptr,
                share_target_override,
                parent_median_time_past);
            tries_consumed.fetch_add(chunk_tries - local_tries, std::memory_order_relaxed);

            if (!local_solved) {
                return;
            }

            {
                std::lock_guard<std::mutex> lock(result_mutex);
                if (!solved) {
                    solved = true;
                    solved_block = local_block;
                    solved_payload = std::move(local_payload);
                }
            }
            shared_abort.store(true, std::memory_order_relaxed);
        });
    }

    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    shared_abort.store(true, std::memory_order_relaxed);
    if (abort_watcher.has_value() && abort_watcher->joinable()) {
        abort_watcher->join();
    }

    const uint64_t consumed = std::min<uint64_t>(
        tries_consumed.load(std::memory_order_relaxed),
        initial_max_tries);
    max_tries = initial_max_tries - consumed;

    if (solved) {
        block = solved_block;
        if (freivalds_payload_out != nullptr) {
            *freivalds_payload_out = std::move(solved_payload);
        }
        return true;
    }

    if (consumed > std::numeric_limits<uint64_t>::max() - initial_nonce64) {
        block.nNonce64 = std::numeric_limits<uint64_t>::max();
    } else {
        block.nNonce64 = initial_nonce64 + consumed;
    }
    block.nNonce = static_cast<uint32_t>(block.nNonce64);
    block.matmul_digest.SetNull();
    return false;
}

// MatMul v4 (spec §I.3): dedicated solver loop, mirroring the v3 solvers'
// nonce/max_tries/abort_flag contract but dispatched separately because v4
// has no pre-hash gate, no noise, and no pooled share-target override (out
// of scope for this fork; see spec §I.3 -- the v4 reference miner MUST
// implement the optimal §E.3 (U*A)(B*V) sketch evaluation, which is an
// internal implementation detail of matmul_v4::ComputeDigest, not something
// this dispatch layer needs to know about).
// MatMul v4.2 / ENC-BMX4C solve loop (spec §8.2 "Mining" row). Profile-gated
// sibling of the SolveMatMulV4 CPU-batched branch: nonces are ground in windows
// of Q through matmul_v4::accel::ComputeDigestsBMX4CDispatched — the ENC-BMX4C
// batched dispatch (CPU batched miner or device path, every result verified via
// VerifySketchBMX4C). Each candidate header carries the §H.4 nonce-bound seed
// re-derivation (which, at BMX4C heights, is the V4.2 domain-tagged seed pair).
// The rare winning candidate is additionally re-derived through the single-nonce
// reference matmul::v4::bmx4::ComputeDigestBMX4C and ONLY the reference result
// is sealed (A14 discipline), so a batch/device bug can never emit a
// non-consensus block.
static bool SolveMatMulV4BMX4C(CBlockHeader& block,
                               const Consensus::Params& params,
                               uint64_t& max_tries,
                               int32_t block_height,
                               const std::atomic<bool>* abort_flag,
                               std::vector<uint32_t>* freivalds_payload_out,
                               std::optional<int64_t> parent_median_time_past,
                               const arith_uint256& bnTarget,
                               std::chrono::steady_clock::time_point start)
{
    const uint32_t n = params.nMatMulV4Dimension;
    uint32_t window_span = matmul::v4::kDefaultMinerBatch;
    if (const char* env = std::getenv("BTX_MATMUL_V4_BATCH")) {
        const auto parsed = static_cast<uint32_t>(std::strtoul(env, nullptr, 10));
        if (parsed > 0) window_span = std::min(parsed, matmul::v4::kMaxMinerBatch);
    }

    while (max_tries > 0) {
        if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed)) {
            RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - start);
            return false;
        }
        const uint64_t nonce_room = std::numeric_limits<uint64_t>::max() - block.nNonce64;
        uint32_t window = static_cast<uint32_t>(std::min<uint64_t>(window_span, max_tries));
        if (nonce_room < window - 1) window = static_cast<uint32_t>(nonce_room) + 1;

        // Fully populate each candidate: nonce plus the §H.4 nonce-bound seed
        // re-derivation (V4.2 domain tags at BMX4C heights; the template
        // projection zeroes the seed fields, so the miner's cached Ahat/U/V/P
        // stay valid across the window).
        std::vector<CBlockHeader> candidates(window, block);
        for (uint32_t i = 0; i < window; ++i) {
            candidates[i].nNonce64 = block.nNonce64 + i;
            candidates[i].nNonce = static_cast<uint32_t>(candidates[i].nNonce64);
            if (!SetDeterministicMatMulSeeds(candidates[i], params, block_height, parent_median_time_past)) {
                RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - start);
                return false;
            }
        }

        std::vector<uint256> digests;
        std::vector<std::vector<unsigned char>> payloads;
        if (!matmul_v4::accel::ComputeDigestsBMX4CDispatched(candidates, n, params.nMatMulV4FreivaldsRounds,
                                                             digests, payloads) ||
            digests.size() != window || payloads.size() != window) {
            LogWarning("SolveMatMulV4BMX4C: batched ENC-BMX4C miner failed; aborting solve\n");
            RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - start);
            return false;
        }

        for (uint32_t i = 0; i < window; ++i) {
            if (UintToArith256(digests[i]) > bnTarget) {
                --max_tries;
                continue;
            }
            // Candidate win: re-derive through the single-nonce ENC-BMX4C
            // reference and seal ONLY the reference result (defense in depth).
            uint256 ref_digest;
            std::vector<unsigned char> ref_payload;
            if (!matmul::v4::bmx4::ComputeDigestBMX4C(candidates[i], n, ref_digest, ref_payload) ||
                ref_digest != digests[i] || ref_payload != payloads[i]) {
                LogWarning("SolveMatMulV4BMX4C: batched digest diverged from reference at nonce=%u; discarding candidate\n",
                           candidates[i].nNonce64);
                --max_tries;
                continue;
            }
            block = candidates[i];
            block.matmul_digest = ref_digest;
            if (freivalds_payload_out != nullptr) {
                *freivalds_payload_out = PackMatMulV4SketchBytesToWords(ref_payload);
            }
            RegisterMatMulSolveRuntimeSample(true, std::chrono::steady_clock::now() - start);
            return true;
        }

        if (nonce_room < window) {
            RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - start);
            return false; // nonce space exhausted (last window ended at UINT64_MAX)
        }
        block.nNonce64 += window;
        block.nNonce = static_cast<uint32_t>(block.nNonce64);
    }
    RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - start);
    return false;
}

static bool SolveMatMulV4(CBlockHeader& block,
                          const Consensus::Params& params,
                          uint64_t& max_tries,
                          int32_t block_height,
                          const std::atomic<bool>* abort_flag,
                          std::vector<uint32_t>* freivalds_payload_out,
                          std::optional<int64_t> parent_median_time_past)
{
    if (!params.IsMatMulV4Active(block_height)) return false;
    if (!parent_median_time_past.has_value()) return false;
    if (params.nMatMulV4Dimension == 0 ||
        params.nMatMulV4Dimension > std::numeric_limits<uint16_t>::max()) {
        LogWarning("SolveMatMulV4: nMatMulV4Dimension=%u out of uint16_t range\n", params.nMatMulV4Dimension);
        return false;
    }
    block.matmul_dim = static_cast<uint16_t>(params.nMatMulV4Dimension);

    auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
    if (!bnTarget) return false;

    const auto start = std::chrono::steady_clock::now();

    // MatMul v4.2 / ENC-BMX4C profile dispatch (spec §8.2): GetMatMulEncodingProfile
    // is the SINGLE selector. At BMX4C heights the whole solve routes to the
    // ENC-BMX4C loop; the ENC-S8 path below is unchanged.
    if (params.GetMatMulEncodingProfile(block_height) == Consensus::MatMulEncodingProfile::ENC_BMX4C) {
        return SolveMatMulV4BMX4C(block, params, max_tries, block_height, abort_flag,
                                  freivalds_payload_out, parent_median_time_past, *bnTarget, start);
    }

    // v4.1 batched-sketch CPU path (spec §K.2b, matmul/matmul_v4_batch.h):
    // when the resolved backend is the CPU reference, grind nonces in windows
    // of Q through BatchedSketchMiner — A, U, V and P = U*A are expanded once
    // per template (invariant I1'), each window's combines run as one stacked
    // dense GEMM, and every digest is byte-identical to the single-nonce
    // matmul_v4::ComputeDigest (enforced by matmul_v4_batch_tests; the rare
    // winning candidate is additionally re-derived through the reference
    // path below before it is sealed, so a batch-miner bug can never emit a
    // non-consensus block). GPU backends keep the per-nonce dispatch loop for
    // now — their device-side batching is tracked in ACTIVATION B2f/B2g.
    if (matmul_v4::accel::ResolveBackend() == matmul_v4::accel::Kind::CPU) {
        uint32_t window_span = matmul::v4::kDefaultMinerBatch;
        if (const char* env = std::getenv("BTX_MATMUL_V4_BATCH")) {
            const auto parsed = static_cast<uint32_t>(std::strtoul(env, nullptr, 10));
            if (parsed > 0) window_span = std::min(parsed, matmul::v4::kMaxMinerBatch);
        }
        const matmul::v4::BatchedSketchMiner batch_miner{block, params.nMatMulV4Dimension};
        if (!batch_miner.Valid()) {
            RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - start);
            return false;
        }
        while (max_tries > 0) {
            if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed)) {
                RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - start);
                return false;
            }
            const uint64_t nonce_room = std::numeric_limits<uint64_t>::max() - block.nNonce64;
            uint32_t window = static_cast<uint32_t>(std::min<uint64_t>(window_span, max_tries));
            if (nonce_room < window - 1) window = static_cast<uint32_t>(nonce_room) + 1;

            // Fully populate each candidate header: nonce plus the §H.4
            // nonce-bound seed_a/seed_b re-derivation (the template projection
            // zeroes both, so the cached A/U/V/P stay valid across the window).
            std::vector<CBlockHeader> candidates(window, block);
            for (uint32_t i = 0; i < window; ++i) {
                candidates[i].nNonce64 = block.nNonce64 + i;
                candidates[i].nNonce = static_cast<uint32_t>(candidates[i].nNonce64);
                if (!SetDeterministicMatMulSeeds(candidates[i], params, block_height, parent_median_time_past)) {
                    RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - start);
                    return false;
                }
            }

            std::vector<matmul::v4::BatchNonceResult> results;
            if (!batch_miner.Mine(candidates, results) || results.size() != window) {
                LogWarning("SolveMatMulV4: batched miner failed (template mismatch?); aborting solve\n");
                RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - start);
                return false;
            }

            for (uint32_t i = 0; i < window; ++i) {
                if (UintToArith256(results[i].digest) > *bnTarget) {
                    --max_tries;
                    continue;
                }
                // Candidate win: re-derive through the single-nonce reference
                // path and seal ONLY the reference result (defense in depth;
                // equality is also pinned by matmul_v4_batch_tests).
                uint256 ref_digest;
                std::vector<unsigned char> ref_payload;
                if (!matmul_v4::ComputeDigest(candidates[i], params.nMatMulV4Dimension,
                                              params.nMatMulV4FreivaldsRounds, ref_digest, ref_payload) ||
                    ref_digest != results[i].digest || ref_payload != results[i].payload) {
                    LogWarning("SolveMatMulV4: batched digest diverged from reference at nonce=%u; discarding candidate\n",
                               candidates[i].nNonce64);
                    --max_tries;
                    continue;
                }
                block = candidates[i];
                block.matmul_digest = ref_digest;
                if (freivalds_payload_out != nullptr) {
                    *freivalds_payload_out = PackMatMulV4SketchBytesToWords(ref_payload);
                }
                RegisterMatMulSolveRuntimeSample(true, std::chrono::steady_clock::now() - start);
                return true;
            }

            if (nonce_room < window) {
                RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - start);
                return false; // nonce space exhausted (last window ended at UINT64_MAX)
            }
            block.nNonce64 += window;
            block.nNonce = static_cast<uint32_t>(block.nNonce64);
        }
        RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - start);
        return false;
    }

    while (max_tries > 0) {
        if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed)) {
            RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - start);
            return false;
        }
        // H.4: v4 seeds are unconditionally nonce-bound, so seed_a/seed_b are
        // re-derived for every nonce attempt (see SetDeterministicMatMulSeeds).
        if (!SetDeterministicMatMulSeeds(block, params, block_height, parent_median_time_past)) {
            RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - start);
            return false;
        }

        uint256 digest;
        std::vector<unsigned char> sketch_payload;
        // matmul_v4::accel::ComputeDigestDispatched runs the single dense INT8
        // GEMM (the O(n^3) miner-side work per spec §A.6/§E.3) on the resolved
        // device backend (CPU / CUDA / Metal / HIP), then re-verifies the
        // result against the CPU reference with matmul_v4::VerifySketch and
        // falls back to the byte-exact CPU path (matmul_v4::ComputeDigest) on
        // any device error or digest mismatch. The returned digest + payload are
        // therefore always consensus-valid: a wrong GPU digest can never win a
        // block. Verifiers Freivalds-check the payload in O(n^2) via
        // matmul_v4::VerifySketch.
        if (matmul_v4::accel::ComputeDigestDispatched(block, params.nMatMulV4Dimension, params.nMatMulV4FreivaldsRounds,
                                      digest, sketch_payload) &&
            UintToArith256(digest) <= *bnTarget) {
            block.matmul_digest = digest;
            if (freivalds_payload_out != nullptr) {
                *freivalds_payload_out = PackMatMulV4SketchBytesToWords(sketch_payload);
            }
            RegisterMatMulSolveRuntimeSample(true, std::chrono::steady_clock::now() - start);
            return true;
        }

        --max_tries;
        if (block.nNonce64 == std::numeric_limits<uint64_t>::max()) {
            RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - start);
            return false;
        }
        ++block.nNonce64;
        block.nNonce = static_cast<uint32_t>(block.nNonce64);
    }
    RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - start);
    return false;
}

bool SolveMatMul(CBlockHeader& block, const Consensus::Params& params, uint64_t& max_tries,
                 int32_t block_height,
                 const std::atomic<bool>* abort_flag,
                 std::vector<uint32_t>* freivalds_payload_out,
                 const uint256* share_target_override,
                 std::optional<int64_t> parent_median_time_past)
{
    if (!params.fMatMulPOW) return false;
    if (freivalds_payload_out != nullptr) {
        freivalds_payload_out->clear();
    }
    if (max_tries == 0) return false;

    // MatMul v4 (spec §I.3): height-gated dispatch to the dedicated v4
    // solver loop, ahead of all v3 nonce-seed/backend-selection machinery
    // below. Mirrors how CheckMatMulProofOfWork_V4ProductCommitted fully
    // replaces the v3 verification ladder at and above nMatMulV4Height.
    if (params.IsMatMulV4Active(block_height)) {
        return SolveMatMulV4(block, params, max_tries, block_height, abort_flag,
                              freivalds_payload_out, parent_median_time_past);
    }
    if (block.matmul_dim == 0) {
        if (params.nMatMulDimension > std::numeric_limits<uint16_t>::max()) {
            LogWarning("SolveMatMul: nMatMulDimension=%u exceeds uint16_t range\n", params.nMatMulDimension);
            return false;
        }
        block.matmul_dim = static_cast<uint16_t>(params.nMatMulDimension);
    }
    const bool nonce_seeded_solver_active =
        params.IsMatMulNonceSeedActive(block_height) ||
        params.IsMatMulParentMtpSeedActive(block_height);
    if (nonce_seeded_solver_active) {
        if (!SetDeterministicMatMulSeeds(block, params, block_height, parent_median_time_past)) {
            return false;
        }
    }
    if (block.seed_a.IsNull() || block.seed_b.IsNull()) return false;
    if (params.nMatMulTranscriptBlockSize == 0) return false;
    if (block.matmul_dim % params.nMatMulTranscriptBlockSize != 0) return false;
    if (params.nMatMulNoiseRank == 0 || params.nMatMulNoiseRank > block.matmul_dim) return false;

    auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
    if (!bnTarget) return false;
    // block_bnTarget is the consensus block target (also re-derived from nBits inside the consensus
    // pre-hash gate and the miner-side pre-hash batch window, both of which stay at block tier). The
    // optional pool/share override relaxes ONLY the digest early-exit, so every returned share is a
    // genuine block candidate and a returned digest that also meets the block target is a valid block.
    // The pre-hash batch window below references *bnTarget (block tier) directly; block_bnTarget names
    // it for clarity at the override site.
    [[maybe_unused]] const arith_uint256 block_bnTarget = *bnTarget;
    arith_uint256 effective_target = *bnTarget;
    if (share_target_override != nullptr) {
        effective_target = UintToArith256(*share_target_override);
        if (effective_target == 0) return false;
    }
    const auto backend_selection = matmul::accelerated::ResolveMiningBackendFromEnvironment();
    const auto backend_requirement = matmul::accelerated::ResolveBackendRequirementFromEnvironment();
    if (!CheckRequiredMatMulBackend(backend_requirement, backend_selection, "solve_resolve")) {
        return false;
    }
    const auto active_backend = backend_selection.active;
    if (nonce_seeded_solver_active) {
        // Nonce-seeded solving cannot reuse the legacy shared A/B matrix instance. CPU backends
        // still fan out disjoint nonce ranges across workers, while GPU backends with nonce-seed
        // scan support keep a single mining lane and move the expensive nonce-seed pre-hash scan into
        // a GPU window before digesting only the candidates that passed the sigma gate.
        if (!g_matmul_parallel_worker_context) {
            const uint32_t solver_threads = static_cast<uint32_t>(ResolveMatMulSolverThreadCount());
            const bool product_digest_active = params.IsMatMulProductDigestActive(block_height);
            const uint32_t pre_hash_epsilon_bits = GetMatMulPreHashEpsilonBitsForHeight(params, block_height);
            const bool gpu_nonce_seed_scan_enabled =
                (active_backend == matmul::backend::Kind::CUDA ||
                 active_backend == matmul::backend::Kind::METAL) &&
                pre_hash_epsilon_bits > 0;
            const uint32_t nonce_seed_batch_size = gpu_nonce_seed_scan_enabled
                ? ResolveGpuNonceSeedBatchSize(
                    active_backend,
                    block.matmul_dim,
                    params.nMatMulTranscriptBlockSize,
                    params.nMatMulNoiseRank,
                    product_digest_active)
                : 1U;
            const bool parallel_solver_enabled =
                !gpu_nonce_seed_scan_enabled &&
                max_tries > 1 &&
                ShouldEnableParallelMatMulSolve(
                    active_backend, solver_threads, block.matmul_dim,
                    params.nMatMulTranscriptBlockSize, params.nMatMulNoiseRank,
                    product_digest_active);
            // The top-level call owns the pipeline diagnostic stats; workers (worker-context true)
            // never touch them, so the parallel state reported here is the one that sticks.
            g_matmul_parallel_solver_enabled.store(parallel_solver_enabled, std::memory_order_relaxed);
            g_matmul_parallel_solver_threads.store(
                parallel_solver_enabled ? solver_threads : 1U, std::memory_order_relaxed);
            g_matmul_async_prepare_enabled.store(false, std::memory_order_relaxed);
            g_matmul_cpu_confirm_candidates.store(false, std::memory_order_relaxed);
            g_matmul_prefetch_depth.store(1U, std::memory_order_relaxed);
            g_matmul_batch_size.store(nonce_seed_batch_size, std::memory_order_relaxed);
            if (parallel_solver_enabled) {
                return SolveMatMulParallel(
                    block, params, max_tries, block_height, abort_flag,
                    freivalds_payload_out, solver_threads, share_target_override, parent_median_time_past);
            }
        }
        return SolveMatMulNonceSeeded(
            block,
            params,
            max_tries,
            block_height,
            abort_flag,
            freivalds_payload_out,
            share_target_override,
            parent_median_time_past);
    }

    const uint32_t n = block.matmul_dim;
    const uint32_t transcript_block_size = params.nMatMulTranscriptBlockSize;
    const uint32_t noise_rank = params.nMatMulNoiseRank;
    const bool product_digest_active = params.IsMatMulProductDigestActive(block_height);
    const uint32_t solver_threads = static_cast<uint32_t>(ResolveMatMulSolverThreadCount());
    const bool parallel_solver_enabled = !g_matmul_parallel_worker_context &&
                                         max_tries > 1 &&
                                         ShouldEnableParallelMatMulSolve(
                                             active_backend,
                                             solver_threads,
                                             n,
                                             transcript_block_size,
                                             noise_rank,
                                             product_digest_active);
    if (!g_matmul_parallel_worker_context) {
        g_matmul_parallel_solver_enabled.store(parallel_solver_enabled, std::memory_order_relaxed);
        g_matmul_parallel_solver_threads.store(parallel_solver_enabled ? solver_threads : 1U, std::memory_order_relaxed);
    }
    if (parallel_solver_enabled) {
        return SolveMatMulParallel(
            block,
            params,
            max_tries,
            block_height,
            abort_flag,
            freivalds_payload_out,
            solver_threads,
            share_target_override,
            parent_median_time_past);
    }

    const bool mem_diag_enabled = []() {
        const char* env = std::getenv("BTX_MATMUL_MEM_DIAG");
        return env != nullptr && env[0] != '\0' && env[0] != '0';
    }();
    const auto solve_start = std::chrono::steady_clock::now();
    const matmul::MatrixMemoryStats matrix_before = mem_diag_enabled
        ? matmul::ProbeMatrixMemoryStats()
        : matmul::MatrixMemoryStats{};
    const matmul::accelerated::BackendRuntimeStats backend_before = mem_diag_enabled
        ? matmul::accelerated::ProbeMatMulBackendRuntimeStats()
        : matmul::accelerated::BackendRuntimeStats{};

    auto log_mem_diag = [&](const char* status) {
        if (!mem_diag_enabled) return;
        const auto matrix_after = matmul::ProbeMatrixMemoryStats();
        const auto backend_after = matmul::accelerated::ProbeMatMulBackendRuntimeStats();
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - solve_start).count();
        const int64_t live_delta = static_cast<int64_t>(matrix_after.live_bytes) -
                                   static_cast<int64_t>(matrix_before.live_bytes);
        const int64_t digest_req_delta = static_cast<int64_t>(backend_after.digest_requests) -
                                         static_cast<int64_t>(backend_before.digest_requests);
        LogPrintf(
            "MATMUL MEM DIAG: status=%s elapsed_ms=%lld solved_nonce64=%llu max_tries_remaining=%llu "
            "matrix_live_before=%llu matrix_live_after=%llu matrix_live_delta=%lld matrix_peak_after=%llu "
            "matrix_constructed=%llu matrix_destroyed=%llu backend_digest_requests_delta=%lld "
            "backend_metal_fallbacks_delta=%lld async_submissions=%llu async_completions=%llu async_workers=%u\n",
            status,
            static_cast<long long>(elapsed_ms),
            static_cast<unsigned long long>(block.nNonce64),
            static_cast<unsigned long long>(max_tries),
            static_cast<unsigned long long>(matrix_before.live_bytes),
            static_cast<unsigned long long>(matrix_after.live_bytes),
            static_cast<long long>(live_delta),
            static_cast<unsigned long long>(matrix_after.peak_live_bytes),
            static_cast<unsigned long long>(matrix_after.matrices_constructed),
            static_cast<unsigned long long>(matrix_after.matrices_destroyed),
            static_cast<long long>(digest_req_delta),
            static_cast<long long>(
                static_cast<int64_t>(backend_after.metal_fallbacks_to_cpu) -
                static_cast<int64_t>(backend_before.metal_fallbacks_to_cpu)),
            static_cast<unsigned long long>(g_matmul_async_prepare_submissions.load(std::memory_order_relaxed)),
            static_cast<unsigned long long>(g_matmul_async_prepare_completions.load(std::memory_order_relaxed)),
            g_matmul_async_prepare_worker_threads.load(std::memory_order_relaxed));
    };

    try {
    // Track the closest digest seen this call so the "exhausted" diagnostic can quantify how far the
    // hardware fell short of the target (issue #44): a healthy GPU computing millions of digests with
    // zero solves is usually under-powered for the current difficulty, not miscomparing the target.
    arith_uint256 best_digest_seen = ~arith_uint256(0);
    const bool solved = [&]() -> bool {

    const auto A = matmul::SharedFromSeed(block.seed_a, n);
    const auto B = matmul::SharedFromSeed(block.seed_b, n);
    const std::string active_backend_label = matmul::backend::ToString(active_backend);
    const bool use_gpu_generated_inputs = matmul::accelerated::ShouldUseGpuGeneratedInputsForShape(
        active_backend,
        n,
        transcript_block_size,
        noise_rank);
    const uint32_t configured_batch_size = ResolveSolveBatchSize(
        active_backend,
        n,
        transcript_block_size,
        noise_rank,
        product_digest_active);
    const bool async_prepare_enabled = ShouldEnableAsyncPrepare(active_backend, configured_batch_size);
    const uint32_t prefetch_depth = ResolvePreparePrefetchDepth(active_backend, configured_batch_size);
    const bool cpu_confirm_candidates = ShouldCpuConfirmSolvedMatMulCandidates(active_backend, params);
    const bool needs_freivalds_payload =
        params.fMatMulFreivaldsEnabled && freivalds_payload_out != nullptr;
    const matmul::accelerated::DigestScheme digest_scheme = product_digest_active
        ? matmul::accelerated::DigestScheme::PRODUCT_COMMITTED
        : matmul::accelerated::DigestScheme::TRANSCRIPT;
    const uint32_t header_time_refresh_interval = ResolveMinerHeaderTimeRefreshAttempts();
    uint32_t attempts_since_time_refresh{0};
    const bool cpu_vs_metal_compare = ShouldEnableCpuVsMetalDigestCompare(active_backend);
    g_matmul_async_prepare_enabled.store(async_prepare_enabled, std::memory_order_relaxed);
    g_matmul_cpu_confirm_candidates.store(cpu_confirm_candidates, std::memory_order_relaxed);
    g_matmul_prefetch_depth.store(prefetch_depth, std::memory_order_relaxed);
    g_matmul_batch_size.store(configured_batch_size, std::memory_order_relaxed);
    g_matmul_digest_compare_enabled.store(cpu_vs_metal_compare, std::memory_order_relaxed);
    if (async_prepare_enabled) {
        GetMatMulPrepareExecutor();
    }

    // Async prepare tasks can outlive this SolveMatMul() frame on abort, so
    // capture the shape/backend configuration by value.
    auto prepare_inputs = [use_gpu_generated_inputs,
                           transcript_block_size,
                           noise_rank,
                           active_backend,
                           digest_scheme](const CBlockHeader& header) {
        if (use_gpu_generated_inputs) {
            return matmul::accelerated::PrepareMatMulDigestInputsForBackend(
                header,
                transcript_block_size,
                noise_rank,
                active_backend,
                digest_scheme);
        }
        return matmul::accelerated::PrepareMatMulDigestInputs(
            header,
            transcript_block_size,
            noise_rank);
    };

    const uint32_t pre_hash_epsilon_bits = GetMatMulPreHashEpsilonBitsForHeight(params, block_height);
    std::deque<MatMulPrefetchedBatch> prefetched_batches;

    auto queue_prefetched_batches = [&](const CBlockHeader& start_block,
                                        uint64_t remaining_max_tries,
                                        uint32_t attempts_since_refresh_start) {
        if (!async_prepare_enabled || prefetch_depth == 0) {
            return;
        }

        CBlockHeader cursor_block = start_block;
        uint64_t cursor_remaining_max_tries = remaining_max_tries;
        uint32_t cursor_attempts_since_refresh = attempts_since_refresh_start;
        if (!prefetched_batches.empty()) {
            const auto& tail = prefetched_batches.back();
            cursor_block = tail.next_block;
            cursor_remaining_max_tries = tail.remaining_max_tries_after;
            cursor_attempts_since_refresh = tail.window.attempts_since_time_refresh_after;
        }

        while (prefetched_batches.size() < prefetch_depth && cursor_remaining_max_tries > 0) {
            if (!params.fPowAllowMinDifficultyBlocks &&
                header_time_refresh_interval != 0 &&
                cursor_attempts_since_refresh >= header_time_refresh_interval) {
                break;
            }

            MatMulPrefetchedBatch prefetched{
                .window = BuildMatMulNonceBatchWindow(
                    cursor_block,
                    cursor_remaining_max_tries,
                    configured_batch_size,
                    pre_hash_epsilon_bits,
                    *bnTarget,
                    cursor_attempts_since_refresh,
                    header_time_refresh_interval,
                    params.fPowAllowMinDifficultyBlocks),
                .futures = {},
                .next_block = cursor_block,
                .remaining_max_tries_after = cursor_remaining_max_tries,
            };
            if (prefetched.window.nonce_space_exhausted || prefetched.window.headers.empty()) {
                break;
            }

            const uint64_t advance_nonce = cursor_block.nNonce64 + prefetched.window.nonces_scanned - 1;
            if (advance_nonce == std::numeric_limits<uint64_t>::max()) {
                break;
            }
            prefetched.next_block.nNonce64 = advance_nonce + 1;
            prefetched.next_block.nNonce = static_cast<uint32_t>(prefetched.next_block.nNonce64);
            prefetched.remaining_max_tries_after =
                cursor_remaining_max_tries > prefetched.window.nonces_scanned
                    ? cursor_remaining_max_tries - prefetched.window.nonces_scanned
                    : 0;
            prefetched.futures = SubmitPreparedBatch(prefetched.window.headers, prepare_inputs);
            g_matmul_prefetched_batches.fetch_add(1, std::memory_order_relaxed);
            g_matmul_prefetched_inputs.fetch_add(prefetched.window.headers.size(), std::memory_order_relaxed);
            prefetched_batches.push_back(std::move(prefetched));

            cursor_block = prefetched_batches.back().next_block;
            cursor_remaining_max_tries = prefetched_batches.back().remaining_max_tries_after;
            cursor_attempts_since_refresh = prefetched_batches.back().window.attempts_since_time_refresh_after;
        }
    };

    while (max_tries > 0) {
        // Check abort flag before each batch (set on tip change or shutdown).
        if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed)) {
            LogDebug(BCLog::MINING, "SolveMatMul: abort flag set, stopping with %lu tries remaining\n",
                     static_cast<unsigned long>(max_tries));
            return false;
        }

        bool used_prefetched_batch{false};
        MatMulNonceBatchWindow current_window;
        std::vector<std::future<matmul::accelerated::PreparedDigestInputs>> prefetched_futures;
        if (!prefetched_batches.empty()) {
            current_window = std::move(prefetched_batches.front().window);
            prefetched_futures = std::move(prefetched_batches.front().futures);
            prefetched_batches.pop_front();
            used_prefetched_batch = true;
        } else {
            current_window = BuildMatMulNonceBatchWindow(
                block,
                max_tries,
                configured_batch_size,
                pre_hash_epsilon_bits,
                *bnTarget,
                attempts_since_time_refresh,
                header_time_refresh_interval,
                params.fPowAllowMinDifficultyBlocks);
        }

        if (current_window.nonce_space_exhausted) {
            const std::string seed_a_prefix = block.seed_a.GetHex().substr(0, 16);
            const std::string seed_b_prefix = block.seed_b.GetHex().substr(0, 16);
            LogPrintf("MatMul mining: nonce64 exhausted (seed_a=%s seed_b=%s)\n", seed_a_prefix, seed_b_prefix);
            break;
        }

        const uint32_t batch_attempts = static_cast<uint32_t>(current_window.headers.size());
        const uint32_t filtered_nonces = current_window.nonces_scanned - batch_attempts;
        max_tries -= filtered_nonces;

        if (batch_attempts == 0) {
            if (current_window.nonces_scanned == 0) {
                break;
            }
            const uint64_t advance_nonce = block.nNonce64 + current_window.nonces_scanned - 1;
            if (advance_nonce == std::numeric_limits<uint64_t>::max()) {
                break;
            }
            block.nNonce64 = advance_nonce + 1;
            block.nNonce = static_cast<uint32_t>(block.nNonce64);
            attempts_since_time_refresh = current_window.attempts_since_time_refresh_after;
            MaybeRefreshMinerHeaderTime(
                block,
                attempts_since_time_refresh,
                header_time_refresh_interval,
                params.fPowAllowMinDifficultyBlocks);
            continue;
        }

        std::vector<matmul::accelerated::PreparedDigestInputs> prepared_batch;
        prepared_batch.reserve(batch_attempts);
        if (used_prefetched_batch) {
            prepared_batch = CollectPreparedBatchFutures(prefetched_futures);
        } else if (async_prepare_enabled && batch_attempts > 1) {
            auto futures = SubmitPreparedBatch(current_window.headers, prepare_inputs);
            g_matmul_overlapped_prepares.fetch_add(batch_attempts - 1, std::memory_order_relaxed);
            prepared_batch = CollectPreparedBatchFutures(futures);
        } else {
            for (const auto& header : current_window.headers) {
                prepared_batch.push_back(prepare_inputs(header));
                g_matmul_prepared_inputs.fetch_add(1, std::memory_order_relaxed);
            }
        }

        auto digest_submission = matmul::accelerated::SubmitMatMulDigestPreparedBatchForMining(
            current_window.headers,
            *A,
            *B,
            transcript_block_size,
            noise_rank,
            prepared_batch,
            active_backend,
            digest_scheme);
        if (batch_attempts > 1) {
            g_matmul_batched_digest_requests.fetch_add(1, std::memory_order_relaxed);
            g_matmul_batched_nonce_attempts.fetch_add(batch_attempts, std::memory_order_relaxed);
        }

        // Check abort between submit and wait.  If a tip change was
        // signalled while the Metal command buffer is in-flight, skip
        // prefetching but still drain the submission so Metal resources
        // are properly released before we exit.
        const bool abort_before_wait = abort_flag != nullptr &&
                                       abort_flag->load(std::memory_order_relaxed);

        if (!abort_before_wait) {
            const uint64_t remaining_max_tries_after_batch = max_tries - batch_attempts;
            if (async_prepare_enabled &&
                remaining_max_tries_after_batch > 0 &&
                current_window.nonces_scanned > 0) {
                const uint64_t advance_nonce = block.nNonce64 + current_window.nonces_scanned - 1;
                if (advance_nonce != std::numeric_limits<uint64_t>::max()) {
                    CBlockHeader next_block{block};
                    next_block.nNonce64 = advance_nonce + 1;
                    next_block.nNonce = static_cast<uint32_t>(next_block.nNonce64);
                    queue_prefetched_batches(
                        next_block,
                        remaining_max_tries_after_batch,
                        current_window.attempts_since_time_refresh_after);
                }
            }
        }

        // Always drain the in-flight submission so Metal buffers are released.
        std::vector<matmul::accelerated::DigestResult> digest_batch =
            matmul::accelerated::WaitForSubmittedMatMulDigestBatch(std::move(digest_submission));

        // If we were aborted while waiting, stop immediately.
        if (abort_before_wait ||
            (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed))) {
            LogDebug(BCLog::MINING, "SolveMatMul: abort flag set after digest wait, stopping with %lu tries remaining\n",
                     static_cast<unsigned long>(max_tries));
            return false;
        }

        if (digest_batch.size() != batch_attempts) {
            return false;
        }

        for (uint32_t i = 0; i < batch_attempts; ++i) {
            const auto& header = current_window.headers[i];
            const auto& digest_result = digest_batch[i];
            if (!digest_result.ok) return false;
            if (!CheckRequiredMatMulDigestBackend(backend_requirement, digest_result, "solve_batch_digest")) {
                return false;
            }

            std::optional<uint256> compared_cpu_digest;
            if (cpu_vs_metal_compare && active_backend == matmul::backend::Kind::METAL) {
                // Use the SAME prepared inputs to isolate field-arithmetic
                // differences from input-generation differences.
                compared_cpu_digest = matmul::accelerated::ComputeDigestCpuFromPreparedInputs(
                    *A,
                    *B,
                    prepared_batch[i],
                    transcript_block_size,
                    digest_scheme);
                RegisterMatMulDigestCompareAttempt(
                    header,
                    digest_result.digest,
                    *compared_cpu_digest,
                    active_backend_label.c_str());
            }

            --max_tries;
            if (const arith_uint256 digest_value = UintToArith256(digest_result.digest); digest_value < best_digest_seen) {
                best_digest_seen = digest_value;
            }
            if (UintToArith256(digest_result.digest) <= effective_target) {
                uint256 accepted_digest = digest_result.digest;
                if (cpu_confirm_candidates || needs_freivalds_payload) {
                    // Recompute on CPU using the same inputs Metal used.
                    // This catches rare GPU field-arithmetic glitches while
                    // guaranteeing the accepted digest is CPU-verifiable.
                    //
                    // If Freivalds payloads are required, keep the canonical
                    // C' matrix from this CPU confirmation and reuse it as the
                    // block payload so we don't perform the O(n^3) product
                    // twice for winning blocks.
                    std::optional<matmul::transcript::CanonicalResult> canonical_cpu_result;
                    uint256 cpu_digest;
                    if (needs_freivalds_payload) {
                        const auto resolved_noise = matmul::accelerated::ResolvePreparedNoiseForCpu(
                            prepared_batch[i],
                            header.matmul_dim,
                            noise_rank);
                        const auto A_prime =
                            *A + (resolved_noise.E_L * resolved_noise.E_R);
                        const auto B_prime =
                            *B + (resolved_noise.F_L * resolved_noise.F_R);
                        canonical_cpu_result = matmul::transcript::CanonicalMatMul(
                            A_prime,
                            B_prime,
                            transcript_block_size,
                            prepared_batch[i].sigma);
                        cpu_digest = digest_scheme == matmul::accelerated::DigestScheme::PRODUCT_COMMITTED
                            ? matmul::transcript::ComputeProductCommittedDigest(
                                canonical_cpu_result->C_prime,
                                transcript_block_size,
                                prepared_batch[i].sigma)
                            : canonical_cpu_result->transcript_hash;
                    } else {
                        cpu_digest = compared_cpu_digest.has_value()
                            ? *compared_cpu_digest
                            : matmul::accelerated::ComputeDigestCpuFromPreparedInputs(
                                *A,
                                *B,
                                prepared_batch[i],
                                transcript_block_size,
                                digest_scheme);
                    }

                    if (!cpu_vs_metal_compare && cpu_digest != digest_result.digest) {
                        RegisterMatMulDigestCompareAttempt(
                            header,
                            digest_result.digest,
                            cpu_digest,
                            active_backend_label.c_str());
                    }

                    if (UintToArith256(cpu_digest) > effective_target) {
                        continue;
                    }
                    accepted_digest = cpu_digest;
                    if (canonical_cpu_result.has_value()) {
                        SetFreivaldsPayloadFromProduct(*freivalds_payload_out, canonical_cpu_result->C_prime);
                    }
                }

                block.nNonce64 = header.nNonce64;
                block.nNonce = header.nNonce;
                block.matmul_digest = accepted_digest;
                return true;
            }
        }

        // Advance nonce past all scanned nonces (including pre-hash rejected ones).
        const uint64_t advance_nonce = block.nNonce64 + current_window.nonces_scanned - 1;
        if (advance_nonce == std::numeric_limits<uint64_t>::max()) {
            const std::string seed_a_prefix = block.seed_a.GetHex().substr(0, 16);
            const std::string seed_b_prefix = block.seed_b.GetHex().substr(0, 16);
            LogPrintf("MatMul mining: nonce64 exhausted (seed_a=%s seed_b=%s)\n", seed_a_prefix, seed_b_prefix);
            break;
        }
        block.nNonce64 = advance_nonce + 1;
        block.nNonce = static_cast<uint32_t>(block.nNonce64);
        attempts_since_time_refresh = current_window.attempts_since_time_refresh_after;
        MaybeRefreshMinerHeaderTime(
            block,
            attempts_since_time_refresh,
            header_time_refresh_interval,
            params.fPowAllowMinDifficultyBlocks);
    }

    return false;
    }(); // end of inner lambda
    RegisterMatMulSolveRuntimeSample(solved, std::chrono::steady_clock::now() - solve_start);
    if (!solved && bnTarget && best_digest_seen != ~arith_uint256(0)) {
        // Report how close we got. best_target_bits_short ~= log2(best_digest / target): roughly the
        // extra factor of digests needed to expect a solve at the current difficulty (issue #44).
        // Measured against effective_target (the share target when pool mining, else the block target).
        const int bits_short = std::max(0, static_cast<int>(best_digest_seen.bits()) - static_cast<int>(effective_target.bits()));
        LogDebug(BCLog::MINING, "SolveMatMul: exhausted, best_digest=%s target=%s ~%d_bits_short\n",
                 best_digest_seen.GetHex(), effective_target.GetHex(), bits_short);
    }
    log_mem_diag(solved ? "solved" : "exhausted");
    return solved;
    } catch (const std::exception& e) {
        RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - solve_start);
        LogWarning("SolveMatMul: exception during mining: %s\n", e.what());
        log_mem_diag("exception_std");
        return false;
    } catch (...) {
        RegisterMatMulSolveRuntimeSample(false, std::chrono::steady_clock::now() - solve_start);
        LogWarning("SolveMatMul: unknown exception during mining\n");
        log_mem_diag("exception_unknown");
        return false;
    }
}

bool CheckKAWPOWProofOfWork(const CBlockHeader& block, uint32_t block_height, const Consensus::Params& params)
{
    if constexpr (G_FUZZING) return (block.GetHash().data()[31] & 0x80) == 0;

    auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
    if (!bnTarget) return false;

    const auto result{kawpow::Hash(block, block_height)};
    if (!result) return false;

    if (result->mix_hash != block.mix_hash) return false;

    if (UintToArith256(result->final_hash) > *bnTarget) return false;

    return true;
}

bool SolveKAWPOW(CBlockHeader& block, uint32_t block_height, const Consensus::Params& params, uint64_t& max_tries)
{
    auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
    if (!bnTarget) return false;
    const uint32_t header_time_refresh_interval = ResolveMinerHeaderTimeRefreshAttempts();
    uint32_t attempts_since_time_refresh{0};

    while (max_tries > 0) {
        const auto result{kawpow::Hash(block, block_height)};
        if (!result) return false;
        --max_tries;

        if (UintToArith256(result->final_hash) <= *bnTarget) {
            block.mix_hash = result->mix_hash;
            return true;
        }

        if (block.nNonce64 == std::numeric_limits<uint64_t>::max()) {
            LogPrintf("KAWPOW mining: nonce64 exhausted for candidate header\n");
            break;
        }
        ++block.nNonce64;
        if (attempts_since_time_refresh < std::numeric_limits<uint32_t>::max()) {
            ++attempts_since_time_refresh;
        }
        MaybeRefreshMinerHeaderTime(
            block,
            attempts_since_time_refresh,
            header_time_refresh_interval,
            params.fPowAllowMinDifficultyBlocks);
    }

    return false;
}
