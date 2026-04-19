// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <threadsafety.h>
#include <chain.h>
#include <crypto/kawpow.h>
#include <hash.h>
#include <logging.h>
#include <matmul/accelerated_solver.h>
#include <matmul/freivalds.h>
#include <matmul/matmul_pow.h>
#include <matmul/noise.h>
#include <matmul/transcript.h>
#include <primitives/block.h>
#include <sync.h>
#include <uint256.h>
#include <util/check.h>
#include <util/strencodings.h>
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
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

uint256 DeterministicMatMulSeed(const uint256& prev_block_hash, uint32_t height, uint8_t which)
{
    HashWriter hw;
    hw << prev_block_hash << height << which;
    return hw.GetSHA256();
}

namespace {
constexpr int64_t DGW_PAST_BLOCKS{180};
constexpr uint32_t DEFAULT_MINER_HEADER_TIME_REFRESH_ATTEMPTS{4'096U};
constexpr uint64_t MATMUL_V2_ABS_MAX_DIM{2048};
constexpr uint64_t MATMUL_V2_MAX_PAYLOAD_WORDS{MATMUL_V2_ABS_MAX_DIM * MATMUL_V2_ABS_MAX_DIM};
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

int32_t ResolveMatMulPrepareWorkerCount()
{
    const char* env = std::getenv("BTX_MATMUL_PREPARE_WORKERS");
    if (env != nullptr && env[0] != '\0') {
        int32_t parsed{0};
        if (ParseInt32(env, &parsed) && parsed > 0) {
            return std::min<int32_t>(parsed, 16);
        }
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
        // Keep one performance core free for the foreground solve loop and
        // let the async prepare pool consume only the remaining performance
        // cores. Local Apple Silicon mining benchmarks consistently beat the
        // old hw-1 heuristic with this split.
        return std::clamp<int32_t>(perf_level0_logicalcpu - 1, 1, 4);
    }
#endif

    const uint32_t hw = std::thread::hardware_concurrency();
    if (hw <= 1) return 1;
    if (hw == 2) return 2;
    return std::min<uint32_t>(hw - 1, 4);
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
    if (backend_selection.active == matmul::backend::Kind::CUDA) {
        const uint32_t hw = std::thread::hardware_concurrency();
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

class MatMulPrepareExecutor
{
public:
    explicit MatMulPrepareExecutor(size_t worker_count)
    {
        m_workers.reserve(worker_count);
        for (size_t i = 0; i < worker_count; ++i) {
            m_workers.emplace_back([this] { WorkerLoop(); });
        }
        g_matmul_async_prepare_worker_threads.store(
            static_cast<uint32_t>(m_workers.size()),
            std::memory_order_relaxed);
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
        info.current_anchor_height = params.nMatMulAsertHalfLifeUpgradeHeight;
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

bool ValidateMatMulAsertParams(const Consensus::Params& params, int32_t next_height)
{
    if (params.nMatMulAsertHalfLife <= 0) {
        LogWarning("MatMulAsert: invalid half-life=%lld at height %d, failing closed to powLimit\n",
                   static_cast<long long>(params.nMatMulAsertHalfLife), next_height);
        return false;
    }
    if (params.nPowTargetSpacing <= 0) {
        LogWarning("MatMulAsert: invalid target spacing=%lld at height %d, failing closed to powLimit\n",
                   static_cast<long long>(params.nPowTargetSpacing), next_height);
        return false;
    }
    if (params.nMatMulAsertBootstrapFactor == 0) {
        LogWarning("MatMulAsert: bootstrap factor is zero at height %d, failing closed to powLimit\n",
                   next_height);
        return false;
    }
    if (params.nMatMulAsertRetuneHardeningFactor == 0) {
        LogWarning("MatMulAsert: retune hardening factor is zero at height %d, failing closed to powLimit\n",
                   next_height);
        return false;
    }
    if (params.nMatMulAsertRetune2TargetNum == 0 || params.nMatMulAsertRetune2TargetDen == 0) {
        LogWarning("MatMulAsert: retune2 ratio is invalid (num=%u den=%u) at height %d, failing closed to powLimit\n",
                   params.nMatMulAsertRetune2TargetNum, params.nMatMulAsertRetune2TargetDen, next_height);
        return false;
    }

    const bool retune_enabled = !IsDisabledHeight(params.nMatMulAsertRetuneHeight);
    const bool retune2_enabled = !IsDisabledHeight(params.nMatMulAsertRetune2Height);
    if (retune_enabled && params.nMatMulAsertRetuneHeight < params.nMatMulAsertHeight) {
        LogWarning("MatMulAsert: retune height=%d is below ASERT activation=%d at height %d, failing closed to powLimit\n",
                   params.nMatMulAsertRetuneHeight, params.nMatMulAsertHeight, next_height);
        return false;
    }
    if (retune2_enabled && params.nMatMulAsertRetune2Height < params.nMatMulAsertHeight) {
        LogWarning("MatMulAsert: retune2 height=%d is below ASERT activation=%d at height %d, failing closed to powLimit\n",
                   params.nMatMulAsertRetune2Height, params.nMatMulAsertHeight, next_height);
        return false;
    }
    if (retune_enabled && retune2_enabled &&
        params.nMatMulAsertRetune2Height < params.nMatMulAsertRetuneHeight) {
        LogWarning("MatMulAsert: retune2 height=%d is below retune height=%d at height %d, failing closed to powLimit\n",
                   params.nMatMulAsertRetune2Height, params.nMatMulAsertRetuneHeight, next_height);
        return false;
    }
    if (IsMatMulAsertHalfLifeUpgradeConfigured(params)) {
        if (params.nMatMulAsertHalfLifeUpgrade <= 0) {
            LogWarning("MatMulAsert: half-life upgrade value=%lld is invalid at height %d, failing closed to powLimit\n",
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
        if (params.nMatMulAsertHalfLifeUpgradeHeight <= latest_pre_upgrade_anchor) {
            LogWarning("MatMulAsert: half-life upgrade height=%d must be above latest prior anchor=%d at height %d, failing closed to powLimit\n",
                       params.nMatMulAsertHalfLifeUpgradeHeight, latest_pre_upgrade_anchor, next_height);
            return false;
        }
    }
    return true;
}

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
        if (configured_batch_size <= 1) {
            return 1;
        }
        return ResolveMatMulSolverThreadCount() >= 5 ? 3 : 2;
    }
    if (backend != matmul::backend::Kind::METAL) {
        return 0;
    }
    if (configured_batch_size <= 1) {
        return 1;
    }

    return 2;
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
        (void)product_digest_active;
        const int32_t solver_threads = ResolveMatMulSolverThreadCount();
        if (n >= 512 && transcript_block_size >= 16 && noise_rank >= 8) {
            return solver_threads >= 5 ? 4 : 2;
        }
        if (n >= 256 && transcript_block_size >= 8 && noise_rank >= 4) {
            return solver_threads >= 4 ? 4 : 2;
        }
        return 1;
    }
    if (backend != matmul::backend::Kind::METAL) {
        return 1;
    }
    const bool has_parallel_solver_support = ResolveMatMulSolverThreadCount() > 1;
    if (n >= 512 && transcript_block_size >= 16 && noise_rank >= 8) {
        // Production mainnet shape: keep the stock node on the conservative
        // single-window path by default. The widened queueing path is exact
        // and opt-in ready, but it still needs host-specific tuning to beat
        // the best single-batch profile consistently on Apple Silicon.
        return 1;
    }
    if (n >= 256 && transcript_block_size >= 8 && noise_rank >= 4) {
        return has_parallel_solver_support ? 2 : 1;
    }
    return 1;
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
    if (height_diff < 0) {
        LogWarning("CalculateMatMulAsertTarget: height_diff=%lld is negative, failing closed to powLimit\n",
                   static_cast<long long>(height_diff));
        return pow_limit;
    }
    if (half_life <= 0 || params.nPowTargetSpacing <= 0) {
        LogWarning("CalculateMatMulAsertTarget: invalid parameters (half_life=%lld target_spacing=%lld), failing closed to powLimit\n",
                   static_cast<long long>(half_life),
                   static_cast<long long>(params.nPowTargetSpacing));
        return pow_limit;
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
        return pow_limit.GetCompact();
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

    if (params.nMatMulTranscriptBlockSize == 0) return false;
    if (block.matmul_dim != params.nMatMulDimension) return false;
    if (block.matmul_dim < params.nMatMulMinDimension) return false;
    if (block.matmul_dim > params.nMatMulMaxDimension) return false;
    if (block.matmul_dim % params.nMatMulTranscriptBlockSize != 0) return false;
    if (params.nMatMulNoiseRank == 0 || params.nMatMulNoiseRank > block.matmul_dim) return false;
    if (block.seed_a.IsNull() || block.seed_b.IsNull()) return false;

    auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
    if (!bnTarget) return false;
    if (UintToArith256(block.matmul_digest) > *bnTarget) return false;

    return true;
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
    const uint32_t pre_hash_epsilon_bits = GetMatMulPreHashEpsilonBitsForHeight(params, block_height);
    if (pre_hash_epsilon_bits > 0) {
        const uint256 sigma = matmul::DeriveSigma(block);
        auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
        if (!bnTarget) return finish(false);
        arith_uint256 pre_hash_target = SaturatingLeftShift256(*bnTarget, pre_hash_epsilon_bits);
        if (UintToArith256(sigma) > pre_hash_target) return finish(false);
    }

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
    const uint32_t pre_hash_epsilon_bits = GetMatMulPreHashEpsilonBitsForHeight(params, block_height);
    if (pre_hash_epsilon_bits > 0) {
        const uint256 sigma = matmul::DeriveSigma(block);
        auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
        if (!bnTarget) return false;
        arith_uint256 pre_hash_target = SaturatingLeftShift256(*bnTarget, pre_hash_epsilon_bits);
        if (UintToArith256(sigma) > pre_hash_target) return false;
    }

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
    const uint32_t pre_hash_epsilon_bits = GetMatMulPreHashEpsilonBitsForHeight(params, block_height);
    if (pre_hash_epsilon_bits > 0) {
        const uint256 sigma = matmul::DeriveSigma(block);
        auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
        if (!bnTarget) return finish(false);
        arith_uint256 pre_hash_target = SaturatingLeftShift256(*bnTarget, pre_hash_epsilon_bits);
        if (UintToArith256(sigma) > pre_hash_target) return finish(false);
    }

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
    const uint32_t pre_hash_epsilon_bits = GetMatMulPreHashEpsilonBitsForHeight(params, block_height);
    if (pre_hash_epsilon_bits > 0) {
        const uint256 sigma = matmul::DeriveSigma(block);
        auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
        if (!bnTarget) return finish(false);
        arith_uint256 pre_hash_target = SaturatingLeftShift256(*bnTarget, pre_hash_epsilon_bits);
        if (UintToArith256(sigma) > pre_hash_target) return finish(false);
    }

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

uint32_t EffectiveMatMulPeerVerifyBudgetPerMin(const Consensus::Params& params, bool is_ibd)
{
    if (!is_ibd) return params.nMatMulPeerVerifyBudgetPerMin;
    // IBD needs to process repeated 2000-header batches without disconnect
    // churn. Keep a finite but substantially higher cap than steady-state.
    return std::max<uint32_t>(params.nMatMulPeerVerifyBudgetPerMin, 200'000U);
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

    uint32_t effective_budget = EffectiveMatMulPeerVerifyBudgetPerMin(params, is_ibd);
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

bool SolveMatMulParallel(CBlockHeader& block,
                         const Consensus::Params& params,
                         uint64_t& max_tries,
                         int32_t block_height,
                         const std::atomic<bool>* abort_flag,
                         std::vector<uint32_t>* freivalds_payload_out,
                         uint32_t solver_threads)
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
                freivalds_payload_out != nullptr ? &local_payload : nullptr);
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

bool SolveMatMul(CBlockHeader& block, const Consensus::Params& params, uint64_t& max_tries,
                 int32_t block_height,
                 const std::atomic<bool>* abort_flag,
                 std::vector<uint32_t>* freivalds_payload_out)
{
    if (!params.fMatMulPOW) return false;
    if (freivalds_payload_out != nullptr) {
        freivalds_payload_out->clear();
    }
    if (max_tries == 0) return false;
    const uint32_t solver_threads = static_cast<uint32_t>(ResolveMatMulSolverThreadCount());
    const bool parallel_solver_enabled = !g_matmul_parallel_worker_context &&
                                         solver_threads > 1 &&
                                         max_tries > 1;
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
            solver_threads);
    }
    if (block.matmul_dim == 0) {
        if (params.nMatMulDimension > std::numeric_limits<uint16_t>::max()) {
            LogWarning("SolveMatMul: nMatMulDimension=%u exceeds uint16_t range\n", params.nMatMulDimension);
            return false;
        }
        block.matmul_dim = static_cast<uint16_t>(params.nMatMulDimension);
    }
    if (block.seed_a.IsNull() || block.seed_b.IsNull()) return false;
    if (params.nMatMulTranscriptBlockSize == 0) return false;
    if (block.matmul_dim % params.nMatMulTranscriptBlockSize != 0) return false;
    if (params.nMatMulNoiseRank == 0 || params.nMatMulNoiseRank > block.matmul_dim) return false;

    auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
    if (!bnTarget) return false;

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
    const bool solved = [&]() -> bool {

    const uint32_t n = block.matmul_dim;
    const auto A = matmul::SharedFromSeed(block.seed_a, n);
    const auto B = matmul::SharedFromSeed(block.seed_b, n);
    const auto backend_selection = matmul::accelerated::ResolveMiningBackendFromEnvironment();
    const auto active_backend = backend_selection.active;
    const std::string active_backend_label = matmul::backend::ToString(active_backend);
    const uint32_t transcript_block_size = params.nMatMulTranscriptBlockSize;
    const uint32_t noise_rank = params.nMatMulNoiseRank;
    const bool product_digest_active = params.IsMatMulProductDigestActive(block_height);
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

    // Async prepare tasks can outlive this SolveMatMul() frame on abort, so
    // capture the shape/backend configuration by value.
    auto prepare_inputs = [use_gpu_generated_inputs,
                           transcript_block_size,
                           noise_rank,
                           active_backend](const CBlockHeader& header) {
        if (use_gpu_generated_inputs) {
            return matmul::accelerated::PrepareMatMulDigestInputsForBackend(
                header,
                transcript_block_size,
                noise_rank,
                active_backend);
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
            if (UintToArith256(digest_result.digest) <= *bnTarget) {
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

                    if (UintToArith256(cpu_digest) > *bnTarget) {
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
