// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc.h>

#include <consensus/params.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc_mx_layout.h>
#include <matmul/matmul_v4_rc_scale.h>
#include <matmul/matmul_v4_rc_stage3_hash_domain_sep.h>
#include <span.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace matmul::v4::rc {
namespace {

namespace bx = matmul::v4::bmx4;
namespace lt = matmul::v4::lt;
thread_local const std::atomic_bool* g_exact_replay_cancelled{nullptr};
thread_local const std::atomic_bool* g_exact_replay_secondary_cancelled{
    nullptr};
constexpr size_t kRCDeviceMerkleLeafBatch{65536};

// --- tagged SHA helpers -----------------------------------------------------

uint256 Sha256Tagged(const char* tag, size_t taglen, const unsigned char* data, size_t len)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(tag), taglen);
    if (len > 0) hasher.Write(data, len);
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

uint256 Sha256TaggedU32(const char* tag, size_t taglen, const uint256& a, uint32_t le32)
{
    unsigned char buf[32 + 4];
    std::memcpy(buf, a.data(), 32);
    WriteLE32(buf + 32, le32);
    return Sha256Tagged(tag, taglen, buf, sizeof(buf));
}

uint256 Sha256dBytes(const unsigned char* data, size_t len)
{
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(data, len).Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    return uint256{Span<const unsigned char>{d2, sizeof(d2)}};
}

uint256 DeriveOperandSeed(const uint256& seed_r, const char* tag)
{
    return Sha256Tagged(tag, std::strlen(tag), seed_r.data(), 32);
}

uint32_t ClampLocalThreads(uint32_t threads, size_t jobs)
{
    if (threads <= 1 || jobs <= 1) return 1;
    if (threads > 64) threads = 64;
    return std::max<uint32_t>(1, std::min<uint32_t>(threads, static_cast<uint32_t>(jobs)));
}

template <typename Fn>
void ParallelForLocal(size_t jobs, uint32_t threads, const Fn& fn)
{
    threads = ClampLocalThreads(threads, jobs);
    if (threads <= 1) {
        for (size_t i = 0; i < jobs; ++i) fn(i);
        return;
    }
    std::atomic<size_t> next{0};
    std::vector<std::thread> workers;
    workers.reserve(threads);
    for (uint32_t t = 0; t < threads; ++t) {
        workers.emplace_back([&]() {
            for (;;) {
                const size_t i = next.fetch_add(1, std::memory_order_relaxed);
                if (i >= jobs) break;
                fn(i);
            }
        });
    }
    for (auto& worker : workers) worker.join();
}

// --- ExactGemm helpers ------------------------------------------------------

enum class RCGemmPhase : uint8_t {
    Phase1,
    Phase2,
};

struct RCGemmDispatch {
    const lt::ExactGemmBackend& gemm;
    RCExactReplayAccelerationStats* stats{nullptr};
    bool require_device{false};
    uint32_t output_row_tile{0};
    uint32_t profile{0};
};

uint64_t GemmMacs(uint32_t rows, uint32_t inner, uint32_t cols)
{
    return static_cast<uint64_t>(rows) * inner * cols;
}

void RecordDeviceGemm(RCGemmDispatch& dispatch, RCGemmPhase phase, uint64_t macs)
{
    if (dispatch.stats == nullptr) return;
    ++dispatch.stats->device_calls;
    dispatch.stats->device_macs += macs;
    if (phase == RCGemmPhase::Phase1) {
        ++dispatch.stats->phase1_device_calls;
        dispatch.stats->phase1_device_macs += macs;
    } else {
        ++dispatch.stats->phase2_device_calls;
        dispatch.stats->phase2_device_macs += macs;
    }
}

void RecordCpuGemm(RCGemmDispatch& dispatch, uint64_t macs, bool fallback,
                   const char* failure)
{
    if (dispatch.stats == nullptr) return;
    ++dispatch.stats->cpu_calls;
    dispatch.stats->cpu_macs += macs;
    if (fallback) ++dispatch.stats->cpu_fallbacks;
    if (failure != nullptr && dispatch.stats->first_failure.empty()) {
        dispatch.stats->first_failure = failure;
    }
}

void RecordStrictDeviceFailure(RCGemmDispatch& dispatch, const char* failure)
{
    if (dispatch.stats == nullptr) return;
    ++dispatch.stats->cpu_fallbacks;
    if (failure != nullptr && dispatch.stats->first_failure.empty()) {
        dispatch.stats->first_failure = failure;
    }
}

void RecordDeviceXof(RCGemmDispatch& dispatch, uint64_t elements,
                     uint64_t calls,
                     std::chrono::steady_clock::duration elapsed)
{
    if (dispatch.stats == nullptr) return;
    dispatch.stats->device_xof_calls += calls;
    dispatch.stats->device_xof_elements += elements;
    dispatch.stats->operand_xof_on_device = true;
    dispatch.stats->device_xof_s +=
        std::chrono::duration<double>(elapsed).count();
}

void RecordHostXof(RCGemmDispatch& dispatch, uint64_t elements,
                   bool device_fallback, const char* failure)
{
    if (dispatch.stats == nullptr) return;
    ++dispatch.stats->host_xof_calls;
    dispatch.stats->host_xof_elements += elements;
    if (device_fallback) ++dispatch.stats->device_xof_fallbacks;
    if (failure != nullptr && dispatch.stats->first_failure.empty()) {
        dispatch.stats->first_failure = failure;
    }
}

void RecordDeviceXofLaneFailure(
    RCGemmDispatch& dispatch, uint64_t elements, uint64_t calls,
    std::chrono::steady_clock::duration elapsed, const char* failure)
{
    if (dispatch.stats == nullptr) return;
    // The fused callback may have generated some or all operands before a
    // later GEMM/extract/cancellation failure. Count the admitted device work
    // as attempted work instead of hiding it merely because the lane declined.
    dispatch.stats->device_xof_calls += calls;
    dispatch.stats->device_xof_elements += elements;
    ++dispatch.stats->device_xof_fallbacks;
    dispatch.stats->device_xof_s +=
        std::chrono::duration<double>(elapsed).count();
    if (failure != nullptr && dispatch.stats->first_failure.empty()) {
        dispatch.stats->first_failure = failure;
    }
}

bool SeededProfile1LaneEligible(
    const RCEpisodeParams& params, const RCGemmDispatch& dispatch)
{
    // Shape is not authority: toy/non-datacenter dimensions can be selected
    // under Profile 2 in tests and future epochs. Only the consensus-selected
    // Profile 1 authority may enter the seeded CUDA lane.
    return dispatch.profile == 1 &&
        !UseDatacenterSharedFfnWeights(params);
}

bool ExpandMxDispatched(
    const uint256& seed,
    uint32_t rows,
    uint32_t columns,
    RCGemmDispatch& dispatch,
    std::vector<int8_t>& output)
{
    bool device_fallback{false};
    if (dispatch.gemm.rc_expand_mx != nullptr) {
        const auto device_start{
            std::chrono::steady_clock::now()};
        bool device_ok{false};
        try {
            device_ok = dispatch.gemm.rc_expand_mx(
                seed, rows, columns, output);
        } catch (...) {
            device_ok = false;
        }
        const size_t expected{
            static_cast<size_t>(rows) * columns};
        if (device_ok && output.size() == expected) {
            RecordDeviceXof(
                dispatch, expected, /*calls=*/1,
                std::chrono::steady_clock::now() - device_start);
            return true;
        }
        output.clear();
        if (dispatch.require_device) {
            RecordStrictDeviceFailure(
                dispatch, "device_operand_xof_declined_or_wrong_size");
            return false;
        }
        device_fallback = true;
    }
    // Host ExpandMx is byte-identical to the serial oracle; use the parallel
    // verifier path for large CUDA/Metal-declined operands (K/V/W).
    const uint32_t threads = std::max(1u, std::thread::hardware_concurrency());
    output = ExpandMxDequantInt8Parallel(seed, rows, columns, threads);
    RecordHostXof(
        dispatch, static_cast<uint64_t>(rows) * columns,
        device_fallback,
        device_fallback
            ? "device_operand_xof_declined_or_wrong_size"
            : nullptr);
    return true;
}

bool ExpandX0ForEpisodeDispatched(
    const uint256& seed_x0,
    const RCEpisodeParams& params,
    RCGemmDispatch& dispatch,
    std::vector<int8_t>& output)
{
    if (!UseDatacenterRowBlockX0(params)) {
        return ExpandMxDispatched(
            seed_x0, params.b_seq, params.d_model,
            dispatch, output);
    }
    assert(params.b_seq % kRCX0RowBlockRows == 0);
    output.resize(
        static_cast<size_t>(params.b_seq) * params.d_model);
    const uint32_t blocks{
        params.b_seq / kRCX0RowBlockRows};
    for (uint32_t block = 0; block < blocks; ++block) {
        std::vector<int8_t> expanded;
        if (!ExpandMxDispatched(
                DeriveX0RowBlockSeed(seed_x0, block),
                kRCX0RowBlockRows, params.d_model,
                dispatch, expanded)) {
            output.clear();
            return false;
        }
        std::copy(
            expanded.begin(), expanded.end(),
            output.begin() +
                static_cast<size_t>(block) *
                    kRCX0RowBlockRows * params.d_model);
    }
    return true;
}

/** P0.3: qualified device ExactGemm REPLACES CPU on the hot path.
 *  CPU runs only when no device backend, device declines/throws/wrong size, or
 *  BTX_RC_EXACT_GEMM_COMPARE=1 dispute mode (device then CPU compare; mismatch→CPU). */
bool ExactGemmS8S8Dispatched(RCGemmDispatch& dispatch, RCGemmPhase phase,
                             const std::vector<int8_t>& L,
                             const std::vector<int8_t>& R, uint32_t rows,
                             uint32_t inner, uint32_t cols,
                             std::vector<int32_t>& out)
{
    const uint64_t macs = GemmMacs(rows, inner, cols);
    const auto run_cpu = [&]() {
        return lt::ExactGemmS8S8(L, R, rows, inner, cols);
    };
    if (dispatch.gemm.gemm_s8s8 == nullptr) {
        if (dispatch.require_device) {
            RecordStrictDeviceFailure(dispatch, "required_device_backend_absent");
            out.clear();
            return false;
        }
        RecordCpuGemm(dispatch, macs, false, nullptr);
        out = run_cpu();
        return true;
    }

    std::vector<int32_t> device;
    bool device_ok = false;
    try {
        device_ok = dispatch.gemm.gemm_s8s8(L, R, rows, inner, cols, device) &&
                    device.size() == static_cast<size_t>(rows) * cols;
    } catch (...) {
        device_ok = false;
    }
    if (!device_ok) {
        if (dispatch.require_device) {
            RecordStrictDeviceFailure(
                dispatch, "device_exactgemm_declined_or_wrong_size");
            out.clear();
            return false;
        }
        RecordCpuGemm(
            dispatch, macs, true, "device_exactgemm_declined_or_wrong_size");
        out = run_cpu();
        return true;
    }

    static const bool compare =
        [] {
            const char* e = std::getenv("BTX_RC_EXACT_GEMM_COMPARE");
            return e != nullptr && e[0] == '1' && e[1] == '\0';
        }();
    if (compare) {
        const std::vector<int32_t> cpu = run_cpu();
        if (device != cpu) {
            if (dispatch.require_device) {
                RecordStrictDeviceFailure(
                    dispatch, "device_exactgemm_mismatch_vs_cpu");
                out.clear();
                return false;
            }
            RecordCpuGemm(
                dispatch, macs, true, "device_exactgemm_mismatch_vs_cpu");
            out = cpu;
            return true;
        }
    }
    RecordDeviceGemm(dispatch, phase, macs);
    out = std::move(device);
    return true;
}

/** G·Xᵀ without materializing Xᵀ over K-range [k0, k0+len): out[r][c] = Σ_t G[k0+t][r]·X[k0+t][c]. */
std::vector<int64_t> GemmGXtInt64Range(const std::vector<int8_t>& G, const std::vector<int8_t>& X,
                                       uint32_t k0, uint32_t len, uint32_t d_model)
{
    std::vector<int64_t> out(static_cast<size_t>(d_model) * d_model, 0);
    for (uint32_t r = 0; r < d_model; ++r) {
        for (uint32_t c = 0; c < d_model; ++c) {
            int64_t acc = 0;
            for (uint32_t t = 0; t < len; ++t) {
                const uint32_t k = k0 + t;
                acc += static_cast<int64_t>(G[static_cast<size_t>(k) * d_model + r]) *
                       static_cast<int64_t>(X[static_cast<size_t>(k) * d_model + c]);
            }
            out[static_cast<size_t>(r) * d_model + c] = acc;
        }
    }
    return out;
}

/** G·Xᵀ without materializing Xᵀ: out[r][c] = Σ_k G[k][r]·X[k][c]
 *  (wgrad D is d_model × d_model; contraction is b_seq). Bound may exceed 2^24
 *  → int64 oracle only in the episode path.
 *  Amendment 1.B: plain LT native FP4 (bounds <2^24) does NOT apply; future
 *  device MX must use Ozaki/limb split
 *  (doc/btx-matmul-v4.5-rc-native-fp4-ozaki-plan-2026-07-20.md,
 *  matmul_v4_rc_mx_ozaki.h) before any RC native_mxfp4_qualified flip. */
std::vector<int64_t> GemmGXtInt64(const std::vector<int8_t>& G, const std::vector<int8_t>& X,
                                  uint32_t b_seq, uint32_t d_model)
{
    assert(G.size() == static_cast<size_t>(b_seq) * d_model);
    assert(X.size() == static_cast<size_t>(b_seq) * d_model);
    return GemmGXtInt64Range(G, X, /*k0=*/0, b_seq, d_model);
}

/** Consensus-fixed kRCSegLen partition of wgrad: per-segment int64 partials + sum.
 *  ExtractMX is NOT applied here — caller Extracts once on the sum (H1).
 *  When keep_segs is false (PARKED segment leaves), only `total` is retained. */
struct SegmentedInt64Gemm {
    std::vector<int64_t> total;                 // sum of segs (same shape)
    std::vector<std::vector<int64_t>> segs;      // each same shape as total (optional)
};

SegmentedInt64Gemm AccumulateSegmentedGemmGXt(const std::vector<int8_t>& G,
                                              const std::vector<int8_t>& X, uint32_t b_seq,
                                              uint32_t d_model, bool keep_segs = true)
{
    assert(G.size() == static_cast<size_t>(b_seq) * d_model);
    assert(X.size() == static_cast<size_t>(b_seq) * d_model);
    SegmentedInt64Gemm out;
    const uint32_t n_seg = RCNumSegs(b_seq);
    if (keep_segs) out.segs.resize(n_seg);
    out.total.assign(static_cast<size_t>(d_model) * d_model, 0);
    for (uint32_t s = 0; s < n_seg; ++s) {
        const uint32_t k0 = s * kRCSegLen;
        const uint32_t len = std::min(kRCSegLen, b_seq - k0);
        auto partial = GemmGXtInt64Range(G, X, k0, len, d_model);
        for (size_t i = 0; i < out.total.size(); ++i) {
            out.total[i] += partial[i];
        }
        if (keep_segs) {
            out.segs[s] = std::move(partial);
        }
    }
    return out;
}

/** Chunked ExactGemm wgrad: split K=b_seq into panels with 2304·chunk < 2^24,
 *  run ExactGemmS8S8(Gᵀ_chunk, X_chunk) → int32, accumulate into int64.
 *  Byte-identical to GemmGXtInt64. */
std::vector<int64_t> GemmGXtViaChunkedExact(const std::vector<int8_t>& G,
                                            const std::vector<int8_t>& X, uint32_t b_seq,
                                            uint32_t d_model, const lt::ExactGemmBackend& gemm)
{
    assert(G.size() == static_cast<size_t>(b_seq) * d_model);
    assert(X.size() == static_cast<size_t>(b_seq) * d_model);
    std::vector<int64_t> out(static_cast<size_t>(d_model) * d_model, 0);

    for (uint32_t k0 = 0; k0 < b_seq; k0 += kRCWgradExactChunk) {
        const uint32_t len = std::min(kRCWgradExactChunk, b_seq - k0);
        // L[r][t] = G[k0+t][r]  (d_model × len) — Gᵀ panel
        // R[t][c] = X[k0+t][c]  (len × d_model)
        std::vector<int8_t> L(static_cast<size_t>(d_model) * len);
        std::vector<int8_t> R(static_cast<size_t>(len) * d_model);
        for (uint32_t t = 0; t < len; ++t) {
            const uint32_t k = k0 + t;
            for (uint32_t r = 0; r < d_model; ++r) {
                L[static_cast<size_t>(r) * len + t] =
                    G[static_cast<size_t>(k) * d_model + r];
            }
            for (uint32_t c = 0; c < d_model; ++c) {
                R[static_cast<size_t>(t) * d_model + c] =
                    X[static_cast<size_t>(k) * d_model + c];
            }
        }
        RCGemmDispatch dispatch{gemm};
        std::vector<int32_t> partial;
        if (!ExactGemmS8S8Dispatched(
                dispatch, RCGemmPhase::Phase2, L, R, d_model, len, d_model, partial)) {
            return {};
        }
        for (size_t i = 0; i < out.size(); ++i) {
            out[i] += static_cast<int64_t>(partial[i]);
        }
    }
    return out;
}

// --- Phase 1 ---------------------------------------------------------------
// Phase-1 Z=S·V bound is 2304·n_ctx ≫ 2^24 (~2^30.76 at consensus n_ctx) —
// streamed int64 only in reference. Plain native FP4 (LT 5090 / <2^24 qual)
// does NOT carry here (Amendment 1.B).
// Optional ExactGemmS32S8ViaRadix256 is not used here; miners may limb-promote
// offline but must match this int64 stream byte-for-byte. Device MXFP4 for Z
// requires Ozaki/limb split with partials <2^24 + exact integer recombine —
// see doc/btx-matmul-v4.5-rc-native-fp4-ozaki-plan-2026-07-20.md and
// matmul_v4_rc_mx_ozaki.h (TryRcOzakiMxfp4* fail-closed until qualified).
//
// Consensus-fixed kRCSegLen segments commit exact int64 Z partials; ExtractMX
// fires once on Σ partials (H1). kRCSegLen % 32 == 0 ⇒ segments align to MX
// block boundaries.
//
// MX layout (P1.2): Q·Kᵀ is row-block–correct on d_head; S·V needs col-block V
// for native MX (see doc/btx-matmul-v4.5-rc-mx-contraction-layouts-p1.2.md).
// Oracle still ExpandMxDequantInt8 (row-block) + dense int8 · V.

struct Phase1Result {
    bool ok{true};
    std::vector<int8_t> Z;                      // n_q × d_head after one ExtractMX
    /** Per-segment int64 partials; empty when kRCSegmentLeavesEnabled is false. */
    std::vector<std::vector<int64_t>> z_segs;    // each n_q × d_head int64 partial
};

bool Phase1AssociativeRecallExactGemm(
    const std::vector<int8_t>& Q, const std::vector<int8_t>& K,
    const std::vector<int8_t>& V, const RCEpisodeParams& p,
    const uint256& prf_S, const uint256& prf_Z, uint32_t round_ordinal,
    RCEpisodeProofWitnessSink* proof_sink, RCGemmDispatch& dispatch,
    Phase1Result& out)
{
    // Keep each int32 panel below 2304*K < 2^24 and align context panels to
    // ExtractMX's 32-column blocks. Q*K^T only contracts d_head; S*V uses the
    // same fixed 4096 context panels and exact int64 recombination.
    constexpr uint32_t kContextPanel = kRCWgradExactChunk;
    static_assert((kContextPanel % kRCMxBlockLen) == 0);

    constexpr bool keep_segs = kRCSegmentLeavesEnabled;
    if constexpr (!keep_segs) {
        if (proof_sink == nullptr && dispatch.gemm.rc_phase1 != nullptr) {
            bool fused_ok = false;
            try {
                fused_ok = dispatch.gemm.rc_phase1(
                    Q, K, V, prf_S, prf_Z,
                    p.n_q, p.n_ctx, p.d_head, out.Z);
            } catch (...) {
                fused_ok = false;
            }
            if (fused_ok &&
                out.Z.size() == static_cast<size_t>(p.n_q) * p.d_head) {
                const uint64_t projection_macs =
                    GemmMacs(p.n_q, p.n_ctx, p.d_head);
                RecordDeviceGemm(
                    dispatch, RCGemmPhase::Phase1, projection_macs);
                RecordDeviceGemm(
                    dispatch, RCGemmPhase::Phase1, projection_macs);
                if (dispatch.stats != nullptr) {
                    ++dispatch.stats->device_fused_phase1_calls;
                    dispatch.stats->device_extract_elements +=
                        static_cast<uint64_t>(p.n_q) *
                        (p.n_ctx + p.d_head);
                    dispatch.stats->phase1_extract_on_device = true;
                }
                return true;
            }
            out.Z.assign(static_cast<size_t>(p.n_q) * p.d_head, 0);
            if (dispatch.require_device) {
                RecordStrictDeviceFailure(
                    dispatch, "device_fused_phase1_declined_or_wrong_size");
                return false;
            }
        }
    }

    if (proof_sink == nullptr) {
        // Verification does not need row-owned proof views. Batch all production
        // query rows (capped to bound scratch if a future profile grows n_q):
        //   * transpose each K panel once per batch,
        //   * launch Q_batch·K_panel^T as one MPP operation,
        //   * launch S_batch_panel·V_panel as one MPP operation.
        // At the epoch-0 n_q=512 this reduces Phase-1 command buffers from
        // 196,608 per round to 384 while retaining exact panel boundaries and
        // int64 S·V recombination. The largest added S scratch is ~384 MiB.
        constexpr uint32_t kQueryBatch = 512;
        for (uint32_t q0 = 0; q0 < p.n_q; q0 += kQueryBatch) {
            const uint32_t q_rows = std::min(kQueryBatch, p.n_q - q0);
            std::vector<int8_t> q_panel(
                Q.begin() + static_cast<size_t>(q0) * p.d_head,
                Q.begin() + static_cast<size_t>(q0 + q_rows) * p.d_head);
            std::vector<int8_t> s_batch(
                static_cast<size_t>(q_rows) * p.n_ctx);

            for (uint32_t t0 = 0; t0 < p.n_ctx; t0 += kContextPanel) {
                const uint32_t len = std::min(kContextPanel, p.n_ctx - t0);
                std::vector<int8_t> k_transposed(
                    static_cast<size_t>(p.d_head) * len);
                for (uint32_t d = 0; d < p.d_head; ++d) {
                    for (uint32_t t = 0; t < len; ++t) {
                        k_transposed[static_cast<size_t>(d) * len + t] =
                            K[static_cast<size_t>(t0 + t) * p.d_head + d];
                    }
                }
                std::vector<int32_t> raw;
                if (!ExactGemmS8S8Dispatched(
                        dispatch, RCGemmPhase::Phase1, q_panel, k_transposed,
                        q_rows, p.d_head, len, raw)) {
                    return false;
                }
                for (uint32_t local_q = 0; local_q < q_rows; ++local_q) {
                    for (uint32_t off = 0; off < len; off += kRCMxBlockLen) {
                        int64_t raw64[kRCMxBlockLen];
                        for (uint32_t x = 0; x < kRCMxBlockLen; ++x) {
                            raw64[x] =
                                raw[static_cast<size_t>(local_q) * len + off + x];
                        }
                        const uint32_t context_begin = t0 + off;
                        ExtractMXTileInt64(
                            prf_S, q0 + local_q,
                            context_begin / kRCMxBlockLen, raw64,
                            s_batch.data() +
                                static_cast<size_t>(local_q) * p.n_ctx +
                                context_begin);
                    }
                }
            }

            std::vector<int64_t> acc_z(
                static_cast<size_t>(q_rows) * p.d_head, 0);
            for (uint32_t k0 = 0; k0 < p.n_ctx;) {
                const uint32_t seg = k0 / kRCSegLen;
                const uint32_t seg_end =
                    std::min(p.n_ctx, (seg + 1) * kRCSegLen);
                const uint32_t len =
                    std::min(kContextPanel, seg_end - k0);
                std::vector<int8_t> s_panel(
                    static_cast<size_t>(q_rows) * len);
                for (uint32_t local_q = 0; local_q < q_rows; ++local_q) {
                    std::copy_n(
                        s_batch.begin() +
                            static_cast<size_t>(local_q) * p.n_ctx + k0,
                        len,
                        s_panel.begin() + static_cast<size_t>(local_q) * len);
                }
                std::vector<int8_t> v_panel(
                    V.begin() + static_cast<size_t>(k0) * p.d_head,
                    V.begin() + static_cast<size_t>(k0 + len) * p.d_head);
                std::vector<int32_t> partial;
                if (!ExactGemmS8S8Dispatched(
                        dispatch, RCGemmPhase::Phase1, s_panel, v_panel,
                        q_rows, len, p.d_head, partial)) {
                    return false;
                }
                for (uint32_t local_q = 0; local_q < q_rows; ++local_q) {
                    for (uint32_t d = 0; d < p.d_head; ++d) {
                        const int64_t value =
                            partial[static_cast<size_t>(local_q) * p.d_head + d];
                        acc_z[static_cast<size_t>(local_q) * p.d_head + d] += value;
                        if constexpr (keep_segs) {
                            out.z_segs[seg][
                                static_cast<size_t>(q0 + local_q) * p.d_head + d] += value;
                        }
                    }
                }
                k0 += len;
            }

            const uint32_t nblk = p.d_head / kRCMxBlockLen;
            for (uint32_t local_q = 0; local_q < q_rows; ++local_q) {
                for (uint32_t bj = 0; bj < nblk; ++bj) {
                    ExtractMXTileInt64(
                        prf_Z, q0 + local_q, bj,
                        acc_z.data() +
                            static_cast<size_t>(local_q) * p.d_head +
                            bj * kRCMxBlockLen,
                        out.Z.data() +
                            static_cast<size_t>(q0 + local_q) * p.d_head +
                            bj * kRCMxBlockLen);
                }
            }
        }
        return true;
    }

    for (uint32_t i = 0; i < p.n_q; ++i) {
        if (ExactReplayCancellationRequested()) return false;
        std::vector<int8_t> s_row(p.n_ctx);
        std::vector<int8_t> q_row(
            Q.begin() + static_cast<size_t>(i) * p.d_head,
            Q.begin() + static_cast<size_t>(i + 1) * p.d_head);

        // Q[i,:] * K^T in context panels. Transpose only the current panel so
        // peak host scratch stays bounded on 36 GiB unified-memory machines.
        for (uint32_t t0 = 0; t0 < p.n_ctx; t0 += kContextPanel) {
            const uint32_t len = std::min(kContextPanel, p.n_ctx - t0);
            std::vector<int8_t> k_transposed(static_cast<size_t>(p.d_head) * len);
            for (uint32_t d = 0; d < p.d_head; ++d) {
                for (uint32_t t = 0; t < len; ++t) {
                    k_transposed[static_cast<size_t>(d) * len + t] =
                        K[static_cast<size_t>(t0 + t) * p.d_head + d];
                }
            }
            std::vector<int32_t> raw;
            if (!ExactGemmS8S8Dispatched(
                    dispatch, RCGemmPhase::Phase1, q_row, k_transposed,
                    /*rows=*/1, p.d_head, len, raw)) {
                return false;
            }
            for (uint32_t off = 0; off < len; off += kRCMxBlockLen) {
                int64_t raw64[kRCMxBlockLen];
                for (uint32_t x = 0; x < kRCMxBlockLen; ++x) {
                    raw64[x] = raw[off + x];
                }
                const uint32_t context_begin = t0 + off;
                const uint32_t block = context_begin / kRCMxBlockLen;
                ExtractMXTileInt64(
                    prf_S, i, block, raw64, s_row.data() + context_begin);
                if (proof_sink != nullptr) {
                    proof_sink->OnPhase1QKtTile({
                        .round_ordinal = round_ordinal,
                        .query_row = i,
                        .context_begin = context_begin,
                        .tile_len = kRCMxBlockLen,
                        .contraction_size = p.d_head,
                        .operand_a = q_row.data(),
                        .operand_b =
                            K.data() + static_cast<size_t>(context_begin) * p.d_head,
                        .gemm_y = raw64,
                        .extract_output = s_row.data() + context_begin,
                        .prf_key = prf_S,
                    });
                }
            }
        }

        std::vector<int64_t> acc_Z(p.d_head, 0);
        for (uint32_t k0 = 0; k0 < p.n_ctx;) {
            const uint32_t seg = k0 / kRCSegLen;
            const uint32_t seg_end = std::min(p.n_ctx, (seg + 1) * kRCSegLen);
            const uint32_t len = std::min(kContextPanel, seg_end - k0);
            std::vector<int8_t> s_panel(
                s_row.begin() + k0, s_row.begin() + k0 + len);
            std::vector<int8_t> v_panel(
                V.begin() + static_cast<size_t>(k0) * p.d_head,
                V.begin() + static_cast<size_t>(k0 + len) * p.d_head);
            std::vector<int32_t> partial;
            if (!ExactGemmS8S8Dispatched(
                    dispatch, RCGemmPhase::Phase1, s_panel, v_panel,
                    /*rows=*/1, len, p.d_head, partial)) {
                return false;
            }
            for (uint32_t d = 0; d < p.d_head; ++d) {
                const int64_t value = partial[d];
                acc_Z[d] += value;
                if constexpr (keep_segs) {
                    out.z_segs[seg][static_cast<size_t>(i) * p.d_head + d] += value;
                }
            }
            k0 += len;
        }

        const uint32_t nblk = p.d_head / kRCMxBlockLen;
        for (uint32_t bj = 0; bj < nblk; ++bj) {
            ExtractMXTileInt64(
                prf_Z, i, bj, acc_Z.data() + bj * kRCMxBlockLen,
                out.Z.data() + static_cast<size_t>(i) * p.d_head +
                    bj * kRCMxBlockLen);
        }
        if (proof_sink != nullptr) {
            proof_sink->OnPhase1SVRow({
                .round_ordinal = round_ordinal,
                .query_row = i,
                .n_ctx = p.n_ctx,
                .d_head = p.d_head,
                .operand_a = s_row.data(),
                .operand_b = V.data(),
                .gemm_y = acc_Z.data(),
                .extract_output =
                    out.Z.data() + static_cast<size_t>(i) * p.d_head,
                .prf_key = prf_Z,
            });
        }
    }
    return true;
}

Phase1Result Phase1AssociativeRecall(const uint256& seed_r, const uint256& sigma,
                                     const RCEpisodeParams& p, uint32_t tile_delta,
                                     RCGemmDispatch& dispatch,
                                     uint32_t round_ordinal = 0,
                                     RCEpisodeProofWitnessSink* proof_sink = nullptr)
{
    // Q is per-round (freshness source that keeps each round's attention distinct).
    // K, V: DATACENTER shares them EPISODE-WIDE (sigma-derived) so the sublinear
    // verifier regenerates them once, not per round — safe since fresh Q_r ⇒ fresh Z_r.
    // BASE keeps K, V per-round (seed_r) so its goldens are untouched. Gated by the same
    // predicate as the FFN weight / X0 sharing.
    const bool share_ep = UseDatacenterSharedFfnWeights(p);
    const uint256 seed_Q = DeriveOperandSeed(seed_r, "BTX_RC_Q_V1");
    const uint256 seed_K = DeriveOperandSeed(share_ep ? sigma : seed_r, "BTX_RC_KV_K_V1");
    const uint256 seed_V = DeriveOperandSeed(share_ep ? sigma : seed_r, "BTX_RC_KV_V_V1");
    const uint256 seed_prf_S = DeriveOperandSeed(seed_r, "BTX_RC_PRF_S_V1");
    const uint256 seed_prf_Z = DeriveOperandSeed(seed_r, "BTX_RC_PRF_Z_V1");
    const uint256 prf_S = lt::DeriveMatExpandPrfKey(seed_prf_S);
    const uint256 prf_Z = lt::DeriveMatExpandPrfKey(seed_prf_Z);

    std::vector<int8_t> Q;
    std::vector<int8_t> K;
    std::vector<int8_t> V;
    Phase1Result out;
    const bool try_seeded =
        proof_sink == nullptr && !kRCSegmentLeavesEnabled &&
        dispatch.gemm.rc_phase1_seeded != nullptr &&
        SeededProfile1LaneEligible(p, dispatch);
    if (try_seeded) {
        const auto seeded_start{
            std::chrono::steady_clock::now()};
        bool seeded_ok{false};
        try {
            seeded_ok = dispatch.gemm.rc_phase1_seeded(
                seed_Q, seed_K, seed_V, prf_S, prf_Z,
                p.n_q, p.n_ctx, p.d_head, out.Z);
        } catch (...) {
            seeded_ok = false;
        }
        if (seeded_ok &&
            out.Z.size() == static_cast<size_t>(p.n_q) * p.d_head) {
            const uint64_t projection_macs{
                GemmMacs(p.n_q, p.n_ctx, p.d_head)};
            RecordDeviceGemm(dispatch, RCGemmPhase::Phase1,
                             projection_macs);
            RecordDeviceGemm(dispatch, RCGemmPhase::Phase1,
                             projection_macs);
            RecordDeviceXof(
                dispatch,
                static_cast<uint64_t>(p.n_q) * p.d_head +
                    2ull * p.n_ctx * p.d_head,
                /*calls=*/3,
                std::chrono::steady_clock::now() - seeded_start);
            if (dispatch.stats != nullptr) {
                ++dispatch.stats->device_fused_phase1_calls;
                dispatch.stats->device_extract_elements +=
                    static_cast<uint64_t>(p.n_q) *
                    (p.n_ctx + p.d_head);
                dispatch.stats->phase1_extract_on_device = true;
            }
            return out;
        }
        out.Z.clear();
        // The established device-input lane remains a valid same-provider
        // recovery path. In non-strict mode it may ultimately reach the host;
        // in strict mode ExpandMxDispatched/Phase1 enforce no CPU fallback.
        RecordDeviceXofLaneFailure(
            dispatch,
            static_cast<uint64_t>(p.n_q) * p.d_head +
                2ull * p.n_ctx * p.d_head,
            /*calls=*/3,
            std::chrono::steady_clock::now() - seeded_start,
            "device_seeded_phase1_declined_or_wrong_size");
        if (dispatch.require_device) {
            RecordStrictDeviceFailure(
                dispatch,
                "device_seeded_phase1_declined_or_wrong_size");
            out.ok = false;
            return out;
        }
    }
    if (!ExpandMxDispatched(
            seed_Q, p.n_q, p.d_head, dispatch, Q) ||
        !ExpandMxDispatched(
            seed_K, p.n_ctx, p.d_head, dispatch, K) ||
        !ExpandMxDispatched(
            seed_V, p.n_ctx, p.d_head, dispatch, V)) {
        out.ok = false;
        return out;
    }
    if (proof_sink != nullptr) {
        proof_sink->OnPhase1Operands({
            .round_ordinal = round_ordinal,
            .n_q = p.n_q,
            .n_ctx = p.n_ctx,
            .d_head = p.d_head,
            .q = &Q,
            .k = &K,
            .v = &V,
        });
    }

    // Any positive ΔT partitioning [0,n_ctx) is allowed (§R.2.2). Incomplete
    // MX 32-blocks are held in a pending buffer across tile windows so Extract
    // always fires on bj = ⌊t/32⌋ boundaries (n_ctx % 32 == 0 by construction).
    const uint32_t delta = tile_delta == 0 ? p.n_ctx : tile_delta;
    assert(delta > 0);
    assert(p.n_ctx % kRCMxBlockLen == 0);
    assert((kRCSegLen % kRCMxBlockLen) == 0);

    const uint32_t n_seg = RCNumSegs(p.n_ctx);
    constexpr bool keep_segs = kRCSegmentLeavesEnabled;
    if constexpr (keep_segs) {
        out.z_segs.resize(n_seg);
        for (uint32_t s = 0; s < n_seg; ++s) {
            out.z_segs[s].assign(static_cast<size_t>(p.n_q) * p.d_head, 0);
        }
    }
    out.Z.assign(static_cast<size_t>(p.n_q) * p.d_head, 0);

    if (dispatch.gemm.gemm_s8s8 != nullptr || dispatch.require_device) {
        out.ok = Phase1AssociativeRecallExactGemm(
            Q, K, V, p, prf_S, prf_Z, round_ordinal, proof_sink, dispatch, out);
        return out;
    }

    for (uint32_t i = 0; i < p.n_q; ++i) {
        if (ExactReplayCancellationRequested()) {
            out.ok = false;
            return out;
        }
        int64_t pending_raw[kRCMxBlockLen];
        uint32_t pending_fill = 0;
        uint32_t pending_bj = 0;
        uint32_t block_t0 = 0; // first t of the MX block being filled
        // The proof sink needs the literal S row as the A operand of S*V.
        // Consensus execution still avoids this allocation when no prover is
        // attached.
        std::vector<int8_t> proof_s_row(
            proof_sink == nullptr ? 0 : p.n_ctx);
        uint32_t cur_seg = 0;
        std::vector<int64_t> seg_row(p.d_head, 0);
        // Running sum of segment rows for the single Extract (H1) when segs
        // are not retained.
        std::vector<int64_t> acc_Z(p.d_head, 0);

        auto flush_s_block = [&]() {
            assert(pending_fill == kRCMxBlockLen);
            int8_t S_tile[kRCMxBlockLen];
            ExtractMXTileInt64(prf_S, i, pending_bj, pending_raw, S_tile);
            if (proof_sink != nullptr) {
                proof_sink->OnPhase1QKtTile({
                    .round_ordinal = round_ordinal,
                    .query_row = i,
                    .context_begin = block_t0,
                    .tile_len = kRCMxBlockLen,
                    .contraction_size = p.d_head,
                    .operand_a =
                        Q.data() +
                        static_cast<size_t>(i) * p.d_head,
                    .operand_b =
                        K.data() +
                        static_cast<size_t>(block_t0) *
                            p.d_head,
                    .gemm_y = pending_raw,
                    .extract_output = S_tile,
                    .prf_key = prf_S,
                });
            }
            for (uint32_t t_off = 0; t_off < kRCMxBlockLen; ++t_off) {
                const uint32_t t = block_t0 + t_off;
                const uint32_t seg = t / kRCSegLen;
                if (seg != cur_seg) {
                    // Commit finished segment row (kRCSegLen % 32 == 0 ⇒ aligned).
                    if constexpr (keep_segs) {
                        for (uint32_t d = 0; d < p.d_head; ++d) {
                            out.z_segs[cur_seg][static_cast<size_t>(i) * p.d_head + d] =
                                seg_row[d];
                        }
                    } else {
                        for (uint32_t d = 0; d < p.d_head; ++d) acc_Z[d] += seg_row[d];
                    }
                    std::fill(seg_row.begin(), seg_row.end(), 0);
                    cur_seg = seg;
                }
                const int8_t s = S_tile[t_off];
                if (proof_sink != nullptr) {
                    proof_s_row[t] = s;
                }
                for (uint32_t d = 0; d < p.d_head; ++d) {
                    seg_row[d] += static_cast<int64_t>(s) *
                                  static_cast<int64_t>(V[static_cast<size_t>(t) * p.d_head + d]);
                }
            }
            pending_fill = 0;
            ++pending_bj;
            block_t0 += kRCMxBlockLen;
        };

        for (uint32_t t0 = 0; t0 < p.n_ctx; t0 += delta) {
            const uint32_t t1 = std::min(t0 + delta, p.n_ctx);
            for (uint32_t t = t0; t < t1; ++t) {
                int64_t acc = 0;
                for (uint32_t d = 0; d < p.d_head; ++d) {
                    acc += static_cast<int64_t>(Q[static_cast<size_t>(i) * p.d_head + d]) *
                           static_cast<int64_t>(K[static_cast<size_t>(t) * p.d_head + d]);
                }
                pending_raw[pending_fill++] = acc;
                if (pending_fill == kRCMxBlockLen) flush_s_block();
            }
        }
        assert(pending_fill == 0);
        // Commit final segment row.
        if constexpr (keep_segs) {
            for (uint32_t d = 0; d < p.d_head; ++d) {
                out.z_segs[cur_seg][static_cast<size_t>(i) * p.d_head + d] = seg_row[d];
            }
            // One ExtractMX on sum of Z segs (P0.5 int64, no int32 narrow).
            for (uint32_t s = 0; s < n_seg; ++s) {
                for (uint32_t d = 0; d < p.d_head; ++d) {
                    acc_Z[d] += out.z_segs[s][static_cast<size_t>(i) * p.d_head + d];
                }
            }
        } else {
            for (uint32_t d = 0; d < p.d_head; ++d) acc_Z[d] += seg_row[d];
        }

        const uint32_t nblk = p.d_head / kRCMxBlockLen;
        for (uint32_t bj = 0; bj < nblk; ++bj) {
            ExtractMXTileInt64(prf_Z, i, bj, acc_Z.data() + bj * kRCMxBlockLen,
                               out.Z.data() + static_cast<size_t>(i) * p.d_head +
                                   bj * kRCMxBlockLen);
        }
        if (proof_sink != nullptr) {
            proof_sink->OnPhase1SVRow({
                .round_ordinal = round_ordinal,
                .query_row = i,
                .n_ctx = p.n_ctx,
                .d_head = p.d_head,
                .operand_a = proof_s_row.data(),
                .operand_b = V.data(),
                .gemm_y = acc_Z.data(),
                .extract_output =
                    out.Z.data() +
                    static_cast<size_t>(i) * p.d_head,
                .prf_key = prf_Z,
            });
        }
    }
    return out;
}

// --- Phase 2 ---------------------------------------------------------------
// MX layout (P1.2): forward X·Wᵀ is contraction-correct after Wᵀ (row-block W).
// Backward G·W and wgrad Gᵀ·X need col-block scales on W / batch — packed
// helpers in matmul_v4_rc_mx_layout.*; oracle stays dequant int8 ExactGemm.

struct Phase2Tensors {
    bool ok{true};
    std::vector<std::vector<int8_t>> X; // X[0..L] — fused-FFN layer activations
    /** Fused-FFN weights + PRF keys retained so checkpointed X can be recomputed
     *  during streaming serialization without a full StoreAll rebuild. W_up is
     *  d_model×d_ff, W_down is d_ff×d_model. The intermediate H (b_seq×d_ff) is
     *  NEVER stored/committed — each layer recomputes it internally. */
    bool ffn_weights_shared{false};
    std::vector<int8_t> W_up_shared;
    std::vector<int8_t> W_down_shared;
    std::vector<std::vector<int8_t>> W_up_layers;
    std::vector<std::vector<int8_t>> W_down_layers;
    std::vector<uint256> prf_up;
    std::vector<uint256> prf_dn;
};

/** Exact int8·int8 → int64 GEMM: out[m×n] = A[m×k]·B[k×n]. Contraction k is split
 *  into fixed panels with 2304·chunk < 2^24 (kRCWgradExactChunk) so each panel is
 *  ExactGemm-exact on any FP32 accelerator; int64 accumulation of the exact int32
 *  panels is byte-identical to a pure int64 dot (GKR's ExactInt64Gemm). Used by
 *  the fused-FFN up (k=d_model) and down (k=d_ff>2^24 ceiling) GEMMs alike. */
bool FusedExactGemmInt64(const std::vector<int8_t>& A, uint32_t m, uint32_t k,
                         const std::vector<int8_t>& B, uint32_t n,
                         RCGemmDispatch& dispatch, std::vector<int64_t>& out)
{
    assert(A.size() == static_cast<size_t>(m) * k);
    assert(B.size() == static_cast<size_t>(k) * n);
    out.assign(static_cast<size_t>(m) * n, 0);
    for (uint32_t k0 = 0; k0 < k; k0 += kRCWgradExactChunk) {
        const uint32_t len = std::min(kRCWgradExactChunk, k - k0);
        std::vector<int8_t> a_panel;
        std::vector<int8_t> b_panel;
        const std::vector<int8_t>* ap = &A;
        const std::vector<int8_t>* bp = &B;
        if (k0 != 0 || len != k) {
            a_panel.resize(static_cast<size_t>(m) * len);
            b_panel.resize(static_cast<size_t>(len) * n);
            for (uint32_t i = 0; i < m; ++i) {
                for (uint32_t t = 0; t < len; ++t) {
                    a_panel[static_cast<size_t>(i) * len + t] =
                        A[static_cast<size_t>(i) * k + (k0 + t)];
                }
            }
            std::copy(
                B.begin() + static_cast<size_t>(k0) * n,
                B.begin() + static_cast<size_t>(k0 + len) * n,
                b_panel.begin());
            ap = &a_panel;
            bp = &b_panel;
        }
        std::vector<int32_t> partial;
        if (!ExactGemmS8S8Dispatched(
                dispatch, RCGemmPhase::Phase2, *ap, *bp, m, len, n, partial)) {
            out.clear();
            return false;
        }
        for (size_t i = 0; i < out.size(); ++i) out[i] += static_cast<int64_t>(partial[i]);
    }
    return true;
}

void ExtractMXMatrixInt64Rows(const uint256& prf_key, const int64_t* input,
                              uint32_t row_begin, uint32_t rows, uint32_t columns,
                              int8_t* output)
{
    assert(columns % kRCMxBlockLen == 0);
    const uint32_t nblk = columns / kRCMxBlockLen;
    for (uint32_t local_row = 0; local_row < rows; ++local_row) {
        for (uint32_t bj = 0; bj < nblk; ++bj) {
            const size_t base =
                static_cast<size_t>(local_row) * columns + bj * kRCMxBlockLen;
            ExtractMXTileInt64(
                prf_key, row_begin + local_row, bj, input + base, output + base);
        }
    }
}

/** One fused 2-layer FFN (scratchpad/fused-ffn-episode-design.md):
 *    H     = Extract(X·W_up)            [b_seq×d_ff]  — INTERNAL (not committed)
 *    X_out = Extract(H·W_down + X)      [b_seq×d_model] — committed (residual +X, H5)
 *  Only X_out is streamed into the round tile-tree; H is recomputed by the sampled
 *  verifier from anchored X and the PRF weights. W_up is d_model×d_ff, W_down is
 *  d_ff×d_model (both natural contraction-major, no transpose). */
bool FusedFfnLayer(const std::vector<int8_t>& X, const std::vector<int8_t>& W_up,
                   const std::vector<int8_t>& W_down, const uint256& prf_up,
                   const uint256& prf_dn, uint32_t b_seq, uint32_t d_model,
                   uint32_t d_ff, RCGemmDispatch& dispatch,
                   uint32_t round_ordinal, uint32_t layer_ordinal,
                   RCEpisodeProofWitnessSink* proof_sink,
                   std::vector<int8_t>& out,
                   uint32_t row_begin = 0)
{
    if (proof_sink == nullptr && dispatch.gemm.rc_fused_ffn != nullptr) {
        if (ExactReplayCancellationRequested()) {
            out.clear();
            return false;
        }
        bool fused_ok = false;
        try {
            fused_ok = dispatch.gemm.rc_fused_ffn(
                X, W_up, W_down, prf_up, prf_dn,
                row_begin, b_seq, d_model, d_ff, out);
        } catch (...) {
            fused_ok = false;
        }
        if (fused_ok &&
            out.size() == static_cast<size_t>(b_seq) * d_model) {
            const uint64_t projection_macs =
                GemmMacs(b_seq, d_model, d_ff);
            RecordDeviceGemm(
                dispatch, RCGemmPhase::Phase2, projection_macs);
            RecordDeviceGemm(
                dispatch, RCGemmPhase::Phase2, projection_macs);
            if (dispatch.stats != nullptr) {
                ++dispatch.stats->device_fused_ffn_calls;
                dispatch.stats->device_extract_elements +=
                    static_cast<uint64_t>(b_seq) * (d_ff + d_model);
                dispatch.stats->phase2_extract_on_device = true;
            }
            return true;
        }
        out.clear();
        if (dispatch.require_device) {
            RecordStrictDeviceFailure(
                dispatch, "device_fused_ffn_declined_or_wrong_size");
            return false;
        }
        // Consensus validation remains fail-safe: if the optional fused lane
        // declines, compose the already-qualified ExactGemm callbacks below.
    }

    const uint32_t requested_tile =
        dispatch.output_row_tile == 0 ? 256u : dispatch.output_row_tile;
    const bool use_tiled_device =
        proof_sink == nullptr && dispatch.gemm.gemm_s8s8 != nullptr &&
        requested_tile < b_seq;

    if (use_tiled_device) {
        // ExactReplay does not need proof-owned whole-matrix int64 witnesses.
        // Tile output rows so M4 unified-memory scratch is bounded: production
        // up-projection scratch falls from multi-GiB to tens of MiB.
        std::vector<int8_t> H(static_cast<size_t>(b_seq) * d_ff);
        for (uint32_t row0 = 0; row0 < b_seq; row0 += requested_tile) {
            if (ExactReplayCancellationRequested()) {
                out.clear();
                return false;
            }
            const uint32_t rows = std::min(requested_tile, b_seq - row0);
            std::vector<int8_t> x_tile(
                X.begin() + static_cast<size_t>(row0) * d_model,
                X.begin() + static_cast<size_t>(row0 + rows) * d_model);
            std::vector<int64_t> h64;
            if (!FusedExactGemmInt64(
                    x_tile, rows, d_model, W_up, d_ff, dispatch, h64)) {
                out.clear();
                return false;
            }
            ExtractMXMatrixInt64Rows(
                prf_up, h64.data(), row_begin + row0, rows, d_ff,
                H.data() + static_cast<size_t>(row0) * d_ff);
        }

        out.resize(static_cast<size_t>(b_seq) * d_model);
        for (uint32_t row0 = 0; row0 < b_seq; row0 += requested_tile) {
            if (ExactReplayCancellationRequested()) {
                out.clear();
                return false;
            }
            const uint32_t rows = std::min(requested_tile, b_seq - row0);
            std::vector<int8_t> h_tile(
                H.begin() + static_cast<size_t>(row0) * d_ff,
                H.begin() + static_cast<size_t>(row0 + rows) * d_ff);
            std::vector<int64_t> y64;
            if (!FusedExactGemmInt64(
                    h_tile, rows, d_ff, W_down, d_model, dispatch, y64)) {
                out.clear();
                return false;
            }
            for (uint32_t i = 0; i < rows; ++i) {
                for (uint32_t j = 0; j < d_model; ++j) {
                    y64[static_cast<size_t>(i) * d_model + j] +=
                        static_cast<int64_t>(
                            X[static_cast<size_t>(row0 + i) * d_model + j]);
                }
            }
            ExtractMXMatrixInt64Rows(
                prf_dn, y64.data(), row_begin + row0, rows, d_model,
                out.data() + static_cast<size_t>(row0) * d_model);
        }
        return true;
    }

    // Up projection: H = Extract(X·W_up), contraction over d_model.
    std::vector<int64_t> h64;
    if (!FusedExactGemmInt64(X, b_seq, d_model, W_up, d_ff, dispatch, h64)) {
        out.clear();
        return false;
    }
    if (proof_sink != nullptr) {
        proof_sink->OnFfnGemm({
            .round_ordinal = round_ordinal,
            .layer_ordinal = layer_ordinal,
            .projection = RCFfnProjection::Up,
            .m = b_seq,
            .k = d_model,
            .n = d_ff,
            .operand_a = &X,
            .operand_b = &W_up,
            .gemm_y = &h64,
            .residual = nullptr,
        });
    }
    std::vector<int8_t> H(h64.size());
    ExtractMXMatrixInt64Rows(
        prf_up, h64.data(), row_begin, b_seq, d_ff, H.data());
    if (proof_sink != nullptr) {
        proof_sink->OnFfnExtract({
            .round_ordinal = round_ordinal,
            .layer_ordinal = layer_ordinal,
            .projection = RCFfnProjection::Up,
            .rows = b_seq,
            .columns = d_ff,
            .input = &h64,
            .output = &H,
            .residual = nullptr,
            .prf_key = prf_up,
        });
    }
    std::vector<int64_t>().swap(h64);
    // Down projection: X_out = Extract(H·W_down + X), contraction over d_ff, residual
    // +X folded INSIDE the single Extract accumulator (H5).
    std::vector<int64_t> y64;
    if (!FusedExactGemmInt64(H, b_seq, d_ff, W_down, d_model, dispatch, y64)) {
        out.clear();
        return false;
    }
    if (proof_sink != nullptr) {
        proof_sink->OnFfnGemm({
            .round_ordinal = round_ordinal,
            .layer_ordinal = layer_ordinal,
            .projection = RCFfnProjection::Down,
            .m = b_seq,
            .k = d_ff,
            .n = d_model,
            .operand_a = &H,
            .operand_b = &W_down,
            .gemm_y = &y64,
            .residual = &X,
        });
    }
    for (uint32_t i = 0; i < b_seq; ++i)
        for (uint32_t j = 0; j < d_model; ++j)
            y64[static_cast<size_t>(i) * d_model + j] +=
                static_cast<int64_t>(X[static_cast<size_t>(i) * d_model + j]);
    out.resize(y64.size());
    ExtractMXMatrixInt64Rows(
        prf_dn, y64.data(), row_begin, b_seq, d_model, out.data());
    if (proof_sink != nullptr) {
        proof_sink->OnFfnExtract({
            .round_ordinal = round_ordinal,
            .layer_ordinal = layer_ordinal,
            .projection = RCFfnProjection::Down,
            .rows = b_seq,
            .columns = d_model,
            .input = &y64,
            .output = &out,
            .residual = &X,
            .prf_key = prf_dn,
        });
    }
    return true;
}

Phase2Tensors Phase2MicroTraining(const uint256& seed_r, const uint256& sigma,
                                  const RCEpisodeParams& p,
                                  RCEpisodeOptions::Checkpoint ckpt,
                                  RCGemmDispatch& dispatch,
                                  uint32_t round_ordinal = 0,
                                  RCEpisodeProofWitnessSink* proof_sink = nullptr)
{
    Phase2Tensors out;
    out.X.resize(p.L_lyr + 1);
    out.ffn_weights_shared = UseDatacenterSharedFfnWeights(p);
    if (!out.ffn_weights_shared) {
        out.W_up_layers.resize(p.L_lyr);
        out.W_down_layers.resize(p.L_lyr);
    }
    out.prf_up.resize(p.L_lyr);
    out.prf_dn.resize(p.L_lyr);

    // Config W (datacenter): X0 is the PER-ROUND FRESHNESS SOURCE — derived from seed_r
    // (which chains off round_roots[r-1]), so each round starts from a distinct, chain-
    // bound state. This lets the FFN weights be shared EPISODE-WIDE (below) while keeping
    // rounds non-collapsible: a miner cannot force X0_r == X0_r' without a seed collision
    // (seed_r = hash(round_roots[r-1], r)), and the verifier's anchored recompute checks
    // X0_r's sampled rows against seed_r, so the chain is verified at no extra cost.
    // BASE keeps X0 per-round already; seed_r is correct for both, so no branch.
    const uint256 seed_X0 = DeriveOperandSeed(seed_r, "BTX_RC_X0_V1");
    if (!ExpandX0ForEpisodeDispatched(
            seed_X0, p, dispatch, out.X[0])) {
        out.ok = false;
        return out;
    }
    const bool try_seeded_chain =
        proof_sink == nullptr &&
        ckpt == RCEpisodeOptions::Checkpoint::StoreAll &&
        dispatch.gemm.rc_fused_ffn_chain_seeded != nullptr &&
        SeededProfile1LaneEligible(p, dispatch);
    std::vector<uint256> up_seeds(
        out.ffn_weights_shared ? 1 : p.L_lyr);
    std::vector<uint256> down_seeds(
        out.ffn_weights_shared ? 1 : p.L_lyr);
    if (out.ffn_weights_shared) {
        // Config W (datacenter): FFN weights SHARED EPISODE-WIDE (sigma-derived, one pair
        // for the whole episode — across all rounds AND all layers). Fable-proven
        // shortcut-free: with X0 as the per-round freshness source, reusing one (W_up,
        // W_down) across the R independent chained instances still forces R full
        // evaluations (batching is not a FLOP shortcut; the Q1/Q2 nonlinearity forecloses
        // cross-instance memoization). Cuts the verifier's dominant weight-regen ~R× (one
        // pair instead of R). Expanded ONCE, reused for every round and layer.
        up_seeds[0] =
            DeriveOperandSeed(sigma, "BTX_RC_WUP_V1");
        down_seeds[0] =
            DeriveOperandSeed(sigma, "BTX_RC_WDN_V1");
    }

    for (uint32_t l = 0; l < p.L_lyr; ++l) {
        char tag[40];
        if (!out.ffn_weights_shared) {
            std::snprintf(tag, sizeof(tag), "BTX_RC_WUP_%u_V1", l);
            up_seeds[l] = DeriveOperandSeed(seed_r, tag);
            std::snprintf(tag, sizeof(tag), "BTX_RC_WDN_%u_V1", l);
            down_seeds[l] = DeriveOperandSeed(seed_r, tag);
        }
        std::snprintf(tag, sizeof(tag), "BTX_RC_PRF_UP_%u_V1", l);
        out.prf_up[l] = lt::DeriveMatExpandPrfKey(DeriveOperandSeed(seed_r, tag));
        std::snprintf(tag, sizeof(tag), "BTX_RC_PRF_DN_%u_V1", l);
        out.prf_dn[l] = lt::DeriveMatExpandPrfKey(DeriveOperandSeed(seed_r, tag));
    }

    bool weights_materialized{false};
    const auto materialize_weights = [&]() -> bool {
        if (weights_materialized) return true;
        if (out.ffn_weights_shared) {
            if (!ExpandMxDispatched(
                    up_seeds[0], p.d_model, p.d_ff, dispatch,
                    out.W_up_shared) ||
                !ExpandMxDispatched(
                    down_seeds[0], p.d_ff, p.d_model, dispatch,
                    out.W_down_shared)) {
                return false;
            }
        } else {
            for (uint32_t l = 0; l < p.L_lyr; ++l) {
                if (ExactReplayCancellationRequested()) return false;
                if (!ExpandMxDispatched(
                        up_seeds[l], p.d_model, p.d_ff, dispatch,
                        out.W_up_layers[l]) ||
                    !ExpandMxDispatched(
                        down_seeds[l], p.d_ff, p.d_model, dispatch,
                        out.W_down_layers[l])) {
                    return false;
                }
            }
        }
        weights_materialized = true;
        return true;
    };
    if (!try_seeded_chain && !materialize_weights()) {
        out.ok = false;
        return out;
    }

    auto need_store = [&](uint32_t layer_idx) -> bool {
        if (ckpt == RCEpisodeOptions::Checkpoint::StoreAll) return true;
        if (ckpt == RCEpisodeOptions::Checkpoint::StoreOnlyX0) return layer_idx == 0;
        return (layer_idx % 4) == 0; // StoreEvery4
    };

    // Fused FFN forward pass — always compute; then drop non-checkpoint
    // activations. The Metal chain lane uploads immutable per-layer weights
    // once and keeps all X[l] buffers resident across four-layer command
    // batches. It is exact-output-only, so proof witness production retains
    // the ordinary per-layer path.
    bool resident_chain_ok{false};
    if (proof_sink == nullptr &&
        (try_seeded_chain ||
         dispatch.gemm.rc_fused_ffn_chain != nullptr)) {
        std::vector<std::vector<int8_t>> layer_outputs;
        // The PR95 datacenter profile intentionally shares one immutable
        // weight pair across every layer and round. The backend ABI already
        // denotes this with a one-element vector; move the pair into that
        // view for the synchronous call and restore it afterwards without a
        // 128 MiB host copy.
        const auto chain_start{
            std::chrono::steady_clock::now()};
        if (try_seeded_chain) {
            try {
                resident_chain_ok =
                    dispatch.gemm.rc_fused_ffn_chain_seeded(
                        out.X[0], up_seeds, down_seeds,
                        out.prf_up, out.prf_dn, p.b_seq,
                        p.d_model, p.d_ff, layer_outputs);
            } catch (...) {
                resident_chain_ok = false;
            }
            if (resident_chain_ok &&
                (layer_outputs.size() != p.L_lyr ||
                 !std::all_of(
                     layer_outputs.begin(), layer_outputs.end(),
                     [&](const std::vector<int8_t>& x) {
                         return x.size() ==
                             static_cast<size_t>(p.b_seq) *
                                 p.d_model;
                     }))) {
                resident_chain_ok = false;
            }
            if (!resident_chain_ok) {
                layer_outputs.clear();
                RecordDeviceXofLaneFailure(
                    dispatch,
                    2ull * p.L_lyr * p.d_model * p.d_ff,
                    2ull * p.L_lyr,
                    std::chrono::steady_clock::now() - chain_start,
                    "device_seeded_ffn_chain_declined_or_wrong_size");
                if (dispatch.require_device) {
                    RecordStrictDeviceFailure(
                        dispatch,
                        "device_seeded_ffn_chain_declined_or_wrong_size");
                    out.ok = false;
                    return out;
                }
            }
        }
        if (!resident_chain_ok &&
            dispatch.gemm.rc_fused_ffn_chain != nullptr &&
            materialize_weights()) {
            std::vector<std::vector<int8_t>> shared_up;
            std::vector<std::vector<int8_t>> shared_down;
            if (out.ffn_weights_shared) {
                shared_up.emplace_back(std::move(out.W_up_shared));
                shared_down.emplace_back(std::move(out.W_down_shared));
            }
            const auto& chain_up = out.ffn_weights_shared
                ? shared_up : out.W_up_layers;
            const auto& chain_down = out.ffn_weights_shared
                ? shared_down : out.W_down_layers;
            try {
                resident_chain_ok = dispatch.gemm.rc_fused_ffn_chain(
                    out.X[0], chain_up, chain_down,
                    out.prf_up, out.prf_dn, p.b_seq,
                    p.d_model, p.d_ff, layer_outputs);
            } catch (...) {
                resident_chain_ok = false;
            }
            if (out.ffn_weights_shared) {
                out.W_up_shared = std::move(shared_up.front());
                out.W_down_shared = std::move(shared_down.front());
            }
        }
        if (resident_chain_ok &&
            layer_outputs.size() == p.L_lyr &&
            std::all_of(
                layer_outputs.begin(), layer_outputs.end(),
                [&](const std::vector<int8_t>& x) {
                    return x.size() ==
                        static_cast<size_t>(p.b_seq) * p.d_model;
                })) {
            for (uint32_t l = 0; l < p.L_lyr; ++l) {
                out.X[l + 1] = std::move(layer_outputs[l]);
                const uint64_t projection_macs{
                    GemmMacs(p.b_seq, p.d_model, p.d_ff)};
                RecordDeviceGemm(
                    dispatch, RCGemmPhase::Phase2,
                    projection_macs);
                RecordDeviceGemm(
                    dispatch, RCGemmPhase::Phase2,
                    projection_macs);
            }
            if (dispatch.stats != nullptr) {
                dispatch.stats->device_fused_ffn_calls += p.L_lyr;
                ++dispatch.stats->device_fused_ffn_chain_calls;
                dispatch.stats->device_extract_elements +=
                    static_cast<uint64_t>(p.L_lyr) * p.b_seq *
                    (p.d_ff + p.d_model);
                dispatch.stats->phase2_extract_on_device = true;
                dispatch.stats->resident_ffn_chain_on_device = true;
                dispatch.stats->resident_ffn_chain_s +=
                    std::chrono::duration<double>(
                        std::chrono::steady_clock::now() -
                        chain_start)
                        .count();
            }
            if (try_seeded_chain && !weights_materialized) {
                RecordDeviceXof(
                    dispatch,
                    2ull * p.L_lyr * p.d_model * p.d_ff,
                    2ull * p.L_lyr,
                    std::chrono::steady_clock::now() - chain_start);
            }
        } else {
            resident_chain_ok = false;
            layer_outputs.clear();
        }
    }
    if (!resident_chain_ok) {
        if (!materialize_weights()) {
            out.ok = false;
            return out;
        }
        // Backward/Wgrad are gone: the fused FFN commits only each layer's
        // output X[l+1].
        for (uint32_t l = 0; l < p.L_lyr; ++l) {
            if (ExactReplayCancellationRequested()) {
                out.ok = false;
                return out;
            }
            const std::vector<int8_t>& W_up =
                out.ffn_weights_shared ? out.W_up_shared :
                                         out.W_up_layers[l];
            const std::vector<int8_t>& W_down =
                out.ffn_weights_shared ? out.W_down_shared :
                                         out.W_down_layers[l];
            if (!FusedFfnLayer(
                    out.X[l], W_up, W_down, out.prf_up[l],
                    out.prf_dn[l], p.b_seq, p.d_model, p.d_ff,
                    dispatch, round_ordinal, l, proof_sink,
                    out.X[l + 1])) {
                out.ok = false;
                return out;
            }
        }
    }
    if (ckpt != RCEpisodeOptions::Checkpoint::StoreAll) {
        for (uint32_t l = 1; l <= p.L_lyr; ++l) {
            if (!need_store(l)) {
                out.X[l].clear();
                out.X[l].shrink_to_fit();
            }
        }
        // Retain X[0] always; X[L] only if need_store(L).
    }

    // P1.1: do NOT rebuild every missing X here — streaming emit recomputes X[l+1]
    // on demand via EnsurePhase2X / W_up / W_down / prf_up / prf_dn.
    return out;
}

// --- Phase 3 / episode -----------------------------------------------------

void AppendInt64LEMatrix(std::vector<int8_t>& stream, const std::vector<int64_t>& M)
{
    unsigned char buf[8];
    for (int64_t v : M) {
        WriteLE64(buf, static_cast<uint64_t>(v));
        stream.insert(stream.end(), reinterpret_cast<const int8_t*>(buf),
                      reinterpret_cast<const int8_t*>(buf) + 8);
    }
}

/** Fold leaf hashes to Merkle root (R.4.2). */
uint256 FoldTileTreeRoot(std::vector<uint256> level)
{
    assert(!level.empty());
    while (level.size() > 1) {
        std::vector<uint256> parent;
        parent.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            unsigned char buf[1 + 64];
            buf[0] = kRCNodeTag;
            std::memcpy(buf + 1, level[i].data(), 32);
            std::memcpy(buf + 1 + 32, level[i + 1].data(), 32);
            parent.push_back(Sha256dBytes(buf, sizeof(buf)));
        }
        level.swap(parent);
    }
    return level.front();
}

uint256 PadLeafHash()
{
    std::vector<unsigned char> pre;
    pre.push_back(kRCPadLeafTag);
    pre.insert(pre.end(), reinterpret_cast<const unsigned char*>(kRCPadTag),
               reinterpret_cast<const unsigned char*>(kRCPadTag) + sizeof(kRCPadTag) - 1);
    return Sha256dBytes(pre.data(), pre.size());
}

/** Recompute X[layer] from the nearest resident checkpoint using retained W/prf. */
bool EnsurePhase2X(Phase2Tensors& p2, uint32_t layer, const RCEpisodeParams& p,
                   RCEpisodeOptions::Checkpoint ckpt, RCGemmDispatch& dispatch)
{
    if (!p2.X[layer].empty()) return true;
    auto need_store = [&](uint32_t layer_idx) -> bool {
        if (ckpt == RCEpisodeOptions::Checkpoint::StoreAll) return true;
        if (ckpt == RCEpisodeOptions::Checkpoint::StoreOnlyX0) return layer_idx == 0;
        return (layer_idx % 4) == 0;
    };
    uint32_t src = layer;
    while (src > 0 && p2.X[src].empty()) --src;
    assert(!p2.X[src].empty());
    for (uint32_t m = src; m < layer; ++m) {
        if (ExactReplayCancellationRequested()) return false;
        const std::vector<int8_t>& W_up =
            p2.ffn_weights_shared ? p2.W_up_shared : p2.W_up_layers[m];
        const std::vector<int8_t>& W_down =
            p2.ffn_weights_shared ? p2.W_down_shared : p2.W_down_layers[m];
        if (!FusedFfnLayer(
                p2.X[m], W_up, W_down, p2.prf_up[m], p2.prf_dn[m],
                p.b_seq, p.d_model, p.d_ff, dispatch, 0, m, nullptr,
                p2.X[m + 1])) {
            return false;
        }
    }
    for (uint32_t m = src + 1; m < layer; ++m) {
        if (!need_store(m)) {
            p2.X[m].clear();
            p2.X[m].shrink_to_fit();
        }
    }
    return true;
}

/**
 * P1.1: stream R.4.1 bytes into the Merkle absorber (and optionally a retained
 * transcript buffer) without ever requiring a full pre-serialized copy for the
 * consensus digest path. Checkpointed X layers are recomputed on demand.
 */
uint256 StreamRoundIntoMerkle(Phase1Result& p1, Phase2Tensors& p2, const RCEpisodeParams& p,
                              RCEpisodeOptions::Checkpoint ckpt,
                              RCGemmDispatch& dispatch, RoundMerkleStream& merkle,
                              std::vector<int8_t>* out_stream)
{
    auto absorb = [&](const std::vector<int8_t>& bytes) {
        merkle.Absorb(bytes);
        if (out_stream) {
            out_stream->insert(out_stream->end(), bytes.begin(), bytes.end());
        }
    };
    auto absorb_i64 = [&](const std::vector<int64_t>& M) {
        merkle.AbsorbInt64LE(M);
        if (out_stream) AppendInt64LEMatrix(*out_stream, M);
    };

    if constexpr (kRCSegmentLeavesEnabled) {
        for (const auto& seg : p1.z_segs) absorb_i64(seg);
    }
    absorb(p1.Z);
    // Free Phase-1 tensors once absorbed.
    {
        std::vector<int8_t>().swap(p1.Z);
        p1.z_segs.clear();
        p1.z_segs.shrink_to_fit();
    }

    auto need_store = [&](uint32_t layer_idx) -> bool {
        if (ckpt == RCEpisodeOptions::Checkpoint::StoreAll) return true;
        if (ckpt == RCEpisodeOptions::Checkpoint::StoreOnlyX0) return layer_idx == 0;
        return (layer_idx % 4) == 0;
    };

    // Fused-FFN round stream: Z ‖ for l: X[l+1]. Only the per-layer output is
    // committed; the intermediate H (b_seq×d_ff) is never streamed (the sampled
    // verifier recomputes it). No G/D (Bwd/Wgrad removed).
    for (uint32_t l = 0; l < p.L_lyr; ++l) {
        if (ExactReplayCancellationRequested()) return uint256{};
        if (!EnsurePhase2X(p2, l + 1, p, ckpt, dispatch)) return uint256{};
        absorb(p2.X[l + 1]);

        if (!need_store(l + 1)) {
            p2.X[l + 1].clear();
            p2.X[l + 1].shrink_to_fit();
        }
    }

    // Weights no longer needed after the last X recompute.
    p2.W_up_shared.clear();
    p2.W_up_shared.shrink_to_fit();
    p2.W_down_shared.clear();
    p2.W_down_shared.shrink_to_fit();
    p2.W_up_layers.clear();
    p2.W_up_layers.shrink_to_fit();
    p2.W_down_layers.clear();
    p2.W_down_layers.shrink_to_fit();
    p2.prf_up.clear();
    p2.prf_up.shrink_to_fit();
    p2.prf_dn.clear();
    p2.prf_dn.shrink_to_fit();

    return merkle.FinalizeRoot();
}

uint256 RunEpisode(const CBlockHeader& header, const RCEpisodeParams& params,
                   const RCEpisodeOptions& options, std::vector<RCRoundTranscript>* out_rounds,
                   RCEpisodeTiming* out_timing, RCGemmDispatch& dispatch,
                   RCEpisodeProofWitnessSink* proof_sink = nullptr)
{
    // Consensus-reachable: malformed dims → REJECT (null digest), never assert/crash.
    if (!ValidateRCEpisodeParams(params)) {
        if (out_rounds) out_rounds->clear();
        return uint256{};
    }
    using clock = std::chrono::steady_clock;
    const auto t_episode0 = clock::now();
    double phase1_s = 0.0, phase2_s = 0.0, phase3_s = 0.0;

    const uint256 sigma = matmul::v4::DeriveSigma(header);
    uint256 seed_r = Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1, sigma, 0);

    std::vector<uint256> round_roots(params.rounds);
    if (out_rounds) {
        out_rounds->assign(params.rounds, RCRoundTranscript{});
    }

    for (uint32_t r = 0; r < params.rounds; ++r) {
        if (ExactReplayCancellationRequested()) return uint256{};
        if (r > 0) {
            seed_r = Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1, round_roots[r - 1], r);
        }
        const auto t1 = clock::now();
        auto p1 = Phase1AssociativeRecall(
            seed_r, sigma, params, options.phase1_tile_delta, dispatch, r, proof_sink);
        if (!p1.ok) return uint256{};
        const auto t2 = clock::now();
        auto p2 = Phase2MicroTraining(
            seed_r, sigma, params, options.checkpoint, dispatch, r, proof_sink);
        if (!p2.ok) return uint256{};
        const auto t3 = clock::now();

        // P1.1: stream leaf hashing — no full-round stream buffer on the
        // consensus path (out_rounds == nullptr).
        RoundMerkleStream merkle(
            params.T_leaf,
            dispatch.gemm.rc_merkle_leaves,
            dispatch.gemm.rc_merkle_root);
        std::vector<int8_t>* stream_out = nullptr;
        if (out_rounds) {
            stream_out = &(*out_rounds)[r].stream;
        }
        round_roots[r] =
            StreamRoundIntoMerkle(
                p1, p2, params, options.checkpoint, dispatch, merkle, stream_out);
        if (round_roots[r].IsNull()) return uint256{};
        if (dispatch.stats != nullptr &&
            merkle.FullyDeviceBacked()) {
            ++dispatch.stats->device_merkle_rounds;
        }
        const auto t4 = clock::now();
        if (proof_sink != nullptr) {
            proof_sink->OnRoundRoot(
                r, round_roots[r]);
        }
        if (out_rounds) {
            (*out_rounds)[r].round_root = round_roots[r];
        }
        if (out_timing) {
            phase1_s += std::chrono::duration<double>(t2 - t1).count();
            phase2_s += std::chrono::duration<double>(t3 - t2).count();
            phase3_s += std::chrono::duration<double>(t4 - t3).count();
        }
    }

    const uint256 digest =
        ComputeRCEpisodeDigestFromRoundRoots(round_roots);
    if (proof_sink != nullptr) {
        proof_sink->OnEpisodeDigest(digest);
    }
    if (out_timing) {
        out_timing->phase1_s = phase1_s;
        out_timing->phase2_s = phase2_s;
        out_timing->phase3_s = phase3_s;
        out_timing->total_s = std::chrono::duration<double>(clock::now() - t_episode0).count();
    }
    return digest;
}

/** Fiat–Shamir: q flat leaf indices from SHA256d("BTX_RC_FS_V1"‖sigma‖digest‖le32(i)). */
std::vector<uint32_t> DeriveFSChallenges(const uint256& sigma, const uint256& claimed_digest,
                                         uint32_t n_rounds, uint32_t n_leaves_per_round)
{
    std::vector<uint32_t> out;
    const uint64_t total = static_cast<uint64_t>(n_rounds) * n_leaves_per_round;
    if (total == 0) return out;
    out.reserve(kRCSpotCheckQueries);
    for (uint32_t q = 0; q < kRCSpotCheckQueries; ++q) {
        unsigned char buf[sizeof(kRCFsTag) - 1 + 32 + 32 + 4];
        size_t off = 0;
        std::memcpy(buf + off, kRCFsTag, sizeof(kRCFsTag) - 1);
        off += sizeof(kRCFsTag) - 1;
        std::memcpy(buf + off, sigma.data(), 32);
        off += 32;
        std::memcpy(buf + off, claimed_digest.data(), 32);
        off += 32;
        WriteLE32(buf + off, q);
        off += 4;
        // O-ENC production routing: D_FS Fiat-Shamir draw. Default (un-scoped)
        // legacy model is byte-identical to Sha256dBytes(buf,off); a V8 proof
        // session prepends the 0xF5 role byte to the whole FS preimage.
        namespace ds = matmul::v4::rc::stage3::domain_sep;
        const uint256 h = ds::Sha256dFsPreimage(ds::ActiveHashModel(), buf, off);
        out.push_back(static_cast<uint32_t>(ReadLE32(h.data()) % total));
    }
    return out;
}

} // namespace

ScopedExactReplayCancellation::ScopedExactReplayCancellation(
    const std::atomic_bool* cancelled,
    const std::atomic_bool* secondary_cancelled)
    : m_previous{g_exact_replay_cancelled},
      m_previous_secondary{g_exact_replay_secondary_cancelled}
{
    g_exact_replay_cancelled = cancelled;
    g_exact_replay_secondary_cancelled = secondary_cancelled;
}

ScopedExactReplayCancellation::~ScopedExactReplayCancellation()
{
    g_exact_replay_cancelled = m_previous;
    g_exact_replay_secondary_cancelled = m_previous_secondary;
}

bool ExactReplayCancellationRequested()
{
    return (g_exact_replay_cancelled != nullptr &&
            g_exact_replay_cancelled->load(std::memory_order_relaxed)) ||
           (g_exact_replay_secondary_cancelled != nullptr &&
            g_exact_replay_secondary_cancelled->load(
                std::memory_order_relaxed));
}

bool ComputeRCFfnRowShard(
    const std::vector<int8_t>& x_rows,
    const std::vector<int8_t>& w_up,
    const std::vector<int8_t>& w_down,
    const uint256& prf_up,
    const uint256& prf_down,
    uint32_t row_begin,
    uint32_t row_count,
    uint32_t d_model,
    uint32_t d_ff,
    const matmul::v4::lt::ExactGemmBackend& backend,
    std::vector<int8_t>& output_rows)
{
    if (row_count == 0 ||
        x_rows.size() != static_cast<size_t>(row_count) * d_model) {
        output_rows.clear();
        return false;
    }
    RCGemmDispatch dispatch{
        backend,
        /*stats=*/nullptr,
        /*require_device=*/false,
        /*output_row_tile=*/0,
    };
    return FusedFfnLayer(
        x_rows, w_up, w_down, prf_up, prf_down,
        row_count, d_model, d_ff, dispatch,
        /*round_ordinal=*/0, /*layer_ordinal=*/0,
        /*proof_sink=*/nullptr, output_rows, row_begin);
}

uint256 ComputeRCEpisodeDigestFromRoundRoots(
    const std::vector<uint256>& round_roots)
{
    if (round_roots.empty() ||
        std::any_of(
            round_roots.begin(), round_roots.end(),
            [](const uint256& root) {
                return root.IsNull();
            })) {
        return {};
    }
    std::vector<unsigned char> buf;
    buf.reserve(
        sizeof(kRCEpisodeTag) - 1 +
        round_roots.size() * 32);
    buf.insert(
        buf.end(),
        reinterpret_cast<const unsigned char*>(
            kRCEpisodeTag),
        reinterpret_cast<const unsigned char*>(
            kRCEpisodeTag) +
            sizeof(kRCEpisodeTag) - 1);
    for (const uint256& root : round_roots) {
        buf.insert(
            buf.end(), root.begin(), root.end());
    }
    return Sha256dBytes(buf.data(), buf.size());
}

bool ValidateRCEpisodeParams(const RCEpisodeParams& p)
{
    auto mod32 = [](uint32_t v) { return v != 0 && (v % 32) == 0; };
    if (p.rounds == 0 || p.L_lyr == 0) return false;
    if (!mod32(p.d_head) || !mod32(p.n_q) || !mod32(p.n_ctx) || !mod32(p.d_model) ||
        !mod32(p.d_ff) || !mod32(p.b_seq)) {
        return false;
    }
    if (p.T_leaf == 0 || (p.T_leaf % 32) != 0) return false;
    if (static_cast<uint64_t>(p.n_ctx) * 2304ull >= (uint64_t{1} << 62)) return false;
    return true;
}

RCEpisodeParams DefaultConsensusRCEpisodeParams()
{
    return EpisodeParamsFromScale(RCScale{kRCW0Res, kRCW0Cap});
}

RCEpisodeParams MakeDatacenterRCEpisodeParams()
{
    // ADDITIVE datacenter profile (design §6.1(A)): copy the epoch-0 base and raise
    // the free extensive axes (rounds/L_lyr/b_seq). The intensive GEMM dims
    // (d_head, n_q, n_ctx, d_model) track the base byte-for-byte. T_leaf is raised
    // (kRCTileLeafBytesDC) as the compute/hash hardware-alignment lever
    // (aicompute-alignment-review.md §4).
    RCEpisodeParams p = DefaultConsensusRCEpisodeParams();
    p.rounds = kRCRoundsDC;         // 8  (2× base)
    p.L_lyr = kRCLayersDC;          // 24 (fused-FFN depth; rounds=8 ⇒ 15.88× MAC)
    p.d_ff = kRCFfnDimDC;           // 16384 (transformer 4× expansion; margin 2·d_ff)
    p.b_seq = kRCBatchSeqDC;        // 87552 (2736·32; ~5.34× base)
    p.T_leaf = kRCTileLeafBytesDC;  // 4096 (compute/hash margin lever, §4)
    // HARD GUARDRAIL (aicompute-alignment-review.md §4, the weakest link): the
    // datacenter profile MUST NOT grow n_ctx above the epoch-0 base. Attention has
    // arithmetic intensity d_head (≈48× below the FFN's 1.5·d_model), so a larger
    // n_ctx tips the episode HASH-BOUND and hands share to SHA-ASICs over AI
    // accelerators. Fail closed if a future edit raises it.
    assert(p.n_ctx == DefaultConsensusRCEpisodeParams().n_ctx &&
           "datacenter n_ctx must never exceed epoch-0 base (hash-bound guardrail, §4)");
    return p;
}

RCEpisodeParams MakeToyRCEpisodeParams()
{
    RCEpisodeParams p;
    p.rounds = 1;
    p.d_head = 32;
    p.n_q = 32;
    p.n_ctx = 64;
    p.L_lyr = 2;
    p.d_model = 32;
    p.d_ff = 4 * p.d_model; // 128 — keep the CI toy self-consistent + tiny (not the 16384 default)
    p.b_seq = 32;
    p.T_leaf = 64; // smaller leaves for tiny streams (still %32==0)
    return p;
}

RCEpisodeParams MakeMediumRCEpisodeParams()
{
    // Medium self-qual: wgrad K=b_seq=8192 → 2304·8192 ≈ 1.89e7 > 2^24.
    RCEpisodeParams p;
    p.rounds = 1;
    p.d_head = 32;
    p.n_q = 32;
    p.n_ctx = 64;
    p.L_lyr = 1;
    p.d_model = 32;
    p.d_ff = 4 * p.d_model; // 128
    p.b_seq = 8192;
    p.T_leaf = 64;
    return p;
}

RCEpisodeParams MakeProductionRCEpisodeParams()
{
    // Frozen Epoch-A episode = Profile-1 consensus shape (DefaultConsensus…).
    // The shape is independent of any network's activation height.
    return DefaultConsensusRCEpisodeParams();
}

RCEpisodeParams MakeCostLadderRCEpisodeParams()
{
    // M9 off-CI ladder rung between toy and medium (b_seq=256). Enable with
    // BTX_RC_GKR_MEASURE_LADDER=1. Still not consensus.
    RCEpisodeParams p;
    p.rounds = 1;
    p.d_head = 32;
    p.n_q = 32;
    p.n_ctx = 64;
    p.L_lyr = 1;
    p.d_model = 32;
    p.d_ff = 4 * p.d_model; // 128
    p.b_seq = 256;
    p.T_leaf = 64;
    return p;
}

RCEpisodeParams MakeSegTestRCEpisodeParams()
{
    // Two Phase-1 segments (n_ctx = kRCSegLen+32); Phase-2 stays single-segment.
    RCEpisodeParams p;
    p.rounds = 1;
    p.d_head = 32;
    p.n_q = 32;
    p.n_ctx = kRCSegLen + 32; // 32800
    p.L_lyr = 1;
    p.d_model = 32;
    p.d_ff = 4 * p.d_model; // 128
    p.b_seq = 32;
    p.T_leaf = 64;
    return p;
}

RCEpisodeParams ResolveRCEpisodeParams(const Consensus::Params& p, int32_t height)
{
    // Regtest CI-scale toy dims take precedence (unchanged). Otherwise the
    // profile selector chooses WHICH consensus dims activate (design §6.1(A)):
    //   profile 1 (MatMul v4.7 Epoch A default) = epoch-0 base
    //   profile 2 (future proof-authoritative epoch) = datacenter
    // This is the ONLY dispatch change — miner / ExactReplay / Λ layout /
    // sampled verifier all read RCEpisodeParams generically.
    if (p.fMatMulRCUseToyDims) return MakeToyRCEpisodeParams();
    if (p.nMatMulRCProfile == 2) return MakeDatacenterRCEpisodeParams();
    return ConsensusRCEpisodeParamsForHeight(height, p);
}

bool UseDatacenterRowBlockX0(const RCEpisodeParams& p)
{
    const RCEpisodeParams dc = MakeDatacenterRCEpisodeParams();
    return p.rounds == dc.rounds && p.d_head == dc.d_head && p.n_q == dc.n_q &&
           p.n_ctx == dc.n_ctx && p.L_lyr == dc.L_lyr && p.d_model == dc.d_model &&
           p.d_ff == dc.d_ff && p.b_seq == dc.b_seq && p.T_leaf == dc.T_leaf;
}

bool UseDatacenterSharedFfnWeights(const RCEpisodeParams& p)
{
    return UseDatacenterRowBlockX0(p);
}

uint256 DeriveX0RowBlockSeed(const uint256& seed_x0, uint32_t row_block)
{
    return Sha256TaggedU32(kRCX0RowBlockTag, sizeof(kRCX0RowBlockTag) - 1, seed_x0,
                           row_block);
}

std::vector<int8_t> ExpandMxDequantInt8(const uint256& seed, uint32_t rows, uint32_t cols)
{
    // Consensus oracle: row-block E8M0 (LT Extract / MatExpand convention).
    // Col-block packs for S·V / bwd / wgrad live in matmul_v4_rc_mx_layout.*.
    assert(rows % kRCMxBlockLen == 0);
    assert(cols % kRCMxBlockLen == 0);
    const size_t count = static_cast<size_t>(rows) * cols;
    const uint32_t nblk = cols / kRCMxBlockLen;
    std::vector<int8_t> mu(count);
    bx::ExpandMantissaStream(seed, count, mu.data());
    std::vector<uint8_t> scales(static_cast<size_t>(rows) * nblk);
    bx::ExpandScaleStream(seed, scales.size(), scales.data());
    std::vector<int8_t> out(count);
    for (uint32_t i = 0; i < rows; ++i) {
        const size_t row = static_cast<size_t>(i) * cols;
        const size_t srow = static_cast<size_t>(i) * nblk;
        for (uint32_t bj = 0; bj < nblk; ++bj) {
            const int32_t scale = int32_t{1} << scales[srow + bj];
            const size_t base = row + static_cast<size_t>(bj) * kRCMxBlockLen;
            for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
                out[base + c] = static_cast<int8_t>(static_cast<int32_t>(mu[base + c]) * scale);
            }
        }
    }
    return out;
}

std::vector<int8_t> ExpandX0RowBlockForEpisode(const uint256& seed_x0,
                                               const RCEpisodeParams& params,
                                               uint32_t row_block)
{
    assert(params.b_seq % kRCX0RowBlockRows == 0);
    assert(params.d_model % kRCMxBlockLen == 0);
    const uint32_t n_blocks = params.b_seq / kRCX0RowBlockRows;
    assert(row_block < n_blocks);
    if (!UseDatacenterRowBlockX0(params)) {
        const std::vector<int8_t> full =
            ExpandMxDequantInt8(seed_x0, params.b_seq, params.d_model);
        std::vector<int8_t> block(static_cast<size_t>(kRCX0RowBlockRows) * params.d_model);
        const size_t off = static_cast<size_t>(row_block) * kRCX0RowBlockRows * params.d_model;
        std::copy_n(full.data() + off, block.size(), block.data());
        return block;
    }
    return ExpandMxDequantInt8(DeriveX0RowBlockSeed(seed_x0, row_block),
                               kRCX0RowBlockRows, params.d_model);
}

std::vector<int8_t> ExpandX0RowForEpisode(const uint256& seed_x0,
                                          const RCEpisodeParams& params, uint32_t row)
{
    assert(row < params.b_seq);
    const uint32_t row_block = row / kRCX0RowBlockRows;
    const uint32_t rel = row % kRCX0RowBlockRows;
    const std::vector<int8_t> block = ExpandX0RowBlockForEpisode(seed_x0, params, row_block);
    std::vector<int8_t> out(params.d_model);
    std::copy_n(block.data() + static_cast<size_t>(rel) * params.d_model, params.d_model,
                out.data());
    return out;
}

std::vector<int8_t> ExpandX0ForEpisode(const uint256& seed_x0, const RCEpisodeParams& params)
{
    if (!UseDatacenterRowBlockX0(params)) {
        return ExpandMxDequantInt8(seed_x0, params.b_seq, params.d_model);
    }
    assert(params.b_seq % kRCX0RowBlockRows == 0);
    std::vector<int8_t> out(static_cast<size_t>(params.b_seq) * params.d_model);
    const uint32_t n_blocks = params.b_seq / kRCX0RowBlockRows;
    for (uint32_t b = 0; b < n_blocks; ++b) {
        const std::vector<int8_t> block = ExpandX0RowBlockForEpisode(seed_x0, params, b);
        std::copy(block.begin(), block.end(),
                  out.begin() + static_cast<size_t>(b) * kRCX0RowBlockRows * params.d_model);
    }
    return out;
}

std::vector<int8_t> ExpandMxDequantInt8Parallel(const uint256& seed, uint32_t rows, uint32_t cols,
                                                uint32_t threads)
{
    // Byte-identical parallel verifier path. It preserves the consensus stream
    // order by block-prefixing the rejection-sampled mantissa XOF, then applies
    // the same row-block scale rule as ExpandMxDequantInt8.
    assert(rows % kRCMxBlockLen == 0);
    assert(cols % kRCMxBlockLen == 0);
    const size_t count = static_cast<size_t>(rows) * cols;
    threads = ClampLocalThreads(threads, std::max<size_t>(1, count / 4096));
    if (threads <= 1 || count < (size_t{1} << 20)) {
        return ExpandMxDequantInt8(seed, rows, cols);
    }

    const uint32_t nblk = cols / kRCMxBlockLen;
    std::vector<int8_t> mu(count);
    bx::ExpandMantissaStreamParallel(seed, count, mu.data(), threads);
    std::vector<uint8_t> scales(static_cast<size_t>(rows) * nblk);
    bx::ExpandScaleStreamParallel(seed, scales.size(), scales.data(), threads);
    std::vector<int8_t> out(count);
    ParallelForLocal(rows, threads, [&](size_t i0) {
        const uint32_t i = static_cast<uint32_t>(i0);
        const size_t row = static_cast<size_t>(i) * cols;
        const size_t srow = static_cast<size_t>(i) * nblk;
        for (uint32_t bj = 0; bj < nblk; ++bj) {
            const int32_t scale = int32_t{1} << scales[srow + bj];
            const size_t base = row + static_cast<size_t>(bj) * kRCMxBlockLen;
            for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
                out[base + c] = static_cast<int8_t>(static_cast<int32_t>(mu[base + c]) * scale);
            }
        }
    });
    return out;
}

std::vector<uint256> BuildTileTreeLeaves(const std::vector<int8_t>& stream, uint32_t t_leaf)
{
    RoundMerkleStream merkle(t_leaf);
    merkle.Absorb(stream.data(), stream.size());
    return merkle.FinalizeLeaves();
}

uint256 BuildTileTreeRoot(const std::vector<int8_t>& stream, uint32_t t_leaf)
{
    RoundMerkleStream merkle(t_leaf);
    merkle.Absorb(stream.data(), stream.size());
    return merkle.FinalizeRoot();
}

RoundMerkleStream::RoundMerkleStream(
    uint32_t t_leaf,
    lt::ExactGemmBackend::RCMerkleLeavesFn device_leaves,
    lt::ExactGemmBackend::RCMerkleRootFn device_root)
    : m_t_leaf(t_leaf),
      m_device_leaves(device_leaves),
      m_device_root(device_root),
      m_device_leaves_complete(device_leaves != nullptr)
{
    assert(t_leaf > 0);
    m_partial.reserve(t_leaf);
    if (m_device_leaves_complete) {
        m_device_leaf_batch.reserve(
            kRCDeviceMerkleLeafBatch * 64);
    }
}

void RoundMerkleStream::EmitLeafCpu(
    const unsigned char* leaf_bytes)
{
    std::vector<unsigned char> pre;
    pre.reserve(1 + m_t_leaf);
    pre.push_back(kRCLeafTag);
    pre.insert(pre.end(), leaf_bytes, leaf_bytes + m_t_leaf);
    m_leaves.push_back(Sha256dBytes(pre.data(), pre.size()));
}

void RoundMerkleStream::FlushDeviceLeafBatch()
{
    if (m_device_leaf_batch.empty()) return;
    assert((m_device_leaf_batch.size() % m_t_leaf) == 0);
    const size_t count{
        m_device_leaf_batch.size() / m_t_leaf};
    std::vector<uint256> hashes;
    bool ok{false};
    if (m_device_leaves_complete &&
        m_device_leaves != nullptr) {
        try {
            ok = m_device_leaves(
                m_device_leaf_batch.data(), m_t_leaf,
                count, hashes);
        } catch (...) {
            ok = false;
        }
    }
    if (ok && hashes.size() == count) {
        m_leaves.insert(
            m_leaves.end(), hashes.begin(), hashes.end());
    } else {
        m_device_leaves_complete = false;
        for (size_t i = 0; i < count; ++i) {
            EmitLeafCpu(
                m_device_leaf_batch.data() + i * m_t_leaf);
        }
    }
    m_device_leaf_batch.clear();
}

void RoundMerkleStream::EmitLeaf(
    const unsigned char* leaf_bytes)
{
    if (!m_device_leaves_complete) {
        EmitLeafCpu(leaf_bytes);
        return;
    }
    m_device_leaf_batch.insert(
        m_device_leaf_batch.end(),
        leaf_bytes, leaf_bytes + m_t_leaf);
    if (m_device_leaf_batch.size() >=
        kRCDeviceMerkleLeafBatch * 64) {
        FlushDeviceLeafBatch();
    }
}

void RoundMerkleStream::Absorb(const int8_t* data, size_t len)
{
    assert(!m_finalized);
    if (len == 0) return;
    m_absorbed += len;

    // Host fast path (CUDA ExactReplay has no device Merkle lane yet): empty
    // partial + T_leaf-aligned payload → parallel leaf SHA256d. Skip when the
    // Metal device-leaves lane is active so EmitLeaf batching stays authoritative.
    if (!m_device_leaves_complete && m_partial.empty() && m_t_leaf > 0 &&
        (len % m_t_leaf) == 0) {
        const size_t n_leaves = len / m_t_leaf;
        if (n_leaves >= 64) {
            const size_t base = m_leaves.size();
            m_leaves.resize(base + n_leaves);
            const uint32_t workers = std::max(
                1u, std::min(static_cast<uint32_t>(n_leaves),
                             std::thread::hardware_concurrency()));
            const uint32_t t_leaf = m_t_leaf;
            ParallelForLocal(n_leaves, workers, [&](size_t i) {
                std::vector<unsigned char> pre;
                pre.reserve(1 + t_leaf);
                pre.push_back(kRCLeafTag);
                const auto* leaf =
                    reinterpret_cast<const unsigned char*>(data) + i * t_leaf;
                pre.insert(pre.end(), leaf, leaf + t_leaf);
                m_leaves[base + i] = Sha256dBytes(pre.data(), pre.size());
            });
            return;
        }
    }

    size_t off = 0;
    while (off < len) {
        const size_t space = static_cast<size_t>(m_t_leaf) - m_partial.size();
        const size_t n = std::min(space, len - off);
        m_partial.insert(m_partial.end(), reinterpret_cast<const unsigned char*>(data + off),
                         reinterpret_cast<const unsigned char*>(data + off) + n);
        off += n;
        if (m_partial.size() == m_t_leaf) {
            EmitLeaf(m_partial.data());
            m_partial.clear();
        }
    }
}

void RoundMerkleStream::AbsorbInt64LE(const std::vector<int64_t>& M)
{
    unsigned char buf[8];
    for (int64_t v : M) {
        WriteLE64(buf, static_cast<uint64_t>(v));
        Absorb(reinterpret_cast<const int8_t*>(buf), 8);
    }
}

std::vector<uint256> RoundMerkleStream::FinalizeLeaves()
{
    assert(!m_finalized);
    m_finalized = true;
    // Match BuildTileTreeLeaves: empty stream still emits one zero leaf.
    if (m_absorbed == 0 && m_leaves.empty()) {
        std::vector<unsigned char> leaf(m_t_leaf, 0);
        EmitLeaf(leaf.data());
    } else if (!m_partial.empty()) {
        // Zero-pad the final partial leaf to T_leaf.
        m_partial.resize(m_t_leaf, 0);
        EmitLeaf(m_partial.data());
        m_partial.clear();
    }
    FlushDeviceLeafBatch();
    auto next_pow2 = [](size_t n) {
        size_t p = 1;
        while (p < n) p <<= 1;
        return p;
    };
    const size_t target = next_pow2(m_leaves.empty() ? 1 : m_leaves.size());
    const uint256 pad_leaf = PadLeafHash();
    while (m_leaves.size() < target) m_leaves.push_back(pad_leaf);
    return std::move(m_leaves);
}

uint256 RoundMerkleStream::FinalizeRoot()
{
    const std::vector<uint256> leaves{FinalizeLeaves()};
    if (m_device_root != nullptr) {
        uint256 root;
        bool ok{false};
        try {
            ok = m_device_root(leaves, root);
        } catch (...) {
            ok = false;
        }
        if (ok) {
            m_device_root_complete = true;
            return root;
        }
    }
    return FoldTileTreeRoot(leaves);
}

RCMerkleProof OpenMerkleProof(const std::vector<uint256>& leaves, uint32_t index)
{
    assert(!leaves.empty());
    assert((leaves.size() & (leaves.size() - 1)) == 0);
    assert(index < leaves.size());
    RCMerkleProof proof;
    std::vector<uint256> level = leaves;
    size_t idx = index;
    while (level.size() > 1) {
        proof.siblings.push_back(level[idx ^ 1]);
        std::vector<uint256> parent;
        parent.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            unsigned char buf[1 + 64];
            buf[0] = kRCNodeTag;
            std::memcpy(buf + 1, level[i].data(), 32);
            std::memcpy(buf + 1 + 32, level[i + 1].data(), 32);
            parent.push_back(Sha256dBytes(buf, sizeof(buf)));
        }
        level.swap(parent);
        idx >>= 1;
    }
    return proof;
}

bool VerifyMerkleProof(const uint256& leaf_hash, uint32_t index, const RCMerkleProof& proof,
                       const uint256& root)
{
    uint256 cur = leaf_hash;
    uint32_t idx = index;
    for (const uint256& sib : proof.siblings) {
        unsigned char buf[1 + 64];
        buf[0] = kRCNodeTag;
        if ((idx & 1u) == 0) {
            std::memcpy(buf + 1, cur.data(), 32);
            std::memcpy(buf + 1 + 32, sib.data(), 32);
        } else {
            std::memcpy(buf + 1, sib.data(), 32);
            std::memcpy(buf + 1 + 32, cur.data(), 32);
        }
        cur = Sha256dBytes(buf, sizeof(buf));
        idx >>= 1;
    }
    // T-BIND (R-01): every index bit ABOVE the supplied path depth must have been
    // consumed by the fold. If bits remain, `index` addresses a leaf below the
    // depth this path spans — a high-bit alias (index i and i + 2^siblings fold
    // along the SAME path). Depth/length are pinned by the callers that know the
    // canonical tree geometry (CheckCoveringLeaf); this is the geometry-independent
    // half of that binding and is safe for every honest caller (index < 2^depth).
    if (idx != 0) return false;
    return cur == root;
}

bool VerifyMerkleProof(const uint256& leaf_hash, uint32_t index, const RCMerkleProof& proof,
                       const uint256& root, uint32_t expected_depth, uint32_t real_leaves)
{
    // T-BIND (R-01): bind the opening to the canonical tree geometry BEFORE the
    // fold. Length pins the tree height; range pins the leaf to a real (non-pad)
    // leaf; the delegated fold pins the leaf hash to `root` and consumes all high
    // index bits (idx == 0). See the header for the attacks this closes.
    if (proof.siblings.size() != expected_depth) return false;
    if (index >= real_leaves) return false;
    return VerifyMerkleProof(leaf_hash, index, proof, root);
}

bool VerifyRCLeafOpening(const std::vector<int8_t>& stream, uint32_t t_leaf, uint32_t leaf_index,
                         const uint256& round_root)
{
    // Geometry is intrinsic here: the tree is rebuilt from the supplied stream, so
    // leaves.size() IS the canonical padded leaf count and the opened path has the
    // canonical depth. (The untrusted-proof T-BIND surface is the sampled carrier;
    // see CheckCoveringLeaf, which pins depth/length from consensus episode params.)
    const std::vector<uint256> leaves = BuildTileTreeLeaves(stream, t_leaf);
    if (leaf_index >= leaves.size()) return false;
    const RCMerkleProof proof = OpenMerkleProof(leaves, leaf_index);
    return VerifyMerkleProof(leaves[leaf_index], leaf_index, proof, round_root);
}

uint64_t TotalRCEpisodeMacs(const RCEpisodeParams& p)
{
    // Attention (QKt + SV) retained per round: 2·n_q·n_ctx·d_head.
    const uint64_t p1 = 2ull * p.n_q * p.n_ctx * p.d_head;
    // Fused FFN per layer = up (b_seq·d_model·d_ff) + down (b_seq·d_ff·d_model)
    // = 2·b_seq·d_model·d_ff. The intermediate H is recomputed by the verifier,
    // not committed; margin = MAC/committed-byte = 2·d_ff.
    const uint64_t p2 = 2ull * p.L_lyr * static_cast<uint64_t>(p.b_seq) * p.d_model * p.d_ff;
    return static_cast<uint64_t>(p.rounds) * (p1 + p2);
}

uint256 RecomputeResidentCurriculumReference(const CBlockHeader& header,
                                             const RCEpisodeParams& params, int32_t /*height*/,
                                             const RCEpisodeOptions& options,
                                             std::vector<RCRoundTranscript>* out_rounds,
                                             RCEpisodeTiming* out_timing,
                                             const lt::ExactGemmBackend& gemm)
{
    // height reserved for future height-selected structural variants; currently
    // the structural set is constant (R.0 / R.4.4).
    RCExactReplayAcceleration acceleration;
    acceleration.gemm = gemm;
    acceleration.backend = gemm.gemm_s8s8 != nullptr ? "device_exactgemm" : "cpu";
    return RecomputeResidentCurriculumAccelerated(
        header, params, /*height=*/0, options, out_rounds, out_timing, acceleration);
}

uint256 RecomputeResidentCurriculumAccelerated(
    const CBlockHeader& header, const RCEpisodeParams& params, int32_t /*height*/,
    const RCEpisodeOptions& options,
    std::vector<RCRoundTranscript>* out_rounds,
    RCEpisodeTiming* out_timing,
    const RCExactReplayAcceleration& acceleration)
{
    if (acceleration.stats != nullptr) {
        *acceleration.stats = RCExactReplayAccelerationStats{};
        acceleration.stats->backend = acceleration.backend;
        acceleration.stats->device_backend_present =
            acceleration.gemm.gemm_s8s8 != nullptr;
        acceleration.stats->require_device = acceleration.require_device;
    }

    RCGemmDispatch dispatch{
        acceleration.gemm,
        acceleration.stats,
        acceleration.require_device,
        acceleration.output_row_tile,
        acceleration.profile,
    };
    const uint256 digest =
        RunEpisode(header, params, options, out_rounds, out_timing, dispatch);
    if (acceleration.stats != nullptr) {
        const uint64_t expected_macs =
            ValidateRCEpisodeParams(params) ? TotalRCEpisodeMacs(params) : 0;
        const uint64_t expected_xof_elements =
            ValidateRCEpisodeParams(params)
            ? static_cast<uint64_t>(params.rounds) *
                (static_cast<uint64_t>(params.n_q) *
                     params.d_head +
                 2ull * params.n_ctx * params.d_head +
                 static_cast<uint64_t>(params.b_seq) *
                     params.d_model +
                 (UseDatacenterSharedFfnWeights(params)
                      ? 2ull
                      : 2ull * params.L_lyr) *
                     params.d_model * params.d_ff)
            : 0;
        acceleration.stats->fully_accelerated =
            !digest.IsNull() &&
            acceleration.stats->device_backend_present &&
            acceleration.stats->cpu_calls == 0 &&
            acceleration.stats->cpu_fallbacks == 0 &&
            acceleration.stats->device_macs == expected_macs;
        acceleration.stats->merkle_on_device =
            !digest.IsNull() &&
            acceleration.stats->device_merkle_rounds ==
                params.rounds;
        acceleration.stats->full_metal_pipeline =
            acceleration.stats->fully_accelerated &&
            acceleration.stats->operand_xof_on_device &&
            acceleration.stats->device_xof_fallbacks == 0 &&
            acceleration.stats->host_xof_calls == 0 &&
            acceleration.stats->device_xof_elements ==
                expected_xof_elements &&
            acceleration.stats->phase1_extract_on_device &&
            acceleration.stats->phase2_extract_on_device &&
            acceleration.stats->resident_ffn_chain_on_device &&
            acceleration.stats->device_fused_ffn_chain_calls ==
                params.rounds &&
            acceleration.stats->merkle_on_device;
        if (acceleration.require_device &&
            !acceleration.stats->fully_accelerated &&
            acceleration.stats->first_failure.empty()) {
            acceleration.stats->first_failure =
                "device_mac_coverage_incomplete";
        }
    }
    return digest;
}

RCStrictDeviceEpisodeResult MineRCEpisodeStrictDevice(
    const CBlockHeader& header,
    const RCEpisodeParams& params,
    int32_t height,
    const lt::ExactGemmBackend& gemm,
    const std::string& provider,
    const std::atomic_bool* cancelled,
    const std::atomic_bool* secondary_cancelled)
{
    RCStrictDeviceEpisodeResult out;
    out.acceleration.backend = provider;
    out.acceleration.device_backend_present =
        gemm.gemm_s8s8 != nullptr;
    out.acceleration.require_device = true;
    if ((cancelled != nullptr &&
         cancelled->load(std::memory_order_relaxed)) ||
        (secondary_cancelled != nullptr &&
         secondary_cancelled->load(std::memory_order_relaxed))) {
        out.outcome = RCStrictDeviceEpisodeOutcome::Cancelled;
        return out;
    }

    RCExactReplayAcceleration acceleration;
    acceleration.gemm = gemm;
    acceleration.backend = provider;
    acceleration.require_device = true;
    acceleration.output_row_tile = 256;
    acceleration.stats = &out.acceleration;
    acceleration.profile = 1;

    const ScopedExactReplayCancellation cancellation_scope{
        cancelled, secondary_cancelled};
    out.digest = RecomputeResidentCurriculumAccelerated(
        header, params, height, {}, nullptr, nullptr, acceleration);

    // If the mining job was invalidated while a device submission was in
    // flight, never publish its result even if that submission completed.
    if (ExactReplayCancellationRequested()) {
        out.outcome = RCStrictDeviceEpisodeOutcome::Cancelled;
        out.digest.SetNull();
        return out;
    }

    const bool complete_device_coverage =
        !out.digest.IsNull() &&
        out.acceleration.device_backend_present &&
        out.acceleration.require_device &&
        out.acceleration.fully_accelerated &&
        out.acceleration.cpu_calls == 0 &&
        out.acceleration.cpu_fallbacks == 0 &&
        out.acceleration.device_macs == TotalRCEpisodeMacs(params);
    if (!complete_device_coverage) {
        out.outcome =
            RCStrictDeviceEpisodeOutcome::LocalAcceleratorFailure;
        out.digest.SetNull();
        return out;
    }
    out.outcome = RCStrictDeviceEpisodeOutcome::Complete;
    return out;
}

RCWinnerResealResult ResealRCWinnerStrict(
    const CBlockHeader& header,
    const RCEpisodeParams& params,
    int32_t height,
    const uint256& candidate_digest,
    const lt::ExactGemmBackend& gemm,
    const std::string& provider,
    const std::atomic_bool* cancelled,
    const std::atomic_bool* secondary_cancelled)
{
    const RCStrictDeviceEpisodeResult replay{
        MineRCEpisodeStrictDevice(
            header, params, height, gemm, provider, cancelled,
            secondary_cancelled)};
    RCWinnerResealResult out;
    out.digest = replay.digest;
    out.acceleration = replay.acceleration;
    switch (replay.outcome) {
    case RCStrictDeviceEpisodeOutcome::Cancelled:
        out.outcome = RCWinnerResealOutcome::Cancelled;
        return out;
    case RCStrictDeviceEpisodeOutcome::LocalAcceleratorFailure:
        out.outcome = RCWinnerResealOutcome::LocalAcceleratorFailure;
        return out;
    case RCStrictDeviceEpisodeOutcome::Complete:
        break;
    }
    if (out.digest != candidate_digest) {
        out.outcome =
            RCWinnerResealOutcome::CandidateDigestDivergence;
        return out;
    }
    out.outcome = RCWinnerResealOutcome::Sealed;
    return out;
}

uint256 MineRCEpisode(const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
                      std::vector<RCRoundTranscript>* out_rounds,
                      const lt::ExactGemmBackend& gemm)
{
    // Generic portable/diagnostic episode entry. Production Profile 1
    // candidate mining and winner reseal use the strict-device wrappers above;
    // this function must not be cited as evidence that production reseals on
    // CPU or tolerates a device fallback.
    return RecomputeResidentCurriculumReference(header, params, height, {}, out_rounds,
                                                /*out_timing=*/nullptr, gemm);
}

uint256 MineRCEpisodeWithProofWitness(
    const CBlockHeader& header,
    const RCEpisodeParams& params,
    int32_t /*height*/,
    RCEpisodeProofWitnessSink& sink,
    std::vector<RCRoundTranscript>* out_rounds,
    const lt::ExactGemmBackend& gemm)
{
    RCExactReplayAcceleration acceleration;
    acceleration.gemm = gemm;
    acceleration.backend = gemm.gemm_s8s8 != nullptr ? "device_exactgemm" : "cpu";
    RCGemmDispatch dispatch{
        acceleration.gemm,
        /*stats=*/nullptr,
        /*require_device=*/false,
        /*output_row_tile=*/0,
    };
    return RunEpisode(
        header, params, {}, out_rounds,
        /*out_timing=*/nullptr, dispatch, &sink);
}

uint256 RecomputeRCRoundRoot(const uint256& seed_r, const uint256& sigma,
                             const RCEpisodeParams& params, const RCEpisodeOptions& options,
                             const lt::ExactGemmBackend& gemm)
{
    // FVT (§4 of the antigrind design doc): identical to one iteration of
    // RunEpisode's per-round loop body (Phase1AssociativeRecall,
    // Phase2MicroTraining, StreamRoundIntoMerkle with stream_out=nullptr — the
    // same streaming path RunEpisode itself uses on the consensus hot path,
    // i.e. out_rounds==nullptr). Bit-identical to the honest builder's round
    // root for the same (seed_r, sigma, params); no new numeric kernel.
    if (!ValidateRCEpisodeParams(params)) return uint256{};
    RCGemmDispatch dispatch{
        gemm,
        /*stats=*/nullptr,
        /*require_device=*/false,
        /*output_row_tile=*/0,
    };
    auto p1 = Phase1AssociativeRecall(
        seed_r, sigma, params, options.phase1_tile_delta, dispatch);
    if (!p1.ok) return uint256{};
    auto p2 = Phase2MicroTraining(
        seed_r, sigma, params, options.checkpoint, dispatch);
    if (!p2.ok) return uint256{};
    RoundMerkleStream merkle(params.T_leaf);
    return StreamRoundIntoMerkle(p1, p2, params, options.checkpoint, dispatch, merkle,
                                 /*out_stream=*/nullptr);
}

bool VerifyRCTranscriptSpotCheck(const CBlockHeader& header, const RCEpisodeParams& params,
                                 int32_t height, const uint256& claimed_digest,
                                 const std::vector<uint32_t>& challenged_leaves,
                                 const std::vector<std::vector<int8_t>>* stream_override)
{
    // Optimistic accept-fast pre-filter (R.5.3 / R1):
    //   - recompute full CPU episode (empty ExactGemm — never accelerate here)
    //   - open challenged Merkle leaves against recomputed round_roots
    // Returning true is ONLY an optimistic accept. Consensus INVALID still
    // requires the full int64 recompute in CheckMatMulProofOfWork_RC.
    if (claimed_digest.IsNull()) return false;
    if (!ValidateRCEpisodeParams(params)) return false;

    std::vector<RCRoundTranscript> rounds;
    const uint256 got =
        RecomputeResidentCurriculumReference(header, params, height, {}, &rounds, nullptr, {});
    if (got != claimed_digest) return false;
    if (rounds.empty()) return false;

    const std::vector<uint256> leaves0 = BuildTileTreeLeaves(rounds[0].stream, params.T_leaf);
    const uint32_t n_leaves = static_cast<uint32_t>(leaves0.size());
    if (n_leaves == 0) return false;

    std::vector<uint32_t> challenges = challenged_leaves;
    if (challenges.empty()) {
        const uint256 sigma = matmul::v4::DeriveSigma(header);
        challenges = DeriveFSChallenges(sigma, claimed_digest, params.rounds, n_leaves);
    }

    for (uint32_t flat : challenges) {
        const uint32_t r = flat / n_leaves;
        const uint32_t leaf = flat % n_leaves;
        if (r >= params.rounds || r >= rounds.size()) return false;
        const std::vector<int8_t>* stream = &rounds[r].stream;
        if (stream_override) {
            if (r >= stream_override->size()) return false;
            stream = &(*stream_override)[r];
        }
        if (!VerifyRCLeafOpening(*stream, params.T_leaf, leaf, rounds[r].round_root)) {
            return false;
        }
    }
    return true;
}

std::vector<int64_t> TestHelperGemmGXtInt64(const std::vector<int8_t>& G,
                                            const std::vector<int8_t>& X, uint32_t b_seq,
                                            uint32_t d_model)
{
    return GemmGXtInt64(G, X, b_seq, d_model);
}

std::vector<int64_t> TestHelperGemmGXtViaChunkedExact(const std::vector<int8_t>& G,
                                                     const std::vector<int8_t>& X,
                                                     uint32_t b_seq, uint32_t d_model,
                                                     const lt::ExactGemmBackend& gemm)
{
    return GemmGXtViaChunkedExact(G, X, b_seq, d_model, gemm);
}

std::vector<std::vector<int64_t>> TestHelperGemmGXtSegmented(const std::vector<int8_t>& G,
                                                             const std::vector<int8_t>& X,
                                                             uint32_t b_seq, uint32_t d_model)
{
    return AccumulateSegmentedGemmGXt(G, X, b_seq, d_model).segs;
}

} // namespace matmul::v4::rc
