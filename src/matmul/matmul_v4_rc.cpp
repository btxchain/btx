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

/** P0.3: qualified device ExactGemm REPLACES CPU on the hot path.
 *  CPU runs only when no device backend, device declines/throws/wrong size, or
 *  BTX_RC_EXACT_GEMM_COMPARE=1 dispute mode (device then CPU compare; mismatch→CPU). */
std::vector<int32_t> ExactGemmS8S8Dispatched(const lt::ExactGemmBackend& gemm,
                                             const std::vector<int8_t>& L,
                                             const std::vector<int8_t>& R, uint32_t rows,
                                             uint32_t inner, uint32_t cols)
{
    const auto run_cpu = [&]() {
        return lt::ExactGemmS8S8(L, R, rows, inner, cols);
    };
    if (gemm.gemm_s8s8 == nullptr) {
        return run_cpu();
    }

    std::vector<int32_t> device;
    bool device_ok = false;
    try {
        device_ok = gemm.gemm_s8s8(L, R, rows, inner, cols, device) &&
                    device.size() == static_cast<size_t>(rows) * cols;
    } catch (...) {
        device_ok = false;
    }
    if (!device_ok) {
        return run_cpu();
    }

    static const bool compare =
        [] {
            const char* e = std::getenv("BTX_RC_EXACT_GEMM_COMPARE");
            return e != nullptr && e[0] == '1' && e[1] == '\0';
        }();
    if (compare) {
        const std::vector<int32_t> cpu = run_cpu();
        if (device != cpu) return cpu;
    }
    return device;
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
        const auto partial = ExactGemmS8S8Dispatched(gemm, L, R, d_model, len, d_model);
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
    std::vector<int8_t> Z;                      // n_q × d_head after one ExtractMX
    /** Per-segment int64 partials; empty when kRCSegmentLeavesEnabled is false. */
    std::vector<std::vector<int64_t>> z_segs;    // each n_q × d_head int64 partial
};

Phase1Result Phase1AssociativeRecall(const uint256& seed_r, const uint256& sigma,
                                     const RCEpisodeParams& p, uint32_t tile_delta,
                                     RoundMerkleStream* acc_merkle)
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

    const auto Q = ExpandMxDequantInt8(seed_Q, p.n_q, p.d_head);
    const auto K = ExpandMxDequantInt8(seed_K, p.n_ctx, p.d_head);
    const auto V = ExpandMxDequantInt8(seed_V, p.n_ctx, p.d_head);

    // Any positive ΔT partitioning [0,n_ctx) is allowed (§R.2.2). Incomplete
    // MX 32-blocks are held in a pending buffer across tile windows so Extract
    // always fires on bj = ⌊t/32⌋ boundaries (n_ctx % 32 == 0 by construction).
    const uint32_t delta = tile_delta == 0 ? p.n_ctx : tile_delta;
    assert(delta > 0);
    assert(p.n_ctx % kRCMxBlockLen == 0);
    assert((kRCSegLen % kRCMxBlockLen) == 0);

    Phase1Result out;
    const uint32_t n_seg = RCNumSegs(p.n_ctx);
    constexpr bool keep_segs = kRCSegmentLeavesEnabled;
    if constexpr (keep_segs) {
        out.z_segs.resize(n_seg);
        for (uint32_t s = 0; s < n_seg; ++s) {
            out.z_segs[s].assign(static_cast<size_t>(p.n_q) * p.d_head, 0);
        }
    }
    out.Z.assign(static_cast<size_t>(p.n_q) * p.d_head, 0);

    for (uint32_t i = 0; i < p.n_q; ++i) {
        int64_t pending_raw[kRCMxBlockLen];
        uint32_t pending_fill = 0;
        uint32_t pending_bj = 0;
        uint32_t block_t0 = 0; // first t of the MX block being filled
        uint32_t cur_seg = 0;
        std::vector<int64_t> seg_row(p.d_head, 0);
        // Running sum of segment rows for the single Extract (H1) when segs
        // are not retained.
        std::vector<int64_t> acc_Z(p.d_head, 0);

        auto flush_s_block = [&]() {
            assert(pending_fill == kRCMxBlockLen);
            if (acc_merkle != nullptr) acc_merkle->AbsorbInt64LE(pending_raw, kRCMxBlockLen);
            int8_t S_tile[kRCMxBlockLen];
            ExtractMXTileInt64(prf_S, i, pending_bj, pending_raw, S_tile);
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
        if (acc_merkle != nullptr) acc_merkle->AbsorbInt64LE(acc_Z.data(), acc_Z.size());
        for (uint32_t bj = 0; bj < nblk; ++bj) {
            ExtractMXTileInt64(prf_Z, i, bj, acc_Z.data() + bj * kRCMxBlockLen,
                               out.Z.data() + static_cast<size_t>(i) * p.d_head +
                                   bj * kRCMxBlockLen);
        }
    }
    return out;
}

// --- Phase 2 ---------------------------------------------------------------
// MX layout (P1.2): forward X·Wᵀ is contraction-correct after Wᵀ (row-block W).
// Backward G·W and wgrad Gᵀ·X need col-block scales on W / batch — packed
// helpers in matmul_v4_rc_mx_layout.*; oracle stays dequant int8 ExactGemm.

struct Phase2Tensors {
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
std::vector<int64_t> FusedExactGemmInt64(const std::vector<int8_t>& A, uint32_t m, uint32_t k,
                                         const std::vector<int8_t>& B, uint32_t n,
                                         const lt::ExactGemmBackend& gemm)
{
    assert(A.size() == static_cast<size_t>(m) * k);
    assert(B.size() == static_cast<size_t>(k) * n);
    std::vector<int64_t> out(static_cast<size_t>(m) * n, 0);
    for (uint32_t k0 = 0; k0 < k; k0 += kRCWgradExactChunk) {
        const uint32_t len = std::min(kRCWgradExactChunk, k - k0);
        std::vector<int8_t> Ap(static_cast<size_t>(m) * len);
        std::vector<int8_t> Bp(static_cast<size_t>(len) * n);
        for (uint32_t i = 0; i < m; ++i)
            for (uint32_t t = 0; t < len; ++t)
                Ap[static_cast<size_t>(i) * len + t] = A[static_cast<size_t>(i) * k + (k0 + t)];
        for (uint32_t t = 0; t < len; ++t)
            for (uint32_t c = 0; c < n; ++c)
                Bp[static_cast<size_t>(t) * n + c] = B[static_cast<size_t>(k0 + t) * n + c];
        const auto partial = ExactGemmS8S8Dispatched(gemm, Ap, Bp, m, len, n);
        for (size_t i = 0; i < out.size(); ++i) out[i] += static_cast<int64_t>(partial[i]);
    }
    return out;
}

/** One fused 2-layer FFN (scratchpad/fused-ffn-episode-design.md):
 *    H     = Extract(X·W_up)            [b_seq×d_ff]  — INTERNAL (not committed)
 *    X_out = Extract(H·W_down + X)      [b_seq×d_model] — committed (residual +X, H5)
 *  Only X_out is streamed into the round tile-tree; H is recomputed by the sampled
 *  verifier from anchored X and the PRF weights. W_up is d_model×d_ff, W_down is
 *  d_ff×d_model (both natural contraction-major, no transpose). */
std::vector<int8_t> FusedFfnLayer(const std::vector<int8_t>& X, const std::vector<int8_t>& W_up,
                                  const std::vector<int8_t>& W_down, const uint256& prf_up,
                                  const uint256& prf_dn, uint32_t b_seq, uint32_t d_model,
                                  uint32_t d_ff, const lt::ExactGemmBackend& gemm,
                                  RoundMerkleStream* acc_merkle)
{
    // Up projection: H = Extract(X·W_up), contraction over d_model.
    std::vector<int64_t> h64 = FusedExactGemmInt64(X, b_seq, d_model, W_up, d_ff, gemm);
    if (acc_merkle != nullptr) acc_merkle->AbsorbInt64LE(h64);
    std::vector<int8_t> H(h64.size());
    ExtractMXMatrixInt64(prf_up, h64.data(), b_seq, d_ff, H.data());
    std::vector<int64_t>().swap(h64);
    // Down projection: X_out = Extract(H·W_down + X), contraction over d_ff, residual
    // +X folded INSIDE the single Extract accumulator (H5).
    std::vector<int64_t> y64 = FusedExactGemmInt64(H, b_seq, d_ff, W_down, d_model, gemm);
    for (uint32_t i = 0; i < b_seq; ++i)
        for (uint32_t j = 0; j < d_model; ++j)
            y64[static_cast<size_t>(i) * d_model + j] +=
                static_cast<int64_t>(X[static_cast<size_t>(i) * d_model + j]);
    if (acc_merkle != nullptr) acc_merkle->AbsorbInt64LE(y64);
    std::vector<int8_t> out(y64.size());
    ExtractMXMatrixInt64(prf_dn, y64.data(), b_seq, d_model, out.data());
    return out;
}

Phase2Tensors Phase2MicroTraining(const uint256& seed_r, const uint256& sigma,
                                  const RCEpisodeParams& p,
                                  RCEpisodeOptions::Checkpoint ckpt,
                                  const lt::ExactGemmBackend& gemm,
                                  RoundMerkleStream* acc_merkle)
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
    out.X[0] = ExpandX0ForEpisode(seed_X0, p);
    if (out.ffn_weights_shared) {
        // Config W (datacenter): FFN weights SHARED EPISODE-WIDE (sigma-derived, one pair
        // for the whole episode — across all rounds AND all layers). Fable-proven
        // shortcut-free: with X0 as the per-round freshness source, reusing one (W_up,
        // W_down) across the R independent chained instances still forces R full
        // evaluations (batching is not a FLOP shortcut; the Q1/Q2 nonlinearity forecloses
        // cross-instance memoization). Cuts the verifier's dominant weight-regen ~R× (one
        // pair instead of R). Expanded ONCE, reused for every round and layer.
        out.W_up_shared = ExpandMxDequantInt8(DeriveOperandSeed(sigma, "BTX_RC_WUP_V1"),
                                              p.d_model, p.d_ff);
        out.W_down_shared = ExpandMxDequantInt8(DeriveOperandSeed(sigma, "BTX_RC_WDN_V1"),
                                                p.d_ff, p.d_model);
    }

    for (uint32_t l = 0; l < p.L_lyr; ++l) {
        char tag[40];
        if (!out.ffn_weights_shared) {
            std::snprintf(tag, sizeof(tag), "BTX_RC_WUP_%u_V1", l);
            out.W_up_layers[l] = ExpandMxDequantInt8(DeriveOperandSeed(seed_r, tag),
                                                     p.d_model, p.d_ff);
            std::snprintf(tag, sizeof(tag), "BTX_RC_WDN_%u_V1", l);
            out.W_down_layers[l] = ExpandMxDequantInt8(DeriveOperandSeed(seed_r, tag),
                                                       p.d_ff, p.d_model);
        }
        std::snprintf(tag, sizeof(tag), "BTX_RC_PRF_UP_%u_V1", l);
        out.prf_up[l] = lt::DeriveMatExpandPrfKey(DeriveOperandSeed(seed_r, tag));
        std::snprintf(tag, sizeof(tag), "BTX_RC_PRF_DN_%u_V1", l);
        out.prf_dn[l] = lt::DeriveMatExpandPrfKey(DeriveOperandSeed(seed_r, tag));
    }

    auto need_store = [&](uint32_t layer_idx) -> bool {
        if (ckpt == RCEpisodeOptions::Checkpoint::StoreAll) return true;
        if (ckpt == RCEpisodeOptions::Checkpoint::StoreOnlyX0) return layer_idx == 0;
        return (layer_idx % 4) == 0; // StoreEvery4
    };

    // Fused FFN forward pass — always compute; then drop non-checkpoint activations.
    // Backward/Wgrad are GONE: the fused FFN commits only the per-layer output X[l+1].
    for (uint32_t l = 0; l < p.L_lyr; ++l) {
        const std::vector<int8_t>& W_up =
            out.ffn_weights_shared ? out.W_up_shared : out.W_up_layers[l];
        const std::vector<int8_t>& W_down =
            out.ffn_weights_shared ? out.W_down_shared : out.W_down_layers[l];
        out.X[l + 1] = FusedFfnLayer(out.X[l], W_up, W_down,
                                     out.prf_up[l], out.prf_dn[l], p.b_seq, p.d_model,
                                     p.d_ff, gemm, acc_merkle);
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
void EnsurePhase2X(Phase2Tensors& p2, uint32_t layer, const RCEpisodeParams& p,
                   RCEpisodeOptions::Checkpoint ckpt, const lt::ExactGemmBackend& gemm)
{
    if (!p2.X[layer].empty()) return;
    auto need_store = [&](uint32_t layer_idx) -> bool {
        if (ckpt == RCEpisodeOptions::Checkpoint::StoreAll) return true;
        if (ckpt == RCEpisodeOptions::Checkpoint::StoreOnlyX0) return layer_idx == 0;
        return (layer_idx % 4) == 0;
    };
    uint32_t src = layer;
    while (src > 0 && p2.X[src].empty()) --src;
    assert(!p2.X[src].empty());
    for (uint32_t m = src; m < layer; ++m) {
        const std::vector<int8_t>& W_up =
            p2.ffn_weights_shared ? p2.W_up_shared : p2.W_up_layers[m];
        const std::vector<int8_t>& W_down =
            p2.ffn_weights_shared ? p2.W_down_shared : p2.W_down_layers[m];
        p2.X[m + 1] = FusedFfnLayer(p2.X[m], W_up, W_down,
                                    p2.prf_up[m], p2.prf_dn[m], p.b_seq, p.d_model,
                                    p.d_ff, gemm, nullptr);
    }
    for (uint32_t m = src + 1; m < layer; ++m) {
        if (!need_store(m)) {
            p2.X[m].clear();
            p2.X[m].shrink_to_fit();
        }
    }
}

/**
 * P1.1: stream R.4.1 bytes into the Merkle absorber (and optionally a retained
 * transcript buffer) without ever requiring a full pre-serialized copy for the
 * consensus digest path. Checkpointed X layers are recomputed on demand.
 */
uint256 StreamRoundIntoMerkle(Phase1Result& p1, Phase2Tensors& p2, const RCEpisodeParams& p,
                              RCEpisodeOptions::Checkpoint ckpt,
                              const lt::ExactGemmBackend& gemm, RoundMerkleStream& merkle,
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
        EnsurePhase2X(p2, l + 1, p, ckpt, gemm);
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
                   RCEpisodeTiming* out_timing, const lt::ExactGemmBackend& gemm)
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
    std::vector<uint256> round_roots(params.rounds);
    const bool use_v2_digest = UseRCEpisodeDigestV2(params);
    std::vector<uint256> acc_roots(use_v2_digest ? params.rounds : 0);
    if (out_rounds) {
        out_rounds->assign(params.rounds, RCRoundTranscript{});
    }

    for (uint32_t r = 0; r < params.rounds; ++r) {
        const uint256 seed_r = RCRoundSeedForParams(params, sigma, round_roots, acc_roots, r);
        const auto t1 = clock::now();
        RoundMerkleStream acc_merkle(params.T_leaf);
        RoundMerkleStream* acc_merkle_ptr = use_v2_digest ? &acc_merkle : nullptr;
        auto p1 = Phase1AssociativeRecall(seed_r, sigma, params, options.phase1_tile_delta,
                                          acc_merkle_ptr);
        const auto t2 = clock::now();
        auto p2 = Phase2MicroTraining(seed_r, sigma, params, options.checkpoint, gemm,
                                      acc_merkle_ptr);
        const auto t3 = clock::now();

        // P1.1: stream leaf hashing — no full-round stream buffer on the
        // consensus path (out_rounds == nullptr).
        RoundMerkleStream merkle(params.T_leaf);
        std::vector<int8_t>* stream_out = nullptr;
        if (out_rounds) {
            stream_out = &(*out_rounds)[r].stream;
        }
        round_roots[r] =
            StreamRoundIntoMerkle(p1, p2, params, options.checkpoint, gemm, merkle, stream_out);
        if (use_v2_digest) acc_roots[r] = acc_merkle.FinalizeRoot();
        const auto t4 = clock::now();
        if (out_rounds) {
            (*out_rounds)[r].round_root = round_roots[r];
            (*out_rounds)[r].acc_root = use_v2_digest ? acc_roots[r] : uint256{};
        }
        if (out_timing) {
            phase1_s += std::chrono::duration<double>(t2 - t1).count();
            phase2_s += std::chrono::duration<double>(t3 - t2).count();
            phase3_s += std::chrono::duration<double>(t4 - t3).count();
        }
    }

    const uint256 digest = RCEpisodeDigestForParams(params, round_roots, acc_roots);
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
        const uint256 h = Sha256dBytes(buf, off);
        out.push_back(static_cast<uint32_t>(ReadLE32(h.data()) % total));
    }
    return out;
}

} // namespace

bool ValidateRCEpisodeParams(const RCEpisodeParams& p)
{
    auto mod32 = [](uint32_t v) { return v != 0 && (v % 32) == 0; };
    if (p.transcript_version != ENC_RC_V1 && p.transcript_version != ENC_RC_V2) return false;
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
    p.transcript_version = ENC_RC_V2;
    p.rounds = kRCRoundsDC;         // 8  (2× base)
    p.L_lyr = kRCLayersDC;          // 24 (fused-FFN depth; rounds=8 ⇒ 15.88× MAC)
    p.d_ff = kRCFfnDimDC;           // 16384 (transformer 4× expansion; margin 2·d_ff)
    p.b_seq = kRCBatchSeqDC;        // 32768 (2× base)
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
    // PROVISIONAL frozen episode = epoch-0 consensus shape (DefaultConsensus…).
    // Freezing ≠ activation; nMatMulRCHeight remains INT32_MAX.
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
    //   profile 2 = datacenter (additive; regtest/testnet override only)
    //   profile 1 (default) = epoch-0 base via the height-selected schedule
    // This is the ONLY dispatch change — miner / ExactReplay / Λ layout /
    // sampled verifier all read RCEpisodeParams generically.
    if (p.fMatMulRCUseToyDims) {
        RCEpisodeParams toy = MakeToyRCEpisodeParams();
        if (p.nMatMulRCProfile == 2) toy.transcript_version = ENC_RC_V2;
        return toy;
    }
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

bool UseRCEpisodeDigestV2(const RCEpisodeParams& p)
{
    return p.transcript_version >= ENC_RC_V2;
}

uint256 RCRoundCommitV2(const uint256& round_root, const uint256& acc_root)
{
    std::vector<unsigned char> buf;
    buf.reserve(sizeof(kRCRoundCommitTagV2) - 1 + 64);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCRoundCommitTagV2),
               reinterpret_cast<const unsigned char*>(kRCRoundCommitTagV2) +
                   sizeof(kRCRoundCommitTagV2) - 1);
    buf.insert(buf.end(), round_root.begin(), round_root.end());
    buf.insert(buf.end(), acc_root.begin(), acc_root.end());
    return Sha256dBytes(buf.data(), buf.size());
}

uint256 RCEpisodeDigestFromRootsV1(const std::vector<uint256>& round_roots)
{
    std::vector<unsigned char> buf;
    buf.reserve(sizeof(kRCEpisodeTag) - 1 + round_roots.size() * 32);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCEpisodeTag),
               reinterpret_cast<const unsigned char*>(kRCEpisodeTag) + sizeof(kRCEpisodeTag) - 1);
    for (const uint256& root : round_roots) {
        buf.insert(buf.end(), root.begin(), root.end());
    }
    return Sha256dBytes(buf.data(), buf.size());
}

uint256 RCEpisodeDigestFromRootsV2(const std::vector<uint256>& round_roots,
                                   const std::vector<uint256>& acc_roots)
{
    if (round_roots.size() != acc_roots.size()) return uint256{};
    std::vector<unsigned char> buf;
    buf.reserve(sizeof(kRCEpisodeTagV2) - 1 + 4 + round_roots.size() * 32);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCEpisodeTagV2),
               reinterpret_cast<const unsigned char*>(kRCEpisodeTagV2) +
                   sizeof(kRCEpisodeTagV2) - 1);
    unsigned char nbuf[4];
    WriteLE32(nbuf, static_cast<uint32_t>(round_roots.size()));
    buf.insert(buf.end(), nbuf, nbuf + sizeof(nbuf));
    for (size_t r = 0; r < round_roots.size(); ++r) {
        const uint256 commit = RCRoundCommitV2(round_roots[r], acc_roots[r]);
        buf.insert(buf.end(), commit.begin(), commit.end());
    }
    return Sha256dBytes(buf.data(), buf.size());
}

uint256 RCEpisodeDigestForParams(const RCEpisodeParams& params,
                                 const std::vector<uint256>& round_roots,
                                 const std::vector<uint256>& acc_roots)
{
    return UseRCEpisodeDigestV2(params) ? RCEpisodeDigestFromRootsV2(round_roots, acc_roots)
                                       : RCEpisodeDigestFromRootsV1(round_roots);
}

uint256 RCRoundSeedForParams(const RCEpisodeParams& params, const uint256& sigma,
                             const std::vector<uint256>& round_roots,
                             const std::vector<uint256>& acc_roots, uint32_t round)
{
    if (round == 0) {
        return UseRCEpisodeDigestV2(params)
                   ? Sha256TaggedU32(kRCRoundTagV2, sizeof(kRCRoundTagV2) - 1, sigma, 0)
                   : Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1, sigma, 0);
    }
    if (UseRCEpisodeDigestV2(params)) {
        if (round - 1 >= round_roots.size() || round - 1 >= acc_roots.size()) return uint256{};
        return Sha256TaggedU32(kRCRoundTagV2, sizeof(kRCRoundTagV2) - 1,
                               RCRoundCommitV2(round_roots[round - 1], acc_roots[round - 1]),
                               round);
    }
    if (round - 1 >= round_roots.size()) return uint256{};
    return Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1, round_roots[round - 1],
                           round);
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

RoundMerkleStream::RoundMerkleStream(uint32_t t_leaf) : m_t_leaf(t_leaf)
{
    assert(t_leaf > 0);
    m_partial.reserve(t_leaf);
}

void RoundMerkleStream::EmitLeaf(const unsigned char* leaf_bytes)
{
    std::vector<unsigned char> pre;
    pre.reserve(1 + m_t_leaf);
    pre.push_back(kRCLeafTag);
    pre.insert(pre.end(), leaf_bytes, leaf_bytes + m_t_leaf);
    m_leaves.push_back(Sha256dBytes(pre.data(), pre.size()));
}

void RoundMerkleStream::Absorb(const int8_t* data, size_t len)
{
    assert(!m_finalized);
    if (len == 0) return;
    m_absorbed += len;
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

void RoundMerkleStream::AbsorbInt64LE(const int64_t* data, size_t count)
{
    unsigned char buf[8];
    for (size_t i = 0; i < count; ++i) {
        WriteLE64(buf, static_cast<uint64_t>(data[i]));
        Absorb(reinterpret_cast<const int8_t*>(buf), 8);
    }
}

void RoundMerkleStream::AbsorbInt64LE(const std::vector<int64_t>& M)
{
    AbsorbInt64LE(M.data(), M.size());
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
    auto next_pow2 = [](size_t n) {
        size_t p = 1;
        while (p < n) p <<= 1;
        return p;
    };
    const size_t target = next_pow2(m_leaves.empty() ? 1 : m_leaves.size());
    const uint256 pad_leaf = PadLeafHash();
    while (m_leaves.size() < target) m_leaves.push_back(pad_leaf);
    return m_leaves;
}

uint256 RoundMerkleStream::FinalizeRoot()
{
    return FoldTileTreeRoot(FinalizeLeaves());
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
    return RunEpisode(header, params, options, out_rounds, out_timing, gemm);
}

bool RecomputeRCEpisodeRoundRoots(const CBlockHeader& header, const RCEpisodeParams& params,
                                  int32_t /*height*/, uint32_t round,
                                  const std::vector<uint256>& round_roots,
                                  const std::vector<uint256>& acc_roots,
                                  RCRoundTranscript& out_round,
                                  const RCEpisodeOptions& options,
                                  const lt::ExactGemmBackend& gemm)
{
    out_round = RCRoundTranscript{};
    if (!ValidateRCEpisodeParams(params) || round >= params.rounds ||
        round_roots.size() != params.rounds) {
        return false;
    }
    const bool use_v2_digest = UseRCEpisodeDigestV2(params);
    if (use_v2_digest && acc_roots.size() != params.rounds) return false;
    static const std::vector<uint256> empty_acc_roots;
    const std::vector<uint256>& seed_acc_roots = use_v2_digest ? acc_roots : empty_acc_roots;

    const uint256 sigma = matmul::v4::DeriveSigma(header);
    const uint256 seed_r = RCRoundSeedForParams(params, sigma, round_roots, seed_acc_roots, round);
    RoundMerkleStream acc_merkle(params.T_leaf);
    RoundMerkleStream* acc_merkle_ptr = use_v2_digest ? &acc_merkle : nullptr;
    auto p1 = Phase1AssociativeRecall(seed_r, sigma, params, options.phase1_tile_delta,
                                      acc_merkle_ptr);
    auto p2 = Phase2MicroTraining(seed_r, sigma, params, options.checkpoint, gemm,
                                  acc_merkle_ptr);
    RoundMerkleStream merkle(params.T_leaf);
    out_round.round_root =
        StreamRoundIntoMerkle(p1, p2, params, options.checkpoint, gemm, merkle, nullptr);
    out_round.acc_root = use_v2_digest ? acc_merkle.FinalizeRoot() : uint256{};
    return true;
}

uint256 MineRCEpisode(const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
                      std::vector<RCRoundTranscript>* out_rounds,
                      const lt::ExactGemmBackend& gemm)
{
    // Miner path reseals through the same oracle; optional ExactGemm inject
    // (after RC self-qual) must still match CPU when verified per-GEMM.
    return RecomputeResidentCurriculumReference(header, params, height, {}, out_rounds,
                                                /*out_timing=*/nullptr, gemm);
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
