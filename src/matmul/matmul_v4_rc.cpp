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
#include <matmul/matmul_v4_rc_scale.h>
#include <span.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>

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

// --- ExactGemm helpers ------------------------------------------------------

/** Try injectable ExactGemmS8S8; accept only when byte-identical to CPU oracle. */
std::vector<int32_t> ExactGemmS8S8Verified(const lt::ExactGemmBackend& gemm,
                                           const std::vector<int8_t>& L,
                                           const std::vector<int8_t>& R, uint32_t rows,
                                           uint32_t inner, uint32_t cols)
{
    const std::vector<int32_t> cpu = lt::ExactGemmS8S8(L, R, rows, inner, cols);
    if (gemm.gemm_s8s8 == nullptr) return cpu;

    std::vector<int32_t> device;
    bool ok = false;
    try {
        ok = gemm.gemm_s8s8(L, R, rows, inner, cols, device) &&
             device.size() == static_cast<size_t>(rows) * cols && device == cpu;
    } catch (...) {
        ok = false;
    }
    return ok ? device : cpu;
}

std::vector<int8_t> TransposeS8(const std::vector<int8_t>& M, uint32_t rows, uint32_t cols)
{
    assert(M.size() == static_cast<size_t>(rows) * cols);
    std::vector<int8_t> T(static_cast<size_t>(cols) * rows);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            T[static_cast<size_t>(c) * rows + r] = M[static_cast<size_t>(r) * cols + c];
        }
    }
    return T;
}

/** Backward feature grad via ExactGemm: G_prev = G · W  (row-major).
 *  Bound 2304·d_model < 2^24 at consensus d_model=4096 → s8xs8 ExactGemm OK. */
std::vector<int32_t> GemmWtS8S8Int32(const std::vector<int8_t>& W, const std::vector<int8_t>& G,
                                     uint32_t d_model, uint32_t b_seq,
                                     const lt::ExactGemmBackend& gemm)
{
    assert(W.size() == static_cast<size_t>(d_model) * d_model);
    assert(G.size() == static_cast<size_t>(b_seq) * d_model);
    // out[i][k] = Σ_j G[i][j]·W[j][k] = ExactGemmS8S8(G, W, b_seq, d_model, d_model)
    return ExactGemmS8S8Verified(gemm, G, W, b_seq, d_model, d_model);
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
 *  → int64 oracle only in the episode path. */
std::vector<int64_t> GemmGXtInt64(const std::vector<int8_t>& G, const std::vector<int8_t>& X,
                                  uint32_t b_seq, uint32_t d_model)
{
    assert(G.size() == static_cast<size_t>(b_seq) * d_model);
    assert(X.size() == static_cast<size_t>(b_seq) * d_model);
    return GemmGXtInt64Range(G, X, /*k0=*/0, b_seq, d_model);
}

/** Consensus-fixed kRCSegLen partition of wgrad: per-segment int64 partials + sum.
 *  ExtractMX is NOT applied here — caller Extracts once on the sum (H1). */
struct SegmentedInt64Gemm {
    std::vector<int64_t> total;                 // sum of segs (same shape)
    std::vector<std::vector<int64_t>> segs;      // each same shape as total
};

SegmentedInt64Gemm AccumulateSegmentedGemmGXt(const std::vector<int8_t>& G,
                                              const std::vector<int8_t>& X, uint32_t b_seq,
                                              uint32_t d_model)
{
    assert(G.size() == static_cast<size_t>(b_seq) * d_model);
    assert(X.size() == static_cast<size_t>(b_seq) * d_model);
    SegmentedInt64Gemm out;
    const uint32_t n_seg = RCNumSegs(b_seq);
    out.segs.resize(n_seg);
    out.total.assign(static_cast<size_t>(d_model) * d_model, 0);
    for (uint32_t s = 0; s < n_seg; ++s) {
        const uint32_t k0 = s * kRCSegLen;
        const uint32_t len = std::min(kRCSegLen, b_seq - k0);
        out.segs[s] = GemmGXtInt64Range(G, X, k0, len, d_model);
        for (size_t i = 0; i < out.total.size(); ++i) {
            out.total[i] += out.segs[s][i];
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
        const auto partial = ExactGemmS8S8Verified(gemm, L, R, d_model, len, d_model);
        for (size_t i = 0; i < out.size(); ++i) {
            out[i] += static_cast<int64_t>(partial[i]);
        }
    }
    return out;
}

// --- Phase 1 ---------------------------------------------------------------
// Phase-1 Z=S·V bound is 2304·n_ctx ≫ 2^24 — streamed int64 only in reference.
// Optional ExactGemmS32S8ViaRadix256 is not used here; miners may limb-promote
// offline but must match this int64 stream byte-for-byte.
//
// Consensus-fixed kRCSegLen segments commit exact int64 Z partials; ExtractMX
// fires once on Σ partials (H1). kRCSegLen % 32 == 0 ⇒ segments align to MX
// block boundaries.

struct Phase1Result {
    std::vector<int8_t> Z;                      // n_q × d_head after one ExtractMX
    std::vector<std::vector<int64_t>> z_segs;    // each n_q × d_head int64 partial
};

Phase1Result Phase1AssociativeRecall(const uint256& seed_r, const RCEpisodeParams& p,
                                     uint32_t tile_delta)
{
    const uint256 seed_Q = DeriveOperandSeed(seed_r, "BTX_RC_Q_V1");
    const uint256 seed_K = DeriveOperandSeed(seed_r, "BTX_RC_KV_K_V1");
    const uint256 seed_V = DeriveOperandSeed(seed_r, "BTX_RC_KV_V_V1");
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
    out.z_segs.resize(n_seg);
    for (uint32_t s = 0; s < n_seg; ++s) {
        out.z_segs[s].assign(static_cast<size_t>(p.n_q) * p.d_head, 0);
    }
    out.Z.assign(static_cast<size_t>(p.n_q) * p.d_head, 0);

    for (uint32_t i = 0; i < p.n_q; ++i) {
        int64_t pending_raw[kRCMxBlockLen];
        uint32_t pending_fill = 0;
        uint32_t pending_bj = 0;
        uint32_t block_t0 = 0; // first t of the MX block being filled
        uint32_t cur_seg = 0;
        std::vector<int64_t> seg_row(p.d_head, 0);

        auto flush_s_block = [&]() {
            assert(pending_fill == kRCMxBlockLen);
            int8_t S_tile[kRCMxBlockLen];
            {
                int32_t raw32[kRCMxBlockLen];
                for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
                    raw32[t] = ExactInt64ToExtractInt32(pending_raw[t]);
                }
                int8_t mu_tile[kRCMxBlockLen];
                lt::ExtractMatExpandMxTileMantissas(prf_S, i, pending_bj, raw32, mu_tile);
                const uint8_t e = lt::DeriveMatExpandMxScale(prf_S, i, pending_bj);
                for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
                    S_tile[t] = static_cast<int8_t>(static_cast<int32_t>(mu_tile[t]) *
                                                    (int32_t{1} << e));
                }
            }
            for (uint32_t t_off = 0; t_off < kRCMxBlockLen; ++t_off) {
                const uint32_t t = block_t0 + t_off;
                const uint32_t seg = t / kRCSegLen;
                if (seg != cur_seg) {
                    // Commit finished segment row (kRCSegLen % 32 == 0 ⇒ aligned).
                    for (uint32_t d = 0; d < p.d_head; ++d) {
                        out.z_segs[cur_seg][static_cast<size_t>(i) * p.d_head + d] = seg_row[d];
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
        for (uint32_t d = 0; d < p.d_head; ++d) {
            out.z_segs[cur_seg][static_cast<size_t>(i) * p.d_head + d] = seg_row[d];
        }

        // One ExtractMX on Σ_s Z_seg[s][i] (H1 / H1') — never per segment.
        std::vector<int64_t> acc_Z(p.d_head, 0);
        for (uint32_t s = 0; s < n_seg; ++s) {
            for (uint32_t d = 0; d < p.d_head; ++d) {
                acc_Z[d] += out.z_segs[s][static_cast<size_t>(i) * p.d_head + d];
            }
        }
        {
            std::vector<int32_t> raw32_row(p.d_head);
            for (uint32_t d = 0; d < p.d_head; ++d) {
                raw32_row[d] = ExactInt64ToExtractInt32(acc_Z[d]);
            }
            const uint32_t nblk = p.d_head / kRCMxBlockLen;
            for (uint32_t bj = 0; bj < nblk; ++bj) {
                int8_t mu_tile[kRCMxBlockLen];
                lt::ExtractMatExpandMxTileMantissas(prf_Z, i, bj, raw32_row.data() + bj * kRCMxBlockLen,
                                                   mu_tile);
                const uint8_t e = lt::DeriveMatExpandMxScale(prf_Z, i, bj);
                for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
                    out.Z[static_cast<size_t>(i) * p.d_head + bj * kRCMxBlockLen + t] =
                        static_cast<int8_t>(static_cast<int32_t>(mu_tile[t]) * (int32_t{1} << e));
                }
            }
        }
    }
    return out;
}

// --- Phase 2 ---------------------------------------------------------------

struct Phase2Tensors {
    std::vector<std::vector<int8_t>> X; // X[0..L]
    std::vector<std::vector<int8_t>> G; // G[0..L]
    std::vector<std::vector<int8_t>> D; // D[0..L-1] after one ExtractMX per layer
    /** Per-layer wgrad int64 segment partials (before Extract); R.4.1 leaves. */
    std::vector<std::vector<std::vector<int64_t>>> d_segs; // [L][n_seg][d_model²]
};

std::vector<int8_t> ForwardLayer(const std::vector<int8_t>& W, const std::vector<int8_t>& X,
                                 const uint256& prf_fwd, uint32_t b_seq, uint32_t d_model,
                                 const lt::ExactGemmBackend& gemm)
{
    // Pin: acc[i][j] = Σ_k W[j][k]·X[i][k] + X[i][j]
    //     = ExactGemmS8S8(X, Wᵀ)[i][j] + X[i][j]
    // Residual is INSIDE the single Extract (H5). Bound < 2^24 at consensus.
    const std::vector<int8_t> Wt = TransposeS8(W, d_model, d_model);
    std::vector<int32_t> y = ExactGemmS8S8Verified(gemm, X, Wt, b_seq, d_model, d_model);
    assert(y.size() == static_cast<size_t>(b_seq) * d_model);
    for (uint32_t i = 0; i < b_seq; ++i) {
        for (uint32_t j = 0; j < d_model; ++j) {
            y[static_cast<size_t>(i) * d_model + j] +=
                static_cast<int32_t>(X[static_cast<size_t>(i) * d_model + j]);
        }
    }
    std::vector<int8_t> out(y.size());
    ExtractMXMatrixInt32(prf_fwd, y.data(), b_seq, d_model, out.data());
    return out;
}

Phase2Tensors Phase2MicroTraining(const uint256& seed_r, const RCEpisodeParams& p,
                                  RCEpisodeOptions::Checkpoint ckpt,
                                  const lt::ExactGemmBackend& gemm)
{
    Phase2Tensors out;
    out.X.resize(p.L_lyr + 1);
    out.G.resize(p.L_lyr + 1);
    out.D.resize(p.L_lyr);
    out.d_segs.resize(p.L_lyr);

    const uint256 seed_X0 = DeriveOperandSeed(seed_r, "BTX_RC_X0_V1");
    const uint256 seed_GL = DeriveOperandSeed(seed_r, "BTX_RC_GL_V1");
    out.X[0] = ExpandMxDequantInt8(seed_X0, p.b_seq, p.d_model);
    out.G[p.L_lyr] = ExpandMxDequantInt8(seed_GL, p.b_seq, p.d_model);

    std::vector<std::vector<int8_t>> W(p.L_lyr);
    std::vector<uint256> prf_fwd(p.L_lyr), prf_bwd(p.L_lyr), prf_wg(p.L_lyr);
    for (uint32_t l = 0; l < p.L_lyr; ++l) {
        char tag[32];
        std::snprintf(tag, sizeof(tag), "BTX_RC_W_%u_V1", l);
        W[l] = ExpandMxDequantInt8(DeriveOperandSeed(seed_r, tag), p.d_model, p.d_model);
        std::snprintf(tag, sizeof(tag), "BTX_RC_PRF_FWD_%u_V1", l);
        prf_fwd[l] = lt::DeriveMatExpandPrfKey(DeriveOperandSeed(seed_r, tag));
        std::snprintf(tag, sizeof(tag), "BTX_RC_PRF_BWD_%u_V1", l);
        prf_bwd[l] = lt::DeriveMatExpandPrfKey(DeriveOperandSeed(seed_r, tag));
        std::snprintf(tag, sizeof(tag), "BTX_RC_PRF_WG_%u_V1", l);
        prf_wg[l] = lt::DeriveMatExpandPrfKey(DeriveOperandSeed(seed_r, tag));
    }

    auto need_store = [&](uint32_t layer_idx) -> bool {
        if (ckpt == RCEpisodeOptions::Checkpoint::StoreAll) return true;
        if (ckpt == RCEpisodeOptions::Checkpoint::StoreOnlyX0) return layer_idx == 0;
        return (layer_idx % 4) == 0; // StoreEvery4
    };

    // Forward — always compute; then drop non-checkpoint activations.
    for (uint32_t l = 0; l < p.L_lyr; ++l) {
        out.X[l + 1] = ForwardLayer(W[l], out.X[l], prf_fwd[l], p.b_seq, p.d_model, gemm);
    }
    if (ckpt != RCEpisodeOptions::Checkpoint::StoreAll) {
        for (uint32_t l = 1; l < p.L_lyr; ++l) {
            if (!need_store(l)) out.X[l].clear();
        }
        // Always retain X[0] and X[L].
    }

    auto ensure_X = [&](uint32_t layer) {
        if (!out.X[layer].empty()) return;
        uint32_t src = layer;
        while (src > 0 && out.X[src].empty()) --src;
        assert(!out.X[src].empty());
        for (uint32_t m = src; m < layer; ++m) {
            out.X[m + 1] = ForwardLayer(W[m], out.X[m], prf_fwd[m], p.b_seq, p.d_model, gemm);
        }
    };

    // Backward + wgrad (segmented int64 oracle; Extract once on Σ partials).
    for (int32_t l = static_cast<int32_t>(p.L_lyr) - 1; l >= 0; --l) {
        ensure_X(static_cast<uint32_t>(l));
        ensure_X(static_cast<uint32_t>(l + 1));
        auto g_acc = GemmWtS8S8Int32(W[l], out.G[l + 1], p.d_model, p.b_seq, gemm);
        out.G[l].assign(g_acc.size(), 0);
        ExtractMXMatrixInt32(prf_bwd[l], g_acc.data(), p.b_seq, p.d_model, out.G[l].data());

        auto seg = AccumulateSegmentedGemmGXt(out.G[l + 1], out.X[l], p.b_seq, p.d_model);
        out.d_segs[l] = std::move(seg.segs);
        out.D[l].assign(seg.total.size(), 0);
        ExtractMXMatrixInt64(prf_wg[l], seg.total.data(), p.d_model, p.d_model, out.D[l].data());
    }

    for (uint32_t l = 0; l <= p.L_lyr; ++l) ensure_X(l);
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

/** R.4.1 round stream with consensus-fixed segment leaves:
 *    concat(
 *      for each Phase-1 Z segment: LE int64 row-major (n_q × d_head),
 *      Z int8 (ExtractMX once on Σ Z segs),
 *      for l = 0..L−1:
 *        X[l+1] int8, G[l] int8,
 *        for each D segment: LE int64 row-major (d_model × d_model),
 *        D[l] int8 (ExtractMX once on Σ D segs)
 *    )
 */
std::vector<int8_t> SerializeRoundStream(const Phase1Result& p1, const Phase2Tensors& p2,
                                         const RCEpisodeParams& p)
{
    std::vector<int8_t> stream;
    const size_t z_seg_bytes = RCSegZBytes(p) * p1.z_segs.size();
    const size_t d_seg_bytes =
        p.L_lyr == 0 ? 0
                     : RCSegDBytes(p) * (p2.d_segs.empty() ? 0 : p2.d_segs[0].size()) * p.L_lyr;
    stream.reserve(z_seg_bytes + p1.Z.size() + d_seg_bytes +
                   p.L_lyr * (p2.X[1].size() + p2.G[0].size() + p2.D[0].size()));

    for (const auto& seg : p1.z_segs) {
        AppendInt64LEMatrix(stream, seg);
    }
    stream.insert(stream.end(), p1.Z.begin(), p1.Z.end());
    for (uint32_t l = 0; l < p.L_lyr; ++l) {
        stream.insert(stream.end(), p2.X[l + 1].begin(), p2.X[l + 1].end());
        stream.insert(stream.end(), p2.G[l].begin(), p2.G[l].end());
        for (const auto& seg : p2.d_segs[l]) {
            AppendInt64LEMatrix(stream, seg);
        }
        stream.insert(stream.end(), p2.D[l].begin(), p2.D[l].end());
    }
    return stream;
}

uint256 RunEpisode(const CBlockHeader& header, const RCEpisodeParams& params,
                   const RCEpisodeOptions& options, std::vector<RCRoundTranscript>* out_rounds,
                   RCEpisodeTiming* out_timing, const lt::ExactGemmBackend& gemm)
{
    assert(ValidateRCEpisodeParams(params));
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
        if (r > 0) {
            seed_r = Sha256TaggedU32(kRCRoundTag, sizeof(kRCRoundTag) - 1, round_roots[r - 1], r);
        }
        const auto t1 = clock::now();
        const auto p1 = Phase1AssociativeRecall(seed_r, params, options.phase1_tile_delta);
        const auto t2 = clock::now();
        const auto p2 = Phase2MicroTraining(seed_r, params, options.checkpoint, gemm);
        const auto t3 = clock::now();
        const auto stream = SerializeRoundStream(p1, p2, params);
        round_roots[r] = BuildTileTreeRoot(stream, params.T_leaf);
        const auto t4 = clock::now();
        if (out_rounds) {
            (*out_rounds)[r].round_root = round_roots[r];
            (*out_rounds)[r].stream = stream;
        }
        if (out_timing) {
            phase1_s += std::chrono::duration<double>(t2 - t1).count();
            phase2_s += std::chrono::duration<double>(t3 - t2).count();
            phase3_s += std::chrono::duration<double>(t4 - t3).count();
        }
    }

    // episode_digest = SHA256d("BTX_RC_EPISODE_V1" ‖ roots…)
    std::vector<unsigned char> buf;
    buf.reserve(sizeof(kRCEpisodeTag) - 1 + round_roots.size() * 32);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCEpisodeTag),
               reinterpret_cast<const unsigned char*>(kRCEpisodeTag) + sizeof(kRCEpisodeTag) - 1);
    for (const uint256& root : round_roots) {
        buf.insert(buf.end(), root.begin(), root.end());
    }
    const uint256 digest = Sha256dBytes(buf.data(), buf.size());
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
    if (p.rounds == 0 || p.L_lyr == 0) return false;
    if (!mod32(p.d_head) || !mod32(p.n_q) || !mod32(p.n_ctx) || !mod32(p.d_model) ||
        !mod32(p.b_seq)) {
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

RCEpisodeParams MakeToyRCEpisodeParams()
{
    RCEpisodeParams p;
    p.rounds = 1;
    p.d_head = 32;
    p.n_q = 32;
    p.n_ctx = 64;
    p.L_lyr = 2;
    p.d_model = 32;
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
    p.b_seq = 8192;
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
    p.b_seq = 32;
    p.T_leaf = 64;
    return p;
}

RCEpisodeParams ResolveRCEpisodeParams(const Consensus::Params& p, int32_t height)
{
    return p.fMatMulRCUseToyDims ? MakeToyRCEpisodeParams()
                                 : ConsensusRCEpisodeParamsForHeight(height, p);
}

std::vector<int8_t> ExpandMxDequantInt8(const uint256& seed, uint32_t rows, uint32_t cols)
{
    assert(cols % kRCMxBlockLen == 0);
    const size_t count = static_cast<size_t>(rows) * cols;
    std::vector<int8_t> mu(count);
    bx::ExpandMantissaStream(seed, count, mu.data());
    const uint32_t nblk = cols / kRCMxBlockLen;
    std::vector<uint8_t> scale(static_cast<size_t>(rows) * nblk);
    bx::ExpandScaleStream(seed, scale.size(), scale.data());
    std::vector<int8_t> out(count);
    for (uint32_t i = 0; i < rows; ++i) {
        for (uint32_t j = 0; j < cols; ++j) {
            const size_t idx = static_cast<size_t>(i) * cols + j;
            const uint8_t e = scale[static_cast<size_t>(i) * nblk + (j / kRCMxBlockLen)];
            out[idx] = static_cast<int8_t>(static_cast<int32_t>(mu[idx]) * (int32_t{1} << e));
        }
    }
    return out;
}

std::vector<uint256> BuildTileTreeLeaves(const std::vector<int8_t>& stream, uint32_t t_leaf)
{
    assert(t_leaf > 0);
    std::vector<uint256> level;
    size_t offset = 0;
    while (offset < stream.size() || level.empty()) {
        std::vector<unsigned char> leaf(t_leaf, 0);
        const size_t n = std::min(static_cast<size_t>(t_leaf), stream.size() - offset);
        if (offset < stream.size()) {
            std::memcpy(leaf.data(), stream.data() + offset, n);
            offset += n;
        } else if (!level.empty()) {
            break;
        }
        std::vector<unsigned char> pre;
        pre.reserve(1 + t_leaf);
        pre.push_back(kRCLeafTag);
        pre.insert(pre.end(), leaf.begin(), leaf.end());
        level.push_back(Sha256dBytes(pre.data(), pre.size()));
        if (offset >= stream.size()) break;
    }
    if (level.empty()) {
        std::vector<unsigned char> leaf(t_leaf, 0);
        std::vector<unsigned char> pre;
        pre.push_back(kRCLeafTag);
        pre.insert(pre.end(), leaf.begin(), leaf.end());
        level.push_back(Sha256dBytes(pre.data(), pre.size()));
    }
    auto next_pow2 = [](size_t n) {
        size_t p = 1;
        while (p < n) p <<= 1;
        return p;
    };
    const size_t target = next_pow2(level.size());
    const uint256 pad_leaf = [&] {
        std::vector<unsigned char> pre;
        pre.push_back(kRCPadLeafTag);
        pre.insert(pre.end(), reinterpret_cast<const unsigned char*>(kRCPadTag),
                   reinterpret_cast<const unsigned char*>(kRCPadTag) + sizeof(kRCPadTag) - 1);
        return Sha256dBytes(pre.data(), pre.size());
    }();
    while (level.size() < target) level.push_back(pad_leaf);
    return level;
}

uint256 BuildTileTreeRoot(const std::vector<int8_t>& stream, uint32_t t_leaf)
{
    std::vector<uint256> level = BuildTileTreeLeaves(stream, t_leaf);
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
    return cur == root;
}

bool VerifyRCLeafOpening(const std::vector<int8_t>& stream, uint32_t t_leaf, uint32_t leaf_index,
                         const uint256& round_root)
{
    const std::vector<uint256> leaves = BuildTileTreeLeaves(stream, t_leaf);
    if (leaf_index >= leaves.size()) return false;
    const RCMerkleProof proof = OpenMerkleProof(leaves, leaf_index);
    return VerifyMerkleProof(leaves[leaf_index], leaf_index, proof, round_root);
}

uint64_t TotalRCEpisodeMacs(const RCEpisodeParams& p)
{
    const uint64_t p1 = 2ull * p.n_q * p.n_ctx * p.d_head;
    const uint64_t p2 = 3ull * p.L_lyr * static_cast<uint64_t>(p.b_seq) * p.d_model * p.d_model;
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
