// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <span.h>

#include <algorithm>
#include <cassert>
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

// --- GEMM helpers (exact int accumulation) ----------------------------------

/** Backward feature grad: G_prev[i][k] = Σ_j W[j][k]·G[i][j] (H12 index form). */
std::vector<int32_t> GemmWtS8S8Int32(const std::vector<int8_t>& W, const std::vector<int8_t>& G,
                                     uint32_t d_model, uint32_t b_seq)
{
    assert(W.size() == static_cast<size_t>(d_model) * d_model);
    assert(G.size() == static_cast<size_t>(b_seq) * d_model);
    std::vector<int32_t> out(static_cast<size_t>(b_seq) * d_model, 0);
    for (uint32_t i = 0; i < b_seq; ++i) {
        for (uint32_t k = 0; k < d_model; ++k) {
            int32_t acc = 0;
            for (uint32_t j = 0; j < d_model; ++j) {
                acc += static_cast<int32_t>(W[static_cast<size_t>(j) * d_model + k]) *
                       static_cast<int32_t>(G[static_cast<size_t>(i) * d_model + j]);
            }
            out[static_cast<size_t>(i) * d_model + k] = acc;
        }
    }
    return out;
}

/** G·Xᵀ without materializing Xᵀ: out[r][c] = Σ_k G[k][r]·X[k][c]
 *  (wgrad D is d_model × d_model; contraction is b_seq). */
std::vector<int64_t> GemmGXtInt64(const std::vector<int8_t>& G, const std::vector<int8_t>& X,
                                  uint32_t b_seq, uint32_t d_model)
{
    assert(G.size() == static_cast<size_t>(b_seq) * d_model);
    assert(X.size() == static_cast<size_t>(b_seq) * d_model);
    std::vector<int64_t> out(static_cast<size_t>(d_model) * d_model, 0);
    for (uint32_t r = 0; r < d_model; ++r) {
        for (uint32_t c = 0; c < d_model; ++c) {
            int64_t acc = 0;
            for (uint32_t k = 0; k < b_seq; ++k) {
                acc += static_cast<int64_t>(G[static_cast<size_t>(k) * d_model + r]) *
                       static_cast<int64_t>(X[static_cast<size_t>(k) * d_model + c]);
            }
            out[static_cast<size_t>(r) * d_model + c] = acc;
        }
    }
    return out;
}

// --- Phase 1 ---------------------------------------------------------------

std::vector<int8_t> Phase1AssociativeRecall(const uint256& seed_r, const RCEpisodeParams& p,
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

    uint32_t delta = tile_delta == 0 ? p.n_ctx : tile_delta;
    // Tile-size invariance holds for any partition; require ΔT % 32 == 0 so each
    // ExtractMX S-tile completes inside a window (simplifies streaming without
    // cross-window pending buffers). Arbitrary ΔT remains future work.
    assert(delta % kRCMxBlockLen == 0);
    assert(p.n_ctx % delta == 0);

    std::vector<int8_t> Z(static_cast<size_t>(p.n_q) * p.d_head);
    std::vector<int64_t> acc_Z(p.d_head);

    for (uint32_t i = 0; i < p.n_q; ++i) {
        std::fill(acc_Z.begin(), acc_Z.end(), 0);
        for (uint32_t t0 = 0; t0 < p.n_ctx; t0 += delta) {
            const uint32_t t1 = t0 + delta;
            for (uint32_t bj_base = t0; bj_base < t1; bj_base += kRCMxBlockLen) {
                const uint32_t bj = bj_base / kRCMxBlockLen;
                int64_t S_raw[kRCMxBlockLen];
                for (uint32_t t_off = 0; t_off < kRCMxBlockLen; ++t_off) {
                    const uint32_t t = bj_base + t_off;
                    int64_t acc = 0;
                    for (uint32_t d = 0; d < p.d_head; ++d) {
                        acc += static_cast<int64_t>(Q[static_cast<size_t>(i) * p.d_head + d]) *
                               static_cast<int64_t>(K[static_cast<size_t>(t) * p.d_head + d]);
                    }
                    S_raw[t_off] = acc;
                }
                // S is n_q × n_ctx: Extract at (row i, block bj).
                int8_t S_tile[kRCMxBlockLen];
                {
                    int32_t raw32[kRCMxBlockLen];
                    for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
                        raw32[t] = ExactInt64ToExtractInt32(S_raw[t]);
                    }
                    int8_t mu_tile[kRCMxBlockLen];
                    lt::ExtractMatExpandMxTileMantissas(prf_S, i, bj, raw32, mu_tile);
                    const uint8_t e = lt::DeriveMatExpandMxScale(prf_S, i, bj);
                    for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
                        S_tile[t] = static_cast<int8_t>(static_cast<int32_t>(mu_tile[t]) *
                                                        (int32_t{1} << e));
                    }
                }
                for (uint32_t t_off = 0; t_off < kRCMxBlockLen; ++t_off) {
                    const uint32_t t = bj_base + t_off;
                    const int8_t s = S_tile[t_off];
                    for (uint32_t d = 0; d < p.d_head; ++d) {
                        acc_Z[d] += static_cast<int64_t>(s) *
                                    static_cast<int64_t>(V[static_cast<size_t>(t) * p.d_head + d]);
                    }
                }
            }
        }
        // Z is n_q × d_head: one final ExtractMX on completed acc_Z (H1').
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
                    Z[static_cast<size_t>(i) * p.d_head + bj * kRCMxBlockLen + t] =
                        static_cast<int8_t>(static_cast<int32_t>(mu_tile[t]) * (int32_t{1} << e));
                }
            }
        }
    }
    return Z;
}

// --- Phase 2 ---------------------------------------------------------------

struct Phase2Tensors {
    std::vector<int8_t> Z_unused; // placeholder alignment with serialize order
    std::vector<std::vector<int8_t>> X; // X[0..L]
    std::vector<std::vector<int8_t>> G; // G[0..L]
    std::vector<std::vector<int8_t>> D; // D[0..L-1]
};

std::vector<int8_t> ForwardLayer(const std::vector<int8_t>& W, const std::vector<int8_t>& X,
                                 const uint256& prf_fwd, uint32_t b_seq, uint32_t d_model)
{
    // Pin: acc[i][j] = Σ_k W[j][k]·X[i][k] + X[i][j]  (row feature transform + residual).
    // Residual is INSIDE the single Extract (H5).
    std::vector<int32_t> y(static_cast<size_t>(b_seq) * d_model, 0);
    for (uint32_t i = 0; i < b_seq; ++i) {
        for (uint32_t j = 0; j < d_model; ++j) {
            int32_t sum = 0;
            for (uint32_t k = 0; k < d_model; ++k) {
                sum += static_cast<int32_t>(W[static_cast<size_t>(j) * d_model + k]) *
                       static_cast<int32_t>(X[static_cast<size_t>(i) * d_model + k]);
            }
            sum += static_cast<int32_t>(X[static_cast<size_t>(i) * d_model + j]);
            y[static_cast<size_t>(i) * d_model + j] = sum;
        }
    }
    std::vector<int8_t> out(y.size());
    ExtractMXMatrixInt32(prf_fwd, y.data(), b_seq, d_model, out.data());
    return out;
}

Phase2Tensors Phase2MicroTraining(const uint256& seed_r, const RCEpisodeParams& p,
                                  RCEpisodeOptions::Checkpoint ckpt)
{
    Phase2Tensors out;
    out.X.resize(p.L_lyr + 1);
    out.G.resize(p.L_lyr + 1);
    out.D.resize(p.L_lyr);

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
        out.X[l + 1] = ForwardLayer(W[l], out.X[l], prf_fwd[l], p.b_seq, p.d_model);
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
            out.X[m + 1] = ForwardLayer(W[m], out.X[m], prf_fwd[m], p.b_seq, p.d_model);
        }
    };

    // Backward + wgrad
    for (int32_t l = static_cast<int32_t>(p.L_lyr) - 1; l >= 0; --l) {
        ensure_X(static_cast<uint32_t>(l));
        ensure_X(static_cast<uint32_t>(l + 1));
        auto g_acc = GemmWtS8S8Int32(W[l], out.G[l + 1], p.d_model, p.b_seq);
        out.G[l].assign(g_acc.size(), 0);
        ExtractMXMatrixInt32(prf_bwd[l], g_acc.data(), p.b_seq, p.d_model, out.G[l].data());

        auto d_acc = GemmGXtInt64(out.G[l + 1], out.X[l], p.b_seq, p.d_model);
        out.D[l].assign(d_acc.size(), 0);
        ExtractMXMatrixInt64(prf_wg[l], d_acc.data(), p.d_model, p.d_model, out.D[l].data());
    }

    for (uint32_t l = 0; l <= p.L_lyr; ++l) ensure_X(l);
    return out;
}

// --- Phase 3 / episode -----------------------------------------------------

std::vector<int8_t> SerializeRoundStream(const std::vector<int8_t>& Z, const Phase2Tensors& p2,
                                         const RCEpisodeParams& p)
{
    std::vector<int8_t> stream;
    stream.reserve(Z.size() + p.L_lyr * (p2.X[1].size() + p2.G[0].size() + p2.D[0].size()));
    stream.insert(stream.end(), Z.begin(), Z.end());
    for (uint32_t l = 0; l < p.L_lyr; ++l) {
        stream.insert(stream.end(), p2.X[l + 1].begin(), p2.X[l + 1].end());
        stream.insert(stream.end(), p2.G[l].begin(), p2.G[l].end());
        stream.insert(stream.end(), p2.D[l].begin(), p2.D[l].end());
    }
    return stream;
}

uint256 RunEpisode(const CBlockHeader& header, const RCEpisodeParams& params,
                   const RCEpisodeOptions& options, std::vector<RCRoundTranscript>* out_rounds)
{
    assert(ValidateRCEpisodeParams(params));
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
        const auto Z = Phase1AssociativeRecall(seed_r, params, options.phase1_tile_delta);
        const auto p2 = Phase2MicroTraining(seed_r, params, options.checkpoint);
        const auto stream = SerializeRoundStream(Z, p2, params);
        round_roots[r] = BuildTileTreeRoot(stream, params.T_leaf);
        if (out_rounds) (*out_rounds)[r].round_root = round_roots[r];
    }

    // episode_digest = SHA256d("BTX_RC_EPISODE_V1" ‖ roots…)
    std::vector<unsigned char> buf;
    buf.reserve(sizeof(kRCEpisodeTag) - 1 + round_roots.size() * 32);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCEpisodeTag),
               reinterpret_cast<const unsigned char*>(kRCEpisodeTag) + sizeof(kRCEpisodeTag) - 1);
    for (const uint256& root : round_roots) {
        buf.insert(buf.end(), root.begin(), root.end());
    }
    return Sha256dBytes(buf.data(), buf.size());
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
    return RCEpisodeParams{};
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

uint256 BuildTileTreeRoot(const std::vector<int8_t>& stream, uint32_t t_leaf)
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
        // Empty stream → one zero leaf.
        std::vector<unsigned char> leaf(t_leaf, 0);
        std::vector<unsigned char> pre;
        pre.push_back(kRCLeafTag);
        pre.insert(pre.end(), leaf.begin(), leaf.end());
        level.push_back(Sha256dBytes(pre.data(), pre.size()));
    }
    // Pad to next power of two with sentinel leaves.
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

uint256 RecomputeResidentCurriculumReference(const CBlockHeader& header,
                                             const RCEpisodeParams& params, int32_t /*height*/,
                                             const RCEpisodeOptions& options,
                                             std::vector<RCRoundTranscript>* out_rounds)
{
    // height reserved for future height-selected structural variants; currently
    // the structural set is constant (R.0 / R.4.4).
    return RunEpisode(header, params, options, out_rounds);
}

uint256 MineRCEpisode(const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
                      std::vector<RCRoundTranscript>* out_rounds)
{
    // Miner path reseals through the same CPU oracle (R.5.3).
    return RecomputeResidentCurriculumReference(header, params, height, {}, out_rounds);
}

bool VerifyRCTranscriptSpotCheck(const CBlockHeader& header, const RCEpisodeParams& params,
                                 int32_t height, const uint256& claimed_digest,
                                 const std::vector<uint32_t>& challenged_leaves)
{
    // Optimistic pre-filter: recompute full reference for now (toy-safe). A
    // reject still requires this CPU path (R1). Leaf openings are validated by
    // recomputing the episode and checking the digest; challenged_leaves is
    // reserved for a future partial-recompute implementation.
    (void)challenged_leaves;
    const uint256 got = RecomputeResidentCurriculumReference(header, params, height);
    return got == claimed_digest && !got.IsNull();
}

} // namespace matmul::v4::rc
