// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_scale.h>

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/params.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <limits>
#include <mutex>
#include <unordered_map>

namespace matmul::v4::rc {
namespace {

/** Q16 identity (1.0). Used when the epoch index is past the table. */
constexpr int64_t kQ16One = 65536;

uint64_t RoundBytesToMultipleOf32(uint64_t x)
{
    if (x == 0) return 0;
    return ((x + 16) / 32) * 32;
}

/** (w * g_q16) / 2^16 with round-half-up, then snap to a multiple of 32 bytes. */
uint64_t MulQ16Round32(uint64_t w, int64_t g_q16)
{
    if (g_q16 <= 0) return w;
    // Use 128-bit intermediate: w can approach hard-cap × ~1.1.
    const unsigned __int128 prod =
        static_cast<unsigned __int128>(w) * static_cast<uint64_t>(g_q16) + (1ull << 15);
    const uint64_t scaled = static_cast<uint64_t>(prod >> 16);
    return RoundBytesToMultipleOf32(scaled);
}

uint64_t ClampHardCap(uint64_t w, int64_t hard_cap)
{
    if (hard_cap <= 0) return w;
    const uint64_t cap = static_cast<uint64_t>(hard_cap);
    return w < cap ? w : cap;
}

uint64_t HashGrowthTables(const Consensus::Params& p)
{
    // FNV-1a 64 over schedule knobs that affect RCScaleForHeight (not brake).
    uint64_t h = 14695981039346656037ull;
    auto mix = [&](uint64_t v) {
        h ^= v;
        h *= 1099511628211ull;
    };
    mix(static_cast<uint64_t>(static_cast<uint32_t>(p.nMatMulRCHeight)));
    mix(static_cast<uint64_t>(static_cast<uint32_t>(p.nRCScaleEpochBlocks)));
    mix(static_cast<uint64_t>(p.nRCScaleHardCapResBytes));
    mix(static_cast<uint64_t>(p.nRCScaleHardCapCapBytes));
    for (size_t i = 0; i < Consensus::Params::kRCGrowthTableLen; ++i) {
        mix(static_cast<uint64_t>(p.nRCGrowthResTableQ16[i]));
        mix(static_cast<uint64_t>(p.nRCGrowthCapTableQ16[i]));
    }
    return h;
}

struct ScaleCacheKey {
    int32_t epoch{0};
    uint64_t table_hash{0};
    bool operator==(const ScaleCacheKey& o) const
    {
        return epoch == o.epoch && table_hash == o.table_hash;
    }
};

struct ScaleCacheKeyHash {
    size_t operator()(const ScaleCacheKey& k) const
    {
        return static_cast<size_t>(k.table_hash ^ (static_cast<uint64_t>(k.epoch) * 0x9e3779b97f4a7c15ull));
    }
};

std::mutex g_scale_cache_mu;
std::unordered_map<ScaleCacheKey, RCScale, ScaleCacheKeyHash> g_scale_cache;

RCScale ComputeScaleForEpoch(int32_t epoch, const Consensus::Params& p, const RCBrakeFn& brake)
{
    RCScale s{kRCW0Res, kRCW0Cap};
    if (epoch <= 0) return s;

    const int32_t steps = epoch; // apply steps e = 0 .. epoch-1
    for (int32_t e = 0; e < steps; ++e) {
        const bool apply = !brake || brake(e);
        if (!apply) continue;

        int64_t g_res = kQ16One;
        int64_t g_cap = kQ16One;
        if (e >= 0 && static_cast<size_t>(e) < Consensus::Params::kRCGrowthTableLen) {
            g_res = p.nRCGrowthResTableQ16[static_cast<size_t>(e)];
            g_cap = p.nRCGrowthCapTableQ16[static_cast<size_t>(e)];
        }
        // Zero / non-positive = misconfigured → skip (pause), never wipe dials.
        if (g_res > 0) {
            s.W_res = ClampHardCap(MulQ16Round32(s.W_res, g_res), p.nRCScaleHardCapResBytes);
        }
        if (g_cap > 0) {
            s.W_cap = ClampHardCap(MulQ16Round32(s.W_cap, g_cap), p.nRCScaleHardCapCapBytes);
        }
    }
    return s;
}

/** Estimate Phase-3 hash work vs MAC work: f3 ≈ (leaves * kHashPerLeaf) / MACs. */
bool CheckF3Bound(const RCEpisodeParams& p, std::string* reason)
{
    // Round stream (R.4.1): Z || per-layer (X[l+1] || G[l] || D[l]).
    const uint64_t z_bytes = static_cast<uint64_t>(p.n_q) * p.d_head;
    const uint64_t x_bytes = static_cast<uint64_t>(p.b_seq) * p.d_model;
    const uint64_t g_bytes = static_cast<uint64_t>(p.b_seq) * p.d_model;
    const uint64_t d_bytes = static_cast<uint64_t>(p.d_model) * p.d_model;
    const uint64_t stream_per_round =
        z_bytes + static_cast<uint64_t>(p.L_lyr) * (x_bytes + g_bytes + d_bytes);
    const uint64_t stream_bytes = static_cast<uint64_t>(p.rounds) * stream_per_round;
    const uint32_t t_leaf = p.T_leaf == 0 ? 1u : p.T_leaf;
    const uint64_t leaf_count = (stream_bytes + t_leaf - 1) / t_leaf;

    // Cheap SHA256d-per-leaf proxy in "MAC equivalents" (order-of-magnitude).
    constexpr uint64_t kHashWorkPerLeaf = 256;
    const uint64_t hash_work = leaf_count * kHashWorkPerLeaf;
    const uint64_t macs = TotalRCEpisodeMacs(p);
    if (macs == 0) {
        if (reason) *reason = "TotalRCEpisodeMacs==0";
        return false;
    }
    // f3 > 5% ⇔ 100 * hash_work > 5 * macs ⇔ 20 * hash_work > macs
    if (hash_work > macs / 20) {
        if (reason) *reason = "f3 hash/MAC ratio exceeds 5%";
        return false;
    }
    return true;
}

RCEpisodeParams DeriveDims(const RCScale& scale)
{
    RCEpisodeParams out;
    out.rounds = kRCRounds;
    out.d_head = kRCHeadDim;
    out.L_lyr = kRCLayers;
    out.d_model = kRCModelDim;
    out.T_leaf = kRCTileLeafBytes;
    out.n_q = kRCQueryPerHead * out.d_head;
    // n_ctx = round32(W_res / (2 * d_head))
    const uint64_t n_ctx_raw = scale.W_res / (2ull * out.d_head);
    out.n_ctx = RoundToMultipleOf32(n_ctx_raw == 0 ? 1 : n_ctx_raw);
    // b_seq = round32(W_cap / (2 * d_model * L_lyr))
    const uint64_t denom = 2ull * out.d_model * out.L_lyr;
    const uint64_t b_seq_raw = denom == 0 ? 0 : scale.W_cap / denom;
    out.b_seq = RoundToMultipleOf32(b_seq_raw == 0 ? 1 : b_seq_raw);
    return out;
}

} // namespace

uint32_t RoundToMultipleOf32(uint64_t x)
{
    if (x == 0) return 32;
    uint64_t rounded = ((x + 16) / 32) * 32;
    if (rounded == 0) rounded = 32;
    if (rounded > UINT32_MAX) rounded = UINT32_MAX - (UINT32_MAX % 32);
    return static_cast<uint32_t>(rounded);
}

RCScale RCScaleForHeight(int32_t height, const Consensus::Params& p, const RCBrakeFn& brake)
{
    if constexpr (!kRCGrowthScheduleEnabled) {
        (void)height; (void)p; (void)brake;
        return RCScale{kRCW0Res, kRCW0Cap};
    }
    if (height < p.nMatMulRCHeight || p.nRCScaleEpochBlocks <= 0) {
        return RCScale{kRCW0Res, kRCW0Cap};
    }

    const int32_t epoch = (height - p.nMatMulRCHeight) / p.nRCScaleEpochBlocks;
    // Brake path is chain-state dependent — do not memoize when a brake is set.
    if (brake) {
        return ComputeScaleForEpoch(epoch, p, brake);
    }

    const ScaleCacheKey key{epoch, HashGrowthTables(p)};
    {
        std::lock_guard<std::mutex> lock(g_scale_cache_mu);
        const auto it = g_scale_cache.find(key);
        if (it != g_scale_cache.end()) return it->second;
    }

    RCScale s = ComputeScaleForEpoch(epoch, p, /*brake=*/{});
    {
        std::lock_guard<std::mutex> lock(g_scale_cache_mu);
        g_scale_cache.emplace(key, s);
    }
    return s;
}

bool CheckRCEpochInvariants(const RCEpisodeParams& p, std::string* reason)
{
    if (!ValidateRCEpisodeParams(p)) {
        if (reason) *reason = "ValidateRCEpisodeParams failed";
        return false;
    }
    if (2304ull * kRCSegLen >= (1ull << 62)) {
        if (reason) *reason = "2304*kRCSegLen >= 2^62";
        return false;
    }
    // C/G floor: (n_q * n_ctx * d_head reads) / (2 * n_ctx * d_head fill) = n_q/2 >= 64
    // → n_q >= 128 (anti-amortization B1).
    if (p.n_q < 128) {
        if (reason) *reason = "C/G floor: n_q < 128 (reuse factor n_q/2 < 64)";
        return false;
    }
    if (!CheckF3Bound(p, reason)) return false;
    return true;
}

RCEpisodeParams EpisodeParamsFromScale(const RCScale& scale, const RCEpisodeParams* prior_ok)
{
    // Zero / absurd dials are not reachable via the ratchet; treat as invariant
    // failure so tests can exercise prior_ok fallback (T-FP7).
    if (scale.W_res == 0 || scale.W_cap == 0) {
        if (prior_ok != nullptr) return *prior_ok;
        RCEpisodeParams base = DeriveDims(RCScale{kRCW0Res, kRCW0Cap});
        if (!ValidateRCEpisodeParams(base) && prior_ok != nullptr) return *prior_ok;
        return base;
    }

    RCEpisodeParams derived = DeriveDims(scale);

    if (CheckRCEpochInvariants(derived)) {
        return derived;
    }
    if (prior_ok != nullptr) {
        return *prior_ok;
    }
    // Best-effort base epoch-0 dims that ValidateRCEpisodeParams accepts.
    RCEpisodeParams base = DeriveDims(RCScale{kRCW0Res, kRCW0Cap});
    if (!ValidateRCEpisodeParams(base) && prior_ok != nullptr) return *prior_ok;
    return base;
}

RCEpisodeParams ConsensusRCEpisodeParamsForHeight(int32_t height, const Consensus::Params& p,
                                                  const RCBrakeFn& brake)
{
    RCEpisodeParams ok = EpisodeParamsFromScale(RCScale{kRCW0Res, kRCW0Cap});
    if constexpr (!kRCGrowthScheduleEnabled) {
        (void)height; (void)p; (void)brake;
        return ok;
    }
    if (height < p.nMatMulRCHeight || p.nRCScaleEpochBlocks <= 0) {
        return ok;
    }

    const int32_t epoch = (height - p.nMatMulRCHeight) / p.nRCScaleEpochBlocks;
    for (int32_t e = 0; e <= epoch; ++e) {
        const int32_t h_e = p.nMatMulRCHeight + e * p.nRCScaleEpochBlocks;
        const RCScale s = RCScaleForHeight(h_e, p, brake);
        ok = EpisodeParamsFromScale(s, &ok);
    }
    return ok;
}

namespace {

/** Mean GetBlockProof over [h_lo, h_hi] inclusive, walking tip→ancestors.
 *  Returns 0 if the window is empty or tip does not cover it. */
arith_uint256 MeanWorkInHeightRange(const CBlockIndex* tip, int32_t h_lo, int32_t h_hi)
{
    if (tip == nullptr || h_hi < h_lo) return arith_uint256{0};
    if (tip->nHeight < h_hi) return arith_uint256{0};

    const CBlockIndex* end = tip->GetAncestor(h_hi);
    if (end == nullptr) return arith_uint256{0};

    arith_uint256 sum{0};
    uint64_t count = 0;
    for (const CBlockIndex* p = end; p != nullptr && p->nHeight >= h_lo; p = p->pprev) {
        sum += GetBlockProof(*p);
        ++count;
        if (p->nHeight == h_lo) break;
    }
    if (count == 0) return arith_uint256{0};
    return sum / count;
}

/** Trailing ~1 year of blocks at 144 blk/day (90s spacing). */
constexpr int32_t kRCBrakeTrailBlocks = 365 * 144; // 52560

} // namespace

bool BrakeAllowsStep(int32_t epoch_index, const Consensus::Params& p, const CBlockIndex* tip)
{
    // Step-1 / unit tests: no chain → never pause.
    if (tip == nullptr) return true;
    if (p.nRCScaleEpochBlocks <= 0) return true;
    if (p.nMatMulRCHeight == std::numeric_limits<int32_t>::max()) return true;
    if (!p.IsMatMulRCActive(tip->nHeight)) return true;
    if (epoch_index < 0) return true;

    const int32_t E = p.nRCScaleEpochBlocks;
    // Closing window for step e: heights [H0 + e*E, H0 + (e+1)*E - 1].
    const int32_t h_lo = p.nMatMulRCHeight + epoch_index * E;
    const int32_t h_hi = h_lo + E - 1;
    if (tip->nHeight < h_hi) {
        // Incomplete closing window — do not pause (insufficient signal).
        return true;
    }

    const arith_uint256 D_now = MeanWorkInHeightRange(tip, h_lo, h_hi);
    if (D_now == 0) return true;

    // Trailing ~1yr of completed epoch means ending at epoch_index.
    const int32_t trail_epochs =
        std::max(1, (kRCBrakeTrailBlocks + E - 1) / E);
    arith_uint256 D_ref{0};
    for (int32_t k = 0; k < trail_epochs; ++k) {
        const int32_t e = epoch_index - k;
        if (e < 0) break;
        const int32_t lo = p.nMatMulRCHeight + e * E;
        const int32_t hi = lo + E - 1;
        const arith_uint256 D = MeanWorkInHeightRange(tip, lo, hi);
        if (D > D_ref) D_ref = D;
    }
    if (D_ref == 0) return true;

    // Allow growth iff D_now >= (1 - δ/100) * D_ref.
    int32_t delta = p.nRCBrakeDeltaPct;
    if (delta < 0) delta = 0;
    if (delta > 100) delta = 100;
    // threshold = D_ref * (100 - delta) / 100
    const arith_uint256 threshold = (D_ref * (100 - static_cast<uint32_t>(delta))) / 100;
    return D_now >= threshold;
}

RCEpisodeParams ConsensusRCEpisodeParamsForHeight(int32_t height, const Consensus::Params& p,
                                                  const CBlockIndex* pprev)
{
    RCBrakeFn brake;
    if (pprev != nullptr) {
        brake = [&p, pprev](int32_t epoch_index) -> bool {
            return BrakeAllowsStep(epoch_index, p, pprev);
        };
    }
    return ConsensusRCEpisodeParamsForHeight(height, p, brake);
}

} // namespace matmul::v4::rc
