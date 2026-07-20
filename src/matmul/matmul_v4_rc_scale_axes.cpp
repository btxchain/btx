// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_scale_axes.h>

#include <matmul/matmul_v4_rc_scale.h>

#include <consensus/params.h>

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace matmul::v4::rc {
namespace {

uint64_t RoundBytesToMultipleOf32(uint64_t x)
{
    if (x == 0) return 0;
    return ((x + 16) / 32) * 32;
}

uint64_t MulQ16Round32(uint64_t w, int64_t g_q16)
{
    if (g_q16 <= 0) return w;
    const unsigned __int128 prod =
        static_cast<unsigned __int128>(w) * static_cast<uint64_t>(g_q16) + (1ull << 15);
    const uint64_t scaled = static_cast<uint64_t>(prod >> 16);
    return RoundBytesToMultipleOf32(scaled);
}

uint64_t ClampHardCap(uint64_t w, uint64_t hard_cap)
{
    return w < hard_cap ? w : hard_cap;
}

/**
 * Pause-only + monotonic ratchet (F4/F5):
 *   - g_q16 < 1.0 → pause (leave dial unchanged; never shrink)
 *   - apply growth, clamp hard cap, then keep max(old, grown)
 * Never assert; never wrap.
 */
uint64_t ApplyPauseOnly(uint64_t w, int64_t g_q16, uint64_t hard_cap)
{
    if (g_q16 < kRCAxisQ16One) return w; // pause / misconfigured shrink step
    const uint64_t grown = ClampHardCap(MulQ16Round32(w, g_q16), hard_cap);
    return grown < w ? w : grown;
}

struct AxisCacheKey {
    int32_t epoch{0};
    int32_t epoch_blocks{0};
    int32_t activation{0};
    bool operator==(const AxisCacheKey& o) const
    {
        return epoch == o.epoch && epoch_blocks == o.epoch_blocks && activation == o.activation;
    }
};

struct AxisCacheKeyHash {
    size_t operator()(const AxisCacheKey& k) const
    {
        uint64_t h = static_cast<uint64_t>(static_cast<uint32_t>(k.epoch));
        h ^= static_cast<uint64_t>(static_cast<uint32_t>(k.epoch_blocks)) * 0x9e3779b97f4a7c15ull;
        h ^= static_cast<uint64_t>(static_cast<uint32_t>(k.activation)) * 0xbf58476d1ce4e5b9ull;
        return static_cast<size_t>(h);
    }
};

std::mutex g_axis_cache_mu;
std::unordered_map<AxisCacheKey, RCThreeAxisScale, AxisCacheKeyHash> g_axis_cache;

/**
 * Compute dials for a given epoch index by walking steps 0..epoch-1.
 * Callers memoize the result so epoch-boundary evaluation is O(1) after the
 * first touch for that epoch (F3). No chainwork brake (F6) → cache is
 * reorg-safe: keys are height/epoch schedule knobs only (tip ignored).
 */
RCThreeAxisScale ComputeAxesForEpoch(int32_t epoch)
{
    RCThreeAxisScale s{kRCAxisW0State, kRCAxisC0Local, kRCAxisX0Exchange};
    if (epoch <= 0) return s;

    for (int32_t e = 0; e < epoch; ++e) {
        int64_t g_w = kRCAxisQ16One;
        int64_t g_c = kRCAxisQ16One;
        int64_t g_x = kRCAxisQ16One;
        if (e >= 0 && static_cast<size_t>(e) < kRCAxisGrowthTableLen) {
            g_w = kRCAxisGrowthStateQ16[static_cast<size_t>(e)];
            g_c = kRCAxisGrowthLocalQ16[static_cast<size_t>(e)];
            g_x = kRCAxisGrowthExchangeQ16[static_cast<size_t>(e)];
        }
        s.W_state = ApplyPauseOnly(s.W_state, g_w, kRCAxisHardCapState);
        s.C_local = ApplyPauseOnly(s.C_local, g_c, kRCAxisHardCapLocal);
        s.X_exchange = ApplyPauseOnly(s.X_exchange, g_x, kRCAxisHardCapExchange);
    }
    return s;
}

RCEpisodeParams DeriveDimsFromAxes(const RCThreeAxisScale& scale)
{
    // Proxy mapping onto today's RCEpisodeParams surface (pre-Stage-C wire).
    // Dimensionless ratios (n_q/d_head, L_lyr, d_model, rounds) stay frozen
    // until Stage G silicon freezes them (F2) — PROVISIONAL.
    RCEpisodeParams out;
    out.rounds = kRCRounds;
    out.d_head = kRCHeadDim;
    out.L_lyr = kRCLayers;
    out.d_model = kRCModelDim;
    out.T_leaf = kRCTileLeafBytes;
    out.n_q = kRCQueryPerHead * out.d_head;

    // W_state → n_ctx proxy (same formula as W_res / (2 * d_head)).
    const uint64_t n_ctx_raw = scale.W_state / (2ull * out.d_head);
    out.n_ctx = RoundToMultipleOf32(n_ctx_raw == 0 ? 1 : n_ctx_raw);

    // C_local does not yet resize matrices; keep b_seq at epoch-0 until Stage C
    // exposes a local-work dial. X_exchange similarly recorded-only while
    // kRCThreeAxisScheduleEnabled is false / ratios PROVISIONAL.
    out.b_seq = kRCBatchSeq;
    (void)scale.C_local;
    (void)scale.X_exchange;
    return out;
}

/** Serialized transcript byte estimate (leaf_count × T_leaf), parked segment policy. */
uint64_t EstimateTranscriptBytesLocal(const RCEpisodeParams& p)
{
    const uint64_t z_bytes = static_cast<uint64_t>(p.n_q) * p.d_head;
    const uint64_t x_bytes = static_cast<uint64_t>(p.b_seq) * p.d_model;
    const uint64_t g_bytes = static_cast<uint64_t>(p.b_seq) * p.d_model;
    const uint64_t d_bytes = static_cast<uint64_t>(p.d_model) * p.d_model;
    uint64_t per_round =
        z_bytes + static_cast<uint64_t>(p.L_lyr) * (x_bytes + g_bytes + d_bytes);
    if constexpr (kRCSegmentLeavesEnabled) {
        const uint64_t z_seg_bytes =
            static_cast<uint64_t>(RCNumSegs(p.n_ctx)) * RCSegZBytes(p);
        const uint64_t d_seg_bytes =
            static_cast<uint64_t>(RCNumSegs(p.b_seq)) * RCSegDBytes(p) *
            static_cast<uint64_t>(p.L_lyr);
        per_round += z_seg_bytes + d_seg_bytes;
    }
    const uint64_t stream_bytes = static_cast<uint64_t>(p.rounds) * per_round;
    const uint32_t t_leaf = p.T_leaf == 0 ? 1u : p.T_leaf;
    const uint64_t leaf_count =
        stream_bytes == 0 ? 0 : (stream_bytes + t_leaf - 1) / t_leaf;
    return leaf_count * static_cast<uint64_t>(t_leaf);
}

} // namespace

uint64_t EstimateRCStreamedPeakBytes(const RCEpisodeParams& p)
{
    // Structural Streamed peak: one X page + one G temp + W + one KV bank page
    // proxy + Q/Z tiles + a small stream ring. NOT measured RSS.
    const uint64_t x = static_cast<uint64_t>(p.b_seq) * p.d_model;
    const uint64_t w = static_cast<uint64_t>(p.d_model) * p.d_model;
    const uint64_t kv = static_cast<uint64_t>(p.n_ctx) * p.d_head * 2ull;
    const uint64_t qz = static_cast<uint64_t>(p.n_q) * p.d_head * 2ull;
    const uint64_t ring = static_cast<uint64_t>(p.T_leaf == 0 ? 1u : p.T_leaf) * 4ull;
    return x * 2ull + w + kv + qz + ring;
}

RCThreeAxisScale RCThreeAxisScaleForHeight(int32_t height, const Consensus::Params& p,
                                           const CBlockIndex* /*tip*/)
{
    if constexpr (!kRCThreeAxisScheduleEnabled) {
        (void)height;
        (void)p;
        return RCThreeAxisScale{kRCAxisW0State, kRCAxisC0Local, kRCAxisX0Exchange};
    }
    if (height < p.nMatMulRCHeight || p.nRCScaleEpochBlocks <= 0) {
        return RCThreeAxisScale{kRCAxisW0State, kRCAxisC0Local, kRCAxisX0Exchange};
    }

    const int32_t epoch = (height - p.nMatMulRCHeight) / p.nRCScaleEpochBlocks;
    const AxisCacheKey key{epoch, p.nRCScaleEpochBlocks, p.nMatMulRCHeight};
    {
        std::lock_guard<std::mutex> lock(g_axis_cache_mu);
        const auto it = g_axis_cache.find(key);
        if (it != g_axis_cache.end()) return it->second;
    }

    RCThreeAxisScale s = ComputeAxesForEpoch(epoch);
    {
        std::lock_guard<std::mutex> lock(g_axis_cache_mu);
        g_axis_cache.emplace(key, s);
    }
    return s;
}

bool CheckRCThreeAxisInvariants(const RCThreeAxisScale& scale, const RCEpisodeParams& derived,
                                std::string* reason)
{
    // --- hard caps on dials ---
    if (scale.W_state == 0 || scale.C_local == 0 || scale.X_exchange == 0) {
        if (reason) *reason = "zero three-axis dial";
        return false;
    }
    if (scale.W_state > kRCAxisHardCapState) {
        if (reason) *reason = "W_state exceeds hard cap";
        return false;
    }
    if (scale.C_local > kRCAxisHardCapLocal) {
        if (reason) *reason = "C_local exceeds hard cap";
        return false;
    }
    if (scale.X_exchange > kRCAxisHardCapExchange) {
        if (reason) *reason = "X_exchange exceeds hard cap";
        return false;
    }

    // --- shared epoch asserts (ValidateRCEpisodeParams, n_q floor, f3/transcript) ---
    if (!CheckRCEpochInvariants(derived, reason)) {
        return false;
    }

    // Accumulator headroom on derived n_ctx (same 2304·n bound as §R.1.4).
    if (static_cast<uint64_t>(derived.n_ctx) * 2304ull >= (1ull << 62)) {
        if (reason) *reason = "2304·n_ctx >= 2^62";
        return false;
    }

    // Fixed work: MAC formula must be positive and match TotalRCEpisodeMacs.
    const uint64_t macs = TotalRCEpisodeMacs(derived);
    if (macs == 0) {
        if (reason) *reason = "fixed work TotalRCEpisodeMacs==0";
        return false;
    }
    const uint64_t expected =
        static_cast<uint64_t>(derived.rounds) *
        (2ull * derived.n_q * derived.n_ctx * derived.d_head +
         3ull * derived.L_lyr * static_cast<uint64_t>(derived.b_seq) * derived.d_model *
             derived.d_model);
    if (macs != expected) {
        if (reason) *reason = "fixed work MAC formula mismatch";
        return false;
    }

    // Transcript / proof-size structural budget (not silicon wall time).
    const uint64_t transcript_bytes = EstimateTranscriptBytesLocal(derived);
    if (transcript_bytes > kRCAxisTranscriptHardCapBytes) {
        if (reason) {
            *reason = "transcript/proof-size estimate exceeds hard cap (" +
                      std::to_string(transcript_bytes) + " bytes)";
        }
        return false;
    }

    // Streamed peak memory estimate — must leave the bounded-memory path viable.
    const uint64_t streamed_peak = EstimateRCStreamedPeakBytes(derived);
    if (streamed_peak > kRCAxisStreamedPeakHardCap) {
        if (reason) {
            *reason = "Streamed peak mem estimate exceeds hard cap (" +
                      std::to_string(streamed_peak) + " bytes)";
        }
        return false;
    }

    return true;
}

RCEpisodeParams EpisodeParamsFromThreeAxis(const RCThreeAxisScale& scale,
                                           const RCEpisodeParams* prior_ok)
{
    RCEpisodeParams derived = DeriveDimsFromAxes(scale);
    if (CheckRCThreeAxisInvariants(scale, derived)) {
        return derived;
    }
    // Checked fallback to previous dims (F4/F5) — never assert.
    if (prior_ok != nullptr) return *prior_ok;
    RCEpisodeParams base = DeriveDimsFromAxes(
        RCThreeAxisScale{kRCAxisW0State, kRCAxisC0Local, kRCAxisX0Exchange});
    return base;
}

RCEpisodeParams ConsensusRCThreeAxisParamsForHeight(int32_t height, const Consensus::Params& p,
                                                    const CBlockIndex* tip)
{
    RCEpisodeParams ok = EpisodeParamsFromThreeAxis(
        RCThreeAxisScale{kRCAxisW0State, kRCAxisC0Local, kRCAxisX0Exchange});
    if constexpr (!kRCThreeAxisScheduleEnabled) {
        (void)height;
        (void)p;
        (void)tip;
        return ok;
    }
    if (height < p.nMatMulRCHeight || p.nRCScaleEpochBlocks <= 0) {
        return ok;
    }

    const int32_t epoch = (height - p.nMatMulRCHeight) / p.nRCScaleEpochBlocks;
    for (int32_t e = 0; e <= epoch; ++e) {
        const int32_t h_e = p.nMatMulRCHeight + e * p.nRCScaleEpochBlocks;
        const RCThreeAxisScale s = RCThreeAxisScaleForHeight(h_e, p, tip);
        ok = EpisodeParamsFromThreeAxis(s, &ok);
    }
    return ok;
}

} // namespace matmul::v4::rc
