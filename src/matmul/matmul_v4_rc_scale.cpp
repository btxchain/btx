// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_scale.h>

#include <consensus/params.h>

#include <cassert>
#include <cstdint>
#include <mutex>
#include <string>
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

/**
 * Committed round-stream byte count for one episode (all rounds).
 * Layout matches RunEpisode / RoundMerkleStream (R.4.1):
 *   per round: Z_int8 ‖ Σ_layer (X ‖ G ‖ D_int8)
 * plus, only when kRCSegmentLeavesEnabled, the LE int64 Z/D segment partials.
 * STOP-AND-STABILIZE parks segment leaves OFF — this estimate respects that.
 */
uint64_t EstimateRCTranscriptStreamBytes(const RCEpisodeParams& p)
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

    return static_cast<uint64_t>(p.rounds) * per_round;
}

/**
 * Epoch assert f3 ≤ 5% (R.7.5 / B5).
 *
 * Uses the ACTUAL serialized transcript byte estimate (leaf_count × T_leaf),
 * including the parked-off segment-leaf policy above. Then forms an estimated
 * hash wall-share from that leaf count and TotalRCEpisodeMacs.
 *
 * This is NOT measured wall time. Do not treat the relative-cost constant as a
 * "MAC equivalent" and do not claim the ratio is a wall-clock measurement —
 * real phase3_s / (phase1+phase2+phase3) comes from matmul-v4-rc-harness /
 * phase-split evidence. This gate is only a structural sanity check so growth
 * cannot mint an episode whose Merkle transcript dominates MAC work.
 */
bool CheckF3Bound(const RCEpisodeParams& p, std::string* reason)
{
    const uint64_t stream_bytes = EstimateRCTranscriptStreamBytes(p);
    const uint32_t t_leaf = p.T_leaf == 0 ? 1u : p.T_leaf;
    const uint64_t leaf_count =
        stream_bytes == 0 ? 0 : (stream_bytes + t_leaf - 1) / t_leaf;
    // Padded Merkle budget: every leaf commits T_leaf bytes (partial final leaf
    // is zero-padded). This is the serialized transcript byte estimate.
    const uint64_t transcript_bytes = leaf_count * static_cast<uint64_t>(t_leaf);

    const uint64_t macs = TotalRCEpisodeMacs(p);
    if (macs == 0) {
        if (reason) *reason = "TotalRCEpisodeMacs==0";
        return false;
    }

    // Relative cost units for one SHA256d leaf hash vs one int8 MAC on the
    // reference miner class. ESTIMATE only — not silicon rates, not wall ns,
    // not "MAC equivalents" pretending to be time.
    constexpr uint64_t kHashRelativeCostPerLeaf = 256;
    const uint64_t hash_cost = leaf_count * kHashRelativeCostPerLeaf;
    // Estimated share = hash_cost / (hash_cost + macs). Fail if share > 5%:
    //   hash_cost / (hash_cost + macs) > 1/20
    // ⇔ 20 * hash_cost > hash_cost + macs
    // ⇔ 19 * hash_cost > macs
    // (equivalent check used below avoids overflow on hash_cost + macs).
    if (hash_cost > macs / 19) {
        if (reason) {
            *reason = "estimated f3 hash wall-share exceeds 5% (transcript_bytes=" +
                      std::to_string(transcript_bytes) + ", leaves=" +
                      std::to_string(leaf_count) + ", macs=" + std::to_string(macs) +
                      "; not measured wall time)";
        }
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

bool BrakeAllowsStep(int32_t epoch_index, const Consensus::Params& p, const CBlockIndex* tip)
{
    // FINAL-FORM A3 / Stage F6: chainwork brake is OMITTED.
    // Growth is already parked via kRCGrowthScheduleEnabled=false. Never
    // half-wire CBlockIndex into one path only — always allow (no pause).
    // Prior mean-GetBlockProof implementation lived here; reintroduce only with
    // full CBlockIndex threading + reorg-safe epoch-boundary cache (F6).
    (void)epoch_index;
    (void)p;
    (void)tip;
    return true;
}

RCEpisodeParams ConsensusRCEpisodeParamsForHeight(int32_t height, const Consensus::Params& p,
                                                  const CBlockIndex* pprev)
{
    // A3 / F6: do not wire the OMITTED chainwork brake through pprev.
    (void)pprev;
    return ConsensusRCEpisodeParamsForHeight(height, p, RCBrakeFn{});
}

} // namespace matmul::v4::rc
