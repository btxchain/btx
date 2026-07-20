// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_SCALE_H
#define BTX_MATMUL_MATMUL_V4_RC_SCALE_H

#include <matmul/matmul_v4_rc.h>

#include <cstdint>
#include <functional>
#include <string>

class CBlockIndex;

namespace Consensus {
struct Params;
}

namespace matmul::v4::rc {

/** Class A — scheduled scale dials (epoch-0 / base). */
inline constexpr uint64_t kRCW0Res = 192ull * 1024 * 1024; // == 2 * kRCContextLen * kRCHeadDim
inline constexpr uint64_t kRCW0Cap = 2ull * 1024 * 1024 * 1024; // == 2 * kRCBatchSeq * kRCModelDim * kRCLayers

/** Class B — frozen n_q / d_head ratio (n_q = kRCQueryPerHead * d_head). */
inline constexpr uint32_t kRCQueryPerHead = 4;

// kRCSegLen is defined in matmul_v4_rc.h (Class C eternal; included above).
static_assert(2304ull * kRCSegLen < (1ull << 62),
              "2304·kRCSegLen must fit in signed int64 headroom (< 2^62)");

struct RCScale {
    uint64_t W_res{kRCW0Res};
    uint64_t W_cap{kRCW0Cap};
};

/** Round to nearest multiple of 32 (H13). Ties round half-up. Asserts x > 0. */
[[nodiscard]] uint32_t RoundToMultipleOf32(uint64_t x);

/**
 * Pure schedule+ratchet WITHOUT brake (all steps applied). For unit tests + Step1.
 * When brake_fn is null/empty, always apply growth. When provided, call
 * brake_fn(epoch_index) before applying step e (true = apply).
 */
using RCBrakeFn = std::function<bool(int32_t epoch_index)>;

[[nodiscard]] RCScale RCScaleForHeight(int32_t height, const Consensus::Params& p,
                                       const RCBrakeFn& brake = {});

/**
 * §2a one-sided brake (pause-only — never accelerates or shrinks).
 * tip==nullptr OR RC inactive at tip → true (no pause) for Step-1 tests.
 * With tip: D_now = mean GetBlockProof over epoch e's closing window;
 * D_ref = max trailing ~1yr of per-epoch means; allow iff
 * D_now >= (1 - nRCBrakeDeltaPct/100) * D_ref. Pure: same tip → same bool.
 */
[[nodiscard]] bool BrakeAllowsStep(int32_t epoch_index, const Consensus::Params& p,
                                   const CBlockIndex* tip /* may be nullptr */);

/**
 * Build episode params from dials + frozen ratios. Epoch asserts (§5): on failure
 * returns prior_ok params (caller passes last good). If prior empty and asserts
 * fail, still return best-effort base epoch-0 dims that ValidateRCEpisodeParams
 * accepts.
 */
[[nodiscard]] RCEpisodeParams EpisodeParamsFromScale(const RCScale& scale,
                                                     const RCEpisodeParams* prior_ok = nullptr);

[[nodiscard]] bool CheckRCEpochInvariants(const RCEpisodeParams& p, std::string* reason = nullptr);

/** Full height→params with assert fallback. Pure schedule (no brake) unless brake given. */
[[nodiscard]] RCEpisodeParams ConsensusRCEpisodeParamsForHeight(
    int32_t height, const Consensus::Params& p, const RCBrakeFn& brake = {});

/** Height→params with §2a brake wired from chain tip (pprev may be nullptr → no pause). */
[[nodiscard]] RCEpisodeParams ConsensusRCEpisodeParamsForHeight(
    int32_t height, const Consensus::Params& p, const CBlockIndex* pprev);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_SCALE_H
