// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_SCALE_AXES_H
#define BTX_MATMUL_MATMUL_V4_RC_SCALE_AXES_H

#include <matmul/matmul_v4_rc.h>

#include <cstdint>
#include <string>

class CBlockIndex;

namespace Consensus {
struct Params;
}

namespace matmul::v4::rc {

/**
 * Stage F — three-axis scheduled scaling (PROVISIONAL, inert).
 *
 * Dials (final-form build spec Stage F1):
 *   W_state    — resident expert/state bytes
 *   C_local    — exact local tensor work units per barrier (proxy: MAC count)
 *   X_exchange — bytes exchanged per barrier × barrier count
 *
 * PROVISIONAL: all growth constants and dimensionless ratios are placeholders.
 * Ratios freeze ONLY after Stage G silicon evidence shows that local tensor
 * work, HBM traffic, and coherent-fabric exchange are each material and that
 * none dominates enough to make the other two decorative (F2).
 *
 * F6: chainwork brake OMITTED — schedule is height/epoch-only (not chain
 * history / reorg dependent). Do not reintroduce BrakeAllowsStep here.
 *
 * Default: kRCThreeAxisScheduleEnabled = false → always epoch-0 dials.
 * Independent of (and does not enable) kRCGrowthScheduleEnabled (§R.7 two-dial).
 */

/** Master enable for the three-axis schedule. Keep false until Stage I. */
inline constexpr bool kRCThreeAxisScheduleEnabled = false;

/** Epoch-0 / Class A base dials (PROVISIONAL — mirror §R.0 footprints). */
inline constexpr uint64_t kRCAxisW0State = 192ull * 1024 * 1024; // ~KV / expert bank
inline constexpr uint64_t kRCAxisC0Local = 1ull << 40;           // ~1 Ti MAC proxy / barrier-set
inline constexpr uint64_t kRCAxisX0Exchange = 256ull * 1024 * 1024; // ~256 MiB exchange budget

/** Absolute hard caps (PROVISIONAL). Growth pauses at the cap — never wraps. */
inline constexpr uint64_t kRCAxisHardCapState = 1ull << 33;     // 8 GiB
inline constexpr uint64_t kRCAxisHardCapLocal = 1ull << 46;     // MAC proxy ceiling
inline constexpr uint64_t kRCAxisHardCapExchange = 1ull << 34;  // 16 GiB exchange budget

/** Q16 identity (1.0). Used when the epoch index is past the growth table. */
inline constexpr int64_t kRCAxisQ16One = 65536;

/** PROVISIONAL decaying geometric (~1.10/yr-ish at Q16). Owner-set; not final. */
inline constexpr size_t kRCAxisGrowthTableLen = 40;
inline constexpr int64_t kRCAxisGrowthStateQ16[kRCAxisGrowthTableLen] = {
    68812, 68545, 68276, 68005, 67732, 67457, 67180, 66901, 66620, 66337,
    66052, 65765, 65476, 65185, 64892, 64597, 64300, 64001, 63700, 63397,
    63092, 62785, 62476, 62165, 61852, 61537, 61220, 60901, 60580, 60257,
    59932, 59605, 59276, 58945, 58612, 58277, 57940, 57601, 57260, 56917,
};
inline constexpr int64_t kRCAxisGrowthLocalQ16[kRCAxisGrowthTableLen] = {
    68812, 68545, 68276, 68005, 67732, 67457, 67180, 66901, 66620, 66337,
    66052, 65765, 65476, 65185, 64892, 64597, 64300, 64001, 63700, 63397,
    63092, 62785, 62476, 62165, 61852, 61537, 61220, 60901, 60580, 60257,
    59932, 59605, 59276, 58945, 58612, 58277, 57940, 57601, 57260, 56917,
};
inline constexpr int64_t kRCAxisGrowthExchangeQ16[kRCAxisGrowthTableLen] = {
    68000, 67700, 67400, 67100, 66800, 66500, 66200, 65900, 65600, 65300,
    65000, 64700, 64400, 64100, 63800, 63500, 63200, 62900, 62600, 62300,
    62000, 61700, 61400, 61100, 60800, 60500, 60200, 59900, 59600, 59300,
    59000, 58700, 58400, 58100, 57800, 57500, 57200, 56900, 56600, 56300,
};

struct RCThreeAxisScale {
    uint64_t W_state{kRCAxisW0State};
    uint64_t C_local{kRCAxisC0Local};
    uint64_t X_exchange{kRCAxisX0Exchange};
};

/**
 * O(1) per epoch-boundary evaluation (memoized). Height → epoch index, then
 * one cache lookup. No chainwork brake (F6). When the schedule is disabled,
 * always returns epoch-0 dials.
 *
 * Pure: same (height, params knobs that affect the table) → same dials.
 * `tip` is accepted for API symmetry with the two-dial path but is IGNORED
 * (brake omitted).
 */
[[nodiscard]] RCThreeAxisScale RCThreeAxisScaleForHeight(
    int32_t height, const Consensus::Params& p, const CBlockIndex* tip = nullptr);

/**
 * Derive a checked episode-shape proxy from the three dials.
 * On invariant failure: return *prior_ok when provided (checked fallback —
 * never assert). If prior empty, return best-effort epoch-0 proxy.
 *
 * NOTE: Until Stage C coupled dims are consensus-wired, this returns the
 * existing RCEpisodeParams epoch-0 shape when the schedule is disabled, and
 * only mutates n_ctx / b_seq proxies from W_state / C_local when enabled.
 * X_exchange is recorded for Stage G measurement; it does not yet alter
 * committed bytes while kRCThreeAxisScheduleEnabled is false.
 */
[[nodiscard]] RCEpisodeParams EpisodeParamsFromThreeAxis(
    const RCThreeAxisScale& scale, const RCEpisodeParams* prior_ok = nullptr);

[[nodiscard]] bool CheckRCThreeAxisInvariants(const RCThreeAxisScale& scale,
                                              const RCEpisodeParams& derived,
                                              std::string* reason = nullptr);

/**
 * Full height→params with checked prior-dim fallback. Inert while
 * kRCThreeAxisScheduleEnabled is false (always epoch-0).
 */
[[nodiscard]] RCEpisodeParams ConsensusRCThreeAxisParamsForHeight(
    int32_t height, const Consensus::Params& p, const CBlockIndex* tip = nullptr);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_SCALE_AXES_H
