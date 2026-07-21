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
 * Stage F — three-axis scheduled scaling.
 *
 * Dials (final-form build spec Stage F1):
 *   W_state    — resident expert/state / packed-bank bytes (HBM floor)
 *   C_local    — exact local tensor work units per barrier (proxy: MAC count)
 *   X_exchange — bytes exchanged per barrier × barrier count (fabric)
 *
 * Analysis lock (2026-07-21): B200:5090 ≈2.3× thruput vs ≈15× rent after
 * Lever-B MX Extract @ w=1024 — tensor params alone leave consumer ahead on
 * blocks/$. Epoch-0 dials are therefore HBM + fabric class (48 GiB / 4 GiB),
 * not the old 192 MiB / 256 MiB scaffolding zeros.
 *
 * Growth-table ratios remain PROVISIONAL (F2) until multi-vendor silicon
 * freezes them. F6: chainwork brake OMITTED.
 *
 * Master enable ON: epoch-0 dials are the live configured defaults. Public
 * nets still inert while nMatMulRCHeight=INT32_MAX. Independent of
 * kRCGrowthScheduleEnabled (§R.7 two-dial).
 */

/** Master enable for the three-axis schedule (epoch-0 live; growth height-gated). */
inline constexpr bool kRCThreeAxisScheduleEnabled = true;

/**
 * Epoch-0 / Class A base dials — LLM datacenter floor.
 * W_state matches MakeProductionRCCoupParams resident bank (768×8192² = 48 GiB)
 * so 32 GiB consumer cards cannot hold Resident and must Stream.
 */
inline constexpr uint64_t kRCAxisW0State = 48ull << 30;          // 48 GiB HBM bank
inline constexpr uint64_t kRCAxisC0Local = 12ull << 40;          // ~12 Ti MAC (× full-bank pages)
inline constexpr uint64_t kRCAxisX0Exchange = 4ull << 30;        // 4 GiB fabric exchange

/** Absolute hard caps. Growth pauses at the cap — never wraps. */
inline constexpr uint64_t kRCAxisHardCapState = 96ull << 30;     // 96 GiB (B200-class ladder)
inline constexpr uint64_t kRCAxisHardCapLocal = 1ull << 46;      // MAC proxy ceiling
inline constexpr uint64_t kRCAxisHardCapExchange = 16ull << 30;  // 16 GiB exchange budget

/**
 * Episode n_ctx proxy cap: W_state is the HBM bank target; RC episode matrix
 * dims stay within the frozen production episode footprint until Stage C
 * wires coupled bank sizing from W_state directly.
 */
inline constexpr uint64_t kRCAxisEpisodeCtxBytesCap = 192ull * 1024 * 1024;

/**
 * Streamed-mode peak-memory hard cap (F4). Growth that would push the
 * structural Streamed peak estimate above this MUST fallback to prior dims.
 * Kept at 8 GiB so cheap cards retain a viable Streamed path.
 */
inline constexpr uint64_t kRCAxisStreamedPeakHardCap = 8ull << 30; // 8 GiB
/**
 * Structural proof/transcript byte budget (PROVISIONAL, F4). Uses the
 * serialized transcript estimate (leaf_count × T_leaf), not a silicon
 * wall-time claim. Fail → prior-dim fallback.
 */
inline constexpr uint64_t kRCAxisTranscriptHardCapBytes = 1ull << 36; // 64 GiB

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

/**
 * Per-step epoch asserts (F4) — checked, never assert():
 *   accumulator bounds, transcript/proof-size, Streamed peak mem estimate,
 *   fixed work (MAC formula), hard caps → caller falls back to prior dims.
 */
[[nodiscard]] bool CheckRCThreeAxisInvariants(const RCThreeAxisScale& scale,
                                              const RCEpisodeParams& derived,
                                              std::string* reason = nullptr);

/**
 * Structural Streamed-mode peak-resident byte estimate (F4). Not measured RSS;
 * used only as a growth-step sanity gate so schedules cannot mint an episode
 * that excludes the bounded-memory path by construction.
 */
[[nodiscard]] uint64_t EstimateRCStreamedPeakBytes(const RCEpisodeParams& p);

/**
 * Full height→params with checked prior-dim fallback. Inert while
 * kRCThreeAxisScheduleEnabled is false (always epoch-0).
 */
[[nodiscard]] RCEpisodeParams ConsensusRCThreeAxisParamsForHeight(
    int32_t height, const Consensus::Params& p, const CBlockIndex* tip = nullptr);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_SCALE_AXES_H
