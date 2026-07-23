// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_RESIDENCY_PLAN_H
#define BTX_MATMUL_MATMUL_V4_RC_RESIDENCY_PLAN_H

#include <matmul/matmul_v4_rc_accel_policy.h>

#include <cstdint>
#include <string>

// ENC_RC resident-vs-streamed VRAM planner (RTX PRO 6000 Blackwell workstation
// path). PURE host logic — no CUDA, unit-testable without a device, mirroring
// the backend_capabilities_v4 ClassifyCudaDevice pure-predicate style.
//
// Rationale (RTX PRO 6000 Blackwell, GB202, 96 GB GDDR7):
//   The RTX PRO 6000's differentiator vs a 32 GB RTX 5090 is that its 96 GB can
//   hold the full ~48 GiB (V2 expanded int8) / ~51 GiB (V3 packed) episode
//   working set DEVICE-RESIDENT, so it runs the resident fast path instead of
//   the streamed/paged path a 32 GB card is forced into. This is the single
//   biggest RTX-PRO-6000-specific optimization.
//
// The plan is NON-consensus provenance only. Digests MUST be byte-identical
// across Resident / Streamed for the same committed work (see
// RCAccelResidencyMode). This planner never changes the int64 reference, the
// portable Ozaki reference, heights, or GKR. It only decides how the working
// set is staged and records that choice.
//
// Fail-closed: when total/free VRAM are unknown (0), or the working set does
// not fit with headroom, the plan degrades to Streamed. Callers that cannot
// stream must treat a non-resident plan on an oversized working set as a
// capacity-short refusal (safe fallback), never as a wrong-digest fast path.

namespace matmul::v4::rc {

/**
 * Total-VRAM floor that marks a "large-VRAM resident-class" card. The RTX PRO
 * 6000 Blackwell (96 GB) and datacenter parts clear it; a 24/32 GB consumer
 * card (RTX 5090 = 32 GB) does not. Set at 64 GiB so the ~48 GiB V2 expanded /
 * ~51 GiB V3 packed resident working set fits with headroom, while consumer
 * cards fall to the Streamed policy class. NON-consensus (staging policy only).
 */
inline constexpr uint64_t kRCResidentVramFloorBytes = 64ull << 30;

/**
 * Absolute reserve floor left free even on a large card: CUDA context, cuBLASLt
 * workspace, allocator fragmentation, the Q-batch state/acc slots and barrier
 * tables that are NOT part of the bank arena's dominant term.
 */
inline constexpr uint64_t kRCResidentHeadroomBytesFloor = 4ull << 30; // 4 GiB

/** Additional proportional headroom (fraction of total VRAM). */
inline constexpr double kRCResidentHeadroomFraction = 0.06; // +6% of total

/** Effective headroom = max(floor, fraction · total). */
[[nodiscard]] uint64_t RCResidentHeadroomBytes(uint64_t total_vram_bytes);

/**
 * Resident-vs-streamed decision for one episode arena.
 *
 *   mode              : Resident iff the card is resident-class AND the working
 *                       set fits with headroom; else Streamed.
 *   resident_capable  : total VRAM >= kRCResidentVramFloorBytes (card class).
 *   working_set_fits  : working_set + headroom <= free VRAM (physical fit).
 *   reason            : machine-readable token (see .cpp).
 */
struct RCResidencyPlan {
    RCAccelResidencyMode mode{RCAccelResidencyMode::Streamed};
    bool resident_capable{false};
    bool working_set_fits{false};
    uint64_t working_set_bytes{0};
    uint64_t headroom_bytes{0};
    uint64_t free_vram_bytes{0};
    uint64_t total_vram_bytes{0};
    std::string reason;
};

/**
 * Decide staging for a `working_set_bytes` arena on a device reporting
 * `free_vram_bytes` free of `total_vram_bytes` total (e.g. from cudaMemGetInfo
 * + cudaDeviceProp::totalGlobalMem). Pure; safe with all-zero inputs.
 *
 * Fail-closed ordering:
 *   working_set_bytes == 0                → Streamed "streamed:degenerate_working_set"
 *   total==0 || free==0 (unknown VRAM)    → Streamed "streamed:vram_unknown"
 *   !working_set_fits                     → Streamed "streamed:capacity_short"
 *   fits but total < floor (small card)   → Streamed "streamed:small_vram_card"
 *   fits and total >= floor (large card)  → Resident "resident:large_vram_fits"
 */
[[nodiscard]] RCResidencyPlan PlanRCResidency(uint64_t working_set_bytes,
                                              uint64_t free_vram_bytes,
                                              uint64_t total_vram_bytes);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_RESIDENCY_PLAN_H
