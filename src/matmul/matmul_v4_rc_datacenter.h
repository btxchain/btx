// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_DATACENTER_H
#define BTX_MATMUL_MATMUL_V4_RC_DATACENTER_H

#include <cstdint>
#include <string>

// ENC_RC / ENC_RC_COUPLED datacenter-advantage levers (B200/H200 vs 5090).
//
// Analysis lock (2026-07-21, Lever-B MX Extract, MatExpand w=1024 model):
//   B200:5090 throughput ≈ 2.3× (was ≈1.2× under ChaCha-cell Extract).
//   B200 rent ≈ 15× a 5090 → tensor-only leaves consumer ahead on blocks/$.
//   Do NOT claim ≥4× from GEMM width / Extract params alone.
//
// Correct default levers therefore push HBM + full-bank traffic + fabric
// exchange so Resident LLM-class nodes win economically while Streamed
// cheap cards remain consensus-valid but uneconomic. Heights stay INT32_MAX;
// GKR arbiter stays OFF. Env must never flip these (digest purity).

namespace matmul::v4::rc::dc {

/** Full-bank page schedule (12 pages / barrier×lobe). Digest-breaking vs legacy
 *  single-page. ON — required for ~12× bank traffic vs consumer Streamed. */
inline constexpr bool kRCCoupFullBankScheduleEnabled = true;
inline constexpr uint32_t kRCCoupPagesPerBarrierLobe = 12;

/** NVLink-shaped multi-row exchange domain in the all-to-all mix. ON — fabric
 *  pressure; digests absorb exchange_rows when Active(). */
inline constexpr bool kRCCoupMaterialExchangeEnabled = true;
/** Row tile for material exchange (sweep 64 / 128 / 256). */
inline constexpr uint32_t kRCCoupExchangeRowsDefault = 128;

/** Wire Stage F three-axis dials as the live scale surface (epoch-0 until
 *  nMatMulRCHeight; public height remains INT32_MAX). */
inline constexpr bool kRCThreeAxisScheduleWireEnabled = true;

inline constexpr uint32_t kRCMinerBatchQDefault = 32;
inline constexpr uint32_t kRCMinerBatchQMax = 256;
inline constexpr double kRCMxPackedBytesPerElem = 0.53125;

/** Packed-MX resident bank targets (GiB). Floor 48 matches MakeProduction
 *  768×8192²; 64 clears 5090 32 GiB; 80/96 are B200-class ladders. */
inline constexpr double kRCPackedBankTargetGiB[] = {48.0, 64.0, 80.0, 96.0};
inline constexpr size_t kRCPackedBankTargetGiBCount = 4;

/** Primary packed-bank floor used by Probe / docs (GiB). */
inline constexpr double kRCPackedBankPrimaryGiB = 48.0;

[[nodiscard]] bool RCCoupFullBankScheduleActive();
[[nodiscard]] bool RCCoupMaterialExchangeActive();
/** Compile-time only — NEVER reads getenv (consensus digest purity). */

struct RCDcStatus {
    bool full_bank_schedule{false};
    bool material_exchange{false};
    bool three_axis_wire{false};
    bool miner_batch_q_default_on{true};
    uint32_t miner_batch_q{kRCMinerBatchQDefault};
    uint32_t exchange_rows_default{kRCCoupExchangeRowsDefault};
    bool gkr_arbiter{false};
    bool cuda_episode_compiled{false};
    bool cuda_episode_ready{false};
    std::string arch_key;
    std::string deficit;
};

[[nodiscard]] RCDcStatus ProbeRCDcStatus();
[[nodiscard]] uint32_t BankPagesForPackedGiB(double gib, uint32_t lobe_width);

} // namespace matmul::v4::rc::dc

#endif // BTX_MATMUL_MATMUL_V4_RC_DATACENTER_H
