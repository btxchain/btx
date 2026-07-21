// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_DATACENTER_H
#define BTX_MATMUL_MATMUL_V4_RC_DATACENTER_H

#include <cstdint>
#include <string>

// ENC_RC / ENC_RC_COUPLED datacenter-advantage levers (B200/H200 vs 5090).
// Research defaults 2026-07-21. Consensus-breaking flags stay FALSE until Stage G.
// Page selection: matmul_v4_rc_coupled.h SelectCoupledBankPageIds.
// Heights remain INT32_MAX; GKR arbiter stays OFF.

namespace matmul::v4::rc::dc {

inline constexpr bool kRCCoupFullBankScheduleEnabled = false;
inline constexpr uint32_t kRCCoupPagesPerBarrierLobe = 12;
inline constexpr bool kRCCoupMaterialExchangeEnabled = false;
inline constexpr uint32_t kRCCoupExchangeRowsDefault = 128;
inline constexpr bool kRCThreeAxisScheduleWireEnabled = false;

inline constexpr uint32_t kRCMinerBatchQDefault = 32;
inline constexpr uint32_t kRCMinerBatchQMax = 256;
inline constexpr double kRCMxPackedBytesPerElem = 0.53125;
inline constexpr double kRCPackedBankTargetGiB[] = {40.0, 56.0, 72.0, 96.0};
inline constexpr size_t kRCPackedBankTargetGiBCount = 4;

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
