// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_VERIFY_BUDGET_H
#define BTX_MATMUL_MATMUL_V4_RC_VERIFY_BUDGET_H

#include <cstdint>
#include <string>

// Stage-I verification budgets for ENC_RC (PROVISIONAL; height stays disabled).
//
// Derived from consensus block interval nPowTargetSpacing (= 90 s on public nets):
//   happy-path (succinct GKR+FRI verify) ≤ kRCVerifyBudgetFracBps of interval
//   ExactReplay (ε=0 int64 CPU, today's load-bearing path while arbiter OFF)
//       ≤ kRCExactReplayBudgetFracBps of interval
//
// See doc/btx-matmul-v4.5-rc-verify-budget-2026-07-21.md.

namespace matmul::v4::rc {

/** Matches Consensus::Params::nPowTargetSpacing on main/test/signet (seconds). */
inline constexpr int64_t kRCPowTargetSpacingS = 90;

/** Happy-path succinct verify budget: 100 bps = 1% of interval → 0.9 s @ 90 s. */
inline constexpr uint32_t kRCVerifyBudgetFracBps = 100;

/** ExactReplay verify budget: 1000 bps = 10% of interval → 9.0 s @ 90 s. */
inline constexpr uint32_t kRCExactReplayBudgetFracBps = 1000;

[[nodiscard]] inline constexpr double RCHappyPathVerifyBudgetS(
    int64_t interval_s = kRCPowTargetSpacingS)
{
    return static_cast<double>(interval_s) *
           (static_cast<double>(kRCVerifyBudgetFracBps) / 10000.0);
}

[[nodiscard]] inline constexpr double RCExactReplayVerifyBudgetS(
    int64_t interval_s = kRCPowTargetSpacingS)
{
    return static_cast<double>(interval_s) *
           (static_cast<double>(kRCExactReplayBudgetFracBps) / 10000.0);
}

/** Unified happy-path budget (GKR+FRI share one per-block ceiling). */
inline constexpr double kRCHappyPathVerifyBudgetS = RCHappyPathVerifyBudgetS();
inline constexpr double kRCExactReplayVerifyBudgetS = RCExactReplayVerifyBudgetS();

enum class RCVerifyPathKind : uint8_t {
    HappyPathSuccinct = 0,
    ExactReplay = 1,
};

/**
 * Stage-I hard gate: measured verify wall must be ≤ the interval-fraction budget
 * for the selected path. Returns false (and fills why) on overrun.
 */
[[nodiscard]] inline bool VerifyMeetsStageIBudget(double measured_verify_s,
                                                  int64_t interval_s,
                                                  RCVerifyPathKind path,
                                                  std::string* why = nullptr)
{
    if (!(measured_verify_s >= 0.0) || interval_s <= 0) {
        if (why) *why = "invalid measured_verify_s or interval_s";
        return false;
    }
    const double budget = (path == RCVerifyPathKind::ExactReplay)
                              ? RCExactReplayVerifyBudgetS(interval_s)
                              : RCHappyPathVerifyBudgetS(interval_s);
    if (measured_verify_s > budget) {
        if (why) {
            *why = "verify wall " + std::to_string(measured_verify_s) + "s exceeds Stage-I budget " +
                   std::to_string(budget) + "s (interval=" + std::to_string(interval_s) + "s)";
        }
        return false;
    }
    return true;
}

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_VERIFY_BUDGET_H
