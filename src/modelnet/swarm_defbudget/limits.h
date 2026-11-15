// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEFBUDGET_LIMITS_H
#define BITCOIN_MODELNET_SWARM_DEFBUDGET_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Pool that holds readiness atoms. Other names are refused. */
inline constexpr char kSwarmDefBudgetPoolReadiness[] = "readiness";

/** Pool that holds incident atoms. Other names are refused. */
inline constexpr char kSwarmDefBudgetPoolIncident[] = "incident";

/** Pool that holds improvement atoms. Other names are refused. */
inline constexpr char kSwarmDefBudgetPoolImprovement[] = "improvement";

/** launched() stays this value. No method sets it true. */
inline constexpr bool kSwarmDefBudgetLaunched = false;

/** gpu() stays this value. No device is used. */
inline constexpr bool kSwarmDefBudgetGpu = false;

/** broadcast() stays this value. Nothing is sent. */
inline constexpr bool kSwarmDefBudgetBroadcast = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmDefBudgetAutomaticSpend[] = "0";

/** atoms_moved() stays this value. Ledger rows are not a move. */
inline constexpr int64_t kSwarmDefBudgetAtomsMoved = 0;

static_assert(kSwarmDefBudgetPoolReadiness[0] != '\0', "readiness name");
static_assert(kSwarmDefBudgetPoolIncident[0] != '\0', "incident name");
static_assert(kSwarmDefBudgetPoolImprovement[0] != '\0', "improvement name");
static_assert(!kSwarmDefBudgetLaunched, "this budget does not launch");
static_assert(!kSwarmDefBudgetGpu, "this budget does not use a gpu");
static_assert(!kSwarmDefBudgetBroadcast, "this budget does not broadcast");
static_assert(kSwarmDefBudgetAutomaticSpend[0] == '0' && kSwarmDefBudgetAutomaticSpend[1] == '\0',
              "automatic spend stays 0");
static_assert(kSwarmDefBudgetAtomsMoved == 0, "atoms moved stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEFBUDGET_LIMITS_H
