// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PLANNER_LIMITS_H
#define BITCOIN_MODELNET_SWARM_PLANNER_LIMITS_H

#include <cstdint>

namespace modelnet {

/** launched() stays this value. Nothing is started. */
inline constexpr bool kSwarmPlannerLaunched = false;

/** gpu() stays this value. No device is used. */
inline constexpr bool kSwarmPlannerGpu = false;

/** broadcast() stays this value. Nothing is published. */
inline constexpr bool kSwarmPlannerBroadcast = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmPlannerAutomaticSpend[] = "0";

/** bytes_moved() stays this value. No bytes are moved. */
inline constexpr int64_t kSwarmPlannerBytesMoved = 0;

static_assert(!kSwarmPlannerLaunched, "this planner does not launch");
static_assert(!kSwarmPlannerGpu, "this planner does not use a gpu");
static_assert(!kSwarmPlannerBroadcast, "this planner does not broadcast");
static_assert(kSwarmPlannerAutomaticSpend[0] == '0' && kSwarmPlannerAutomaticSpend[1] == '\0',
              "automatic spend stays 0");
static_assert(kSwarmPlannerBytesMoved == 0, "bytes moved stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PLANNER_LIMITS_H
