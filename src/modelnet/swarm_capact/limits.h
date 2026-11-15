// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_LIMITS_H
#define BITCOIN_MODELNET_SWARM_CAPACT_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmCapActBytesMoved = 0;

/** Grant and Act do not launch a process. */
inline constexpr bool kSwarmCapActLaunched = false;

/** This plane does not claim a GPU ran. */
inline constexpr bool kSwarmCapActGpu = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmCapActAutomaticSpend[] = "0";

static_assert(kSwarmCapActBytesMoved == 0, "capability action moves no bytes");
static_assert(!kSwarmCapActLaunched, "capability action does not launch");
static_assert(!kSwarmCapActGpu, "capability action does not use a GPU");
static_assert(kSwarmCapActAutomaticSpend[0] == '0' && kSwarmCapActAutomaticSpend[1] == '\0',
              "automatic spend stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_LIMITS_H
