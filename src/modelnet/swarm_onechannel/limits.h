// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ONECHANNEL_LIMITS_H
#define BITCOIN_MODELNET_SWARM_ONECHANNEL_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane keeps a single channel id. A second id is not stored. */
inline constexpr int kSwarmOneChannelSeatLimit = 1;

/** A reserved channel id is not a network open. */
inline constexpr bool kSwarmOneChannelNetworkOpened = false;

/** This plane does not broadcast. */
inline constexpr bool kSwarmOneChannelBroadcast = false;

/** This plane does not launch work. */
inline constexpr bool kSwarmOneChannelLaunched = false;

/** This plane does not use a gpu. */
inline constexpr bool kSwarmOneChannelGpu = false;

/** This plane moves no atoms. */
inline constexpr int64_t kSwarmOneChannelAtomsMoved = 0;

/** No automatic spend is armed. The value is the string "0". */
inline constexpr char kSwarmOneChannelAutomaticSpend[] = "0";

static_assert(kSwarmOneChannelSeatLimit == 1, "one channel seat");
static_assert(!kSwarmOneChannelNetworkOpened, "network opened stays false");
static_assert(!kSwarmOneChannelBroadcast, "broadcast stays false");
static_assert(!kSwarmOneChannelLaunched, "launched stays false");
static_assert(!kSwarmOneChannelGpu, "gpu stays false");
static_assert(kSwarmOneChannelAtomsMoved == 0, "atoms moved stay 0");
static_assert(kSwarmOneChannelAutomaticSpend[0] == '0', "automatic spend stays 0");
static_assert(kSwarmOneChannelAutomaticSpend[1] == '\0', "automatic spend is the string 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ONECHANNEL_LIMITS_H
