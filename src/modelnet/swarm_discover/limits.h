// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISCOVER_LIMITS_H
#define BITCOIN_MODELNET_SWARM_DISCOVER_LIMITS_H

#include <cstdint>

namespace modelnet {

/** launched() stays this value. Nothing is started. */
inline constexpr bool kSwarmDiscoverLaunched = false;

/** gpu() stays this value. No device is used. */
inline constexpr bool kSwarmDiscoverGpu = false;

/** broadcast() stays this value. Nothing is published. */
inline constexpr bool kSwarmDiscoverBroadcast = false;

/** connected() stays this value. No socket is opened. */
inline constexpr bool kSwarmDiscoverConnected = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmDiscoverAutomaticSpend[] = "0";

/** bytes_moved() stays this value. No bytes are moved. */
inline constexpr int64_t kSwarmDiscoverBytesMoved = 0;

static_assert(!kSwarmDiscoverLaunched, "this record does not launch");
static_assert(!kSwarmDiscoverGpu, "this record does not use a gpu");
static_assert(!kSwarmDiscoverBroadcast, "this record does not broadcast");
static_assert(!kSwarmDiscoverConnected, "this record does not connect");
static_assert(kSwarmDiscoverAutomaticSpend[0] == '0' && kSwarmDiscoverAutomaticSpend[1] == '\0',
              "automatic spend stays 0");
static_assert(kSwarmDiscoverBytesMoved == 0, "bytes moved stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISCOVER_LIMITS_H
