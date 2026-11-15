// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LANWIRE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_LANWIRE_LIMITS_H

#include <cstdint>

namespace modelnet {

/** SO_RCVTIMEO for the one loopback recv, in milliseconds. */
inline constexpr int64_t kSwarmLanWireRecvTimeoutMs = 200;

/** launched() stays this value. Nothing is started. */
inline constexpr bool kSwarmLanWireLaunched = false;

/** gpu() stays this value. No device is used. */
inline constexpr bool kSwarmLanWireGpu = false;

/** broadcast() stays this value. Nothing is published. */
inline constexpr bool kSwarmLanWireBroadcast = false;

/** connected() stays this value. The datagram socket is closed before return. */
inline constexpr bool kSwarmLanWireConnected = false;

/** wan_received() stays this value. Wan does not receive. */
inline constexpr bool kSwarmLanWireWanReceived = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmLanWireAutomaticSpend[] = "0";

/** bytes_moved() before a successful Exchange, and after a failed one that stored nothing. */
inline constexpr int64_t kSwarmLanWireBytesIdle = 0;

/** packets() before a successful Exchange. */
inline constexpr int64_t kSwarmLanWirePacketsIdle = 0;

/** packets() after a successful Exchange. One datagram. */
inline constexpr int64_t kSwarmLanWirePacketsOne = 1;

static_assert(kSwarmLanWireRecvTimeoutMs == 200, "recv timeout is 200 ms");
static_assert(!kSwarmLanWireLaunched, "this wire does not launch");
static_assert(!kSwarmLanWireGpu, "this wire does not use a gpu");
static_assert(!kSwarmLanWireBroadcast, "this wire does not broadcast");
static_assert(!kSwarmLanWireConnected, "this wire does not stay connected");
static_assert(!kSwarmLanWireWanReceived, "wan receives nothing");
static_assert(kSwarmLanWireAutomaticSpend[0] == '0' && kSwarmLanWireAutomaticSpend[1] == '\0',
              "automatic spend stays 0");
static_assert(kSwarmLanWireBytesIdle == 0, "idle bytes moved stay 0");
static_assert(kSwarmLanWirePacketsIdle == 0, "idle packet count stays 0");
static_assert(kSwarmLanWirePacketsOne == 1, "one exchange counts one packet");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LANWIRE_LIMITS_H
