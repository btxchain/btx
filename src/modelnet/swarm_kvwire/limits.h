// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVWIRE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_KVWIRE_LIMITS_H

namespace modelnet {

/** launched() stays this value. Nothing starts. */
inline constexpr bool kSwarmKvWireLaunched = false;

/** gpu() stays this value. No device is used. */
inline constexpr bool kSwarmKvWireGpu = false;

/** broadcast() stays this value. Nothing is published. */
inline constexpr bool kSwarmKvWireBroadcast = false;

/** connected() stays this value. The pair is closed before return. */
inline constexpr bool kSwarmKvWireConnected = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmKvWireAutomaticSpend[] = "0";

static_assert(!kSwarmKvWireLaunched, "this plane does not launch");
static_assert(!kSwarmKvWireGpu, "this plane does not use a gpu");
static_assert(!kSwarmKvWireBroadcast, "this plane does not broadcast");
static_assert(!kSwarmKvWireConnected, "this plane does not stay connected");
static_assert(kSwarmKvWireAutomaticSpend[0] == '0' && kSwarmKvWireAutomaticSpend[1] == '\0',
              "automatic spend stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVWIRE_LIMITS_H
