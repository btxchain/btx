// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEFWORK_LIMITS_H
#define BITCOIN_MODELNET_SWARM_DEFWORK_LIMITS_H

#include <cstdint>

namespace modelnet {

/** launched() stays this value. Nothing is started. */
inline constexpr bool kSwarmDefWorkLaunched = false;

/** gpu() stays this value. No device is used. */
inline constexpr bool kSwarmDefWorkGpu = false;

/** broadcast() stays this value. Nothing is published. */
inline constexpr bool kSwarmDefWorkBroadcast = false;

/** connected() stays this value. No socket is opened. */
inline constexpr bool kSwarmDefWorkConnected = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmDefWorkAutomaticSpend[] = "0";

/** atoms_moved() stays this value. Nothing is moved. */
inline constexpr int64_t kSwarmDefWorkAtomsMoved = 0;

static_assert(!kSwarmDefWorkLaunched, "this broker does not launch");
static_assert(!kSwarmDefWorkGpu, "this broker does not use a gpu");
static_assert(!kSwarmDefWorkBroadcast, "this broker does not broadcast");
static_assert(!kSwarmDefWorkConnected, "this broker does not connect");
static_assert(kSwarmDefWorkAutomaticSpend[0] == '0' && kSwarmDefWorkAutomaticSpend[1] == '\0',
              "automatic spend stays 0");
static_assert(kSwarmDefWorkAtomsMoved == 0, "atoms moved stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEFWORK_LIMITS_H
