// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEFENSE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_DEFENSE_LIMITS_H

#include <cstdint>

namespace modelnet {

/** launched() stays this value. No method sets it true. Nothing is started. */
inline constexpr bool kSwarmDefenseLaunched = false;

/** gpu() stays this value. No device is used. */
inline constexpr bool kSwarmDefenseGpu = false;

/** broadcast() stays this value. Nothing is sent. */
inline constexpr bool kSwarmDefenseBroadcast = false;

/** connected() stays this value. No session is opened. */
inline constexpr bool kSwarmDefenseConnected = false;

/** windows_passed() stays this value. No method sets it true. */
inline constexpr bool kSwarmDefenseWindowsPassed = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmDefenseAutomaticSpend[] = "0";

/** bytes_moved() stays this value. This plane does not move bytes off the node. */
inline constexpr int64_t kSwarmDefenseBytesMoved = 0;

static_assert(!kSwarmDefenseLaunched, "this plane does not launch");
static_assert(!kSwarmDefenseGpu, "this plane does not use a gpu");
static_assert(!kSwarmDefenseBroadcast, "this plane does not broadcast");
static_assert(!kSwarmDefenseConnected, "this plane does not connect");
static_assert(!kSwarmDefenseWindowsPassed, "this plane does not pass windows");
static_assert(kSwarmDefenseAutomaticSpend[0] == '0' && kSwarmDefenseAutomaticSpend[1] == '\0',
              "automatic spend stays 0");
static_assert(kSwarmDefenseBytesMoved == 0, "bytes moved stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEFENSE_LIMITS_H
