// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FLAGSHIP_LIMITS_H
#define BITCOIN_MODELNET_SWARM_FLAGSHIP_LIMITS_H

#include <cstdint>

namespace modelnet {

/** A recorded evidence id is not a passed flagship stage. */
inline constexpr bool kSwarmFlagshipPassed = false;

/** A recorded evidence id is not a passed GPU run. */
inline constexpr bool kSwarmFlagshipGpuPassed = false;

/** A recorded evidence id is not a passed Windows run. */
inline constexpr bool kSwarmFlagshipWindowsPassed = false;

/** A recorded evidence id is not a passed payment. */
inline constexpr bool kSwarmFlagshipPayPassed = false;

/** This plane does not launch a process. */
inline constexpr bool kSwarmFlagshipLaunched = false;

/** This plane does not use a GPU. */
inline constexpr bool kSwarmFlagshipGpu = false;

/** This plane does not broadcast. */
inline constexpr bool kSwarmFlagshipBroadcast = false;

/** This plane moves no bytes. */
inline constexpr std::uint64_t kSwarmFlagshipBytesMoved = 0;

/** This plane moves no atoms. */
inline constexpr std::uint64_t kSwarmFlagshipAtomsMoved = 0;

/** This plane does not spend. The text is the zero amount. */
inline constexpr char kSwarmFlagshipAutomaticSpend[] = "0";

static_assert(!kSwarmFlagshipPassed, "a flagship stage is not passed");
static_assert(!kSwarmFlagshipGpuPassed, "a gpu run is not passed");
static_assert(!kSwarmFlagshipWindowsPassed, "a windows run is not passed");
static_assert(!kSwarmFlagshipPayPassed, "a payment is not passed");
static_assert(!kSwarmFlagshipLaunched, "flagship evidence does not launch");
static_assert(!kSwarmFlagshipGpu, "flagship evidence does not use a gpu");
static_assert(!kSwarmFlagshipBroadcast, "flagship evidence does not broadcast");
static_assert(kSwarmFlagshipBytesMoved == 0, "flagship evidence moves no bytes");
static_assert(kSwarmFlagshipAtomsMoved == 0, "flagship evidence moves no atoms");
static_assert(kSwarmFlagshipAutomaticSpend[0] == '0', "spend stays 0");
static_assert(kSwarmFlagshipAutomaticSpend[1] == '\0', "spend stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FLAGSHIP_LIMITS_H
