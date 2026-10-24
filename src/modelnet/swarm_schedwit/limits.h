// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCHEDWITNESS_LIMITS_H
#define BITCOIN_MODELNET_SWARM_SCHEDWITNESS_LIMITS_H

#include <cstdint>

namespace modelnet {

/** atoms_moved() stays this value. A stored witness moves no atoms. */
inline constexpr int64_t kSwarmSchedWitnessAtomsMoved = 0;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmSchedWitnessAutomaticSpend[] = "0";

/** Sign does not broadcast. */
inline constexpr bool kSwarmSchedWitnessBroadcast = false;

/** This plane moves no bytes. A recorded witness is not a payload. */
inline constexpr int64_t kSwarmSchedWitnessBytesMoved = 0;

/** Sign does not touch a GPU. */
inline constexpr bool kSwarmSchedWitnessGpu = false;

/** A stored witness is never signed. */
inline constexpr bool kSwarmSchedWitnessSignedOk = false;

static_assert(kSwarmSchedWitnessAtomsMoved == 0, "a scheduler witness moves no atoms");
static_assert(kSwarmSchedWitnessAutomaticSpend[0] == '0' && kSwarmSchedWitnessAutomaticSpend[1] == '\0',
              "automatic spend stays 0");
static_assert(!kSwarmSchedWitnessBroadcast, "a scheduler witness does not broadcast");
static_assert(kSwarmSchedWitnessBytesMoved == 0, "a scheduler witness moves no bytes");
static_assert(!kSwarmSchedWitnessGpu, "a scheduler witness does not use a gpu");
static_assert(!kSwarmSchedWitnessSignedOk, "a scheduler witness is not signed");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCHEDWITNESS_LIMITS_H
