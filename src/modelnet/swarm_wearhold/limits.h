// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WEARHOLD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_WEARHOLD_LIMITS_H

#include <cstdint>

namespace modelnet {

/** joules below this is MEASURE and is not stored. */
inline constexpr int64_t kSwarmWearHoldMinJoule = 1;

/** joules() when Measure has stored nothing. */
inline constexpr int64_t kSwarmWearHoldUnset = 0;

/** atoms_moved() stays this value. A measurement is not a charge. */
inline constexpr int64_t kSwarmWearHoldAtomsMoved = 0;

/** charged() stays this value. Charge adds no atoms. */
inline constexpr bool kSwarmWearHoldCharged = false;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmWearHoldBytesMoved = 0;

/** Measure and Charge do not broadcast. */
inline constexpr bool kSwarmWearHoldBroadcast = false;

/** Measure and Charge do not use a gpu. */
inline constexpr bool kSwarmWearHoldGpu = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmWearHoldAutomaticSpend[] = "0";

static_assert(kSwarmWearHoldMinJoule == 1, "a stored measurement is at least 1 joule");
static_assert(kSwarmWearHoldUnset == 0, "an empty plane stores no joules");
static_assert(kSwarmWearHoldMinJoule != kSwarmWearHoldUnset, "a stored joule count is distinct from empty");
static_assert(kSwarmWearHoldAtomsMoved == 0, "a wear measurement moves no atoms");
static_assert(!kSwarmWearHoldCharged, "a wear measurement is not a charge");
static_assert(kSwarmWearHoldBytesMoved == 0, "a wear measurement moves no bytes");
static_assert(!kSwarmWearHoldBroadcast, "a wear measurement does not broadcast");
static_assert(!kSwarmWearHoldGpu, "a wear measurement does not use a gpu");
static_assert(kSwarmWearHoldAutomaticSpend[0] == '0' && kSwarmWearHoldAutomaticSpend[1] == '\0',
              "automatic spend stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WEARHOLD_LIMITS_H
