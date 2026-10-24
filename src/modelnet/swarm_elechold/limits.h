// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ELECHOLD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_ELECHOLD_LIMITS_H

#include <cstdint>

namespace modelnet {

/** watt_hours below this is MEASURE and is not stored. */
inline constexpr int64_t kSwarmElecHoldMinWattHour = 1;

/** watt_hours() when Measure has stored nothing. */
inline constexpr int64_t kSwarmElecHoldUnset = 0;

/** atoms_moved() stays this value. A measurement is not a charge. */
inline constexpr int64_t kSwarmElecHoldAtomsMoved = 0;

/** charged() stays this value. Charge adds no atoms. */
inline constexpr bool kSwarmElecHoldCharged = false;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmElecHoldBytesMoved = 0;

/** Measure and Charge do not broadcast. */
inline constexpr bool kSwarmElecHoldBroadcast = false;

/** Measure and Charge do not use a gpu. */
inline constexpr bool kSwarmElecHoldGpu = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmElecHoldAutomaticSpend[] = "0";

static_assert(kSwarmElecHoldMinWattHour == 1, "a stored measurement is at least 1 watt-hour");
static_assert(kSwarmElecHoldUnset == 0, "an empty plane stores no watt-hours");
static_assert(kSwarmElecHoldMinWattHour != kSwarmElecHoldUnset, "a stored watt-hour count is distinct from empty");
static_assert(kSwarmElecHoldAtomsMoved == 0, "a watt-hour measurement moves no atoms");
static_assert(!kSwarmElecHoldCharged, "a watt-hour measurement is not a charge");
static_assert(kSwarmElecHoldBytesMoved == 0, "a watt-hour measurement moves no bytes");
static_assert(!kSwarmElecHoldBroadcast, "a watt-hour measurement does not broadcast");
static_assert(!kSwarmElecHoldGpu, "a watt-hour measurement does not use a gpu");
static_assert(kSwarmElecHoldAutomaticSpend[0] == '0' && kSwarmElecHoldAutomaticSpend[1] == '\0',
              "automatic spend stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ELECHOLD_LIMITS_H
