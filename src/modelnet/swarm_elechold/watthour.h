// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ELECHOLD_WATTHOUR_H
#define BITCOIN_MODELNET_SWARM_ELECHOLD_WATTHOUR_H

#include <cstdint>

namespace modelnet {

/** True when watt_hours is below 1. That measure stores nothing. */
bool SwarmElecHoldBelowOne(int64_t watt_hours);

/** True when watt_hours is at least 1 and may be stored. */
bool SwarmElecHoldStorable(int64_t watt_hours);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ELECHOLD_WATTHOUR_H
