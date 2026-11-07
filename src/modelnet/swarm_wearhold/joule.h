// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WEARHOLD_JOULE_H
#define BITCOIN_MODELNET_SWARM_WEARHOLD_JOULE_H

#include <cstdint>

namespace modelnet {

/** True when joules is below 1. That measure stores nothing. */
bool SwarmWearHoldBelowOne(int64_t joules);

/** True when joules is at least 1 and may be stored. */
bool SwarmWearHoldStorable(int64_t joules);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WEARHOLD_JOULE_H
