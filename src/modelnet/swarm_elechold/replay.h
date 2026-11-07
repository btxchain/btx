// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ELECHOLD_REPLAY_H
#define BITCOIN_MODELNET_SWARM_ELECHOLD_REPLAY_H

#include <modelnet/swarm_elechold/book.h>

#include <cstdint>

namespace modelnet {

/**
 * True when watt_hours is at least 1 and a measurement is already stored.
 * A value below 1 is not a replay.
 */
bool SwarmElecHoldIsReplay(const SwarmElecHoldBook& book, int64_t watt_hours);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ELECHOLD_REPLAY_H
