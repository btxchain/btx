// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_RESCAP_REPLAY_H
#define BITCOIN_MODELNET_SWARM_RESCAP_REPLAY_H

#include <modelnet/swarm_rescap/book.h>

#include <cstdint>

namespace modelnet {

/**
 * True when threads is already stored.
 * A count below 1 or above 64 is never a replay.
 */
bool SwarmResCapIsReplay(const SwarmResCapBook& book, int64_t threads);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_RESCAP_REPLAY_H
