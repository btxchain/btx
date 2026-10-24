// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_COLLATBOOK_QUIET_H
#define BITCOIN_MODELNET_SWARM_COLLATBOOK_QUIET_H

#include <cstdint>

namespace modelnet {

/** Nothing is broadcast. */
bool SwarmCollatBroadcast();

/** Nothing is sent. This stays 0. */
int64_t SwarmCollatBytesMoved();

/** A reservation does not earn. This stays 0. */
int64_t SwarmCollatEarned();

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_COLLATBOOK_QUIET_H
