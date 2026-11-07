// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GUESTHOLD_REPLAY_H
#define BITCOIN_MODELNET_SWARM_GUESTHOLD_REPLAY_H

#include <modelnet/swarm_guesthold/book.h>

#include <string>

namespace modelnet {

/** True when name is already stored. An empty name is never a replay. */
bool SwarmGuestHoldIsReplay(const SwarmGuestHoldBook& book, const std::string& name);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GUESTHOLD_REPLAY_H
