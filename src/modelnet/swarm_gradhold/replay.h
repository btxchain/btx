// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GRADHOLD_REPLAY_H
#define BITCOIN_MODELNET_SWARM_GRADHOLD_REPLAY_H

#include <modelnet/swarm_gradhold/book.h>

#include <string>

namespace modelnet {

/** True when update_id is already stored. An empty id is never a replay. */
bool SwarmGradHoldIsReplay(const SwarmGradHoldBook& book, const std::string& update_id);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GRADHOLD_REPLAY_H
