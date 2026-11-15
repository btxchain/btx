// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINHOLD_REPLAY_H
#define BITCOIN_MODELNET_SWARM_ADMINHOLD_REPLAY_H

#include <modelnet/swarm_adminhold/book.h>

#include <string>

namespace modelnet {

/** True when channel is already stored. An empty channel is never a replay. */
bool SwarmAdminHoldIsReplay(const SwarmAdminHoldBook& book, const std::string& channel);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINHOLD_REPLAY_H
