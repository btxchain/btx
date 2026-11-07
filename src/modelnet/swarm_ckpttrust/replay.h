// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTTRUST_REPLAY_H
#define BITCOIN_MODELNET_SWARM_CKPTTRUST_REPLAY_H

#include <modelnet/swarm_ckpttrust/book.h>

#include <string>

namespace modelnet {

/** True when claim is already stored. An empty claim is never a replay. */
bool SwarmCheckpointTrustIsReplay(const SwarmCheckpointTrustBook& book, const std::string& claim);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTTRUST_REPLAY_H
