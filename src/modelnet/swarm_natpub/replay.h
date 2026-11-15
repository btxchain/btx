// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NATPUB_REPLAY_H
#define BITCOIN_MODELNET_SWARM_NATPUB_REPLAY_H

#include <modelnet/swarm_natpub/book.h>

#include <string>

namespace modelnet {

/** True when endpoint is already stored. An empty endpoint is never a replay. */
bool SwarmNatPubIsReplay(const SwarmNatPubBook& book, const std::string& endpoint);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NATPUB_REPLAY_H
