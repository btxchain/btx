// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISPUTESTAY_REPLAY_H
#define BITCOIN_MODELNET_SWARM_DISPUTESTAY_REPLAY_H

#include <modelnet/swarm_disputestay/book.h>

#include <string>

namespace modelnet {

/** True when dispute is already stored. An empty id is never a replay. */
bool SwarmDisputeStayIsReplay(const SwarmDisputeStayBook& book, const std::string& dispute);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISPUTESTAY_REPLAY_H
