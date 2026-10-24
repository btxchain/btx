// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_QUOTEFIAT_REPLAY_H
#define BITCOIN_MODELNET_SWARM_QUOTEFIAT_REPLAY_H

#include <modelnet/swarm_quotefiat/book.h>

#include <string>

namespace modelnet {

/** True when usd is already stored. An empty usd is never a replay. */
bool SwarmQuoteFiatIsReplay(const SwarmQuoteFiatBook& book, const std::string& usd);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_QUOTEFIAT_REPLAY_H
