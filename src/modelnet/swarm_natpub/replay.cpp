// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/replay.h>

namespace modelnet {

bool SwarmNatPubIsReplay(const SwarmNatPubBook& book, const std::string& endpoint)
{
    if (endpoint.empty()) return false;
    return book.contains(endpoint);
}

} // namespace modelnet
