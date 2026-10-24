// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckpttrust/replay.h>

namespace modelnet {

bool SwarmCheckpointTrustIsReplay(const SwarmCheckpointTrustBook& book, const std::string& claim)
{
    if (claim.empty()) return false;
    return book.contains(claim);
}

} // namespace modelnet
