// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckpttrust/keep.h>

namespace modelnet {

std::string SwarmCheckpointTrustKeep::first(const SwarmCheckpointTrustBook& book, const std::string& claim) const
{
    if (!book.contains(claim)) return {};
    return book.claim_of(claim);
}

} // namespace modelnet
