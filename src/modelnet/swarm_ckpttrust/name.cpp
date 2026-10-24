// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckpttrust/name.h>

namespace modelnet {

std::string SwarmCheckpointTrustName::copy(const std::string& claim) const
{
    if (claim.empty()) return {};
    return claim;
}

} // namespace modelnet
