// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckpttrust/blank.h>

#include <modelnet/swarm_ckpttrust/codes.h>

namespace modelnet {

bool SwarmCheckpointTrustBlank::accept(const std::string& claim, std::string& err) const
{
    if (claim.empty()) {
        err = kSwarmCheckpointTrustClaim;
        return false;
    }
    return true;
}

} // namespace modelnet
