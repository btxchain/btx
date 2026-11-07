// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckpttrust/stay.h>

#include <modelnet/swarm_ckpttrust/codes.h>
#include <modelnet/swarm_ckpttrust/limits.h>

#include <string>

namespace modelnet {

std::string SwarmCheckpointTrustStay::refusal() const
{
    return std::string{kSwarmCheckpointTrustNotTrust};
}

bool SwarmCheckpointTrustStay::trusted() const
{
    return kSwarmCheckpointTrustTrusted;
}

} // namespace modelnet
