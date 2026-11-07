// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/discover.h>

#include <modelnet/swarm_natpub/limits.h>

namespace modelnet {

bool SwarmNatPubDiscover::connects() const
{
    return kSwarmNatPubConnected;
}

bool SwarmNatPubDiscover::connects(const std::string& endpoint) const
{
    // A stored endpoint and an unknown endpoint are the same: nothing connects.
    (void)endpoint;
    return kSwarmNatPubConnected;
}

} // namespace modelnet
