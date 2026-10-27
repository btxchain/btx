// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/discover.h>

#include <modelnet/swarm_privfam/limits.h>

namespace modelnet {

bool SwarmPrivFamDiscover::connects() const
{
    return kSwarmPrivFamConnected;
}

bool SwarmPrivFamDiscover::connects(const std::string& family) const
{
    // A stored family and an unknown family are the same: nothing connects.
    (void)family;
    return kSwarmPrivFamConnected;
}

} // namespace modelnet
