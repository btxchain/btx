// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/discover.h>

#include <modelnet/swarm_familyadmit/limits.h>

namespace modelnet {

bool SwarmFamilyAdmitDiscover::connects(const std::string& peer) const
{
    // An admitted id and an unknown id are the same: discovery does not connect.
    (void)peer;
    return kSwarmFamilyAdmitConnected;
}

} // namespace modelnet
