// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/seeds.h>

#include <modelnet/swarm_familyadmit/codes.h>

namespace modelnet {

bool SwarmFamilyAdmitSeeds::Add(const std::string& seed, std::string& err)
{
    // The name is not retained, empty or not. Discovery does not connect.
    (void)seed;
    err = kSwarmFamilyAdmitHeld;
    return false;
}

const std::vector<std::string>& SwarmFamilyAdmitSeeds::list() const
{
    return m_seeds;
}

} // namespace modelnet
