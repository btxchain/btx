// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/seeds.h>

#include <modelnet/swarm_nodedefault/codes.h>

namespace modelnet {

const std::vector<std::string>& SwarmNodeDefaultSeeds::dns_seeds() const
{
    return m_seeds;
}

bool SwarmNodeDefaultSeeds::AddSeed(const std::string&, std::string& err)
{
    err = kSwarmNodeDefaultHeld;
    return false;
}

} // namespace modelnet
