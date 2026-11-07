// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/seeds.h>

#include <modelnet/swarm_privfam/codes.h>

namespace modelnet {

bool SwarmPrivFamSeeds::Add(const std::string& host, std::string& err)
{
    // The host is not retained, empty or not. Nothing connects.
    (void)host;
    err = kSwarmPrivFamHeld;
    return false;
}

const std::vector<std::string>& SwarmPrivFamSeeds::list() const
{
    return m_seeds;
}

} // namespace modelnet
