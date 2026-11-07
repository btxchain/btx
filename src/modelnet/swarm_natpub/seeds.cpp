// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/seeds.h>

namespace modelnet {

const std::vector<std::string>& SwarmNatPubSeeds::list() const
{
    return m_seeds;
}

} // namespace modelnet
