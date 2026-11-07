// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/lineage.h>

namespace modelnet {

void SwarmGenerationLineage::advance(const std::string& parent)
{
    m_parent = parent;
    ++m_cycle;
}

} // namespace modelnet
