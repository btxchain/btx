// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forward/ledger.h>

namespace modelnet {

void SwarmForwardLedger::Note(const SwarmForwardHop& hop)
{
    m_hops.push_back(hop);
}

std::size_t SwarmForwardLedger::size() const
{
    return m_hops.size();
}

} // namespace modelnet
