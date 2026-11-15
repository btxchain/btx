// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promotegate/candidate.h>

namespace modelnet {

bool SwarmPromoteCandidate::replace(const std::string& id)
{
    if (id.empty()) return false;
    m_id = id;
    return true;
}

void SwarmPromoteCandidate::clear()
{
    m_id.clear();
}

} // namespace modelnet
