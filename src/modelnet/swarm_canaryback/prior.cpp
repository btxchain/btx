// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canaryback/prior.h>

namespace modelnet {

SwarmCanaryBackPriorKind SwarmCanaryBackPrior::kind() const
{
    if (m_armed) return SwarmCanaryBackPriorKind::Armed;
    if (m_ever) return SwarmCanaryBackPriorKind::Spent;
    return SwarmCanaryBackPriorKind::Unadopted;
}

const std::string& SwarmCanaryBackPrior::id() const
{
    return m_id;
}

void SwarmCanaryBackPrior::arm(const std::string& id)
{
    m_id = id;
    m_armed = true;
    m_ever = true;
}

void SwarmCanaryBackPrior::disarm()
{
    m_id.clear();
    m_armed = false;
}

} // namespace modelnet
