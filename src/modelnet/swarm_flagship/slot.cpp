// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flagship/slot.h>

#include <string>

namespace modelnet {

bool SwarmFlagshipSlot::recorded() const
{
    return !m_evidence.empty();
}

const std::string& SwarmFlagshipSlot::evidence() const
{
    return m_evidence;
}

bool SwarmFlagshipSlot::store(const std::string& evidence)
{
    if (evidence.empty() || !m_evidence.empty()) {
        return false;
    }
    m_evidence = evidence;
    return true;
}

void SwarmFlagshipSlot::clear()
{
    m_evidence.clear();
}

} // namespace modelnet
