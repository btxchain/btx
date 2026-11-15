// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canaryback/candidate.h>

namespace modelnet {

bool SwarmCanaryBackCandidate::held() const
{
    return !m_id.empty();
}

bool SwarmCanaryBackCandidate::adopted() const
{
    return m_adopted;
}

const std::string& SwarmCanaryBackCandidate::id() const
{
    return m_id;
}

void SwarmCanaryBackCandidate::store(const std::string& id)
{
    m_id = id;
    m_adopted = false;
}

void SwarmCanaryBackCandidate::mark_adopted()
{
    m_adopted = true;
}

void SwarmCanaryBackCandidate::clear()
{
    m_id.clear();
    m_adopted = false;
}

} // namespace modelnet
