// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/experience.h>

#include <modelnet/swarm_frontier.h>

#include <utility>

namespace modelnet {

bool SwarmEvolveExperience::Accept(const std::string& kind, const std::string& body, std::string& err)
{
    if (!SwarmContributionKind(kind, err)) {
        return false;
    }
    SwarmEvolveExperienceItem item;
    item.kind = kind;
    item.body = body;
    m_items.push_back(std::move(item));
    err.clear();
    return true;
}

void SwarmEvolveExperience::Clear()
{
    m_items.clear();
}

} // namespace modelnet
