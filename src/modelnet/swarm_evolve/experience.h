// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVOLVE_EXPERIENCE_H
#define BITCOIN_MODELNET_SWARM_EVOLVE_EXPERIENCE_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

/** One accepted trajectory. Private kinds never become a row. */
struct SwarmEvolveExperienceItem {
    std::string kind;
    std::string body;
};

/**
 * Experience intake for one generation.
 * SwarmContributionKind accepts public_trajectory and synthetic_trajectory.
 * Any other kind is PRIVATE_DATA and is not stored.
 */
class SwarmEvolveExperience {
public:
    bool Accept(const std::string& kind, const std::string& body, std::string& err);
    void Clear();
    std::size_t Size() const { return m_items.size(); }
    const std::vector<SwarmEvolveExperienceItem>& Items() const { return m_items; }

private:
    std::vector<SwarmEvolveExperienceItem> m_items;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVOLVE_EXPERIENCE_H
