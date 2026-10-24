// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVOLVE_LINEAGE_GATE_H
#define BITCOIN_MODELNET_SWARM_EVOLVE_LINEAGE_GATE_H

#include <modelnet/swarm_lineage.h>

#include <string>
#include <vector>

namespace modelnet {

/**
 * Parent pointer for the next generation.
 * Adopt follows SwarmAdopt and a compatible SwarmLineage fork.
 * Average records incompatible descendant forks, then SwarmLineage::Average.
 * That returns NOT_AVERAGED and leaves the parent in place.
 */
class SwarmEvolveLineage {
public:
    bool Seed(const std::string& baseline, std::string& err);
    bool Adopt(const std::string& graduated_id, std::string& err);
    bool Average(const std::string& left, const std::string& right, std::string& err);

    bool Seeded() const { return m_seeded; }
    const std::string& Parent() const { return m_parent; }
    std::vector<std::string> Heads(const std::string& channel) const;

private:
    SwarmLineage m_lineage;
    std::string m_parent;
    bool m_seeded{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVOLVE_LINEAGE_GATE_H
