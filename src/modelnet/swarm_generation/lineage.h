// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_LINEAGE_H
#define BITCOIN_MODELNET_SWARM_GENERATION_LINEAGE_H

#include <string>

namespace modelnet {

/**
 * Parent and cycle for one family.
 * The parent starts empty. Continue is the only call that advances it.
 */
class SwarmGenerationLineage {
public:
    const std::string& parent() const { return m_parent; }
    int cycle() const { return m_cycle; }
    void advance(const std::string& parent);

private:
    std::string m_parent;
    int m_cycle{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_LINEAGE_H
