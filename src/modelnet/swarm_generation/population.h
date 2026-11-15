// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_POPULATION_H
#define BITCOIN_MODELNET_SWARM_GENERATION_POPULATION_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmGenerationCandidate {
    std::string id;
    std::string parent;
    std::string recipe;
    std::string weights;
    std::string nonce;
    bool verified{false};
};

/**
 * In-memory candidate population. Produce does not write a checkpoint.
 */
class SwarmGenerationPopulation {
public:
    const std::string& last_id() const;
    std::size_t size() const { return m_rows.size(); }
    const SwarmGenerationCandidate* find(const std::string& id) const;
    bool store(SwarmGenerationCandidate candidate);
    bool mark_verified(const std::string& id, const std::string& parent);
    bool verified(const std::string& id) const;

private:
    SwarmGenerationCandidate* find_mut(const std::string& id);
    std::vector<SwarmGenerationCandidate> m_rows;
    std::string m_last_id;
    std::string m_blank;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_POPULATION_H
