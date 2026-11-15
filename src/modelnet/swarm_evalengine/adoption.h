// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_ADOPTION_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_ADOPTION_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One adoption on a channel.
 * previous_active is the head that was active before this adoption.
 * adopted is the staged candidate that became active. The first
 * adoption records an empty previous head when nothing was active.
 */
struct SwarmEvaluationAdoption {
    std::string channel;
    std::string previous_active;
    std::string adopted;
};

/**
 * Adoption history.
 * push appends one row. count is the number of rows for that channel.
 * There is no erase. Adopting one channel does not change another.
 */
class SwarmEvaluationAdoptionBook {
public:
    void push(const std::string& channel, const std::string& previous_active, const std::string& adopted);
    std::size_t count(const std::string& channel) const;

private:
    std::vector<SwarmEvaluationAdoption> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_ADOPTION_H
