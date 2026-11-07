// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_ADOPTION_H
#define BITCOIN_MODELNET_SWARM_GENERATION_ADOPTION_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmGenerationAdoptionRow {
    std::string channel;
    std::string candidate_id;
};

/**
 * Adopted heads. Adopting a channel does not change any other channel.
 */
class SwarmGenerationAdoptions {
public:
    std::size_t count() const { return m_rows.size(); }
    void add(std::string channel, std::string candidate_id);
    const std::vector<SwarmGenerationAdoptionRow>& rows() const { return m_rows; }

private:
    std::vector<SwarmGenerationAdoptionRow> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_ADOPTION_H
