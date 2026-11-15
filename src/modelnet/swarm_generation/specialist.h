// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_SPECIALIST_H
#define BITCOIN_MODELNET_SWARM_GENERATION_SPECIALIST_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmGenerationSpecialistRow {
    std::string name;
    std::string candidate_id;
};

/**
 * Named specialists. They do not replace general/stable.
 */
class SwarmGenerationSpecialists {
public:
    std::size_t count() const { return m_rows.size(); }
    void add(std::string name, std::string candidate_id);
    const std::vector<SwarmGenerationSpecialistRow>& rows() const { return m_rows; }

private:
    std::vector<SwarmGenerationSpecialistRow> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_SPECIALIST_H
