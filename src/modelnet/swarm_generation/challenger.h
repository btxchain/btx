// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_CHALLENGER_H
#define BITCOIN_MODELNET_SWARM_GENERATION_CHALLENGER_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmGenerationChallengerRow {
    std::string candidate_id;
    std::string parent;
};

/**
 * Candidates that challenge the parent they were produced from.
 * Promotion does not remove the challenger row.
 */
class SwarmGenerationChallengers {
public:
    std::size_t count() const { return m_rows.size(); }
    void add(std::string candidate_id, std::string parent);
    const std::vector<SwarmGenerationChallengerRow>& rows() const { return m_rows; }

private:
    std::vector<SwarmGenerationChallengerRow> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_CHALLENGER_H
