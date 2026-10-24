// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_ROLLBACK_H
#define BITCOIN_MODELNET_SWARM_GENERATION_ROLLBACK_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmGenerationRollbackRow {
    std::string channel;
    std::string previous_active;
};

/**
 * Heads replaced by Adopt. The history is append-only.
 */
class SwarmGenerationRollbacks {
public:
    std::size_t count() const { return m_rows.size(); }
    void push(std::string channel, std::string previous_active);
    const std::vector<SwarmGenerationRollbackRow>& rows() const { return m_rows; }

private:
    std::vector<SwarmGenerationRollbackRow> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_ROLLBACK_H
