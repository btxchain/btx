// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_TRAINING_H
#define BITCOIN_MODELNET_SWARM_GENERATION_TRAINING_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmGenerationTrainAttempt {
    int cycle{0};
    std::string outcome;
};

/**
 * Training attempts. Execute records a row and does not start a process.
 */
class SwarmGenerationTraining {
public:
    std::size_t count() const { return m_rows.size(); }
    void add(int cycle, std::string outcome);
    const std::vector<SwarmGenerationTrainAttempt>& rows() const { return m_rows; }

private:
    std::vector<SwarmGenerationTrainAttempt> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_TRAINING_H
