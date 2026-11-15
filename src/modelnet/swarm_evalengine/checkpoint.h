// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_CHECKPOINT_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_CHECKPOINT_H

#include <map>
#include <string>
#include <utility>

namespace modelnet {

/**
 * Candidate checkpoint id bound to one experiment.
 * The candidate string is the checkpoint id. The pair is the binding.
 * A second bind of the same pair keeps the first record.
 */
struct SwarmEvaluationCheckpoint {
    std::string experiment;
    std::string candidate;
};

/**
 * Bindings for the population. Keyed by experiment and candidate.
 * store refuses an empty candidate and a pair already present.
 * There is no erase.
 */
class SwarmEvaluationCheckpointBook {
public:
    bool bound(const std::string& experiment, const std::string& candidate) const;
    bool store(const std::string& experiment, const std::string& candidate);

private:
    using Key = std::pair<std::string, std::string>;
    std::map<Key, SwarmEvaluationCheckpoint> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_CHECKPOINT_H
