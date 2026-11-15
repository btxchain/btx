// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/checkpoint.h>

namespace modelnet {

bool SwarmEvaluationCheckpointBook::bound(const std::string& experiment, const std::string& candidate) const
{
    return m_rows.find(Key{experiment, candidate}) != m_rows.end();
}

bool SwarmEvaluationCheckpointBook::store(const std::string& experiment, const std::string& candidate)
{
    if (candidate.empty() || bound(experiment, candidate)) {
        return false;
    }
    SwarmEvaluationCheckpoint checkpoint;
    checkpoint.experiment = experiment;
    checkpoint.candidate = candidate;
    m_rows.emplace(Key{experiment, candidate}, checkpoint);
    return true;
}

} // namespace modelnet
