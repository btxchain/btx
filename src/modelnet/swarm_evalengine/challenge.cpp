// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/challenge.h>

namespace modelnet {

bool SwarmEvaluationChallengeBook::contains(const std::string& id) const
{
    return m_rows.find(id) != m_rows.end();
}

bool SwarmEvaluationChallengeBook::moves_fitness(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) {
        return false;
    }
    return it->second.moves_fitness;
}

bool SwarmEvaluationChallengeBook::store(const std::string& id, bool informative, bool solvable)
{
    if (id.empty() || !informative || !solvable || contains(id)) {
        return false;
    }
    SwarmEvaluationChallenge challenge;
    challenge.id = id;
    challenge.informative = true;
    challenge.solvable = true;
    challenge.moves_fitness = false;
    m_rows.emplace(id, challenge);
    return true;
}

} // namespace modelnet
