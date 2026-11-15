// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_CHALLENGE_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_CHALLENGE_H

#include <map>
#include <string>

namespace modelnet {

/**
 * One stored challenge.
 * It is informative and solvable. moves_fitness stays false: storing a
 * challenge does not move fitness. An empty id is not stored. A challenge
 * that is not informative or not solvable is not stored.
 */
struct SwarmEvaluationChallenge {
    std::string id;
    bool informative{false};
    bool solvable{false};
    bool moves_fitness{false};
};

/**
 * Challenges keyed by id.
 * store refuses an empty id, a challenge that is not informative, a
 * challenge that is not solvable, and an id already present.
 * The stored row does not move fitness. There is no erase.
 */
class SwarmEvaluationChallengeBook {
public:
    bool contains(const std::string& id) const;
    bool moves_fitness(const std::string& id) const;
    bool store(const std::string& id, bool informative, bool solvable);

private:
    std::map<std::string, SwarmEvaluationChallenge> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_CHALLENGE_H
