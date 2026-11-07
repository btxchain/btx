// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_PRODUCE_H
#define BITCOIN_MODELNET_SWARM_GENERATION_PRODUCE_H

#include <modelnet/swarm_generation/challenger.h>
#include <modelnet/swarm_generation/population.h>

#include <string>

namespace modelnet {

class SwarmGenerationProduce {
public:
    bool Apply(SwarmGenerationPopulation& population, SwarmGenerationChallengers& challengers,
               const std::string& parent, const std::string& recipe, const std::string& weights,
               const std::string& nonce, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_PRODUCE_H
