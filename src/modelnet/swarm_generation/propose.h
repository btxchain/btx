// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_PROPOSE_H
#define BITCOIN_MODELNET_SWARM_GENERATION_PROPOSE_H

#include <modelnet/swarm_generation/frontier.h>
#include <modelnet/swarm_generation/strategy.h>

#include <string>

namespace modelnet {

class SwarmGenerationPropose {
public:
    bool Apply(const SwarmGenerationStrategy& strategy, SwarmGenerationFrontier& frontier, const std::string& experiment, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_PROPOSE_H
