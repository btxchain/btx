// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_ALLOCATE_H
#define BITCOIN_MODELNET_SWARM_GENERATION_ALLOCATE_H

#include <modelnet/swarm_generation/strategy.h>

#include <string>

namespace modelnet {

class SwarmGenerationAllocate {
public:
    bool Apply(SwarmGenerationStrategy& strategy, int slots, int exploration_percent, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_ALLOCATE_H
